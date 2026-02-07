//! Code generation for compiled policies

use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use scmm_common::{
    capture::arch,
    categories::x86_64 as syscalls,
    policy::{policy_flags, Action, CompiledPolicyHeader, YamlPolicy},
};

/// Compile a YAML policy to binary format
pub fn compile(policy: &YamlPolicy, target_arch: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    // Determine architecture
    let arch_id = match target_arch {
        "x86_64" => arch::X86_64,
        "aarch64" => arch::AARCH64,
        _ => arch::X86_64,
    };

    // Build seccomp filter
    let seccomp_filter = generate_seccomp_filter(policy, arch_id)?;

    // Build Landlock rules
    let landlock_rules = generate_landlock_rules(policy)?;

    // Build path table
    let path_table = generate_path_table(policy)?;

    // Calculate offsets
    let header_size = std::mem::size_of::<CompiledPolicyHeader>();
    let seccomp_offset = header_size;
    let landlock_offset = seccomp_offset + seccomp_filter.len();
    let path_table_offset = landlock_offset + landlock_rules.len();

    // Build flags
    let mut flags = 0u32;
    if !seccomp_filter.is_empty() {
        flags |= policy_flags::HAS_SECCOMP;
    }
    if !landlock_rules.is_empty() {
        flags |= policy_flags::HAS_LANDLOCK;
    }
    if policy.settings.default_action == Action::Allow {
        flags |= policy_flags::DEFAULT_ALLOW;
    }
    if policy.settings.log_denials {
        flags |= policy_flags::LOG_DENIALS;
    }

    // Build header
    let mut header = CompiledPolicyHeader::default();
    header.arch = arch_id;
    header.flags = flags;
    header.seccomp_filter_offset = seccomp_offset as u32;
    header.seccomp_filter_len = seccomp_filter.len() as u32;
    header.landlock_rules_offset = landlock_offset as u32;
    header.landlock_rules_len = landlock_rules.len() as u32;
    header.path_table_offset = path_table_offset as u32;
    header.path_table_len = path_table.len() as u32;

    // Write header
    let header_bytes = unsafe { scmm_common::struct_to_bytes(&header) };
    output.extend_from_slice(header_bytes);

    // Write seccomp filter
    output.extend_from_slice(&seccomp_filter);

    // Write Landlock rules
    output.extend_from_slice(&landlock_rules);

    // Write path table
    output.extend_from_slice(&path_table);

    Ok(output)
}

/// Generate seccomp BPF filter
fn generate_seccomp_filter(policy: &YamlPolicy, arch_id: u32) -> Result<Vec<u8>> {
    let mut instructions = Vec::new();

    // Seccomp BPF instruction format (sock_filter):
    // struct { u16 code, u8 jt, u8 jf, u32 k }

    // BPF instruction codes
    const BPF_LD: u16 = 0x00;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;

    // Seccomp return values
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
    const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    const EPERM: u32 = 1;

    // Helper to emit instruction
    fn emit(instructions: &mut Vec<u8>, code: u16, jt: u8, jf: u8, k: u32) {
        instructions.write_u16::<LittleEndian>(code).unwrap();
        instructions.push(jt);
        instructions.push(jf);
        instructions.write_u32::<LittleEndian>(k).unwrap();
    }

    // Load architecture (offset 4 in seccomp_data)
    emit(&mut instructions, BPF_LD | BPF_W | BPF_ABS, 0, 0, 4);

    // Check architecture - if not matching, kill
    // JEQ arch_id, 0, 1 (if equal, continue; if not, jump to kill)
    emit(&mut instructions, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, arch_id);
    emit(&mut instructions, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);

    // Load syscall number (offset 0 in seccomp_data)
    emit(&mut instructions, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0);

    // Build syscall lookup
    let mut allow_set: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut deny_syscalls: Vec<u32> = Vec::new();

    // Map syscall names to numbers (x86_64)
    let syscall_map = syscalls::build_name_to_nr_map();

    // Always allow bootstrap/enforcement syscalls.
    // The recorder captures syscalls after exec, so some are never in the trace
    // but the enforcer needs them to launch the target and apply Landlock.
    let bootstrap_syscalls: &[u32] = &[
        59,  // execve
        322, // execveat
        231, // exit_group
        60,  // exit
        157, // prctl (needed for PR_SET_NO_NEW_PRIVS)
        444, // landlock_create_ruleset
        445, // landlock_add_rule
        446, // landlock_restrict_self
    ];
    for &nr in bootstrap_syscalls {
        allow_set.insert(nr);
    }

    for rule in &policy.syscalls {
        if let Some(&nr) = syscall_map.get(rule.name.as_str()) {
            match rule.action {
                Action::Allow | Action::Log => { allow_set.insert(nr); }
                Action::Deny | Action::Kill => { deny_syscalls.push(nr); }
                Action::Trap => {}
            }
        }
    }

    let allow_syscalls: Vec<u32> = allow_set.into_iter().collect();

    // Calculate jump offsets
    // After all checks, we have: deny instruction, then allow instruction
    let total_checks = allow_syscalls.len() + deny_syscalls.len();

    // Emit deny checks (jump to deny label if match)
    for (i, &nr) in deny_syscalls.iter().enumerate() {
        let remaining = total_checks - i - 1;
        let jt = remaining as u8 + 1; // Jump past remaining checks to deny
        emit(&mut instructions, BPF_JMP | BPF_JEQ | BPF_K, jt, 0, nr);
    }

    // Emit allow checks (jump to allow label if match)
    for (i, &nr) in allow_syscalls.iter().enumerate() {
        let remaining = allow_syscalls.len() - i - 1;
        let jt = remaining as u8 + 2; // Jump past remaining + deny to allow
        emit(&mut instructions, BPF_JMP | BPF_JEQ | BPF_K, jt, 0, nr);
    }

    // Default action (if no match)
    let default_ret = match policy.settings.default_action {
        Action::Allow => SECCOMP_RET_ALLOW,
        Action::Deny => SECCOMP_RET_ERRNO | EPERM,
        Action::Log => SECCOMP_RET_LOG,
        Action::Kill => SECCOMP_RET_KILL_PROCESS,
        Action::Trap => SECCOMP_RET_ERRNO | EPERM,
    };
    emit(&mut instructions, BPF_RET | BPF_K, 0, 0, default_ret);

    // Deny label
    emit(&mut instructions, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);

    // Allow label
    emit(&mut instructions, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);

    Ok(instructions)
}

/// Generate Landlock rules
fn generate_landlock_rules(policy: &YamlPolicy) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    // Rule format:
    // u8 rule_type (1 = path, 2 = port)
    // u64 access_rights
    // u16 path_index (for path rules) or port (for port rules)

    for (i, rule) in policy.filesystem.rules.iter().enumerate() {
        // Rule type: path beneath
        output.push(1u8);

        // Access rights bitmap
        let mut access: u64 = 0;
        for a in &rule.access {
            access |= scmm_common::policy::landlock_access::name_to_bit(a);
        }
        output.write_u64::<LittleEndian>(access)?;

        // Path index (reference to path table)
        output.write_u16::<LittleEndian>(i as u16)?;
    }

    Ok(output)
}

/// Generate path string table
fn generate_path_table(policy: &YamlPolicy) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    // Table format:
    // u16 count
    // For each entry:
    //   u16 length
    //   [u8] path bytes (null-terminated)

    output.write_u16::<LittleEndian>(policy.filesystem.rules.len() as u16)?;

    for rule in &policy.filesystem.rules {
        let path_bytes = rule.path.as_bytes();
        output.write_u16::<LittleEndian>(path_bytes.len() as u16)?;
        output.extend_from_slice(path_bytes);
        output.push(0); // Null terminator
    }

    Ok(output)
}

