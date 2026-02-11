//! Code generation for compiled policies

use anyhow::{bail, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use tracing::warn;

use scmm_common::{
    capture::arch,
    categories::x86_64 as syscalls,
    policy::{
        policy_flags, Action, ArgConstraint, CompiledPolicyHeader, RunAs, YamlPolicy, RUN_AS_UNSET,
    },
};

// ── BPF instruction codes ──────────────────────────────────────────────

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40; // test if (A & k) != 0
const BPF_K: u16 = 0x00;
const BPF_AND: u16 = 0x50;
const BPF_JA: u16 = 0x00; // unconditional jump (within BPF_JMP class)

// ── Seccomp return values ──────────────────────────────────────────────

const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const EPERM: u32 = 1;

/// Maximum BPF program length (kernel limit)
const BPF_MAXINSNS: usize = 4096;

// ── Internal types for two-pass BPF emission ───────────────────────────

/// A label target for forward-reference patching.
#[derive(Debug, Clone, Copy)]
enum Label {
    Allow,
    Deny,
}

/// A pending BPF instruction with optional label fixups.
/// Jump offsets targeting `Allow` or `Deny` labels are patched in a second pass.
#[derive(Debug, Clone)]
struct PendingInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
    /// If set, patch `jt` to (label_pos - self_pos - 1)
    fixup_jt: Option<Label>,
    /// If set, patch `jf` to (label_pos - self_pos - 1)
    fixup_jf: Option<Label>,
    /// If set, patch `k` to (label_pos - self_pos - 1) — for unconditional JA jumps
    fixup_k: Option<Label>,
}

impl PendingInsn {
    fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self {
            code,
            jt,
            jf,
            k,
            fixup_jt: None,
            fixup_jf: None,
            fixup_k: None,
        }
    }
}

/// Info about a constrained syscall for dispatch patching.
struct ConstrainedEntry {
    /// Position of the JEQ dispatch instruction in the program
    dispatch_pos: usize,
    /// Position of the first instruction of the constraint block
    block_start: usize,
}

// ── Public API ─────────────────────────────────────────────────────────

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

    // Build capabilities
    let capabilities = generate_capabilities(policy)?;

    // Calculate offsets
    let header_size = std::mem::size_of::<CompiledPolicyHeader>();
    let seccomp_offset = header_size;
    let landlock_offset = seccomp_offset + seccomp_filter.len();
    let path_table_offset = landlock_offset + landlock_rules.len();
    let capabilities_offset = path_table_offset + path_table.len();

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

    // Resolve run_as uid/gid and encode into reserved bytes
    let mut reserved = [0u8; 16];
    reserved[0..4].copy_from_slice(&RUN_AS_UNSET.to_le_bytes());
    reserved[4..8].copy_from_slice(&RUN_AS_UNSET.to_le_bytes());

    if let Some(ref run_as) = policy.settings.run_as {
        let uid = resolve_uid(run_as)?;
        let gid = resolve_gid(run_as)?;
        reserved[0..4].copy_from_slice(&uid.to_le_bytes());
        reserved[4..8].copy_from_slice(&gid.to_le_bytes());
        flags |= policy_flags::HAS_RUN_AS;

        if !policy.capabilities.is_empty() {
            warn!("run_as with capabilities: ambient capabilities will be cleared by setuid. File capabilities on the target binary will still be effective.");
        }
    }

    // Build header
    let header = CompiledPolicyHeader {
        arch: arch_id,
        flags,
        seccomp_filter_offset: seccomp_offset as u32,
        seccomp_filter_len: seccomp_filter.len() as u32,
        landlock_rules_offset: landlock_offset as u32,
        landlock_rules_len: landlock_rules.len() as u32,
        path_table_offset: path_table_offset as u32,
        path_table_len: path_table.len() as u32,
        capabilities_offset: capabilities_offset as u32,
        capabilities_len: capabilities.len() as u32,
        _reserved: reserved,
        ..Default::default()
    };

    // Write header
    let header_bytes = unsafe { scmm_common::struct_to_bytes(&header) };
    output.extend_from_slice(header_bytes);

    // Write seccomp filter
    output.extend_from_slice(&seccomp_filter);

    // Write Landlock rules
    output.extend_from_slice(&landlock_rules);

    // Write path table
    output.extend_from_slice(&path_table);

    // Write capabilities
    output.extend_from_slice(&capabilities);

    Ok(output)
}

// ── Seccomp BPF filter generation ──────────────────────────────────────

/// Compute the byte offset into `seccomp_data` for a given arg index (0-5).
/// `seccomp_data` layout: [0] nr(u32), [4] arch(u32), [8] instruction_pointer(u64),
/// [16] args[0](u64), [24] args[1](u64), ... [56] args[5](u64).
/// BPF_W loads the low 32 bits on little-endian.
fn arg_offset(arg_idx: u32) -> u32 {
    16 + arg_idx * 8
}

/// Compute a jump offset from instruction at `from` to instruction at `to`.
/// In BPF, jt/jf offsets are relative to the *next* instruction, so offset = to - from - 1.
fn safe_offset(from: usize, to: usize) -> Result<u8> {
    let offset = to
        .checked_sub(from + 1)
        .ok_or_else(|| anyhow::anyhow!("backward jump in BPF: from={} to={}", from, to))?;
    if offset > 255 {
        bail!(
            "BPF jump offset {} exceeds max 255 (from={} to={})",
            offset,
            from,
            to
        );
    }
    Ok(offset as u8)
}

/// Serialize a `PendingInsn` slice to the final BPF bytecode (little-endian `sock_filter` array).
fn serialize_insns(insns: &[PendingInsn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
        out.write_u16::<LittleEndian>(insn.code).unwrap();
        out.push(insn.jt);
        out.push(insn.jf);
        out.write_u32::<LittleEndian>(insn.k).unwrap();
    }
    out
}

/// Generate seccomp BPF filter from policy.
///
/// Filter layout:
/// ```text
/// [0]   LD arch
/// [1]   JEQ arch_id → +1 / kill
/// [2]   RET KILL_PROCESS
/// [3]   LD syscall_nr
///       ── unconstrained deny checks ──
/// [4..] JEQ deny_nr → deny_label
///       ── constrained dispatch ──
/// [N..] JEQ constrained_nr → constraint_block_start
///       ── unconstrained allow checks ──
/// [M..] JEQ allow_nr → allow_label
///       ── default action ──
/// [D]   RET default_action
///       ── constraint blocks ──
/// [C0]  constraint block for syscall 0 ...
/// [C1]  constraint block for syscall 1 ...
///       ── terminal labels ──
/// [DL]  RET ERRNO|EPERM      ← deny_label
/// [AL]  RET ALLOW             ← allow_label
/// ```
fn generate_seccomp_filter(policy: &YamlPolicy, arch_id: u32) -> Result<Vec<u8>> {
    let syscall_map = syscalls::build_name_to_nr_map();

    // ── Phase 1: Classify rules ────────────────────────────────────────

    // Bootstrap/enforcement syscalls that must always be allowed.
    // These are needed for process startup and enforcement setup.
    //
    // Note: write/writev are NOT bootstrapped. The enforcer moves all
    // logging before seccomp installation and uses _exit(127) on exec
    // failure, so no writes happen after the filter is active. This
    // means the sandboxed program cannot write unless the policy
    // explicitly allows it.
    let bootstrap_syscalls: &[u32] = &[
        59,  // execve
        322, // execveat
        231, // exit_group
        60,  // exit
        15,  // rt_sigreturn (kernel uses this to return from signal handlers; not recordable)
        157, // prctl (needed for PR_SET_NO_NEW_PRIVS)
        444, // landlock_create_ruleset
        445, // landlock_add_rule
        446, // landlock_restrict_self
    ];

    let mut unconstrained_allow: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut unconstrained_deny: Vec<u32> = Vec::new();
    // (syscall_nr, action, constraints)
    let mut constrained: Vec<(u32, Action, &[ArgConstraint])> = Vec::new();

    // Track which syscall numbers appear in constrained rules
    let mut constrained_nrs: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for rule in &policy.syscalls {
        let Some(&nr) = syscall_map.get(rule.name.as_str()) else {
            continue;
        };

        // Filter constraints to only types seccomp can enforce
        let enforceable: Vec<&ArgConstraint> = rule
            .constraints
            .iter()
            .filter(|c| matches!(c.arg_type.as_str(), "integer" | "flags"))
            .collect();

        if !enforceable.is_empty() {
            constrained.push((nr, rule.action, &rule.constraints));
            constrained_nrs.insert(nr);
        } else {
            match rule.action {
                Action::Allow | Action::Log => {
                    unconstrained_allow.insert(nr);
                }
                Action::Deny | Action::Kill => {
                    unconstrained_deny.push(nr);
                }
                Action::Trap => {}
            }
        }
    }

    // Add bootstrap syscalls (unless they have constrained rules)
    for &nr in bootstrap_syscalls {
        if !constrained_nrs.contains(&nr) {
            unconstrained_allow.insert(nr);
        }
    }

    // Remove syscalls from unconstrained sets if they appear in constrained
    unconstrained_allow.retain(|nr| !constrained_nrs.contains(nr));
    unconstrained_deny.retain(|nr| !constrained_nrs.contains(nr));

    let unconstrained_allow: Vec<u32> = unconstrained_allow.into_iter().collect();

    // ── Phase 2: Build constraint blocks ───────────────────────────────

    // Build the constraint block instructions for each constrained syscall.
    // Each block ends with JA → allow_label (for allow-action rules) or
    // JA → deny_label (for deny-action rules). If all constraints pass,
    // the action fires; if any constraint fails, we go to deny.
    let mut constraint_blocks: Vec<(u32, Vec<PendingInsn>)> = Vec::new();

    for &(nr, action, constraints) in &constrained {
        let block = build_constraint_block(nr, action, constraints)?;
        if block.is_empty() {
            // All constraints were unenforecable (pointer types) — treat as unconstrained
            warn!(
                "Syscall nr {} has no enforceable constraints, treating as unconstrained",
                nr
            );
            continue;
        }
        constraint_blocks.push((nr, block));
    }

    // ── Phase 3: Assemble program ──────────────────────────────────────

    let mut prog: Vec<PendingInsn> = vec![
        // [0] LD arch (offset 4 in seccomp_data)
        PendingInsn::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
        // [1] JEQ arch_id → +1 / kill
        PendingInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, arch_id),
        // [2] RET KILL_PROCESS
        PendingInsn::new(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        // [3] LD syscall_nr (offset 0)
        PendingInsn::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
    ];

    // ── Unconstrained deny checks ──
    // JEQ deny_nr → deny_label (jt fixup)
    for &nr in &unconstrained_deny {
        let mut insn = PendingInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, nr);
        insn.fixup_jt = Some(Label::Deny);
        prog.push(insn);
    }

    // ── Constrained dispatch ──
    // JEQ constrained_nr → block_start (patched after blocks are placed)
    // We record positions for patching later.
    let mut constrained_entries: Vec<ConstrainedEntry> = Vec::new();
    for &(nr, ref _block) in &constraint_blocks {
        let pos = prog.len();
        // jt will be patched to block_start later; jf=0 falls through
        prog.push(PendingInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, nr));
        constrained_entries.push(ConstrainedEntry {
            dispatch_pos: pos,
            block_start: 0, // filled in phase 4
        });
    }

    // ── Unconstrained allow checks ──
    // JEQ allow_nr → allow_label (jt fixup)
    for &nr in &unconstrained_allow {
        let mut insn = PendingInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, nr);
        insn.fixup_jt = Some(Label::Allow);
        prog.push(insn);
    }

    // ── Default action ──
    let default_ret = match policy.settings.default_action {
        Action::Allow => SECCOMP_RET_ALLOW,
        Action::Deny => SECCOMP_RET_ERRNO | EPERM,
        Action::Log => SECCOMP_RET_LOG,
        Action::Kill => SECCOMP_RET_KILL_PROCESS,
        Action::Trap => SECCOMP_RET_ERRNO | EPERM,
    };
    prog.push(PendingInsn::new(BPF_RET | BPF_K, 0, 0, default_ret));

    // ── Constraint blocks ──
    // Each block needs a LD syscall_nr reload at the end so the next block
    // or the allow/deny label works correctly. Actually, constraint blocks
    // end with JA → allow/deny, and the terminal labels are just RET, so
    // no reload is needed.
    for (i, (_nr, block)) in constraint_blocks.iter().enumerate() {
        constrained_entries[i].block_start = prog.len();
        prog.extend_from_slice(block);
    }

    // ── Terminal labels ──
    let deny_label_pos = prog.len();
    prog.push(PendingInsn::new(
        BPF_RET | BPF_K,
        0,
        0,
        SECCOMP_RET_ERRNO | EPERM,
    ));

    let allow_label_pos = prog.len();
    prog.push(PendingInsn::new(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW));

    // ── Phase 4: Patch fixups ──────────────────────────────────────────

    // Patch label fixups
    #[allow(clippy::needless_range_loop)]
    for i in 0..prog.len() {
        if let Some(label) = prog[i].fixup_jt {
            let target = match label {
                Label::Allow => allow_label_pos,
                Label::Deny => deny_label_pos,
            };
            prog[i].jt = safe_offset(i, target)?;
        }
        if let Some(label) = prog[i].fixup_jf {
            let target = match label {
                Label::Allow => allow_label_pos,
                Label::Deny => deny_label_pos,
            };
            prog[i].jf = safe_offset(i, target)?;
        }
        if let Some(label) = prog[i].fixup_k {
            let target = match label {
                Label::Allow => allow_label_pos,
                Label::Deny => deny_label_pos,
            };
            prog[i].k = safe_offset(i, target)? as u32;
        }
    }

    // Patch constrained dispatch JEQ → block_start
    for entry in &constrained_entries {
        let offset = safe_offset(entry.dispatch_pos, entry.block_start)?;
        prog[entry.dispatch_pos].jt = offset;
    }

    // ── Validation ─────────────────────────────────────────────────────

    if prog.len() > BPF_MAXINSNS {
        bail!(
            "BPF program too large: {} instructions (max {})",
            prog.len(),
            BPF_MAXINSNS
        );
    }

    Ok(serialize_insns(&prog))
}

// ── Constraint block builders ──────────────────────────────────────────

/// Build a constraint block for a single syscall.
///
/// The block checks all enforceable constraints (ANDed together). If all pass,
/// jumps to the action label. If any fails, jumps to deny.
///
/// For `action=Allow`: pass → allow, fail → deny
/// For `action=Deny`:  pass (matches deny pattern) → deny, fail → allow
fn build_constraint_block(
    nr: u32,
    action: Action,
    constraints: &[ArgConstraint],
) -> Result<Vec<PendingInsn>> {
    let mut block: Vec<PendingInsn> = Vec::new();

    // Determine what "pass" and "fail" mean for this action
    let (pass_label, fail_label) = match action {
        Action::Allow | Action::Log => (Label::Allow, Label::Deny),
        Action::Deny | Action::Kill => (Label::Deny, Label::Allow),
        Action::Trap => (Label::Deny, Label::Allow),
    };

    for constraint in constraints {
        match constraint.arg_type.as_str() {
            "flags" => {
                let insns = build_flags_constraint(constraint, pass_label, fail_label)?;
                block.extend(insns);
            }
            "integer" => {
                let insns = build_integer_constraint(constraint, pass_label, fail_label)?;
                block.extend(insns);
            }
            _ => {
                // pointer/path/string — can't be checked by seccomp, skip
                warn!(
                    "Skipping {} constraint on arg {} for syscall nr {} (seccomp can't dereference pointers)",
                    constraint.arg_type,
                    constraint.arg,
                    nr
                );
                continue;
            }
        }
    }

    if block.is_empty() {
        return Ok(block);
    }

    // All constraints passed → jump to pass_label
    let mut ja = PendingInsn::new(BPF_JMP | BPF_JA, 0, 0, 0);
    ja.fixup_k = Some(pass_label);
    block.push(ja);

    Ok(block)
}

/// Build BPF instructions for a `flags` constraint.
///
/// - `denied` list: if ANY denied bit is set → fail
///   `LD arg[N]; JSET denied_mask → fail_label`
///
/// - `allowed` list: if ANY bit outside allowed set → fail
///   `LD arg[N]; AND ~allowed_mask; JEQ 0 → (next) / fail_label`
///
/// Special case: O_RDONLY (value 0) in `denied` needs `AND 0x3; JEQ 0 → fail`
/// since JSET can't test for zero bits.
fn build_flags_constraint(
    constraint: &ArgConstraint,
    _pass_label: Label,
    fail_label: Label,
) -> Result<Vec<PendingInsn>> {
    let arg_idx: u32 = constraint.arg.parse()?;
    let offset = arg_offset(arg_idx);
    let mut insns: Vec<PendingInsn> = Vec::new();

    if !constraint.denied.is_empty() {
        let mut denied_mask: u64 = 0;
        let mut has_zero_flag = false;

        for name in &constraint.denied {
            match scmm_common::flags::resolve(name) {
                Some(0) => {
                    // O_RDONLY or PROT_NONE — value is 0, can't use JSET
                    has_zero_flag = true;
                }
                Some(val) => {
                    denied_mask |= val;
                }
                None => {
                    warn!("Unknown flag '{}' in denied list, skipping", name);
                }
            }
        }

        // Handle zero-valued flags (e.g. O_RDONLY = 0)
        // Check: LD arg; AND 0x3 (access mode mask); JEQ 0 → fail
        if has_zero_flag {
            // Load arg
            insns.push(PendingInsn::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset));
            // AND with access mode mask (bits 0-1)
            insns.push(PendingInsn::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x3));
            // JEQ 0 → fail (if access mode is 0 = O_RDONLY, deny)
            let mut jeq = PendingInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0);
            jeq.fixup_jt = Some(fail_label);
            insns.push(jeq);
        }

        // Handle nonzero denied flags
        if denied_mask != 0 {
            // Load arg
            insns.push(PendingInsn::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset));
            // JSET denied_mask → fail (if any denied bit is set)
            let mut jset = PendingInsn::new(BPF_JMP | BPF_JSET | BPF_K, 0, 0, denied_mask as u32);
            jset.fixup_jt = Some(fail_label);
            insns.push(jset);
        }
    }

    if !constraint.allowed.is_empty() {
        let mut allowed_mask: u64 = 0;
        for name in &constraint.allowed {
            match scmm_common::flags::resolve(name) {
                Some(val) => {
                    allowed_mask |= val;
                }
                None => {
                    warn!("Unknown flag '{}' in allowed list, skipping", name);
                }
            }
        }

        if allowed_mask != 0 {
            // Load arg
            insns.push(PendingInsn::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset));
            // Mask off allowed bits: AND ~allowed_mask
            let inv_mask = !allowed_mask as u32;
            insns.push(PendingInsn::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, inv_mask));
            // If result != 0, there are bits outside the allowed set → fail
            // JEQ 0 → next (ok) / fail
            let mut jeq = PendingInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0);
            jeq.fixup_jf = Some(fail_label);
            insns.push(jeq);
        }
    }

    Ok(insns)
}

/// Build BPF instructions for an `integer` constraint (exact match).
///
/// ```text
/// LD arg[N]
/// JEQ val_0 → skip_to_next_constraint
/// JEQ val_1 → skip_to_next_constraint
/// ...
/// JEQ val_K-1 → skip_to_next_constraint
/// JA → fail_label  (no match)
/// ```
///
/// The JEQ targets point past the final JA of this constraint, which is
/// the first instruction of the next constraint (or the block's terminal JA).
fn build_integer_constraint(
    constraint: &ArgConstraint,
    _pass_label: Label,
    fail_label: Label,
) -> Result<Vec<PendingInsn>> {
    let arg_idx: u32 = constraint.arg.parse()?;
    let offset = arg_offset(arg_idx);

    let values: Vec<u64> = constraint
        .r#match
        .iter()
        .filter_map(|p| p.pattern.parse::<u64>().ok())
        .collect();

    if values.is_empty() {
        return Ok(Vec::new());
    }

    let mut insns: Vec<PendingInsn> = Vec::new();

    // Load arg
    insns.push(PendingInsn::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset));

    // JEQ chain: each JEQ jumps past remaining JEQs + the final JA on match.
    // There are `values.len()` JEQ instructions followed by 1 JA instruction.
    // JEQ at index i (0-based among the JEQs) needs to jump over
    // (values.len() - 1 - i) remaining JEQs + 1 JA = (values.len() - i) instructions.
    let n = values.len();
    for (i, &val) in values.iter().enumerate() {
        let skip = (n - i) as u8; // jump over remaining JEQs + JA
        insns.push(PendingInsn::new(
            BPF_JMP | BPF_JEQ | BPF_K,
            skip,
            0,
            val as u32,
        ));
    }

    // No match → fail
    let mut ja = PendingInsn::new(BPF_JMP | BPF_JA, 0, 0, 0);
    ja.fixup_k = Some(fail_label);
    insns.push(ja);

    Ok(insns)
}

// ── Landlock & path table (unchanged) ──────────────────────────────────

/// Generate Landlock rules
fn generate_landlock_rules(policy: &YamlPolicy) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    // Rule format:
    // u8 rule_type (1 = path, 2 = port)
    // u64 access_rights
    // u16 path_index (for path rules) or port (for port rules)
    // u8 on_missing strategy (0 = precreate, 1 = parentdir, 2 = skip)

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

        // On-missing strategy
        output.push(rule.on_missing as u8);
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

/// Generate capability bitmask
fn generate_capabilities(policy: &YamlPolicy) -> Result<Vec<u8>> {
    let mut caps_mask: u64 = 0;

    for cap_name in &policy.capabilities {
        let cap = match cap_name.parse::<caps::Capability>() {
            Ok(c) => c,
            Err(_) => {
                // Try with CAP_ prefix if missing
                if !cap_name.starts_with("CAP_") {
                    match format!("CAP_{}", cap_name).parse::<caps::Capability>() {
                        Ok(c) => c,
                        Err(_) => anyhow::bail!("Unknown capability: {}", cap_name),
                    }
                } else {
                    anyhow::bail!("Unknown capability: {}", cap_name);
                }
            }
        };

        caps_mask |= 1 << cap.index();
    }

    let mut output = Vec::new();
    output.write_u64::<LittleEndian>(caps_mask)?;

    Ok(output)
}

// ── run_as resolution ──────────────────────────────────────────────────

/// Resolve uid from RunAs config: name takes precedence, numeric fallback.
fn resolve_uid(run_as: &RunAs) -> Result<u32> {
    if let Some(ref name) = run_as.user {
        match nix::unistd::User::from_name(name) {
            Ok(Some(user)) => return Ok(user.uid.as_raw()),
            Ok(None) => {
                if let Some(uid) = run_as.uid {
                    warn!("User '{}' not found, using numeric uid {}", name, uid);
                    return Ok(uid);
                }
                bail!("User '{}' not found and no numeric uid specified", name);
            }
            Err(e) => {
                if let Some(uid) = run_as.uid {
                    warn!(
                        "Failed to look up user '{}': {}, using numeric uid {}",
                        name, e, uid
                    );
                    return Ok(uid);
                }
                bail!("Failed to look up user '{}': {}", name, e);
            }
        }
    }
    if let Some(uid) = run_as.uid {
        return Ok(uid);
    }
    bail!("run_as specified but no user or uid provided");
}

/// Resolve gid from RunAs config: name takes precedence, numeric fallback.
fn resolve_gid(run_as: &RunAs) -> Result<u32> {
    if let Some(ref name) = run_as.group {
        match nix::unistd::Group::from_name(name) {
            Ok(Some(group)) => return Ok(group.gid.as_raw()),
            Ok(None) => {
                if let Some(gid) = run_as.gid {
                    warn!("Group '{}' not found, using numeric gid {}", name, gid);
                    return Ok(gid);
                }
                bail!("Group '{}' not found and no numeric gid specified", name);
            }
            Err(e) => {
                if let Some(gid) = run_as.gid {
                    warn!(
                        "Failed to look up group '{}': {}, using numeric gid {}",
                        name, e, gid
                    );
                    return Ok(gid);
                }
                bail!("Failed to look up group '{}': {}", name, e);
            }
        }
    }
    if let Some(gid) = run_as.gid {
        return Ok(gid);
    }
    // If no group specified but user was, use the user's primary group
    if let Some(ref name) = run_as.user {
        if let Ok(Some(user)) = nix::unistd::User::from_name(name) {
            return Ok(user.gid.as_raw());
        }
    }
    if let Some(uid) = run_as.uid {
        if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
            return Ok(user.gid.as_raw());
        }
    }
    bail!("run_as specified but no group or gid provided and could not infer from user");
}
