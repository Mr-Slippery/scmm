//! Policy validation

use anyhow::{bail, Result};

use scmm_common::policy::{Action, YamlPolicy};

/// Dangerous syscalls that should be warned about
const DANGEROUS_SYSCALLS: &[(&str, &str)] = &[
    ("ptrace", "allows process inspection and manipulation"),
    ("process_vm_readv", "allows reading other process memory"),
    ("process_vm_writev", "allows writing other process memory"),
    ("prctl", "can modify process behavior including seccomp"),
    ("seccomp", "can modify seccomp filters"),
    ("bpf", "can load eBPF programs"),
    ("perf_event_open", "can access performance events"),
    ("init_module", "can load kernel modules"),
    ("finit_module", "can load kernel modules"),
    ("delete_module", "can unload kernel modules"),
    ("kexec_load", "can load new kernel"),
    ("kexec_file_load", "can load new kernel"),
    ("reboot", "can reboot system"),
    ("swapon", "can enable swap"),
    ("swapoff", "can disable swap"),
    ("mount", "can mount filesystems"),
    ("umount2", "can unmount filesystems"),
    ("pivot_root", "can change root filesystem"),
    ("chroot", "can change root directory"),
    ("setns", "can change namespaces"),
    ("unshare", "can create namespaces"),
];

/// Validate a policy and return warnings
pub fn validate(policy: &YamlPolicy, arch: &str) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    // Check architecture
    if arch != "x86_64" && arch != "aarch64" {
        bail!(
            "Unsupported architecture: {}. Supported: x86_64, aarch64",
            arch
        );
    }

    // Check for unknown syscalls
    for rule in &policy.syscalls {
        // Simple check - in production would use syscall table lookup
        if rule.name == "unknown" {
            warnings.push(format!("Unknown syscall name in rule: {}", rule.name));
        }
    }

    // Check for dangerous syscalls
    for rule in &policy.syscalls {
        if rule.action == Action::Allow {
            for (dangerous, reason) in DANGEROUS_SYSCALLS {
                if rule.name == *dangerous {
                    warnings.push(format!(
                        "Warning: allowing dangerous syscall '{}' - {}",
                        dangerous, reason
                    ));
                }
            }
        }
    }

    // Check for conflicting rules
    let mut seen_syscalls: std::collections::HashMap<&str, Action> =
        std::collections::HashMap::new();
    for rule in &policy.syscalls {
        if let Some(&prev_action) = seen_syscalls.get(rule.name.as_str()) {
            if prev_action != rule.action && rule.constraints.is_empty() {
                warnings.push(format!(
                    "Conflicting rules for syscall '{}': {:?} and {:?}",
                    rule.name, prev_action, rule.action
                ));
            }
        }
        if rule.constraints.is_empty() {
            seen_syscalls.insert(&rule.name, rule.action);
        }
    }

    // Validate constraints
    let constrained_names: std::collections::HashSet<&str> = policy
        .syscalls
        .iter()
        .filter(|r| !r.constraints.is_empty())
        .map(|r| r.name.as_str())
        .collect();

    for rule in &policy.syscalls {
        // Warn if a syscall has both constrained and unconstrained rules
        if rule.constraints.is_empty() && constrained_names.contains(rule.name.as_str()) {
            warnings.push(format!(
                "Syscall '{}' has both constrained and unconstrained rules. \
                 The unconstrained rule will be ignored in favor of the constrained one.",
                rule.name
            ));
        }

        for (ci, constraint) in rule.constraints.iter().enumerate() {
            // Validate arg index
            match constraint.arg.parse::<u32>() {
                Ok(idx) if idx <= 5 => {}
                Ok(idx) => {
                    warnings.push(format!(
                        "Syscall '{}' constraint {}: arg index {} out of range (0-5)",
                        rule.name, ci, idx
                    ));
                }
                Err(_) => {
                    warnings.push(format!(
                        "Syscall '{}' constraint {}: invalid arg index '{}'",
                        rule.name, ci, constraint.arg
                    ));
                }
            }

            // Validate arg type
            match constraint.arg_type.as_str() {
                "integer" | "flags" => {}
                "pointer" | "path" | "string" => {
                    warnings.push(format!(
                        "Syscall '{}' constraint {}: type '{}' cannot be checked by seccomp \
                         (pointer dereference not allowed). Use filesystem rules for path restrictions.",
                        rule.name, ci, constraint.arg_type
                    ));
                }
                other => {
                    warnings.push(format!(
                        "Syscall '{}' constraint {}: unknown arg type '{}'",
                        rule.name, ci, other
                    ));
                }
            }

            // Validate flag names resolve
            if constraint.arg_type == "flags" {
                for flag_name in constraint.denied.iter().chain(constraint.allowed.iter()) {
                    if scmm_common::flags::resolve(flag_name).is_none() {
                        warnings.push(format!(
                            "Syscall '{}' constraint {}: unknown flag name '{}'",
                            rule.name, ci, flag_name
                        ));
                    }
                }
            }

            // Validate integer match patterns
            if constraint.arg_type == "integer" {
                for pattern in &constraint.r#match {
                    if pattern.pattern.parse::<u64>().is_err() {
                        warnings.push(format!(
                            "Syscall '{}' constraint {}: invalid integer match value '{}'",
                            rule.name, ci, pattern.pattern
                        ));
                    }
                }
            }

            // Warn if constraint has no checks
            if constraint.r#match.is_empty()
                && constraint.allowed.is_empty()
                && constraint.denied.is_empty()
            {
                warnings.push(format!(
                    "Syscall '{}' constraint {}: no match/allowed/denied values specified",
                    rule.name, ci
                ));
            }
        }
    }

    // Check filesystem rules
    for rule in &policy.filesystem.rules {
        if rule.path.is_empty() {
            warnings.push("Empty path in filesystem rule".to_string());
        }
        if rule.access.is_empty() {
            warnings.push(format!("No access types specified for path: {}", rule.path));
        }
    }

    // Check network rules
    for rule in &policy.network.outbound {
        if rule.ports.is_empty() && rule.addresses.is_empty() {
            warnings.push("Network rule with no ports or addresses".to_string());
        }
    }

    // Check run_as configuration
    if let Some(ref run_as) = policy.settings.run_as {
        if run_as.uid == Some(0) {
            warnings.push(
                "run_as uid is 0 (root) - this defeats the purpose of privilege dropping"
                    .to_string(),
            );
        }
        if run_as.user.is_none() && run_as.uid.is_none() {
            warnings.push("run_as specified but no user or uid provided".to_string());
        }
        if run_as.group.is_none()
            && run_as.gid.is_none()
            && run_as.user.is_none()
            && run_as.uid.is_none()
        {
            warnings.push("run_as specified but completely empty".to_string());
        }
        if !policy.capabilities.is_empty() {
            warnings.push(
                "run_as with capabilities: ambient capabilities will be cleared by setuid. \
                 File capabilities on the target binary will still be effective."
                    .to_string(),
            );
        }
    }

    // Security recommendations
    if policy.settings.default_action == Action::Allow {
        warnings.push(
            "Default action is 'allow' - this is less secure than 'deny'. \
             Consider using default_action: deny"
                .to_string(),
        );
    }

    Ok(warnings)
}
