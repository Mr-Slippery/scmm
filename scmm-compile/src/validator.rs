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
        bail!("Unsupported architecture: {}. Supported: x86_64, aarch64", arch);
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
    let mut seen_syscalls: std::collections::HashMap<&str, Action> = std::collections::HashMap::new();
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

    // Check filesystem rules
    for rule in &policy.filesystem.rules {
        if rule.path.is_empty() {
            warnings.push("Empty path in filesystem rule".to_string());
        }
        if rule.access.is_empty() {
            warnings.push(format!(
                "No access types specified for path: {}",
                rule.path
            ));
        }
    }

    // Check network rules
    for rule in &policy.network.outbound {
        if rule.ports.is_empty() && rule.addresses.is_empty() {
            warnings.push("Network rule with no ports or addresses".to_string());
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
