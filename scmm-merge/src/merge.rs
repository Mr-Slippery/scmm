//! Policy merge logic — union of multiple YAML policies

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use tracing::warn;

use scmm_common::policy::{
    Action, FilesystemRule, FilesystemRules, NetworkRule, NetworkRules, OnMissing,
    PolicyMetadata, PolicySettings, SyscallRule, TcpRules, YamlPolicy,
};

/// Merge multiple policies into a single unified policy (union semantics).
pub fn merge_policies(
    policies: Vec<YamlPolicy>,
    name: Option<&str>,
    input_names: &[String],
) -> Result<YamlPolicy> {
    assert!(policies.len() >= 2);

    let merged_name = name
        .map(|n| n.to_string())
        .unwrap_or_else(|| "merged-policy".to_string());

    Ok(YamlPolicy {
        version: "1.0".to_string(),
        metadata: merge_metadata(&policies, &merged_name, input_names),
        settings: merge_settings(&policies),
        syscalls: merge_syscalls(&policies),
        capabilities: merge_capabilities(&policies),
        filesystem: merge_filesystem(&policies),
        network: merge_network(&policies),
    })
}

fn merge_metadata(
    policies: &[YamlPolicy],
    name: &str,
    input_names: &[String],
) -> PolicyMetadata {
    // Collect all source capture files
    let sources: Vec<&str> = policies
        .iter()
        .filter_map(|p| p.metadata.generated_from.as_deref())
        .collect();

    let source_list = if sources.is_empty() {
        None
    } else {
        Some(sources.join(", "))
    };

    // Use target_executable from first policy that has one
    let target = policies
        .iter()
        .find_map(|p| p.metadata.target_executable.clone());

    let description = format!(
        "Merged from {} policies: {}",
        input_names.len(),
        input_names.join(", ")
    );

    let now = chrono::Utc::now().to_rfc3339();

    PolicyMetadata {
        name: name.to_string(),
        description,
        generated_from: source_list,
        target_executable: target,
        generated_at: Some(now),
    }
}

fn merge_settings(policies: &[YamlPolicy]) -> PolicySettings {
    // Most permissive default_action wins
    let default_action = policies
        .iter()
        .map(|p| p.settings.default_action)
        .max_by_key(|a| action_permissiveness(*a))
        .unwrap_or(Action::Deny);

    // log_denials = true if any policy has it
    let log_denials = policies.iter().any(|p| p.settings.log_denials);

    // Use first policy's arch; warn if others differ
    let arch = policies[0].settings.arch.clone();
    for p in &policies[1..] {
        if p.settings.arch != arch {
            warn!(
                "Architecture mismatch: '{}' vs '{}' — using '{}'",
                arch, p.settings.arch, arch
            );
        }
    }

    // Use first policy's run_as that has one
    let run_as = policies.iter().find_map(|p| p.settings.run_as.clone());

    PolicySettings {
        default_action,
        log_denials,
        arch,
        run_as,
    }
}

/// Higher value = more permissive
fn action_permissiveness(action: Action) -> u8 {
    match action {
        Action::Kill => 0,
        Action::Trap => 1,
        Action::Deny => 2,
        Action::Log => 3,
        Action::Allow => 4,
    }
}

fn merge_syscalls(policies: &[YamlPolicy]) -> Vec<SyscallRule> {
    // Group by syscall name; take most permissive action, union constraints
    let mut map: BTreeMap<String, SyscallRule> = BTreeMap::new();

    for policy in policies {
        for rule in &policy.syscalls {
            match map.get_mut(&rule.name) {
                Some(existing) => {
                    // Take most permissive action
                    if action_permissiveness(rule.action)
                        > action_permissiveness(existing.action)
                    {
                        existing.action = rule.action;
                    }
                    // Union constraints (append non-duplicates)
                    for c in &rule.constraints {
                        let already_has = existing.constraints.iter().any(|ec| {
                            ec.arg == c.arg && ec.arg_type == c.arg_type
                        });
                        if !already_has {
                            existing.constraints.push(c.clone());
                        }
                    }
                }
                None => {
                    map.insert(rule.name.clone(), rule.clone());
                }
            }
        }
    }

    map.into_values().collect()
}

fn merge_capabilities(policies: &[YamlPolicy]) -> Vec<String> {
    let mut caps: BTreeSet<String> = BTreeSet::new();
    for policy in policies {
        for cap in &policy.capabilities {
            caps.insert(cap.clone());
        }
    }
    caps.into_iter().collect()
}

fn merge_filesystem(policies: &[YamlPolicy]) -> FilesystemRules {
    // Group by path; union access rights, most conservative on_missing
    let mut map: BTreeMap<String, FilesystemRule> = BTreeMap::new();

    for policy in policies {
        for rule in &policy.filesystem.rules {
            match map.get_mut(&rule.path) {
                Some(existing) => {
                    // Union access rights
                    for access in &rule.access {
                        if !existing.access.contains(access) {
                            existing.access.push(access.clone());
                        }
                    }
                    // Most conservative on_missing (precreate > parentdir > skip)
                    existing.on_missing = more_conservative_on_missing(
                        existing.on_missing,
                        rule.on_missing,
                    );
                }
                None => {
                    map.insert(rule.path.clone(), rule.clone());
                }
            }
        }
    }

    FilesystemRules {
        rules: map.into_values().collect(),
    }
}

/// Precreate is most conservative (most precise), then Parentdir, then Skip
fn more_conservative_on_missing(a: OnMissing, b: OnMissing) -> OnMissing {
    let rank = |m: OnMissing| -> u8 {
        match m {
            OnMissing::Precreate => 2,
            OnMissing::Parentdir => 1,
            OnMissing::Skip => 0,
        }
    };
    if rank(a) >= rank(b) { a } else { b }
}

fn merge_network(policies: &[YamlPolicy]) -> NetworkRules {
    // allow_loopback = true if any policy has it
    let allow_loopback = policies.iter().any(|p| p.network.allow_loopback);

    let outbound = merge_network_rules(
        policies.iter().flat_map(|p| &p.network.tcp.outbound),
    );
    let inbound = merge_network_rules(
        policies.iter().flat_map(|p| &p.network.tcp.inbound),
    );

    NetworkRules {
        allow_loopback,
        tcp: TcpRules { outbound, inbound },
    }
}

/// Deduplicate network rules by (protocol, sorted addresses, sorted ports)
fn merge_network_rules<'a>(rules: impl Iterator<Item = &'a NetworkRule>) -> Vec<NetworkRule> {
    let mut seen: BTreeSet<(String, Vec<String>, Vec<u16>)> = BTreeSet::new();
    let mut result = Vec::new();

    for rule in rules {
        let mut addrs = rule.addresses.clone();
        addrs.sort();
        let mut ports = rule.ports.clone();
        ports.sort();
        let key = (rule.protocol.clone(), addrs, ports);

        if seen.insert(key) {
            result.push(rule.clone());
        }
    }

    result
}
