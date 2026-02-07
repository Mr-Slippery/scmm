//! Interactive CLI for policy extraction

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use console::style;
use dialoguer::{Input, Select};

use scmm_common::{
    categories::x86_64 as syscalls,
    policy::{
        Action, FilesystemRule, FilesystemRules, NetworkRule,
        NetworkRules, PolicyMetadata, PolicySettings, SyscallRule, YamlPolicy,
    },
    SyscallCategory,
};

use crate::generalize::PathGeneralizer;
use crate::parser::ParsedCapture;

/// Run interactive extraction
pub fn run_interactive_extraction(capture: &ParsedCapture, policy_name: &str) -> Result<YamlPolicy> {
    let mut policy = YamlPolicy {
        version: "1.0".to_string(),
        metadata: PolicyMetadata {
            name: policy_name.to_string(),
            description: format!(
                "Generated from capture of: {}",
                capture.metadata.command.join(" ")
            ),
            generated_from: None,
            target_executable: capture.metadata.command.first().cloned(),
            generated_at: Some(chrono::Utc::now().to_rfc3339()),
        },
        settings: PolicySettings::default(),
        syscalls: Vec::new(),
        filesystem: FilesystemRules::default(),
        network: NetworkRules::default(),
    };

    println!("{}", style("Interactive Policy Extraction").bold().cyan());
    println!();

    // Ask about default action
    let default_action = Select::new()
        .with_prompt("What should be the default action for unmatched syscalls?")
        .items(&["Deny (recommended for security)", "Allow", "Log only"])
        .default(0)
        .interact()?;

    policy.settings.default_action = match default_action {
        0 => Action::Deny,
        1 => Action::Allow,
        2 => Action::Log,
        _ => Action::Deny,
    };

    // Analyze syscalls
    println!();
    println!("{}", style("Analyzing syscalls...").bold());

    let syscall_counts = analyze_syscalls(capture);

    if policy.settings.default_action == Action::Allow {
        println!(
            "Default action is allow - all syscalls are permitted. \
             Adding {} observed syscalls to policy for documentation.",
            syscall_counts.len()
        );
        for (&nr, _) in &syscall_counts {
            policy.syscalls.push(SyscallRule {
                name: syscalls::get_name(nr).to_string(),
                action: Action::Allow,
                constraints: Vec::new(),
            });
        }
    } else {
        process_syscalls(&mut policy, &syscall_counts)?;
    }

    // Analyze file paths
    println!();
    println!("{}", style("Analyzing file accesses...").bold());

    let file_paths = extract_file_paths(capture);
    if !file_paths.is_empty() {
        process_file_paths(&mut policy, &file_paths)?;
    } else {
        println!("No file paths found in capture.");
    }

    // Analyze network connections
    println!();
    println!("{}", style("Analyzing network connections...").bold());

    let connections = extract_network_connections(capture);
    if !connections.is_empty() {
        process_network(&mut policy, &connections)?;
    } else {
        println!("No network connections found in capture.");
    }

    Ok(policy)
}

/// Analyze syscalls in the capture
fn analyze_syscalls(capture: &ParsedCapture) -> HashMap<u32, (usize, SyscallCategory)> {
    let mut counts: HashMap<u32, (usize, SyscallCategory)> = HashMap::new();

    for event in &capture.events {
        let category = syscalls::get_category(event.syscall_nr);
        counts
            .entry(event.syscall_nr)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, category));
    }

    counts
}

/// Process syscalls interactively
fn process_syscalls(
    policy: &mut YamlPolicy,
    syscall_counts: &HashMap<u32, (usize, SyscallCategory)>,
) -> Result<()> {
    // Group by category
    let mut by_category: HashMap<SyscallCategory, Vec<(u32, usize)>> = HashMap::new();
    for (&nr, &(count, category)) in syscall_counts {
        by_category.entry(category).or_default().push((nr, count));
    }

    // Sort each category by count
    for syscalls in by_category.values_mut() {
        syscalls.sort_by(|a, b| b.1.cmp(&a.1));
    }

    println!(
        "Found {} unique syscalls across {} categories",
        syscall_counts.len(),
        by_category.len()
    );
    println!();

    // Process each category
    let category_order = [
        SyscallCategory::Files,
        SyscallCategory::Network,
        SyscallCategory::Process,
        SyscallCategory::Memory,
        SyscallCategory::Ipc,
        SyscallCategory::Time,
        SyscallCategory::Signal,
        SyscallCategory::Other,
    ];

    for category in category_order {
        if let Some(syscalls_in_cat) = by_category.get(&category) {
            println!(
                "{}: {} syscalls",
                style(format!("{:?}", category)).bold(),
                syscalls_in_cat.len()
            );

            // Show top syscalls
            for (nr, count) in syscalls_in_cat.iter().take(5) {
                println!("  {} ({}): {} calls", syscalls::get_name(*nr), nr, count);
            }
            if syscalls_in_cat.len() > 5 {
                println!("  ... and {} more", syscalls_in_cat.len() - 5);
            }

            // Ask how to handle this category
            let action = Select::new()
                .with_prompt(format!("How to handle {:?} syscalls?", category))
                .items(&[
                    "Allow all observed syscalls in this category",
                    "Allow only top 10 most frequent",
                    "Review each syscall individually",
                    "Deny all (rely on defaults)",
                ])
                .default(0)
                .interact()?;

            match action {
                0 => {
                    // Allow all
                    for (nr, _) in syscalls_in_cat {
                        policy.syscalls.push(SyscallRule {
                            name: syscalls::get_name(*nr).to_string(),
                            action: Action::Allow,
                            constraints: Vec::new(),
                        });
                    }
                }
                1 => {
                    // Top 10
                    for (nr, _) in syscalls_in_cat.iter().take(10) {
                        policy.syscalls.push(SyscallRule {
                            name: syscalls::get_name(*nr).to_string(),
                            action: Action::Allow,
                            constraints: Vec::new(),
                        });
                    }
                }
                2 => {
                    // Review each
                    for (nr, count) in syscalls_in_cat {
                        let name = syscalls::get_name(*nr);
                        let choice = Select::new()
                            .with_prompt(format!("{} ({} calls)", name, count))
                            .items(&["Allow", "Deny", "Skip (use default)"])
                            .default(0)
                            .interact()?;

                        match choice {
                            0 => {
                                policy.syscalls.push(SyscallRule {
                                    name: name.to_string(),
                                    action: Action::Allow,
                                    constraints: Vec::new(),
                                });
                            }
                            1 => {
                                policy.syscalls.push(SyscallRule {
                                    name: name.to_string(),
                                    action: Action::Deny,
                                    constraints: Vec::new(),
                                });
                            }
                            _ => {} // Skip
                        }
                    }
                }
                _ => {} // Deny all - don't add rules
            }

            println!();
        }
    }

    Ok(())
}

/// Extract file paths from capture
fn extract_file_paths(_capture: &ParsedCapture) -> Vec<String> {
    // For now, return placeholder since we don't capture paths in the basic version
    // In a full implementation, this would parse the captured argument strings
    Vec::new()
}

/// Process file paths interactively
fn process_file_paths(policy: &mut YamlPolicy, paths: &[String]) -> Result<()> {
    let generalizer = PathGeneralizer::new();
    let suggestions = generalizer.analyze(paths);

    println!("Found {} unique file paths", paths.len());
    println!();

    // Group paths by directory for display
    let mut processed = HashSet::new();

    for suggestion in suggestions {
        if suggestion.confidence < 0.5 {
            continue;
        }

        println!("{}", style(&suggestion.reason).yellow());
        println!("Paths:");
        for path in suggestion.original_paths.iter().take(5) {
            println!("  - {}", path);
        }
        if suggestion.original_paths.len() > 5 {
            println!("  ... and {} more", suggestion.original_paths.len() - 5);
        }

        let (pattern_str, _) = suggestion.pattern.to_yaml_pattern();

        let choices = vec![
            format!("Use pattern: {}", pattern_str),
            "Keep as exact paths".to_string(),
            "Enter custom pattern".to_string(),
            "Skip these paths".to_string(),
        ];

        let selection = Select::new()
            .with_prompt("How should these paths be handled?")
            .items(&choices)
            .default(0)
            .interact()?;

        match selection {
            0 => {
                // Use suggested pattern
                policy.filesystem.rules.push(FilesystemRule {
                    path: pattern_str,
                    access: vec!["read_file".to_string()],
                });
                for path in &suggestion.original_paths {
                    processed.insert(path.clone());
                }
            }
            1 => {
                // Exact paths
                for path in &suggestion.original_paths {
                    policy.filesystem.rules.push(FilesystemRule {
                        path: path.clone(),
                        access: vec!["read_file".to_string()],
                    });
                    processed.insert(path.clone());
                }
            }
            2 => {
                // Custom pattern
                let custom: String = Input::new()
                    .with_prompt("Enter pattern (use * for wildcard, ** for recursive)")
                    .interact_text()?;
                policy.filesystem.rules.push(FilesystemRule {
                    path: custom,
                    access: vec!["read_file".to_string()],
                });
                for path in &suggestion.original_paths {
                    processed.insert(path.clone());
                }
            }
            _ => {} // Skip
        }

        println!();
    }

    // Handle remaining paths
    let remaining: Vec<_> = paths
        .iter()
        .filter(|p| !processed.contains(*p))
        .collect();

    if !remaining.is_empty() {
        println!("{} paths not yet handled", remaining.len());

        let action = Select::new()
            .with_prompt("How to handle remaining paths?")
            .items(&[
                "Add each as exact match",
                "Skip (rely on Landlock defaults)",
            ])
            .default(1)
            .interact()?;

        if action == 0 {
            for path in remaining {
                policy.filesystem.rules.push(FilesystemRule {
                    path: path.clone(),
                    access: vec!["read_file".to_string()],
                });
            }
        }
    }

    Ok(())
}

/// Extract network connections from capture
fn extract_network_connections(_capture: &ParsedCapture) -> Vec<(String, u16, String)> {
    // Placeholder - would need proper sockaddr parsing
    Vec::new()
}

/// Process network connections interactively
fn process_network(
    policy: &mut YamlPolicy,
    connections: &[(String, u16, String)],
) -> Result<()> {
    println!("Found {} unique network connections", connections.len());

    // Group by port
    let mut by_port: HashMap<u16, Vec<String>> = HashMap::new();
    for (addr, port, _proto) in connections {
        by_port.entry(*port).or_default().push(addr.clone());
    }

    for (&port, addrs) in &by_port {
        let port_name = match port {
            80 => "HTTP",
            443 => "HTTPS",
            53 => "DNS",
            22 => "SSH",
            _ => "unknown",
        };

        println!(
            "Port {} ({}): {} unique addresses",
            port,
            port_name,
            addrs.len()
        );

        let choices = vec![
            format!("Allow port {} to any address", port),
            "Allow only these specific addresses".to_string(),
            "Skip (deny by default)".to_string(),
        ];

        let selection = Select::new()
            .with_prompt(format!("How to handle port {}?", port))
            .items(&choices)
            .default(0)
            .interact()?;

        match selection {
            0 => {
                policy.network.outbound.push(NetworkRule {
                    protocol: "tcp".to_string(),
                    addresses: vec!["0.0.0.0/0".to_string()],
                    ports: vec![port],
                });
            }
            1 => {
                policy.network.outbound.push(NetworkRule {
                    protocol: "tcp".to_string(),
                    addresses: addrs.clone(),
                    ports: vec![port],
                });
            }
            _ => {} // Skip
        }
    }

    Ok(())
}
