//! Interactive CLI for policy extraction

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use console::style;
use dialoguer::{Input, Select};

use scmm_common::{
    categories::x86_64 as syscalls,
    policy::{
        landlock_access, Action, FilesystemRule, FilesystemRules, NetworkRule,
        NetworkRules, PolicyMetadata, PolicySettings, SyscallRule, YamlPolicy,
    },
    ArgType, SyscallCategory,
};

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

    let file_accesses = extract_file_paths(capture);
    if !file_accesses.is_empty() {
        process_file_paths(&mut policy, &file_accesses)?;
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

/// Info about a unique file path observed in the capture
struct FileAccessInfo {
    /// The resolved absolute path
    path: String,
    /// Syscall names that accessed this path
    syscall_names: Vec<String>,
    /// Total number of accesses
    count: usize,
}

/// Normalize a path by resolving `.` and `..` components without touching the filesystem.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => { parts.pop(); }
            other => parts.push(other),
        }
    }
    if path.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// Extract file paths from capture events
fn extract_file_paths(capture: &ParsedCapture) -> Vec<FileAccessInfo> {
    // Collect (path, syscall_nr) -> count
    let mut path_map: HashMap<(String, u32), usize> = HashMap::new();

    let working_dir = &capture.metadata.working_dir;

    for event in &capture.events {
        for arg in &event.args {
            if arg.arg_type == ArgType::Path && arg.str_len > 0 {
                if let Ok(path_str) = std::str::from_utf8(&arg.str_data[..arg.str_len as usize]) {
                    // Resolve relative paths against working directory
                    let resolved = if path_str.starts_with('/') {
                        path_str.to_string()
                    } else if !working_dir.is_empty() {
                        format!("{}/{}", working_dir, path_str)
                    } else {
                        path_str.to_string()
                    };

                    // Normalize . and .. components
                    let normalized = normalize_path(&resolved);

                    // Filter out pseudo-paths
                    if normalized.starts_with("/proc/self/fd/")
                        || normalized.starts_with("/dev/fd/")
                    {
                        continue;
                    }

                    *path_map.entry((normalized, event.syscall_nr)).or_insert(0) += 1;
                }
            }
        }
    }

    // Group by path
    let mut by_path: HashMap<String, (Vec<String>, usize)> = HashMap::new();
    for ((path, nr), count) in path_map {
        let entry = by_path.entry(path).or_insert_with(|| (Vec::new(), 0));
        let name = syscalls::get_name(nr).to_string();
        if !entry.0.contains(&name) {
            entry.0.push(name);
        }
        entry.1 += count;
    }

    let mut results: Vec<FileAccessInfo> = by_path
        .into_iter()
        .map(|(path, (syscall_names, count))| FileAccessInfo {
            path,
            syscall_names,
            count,
        })
        .collect();

    results.sort_by(|a, b| a.path.cmp(&b.path));
    results
}

/// Build ancestor subtree choices for a path.
/// E.g. "/var/www/index.html" produces:
///   /var/www/index.html (exact file)
///   /var/www/**
///   /var/**
///   /**
///   Custom pattern...
///   Skip
fn build_subtree_choices(path: &str) -> Vec<(String, String)> {
    let mut choices = Vec::new();

    // First option: exact path
    choices.push((path.to_string(), path.to_string()));

    // Build ancestor subtrees from most specific to least
    let path_obj = Path::new(path);
    for ancestor in path_obj.ancestors().skip(1) {
        let ancestor_str = ancestor.to_string_lossy();
        if ancestor_str == "/" {
            choices.push(("/**".to_string(), "/**".to_string()));
        } else if !ancestor_str.is_empty() {
            choices.push((
                format!("{}/**", ancestor_str),
                format!("{}/**", ancestor_str),
            ));
        }
    }

    choices.push(("Custom pattern...".to_string(), "CUSTOM".to_string()));
    choices.push(("Skip".to_string(), "SKIP".to_string()));

    choices
}

/// Infer Landlock access rights from observed syscall names.
/// If `is_directory_rule` is true (e.g. pattern ends with `/**`), also grant
/// read_dir and execute so directory traversal works.
fn infer_access_rights(syscall_names: &[String], is_directory_rule: bool) -> Vec<String> {
    let mut rights = std::collections::HashSet::new();

    for name in syscall_names {
        match name.as_str() {
            "open" | "openat" | "openat2" => {
                rights.insert(landlock_access::READ_FILE);
            }
            "stat" | "lstat" | "newfstatat" | "statx" | "statfs"
            | "access" | "faccessat" | "faccessat2" => {
                rights.insert(landlock_access::READ_FILE);
            }
            "readlink" | "readlinkat" => {
                rights.insert(landlock_access::READ_FILE);
            }
            "unlink" | "unlinkat" => {
                rights.insert(landlock_access::REMOVE_FILE);
            }
            "rmdir" => {
                rights.insert(landlock_access::REMOVE_DIR);
            }
            "mkdir" | "mkdirat" => {
                rights.insert(landlock_access::MAKE_DIR);
            }
            "creat" => {
                rights.insert(landlock_access::WRITE_FILE);
                rights.insert(landlock_access::MAKE_REG);
            }
            "rename" | "renameat" | "renameat2" => {
                rights.insert(landlock_access::REFER);
            }
            "chmod" | "fchmodat" | "chown" | "lchown" | "fchownat" => {
                rights.insert(landlock_access::WRITE_FILE);
            }
            "truncate" => {
                rights.insert(landlock_access::TRUNCATE);
            }
            "execve" | "execveat" => {
                rights.insert(landlock_access::EXECUTE);
            }
            "link" | "linkat" | "symlink" | "symlinkat" => {
                rights.insert(landlock_access::MAKE_SYM);
                rights.insert(landlock_access::REFER);
            }
            "chdir" | "chroot" => {
                rights.insert(landlock_access::READ_DIR);
            }
            _ => {
                rights.insert(landlock_access::READ_FILE);
            }
        }
    }

    // Directory rules (glob patterns like /foo/**) need read_dir and execute
    // so that the kernel allows traversal into the directory hierarchy.
    if is_directory_rule {
        rights.insert(landlock_access::READ_DIR);
        rights.insert(landlock_access::EXECUTE);
    }

    let mut result: Vec<String> = rights.into_iter().map(|s| s.to_string()).collect();
    result.sort();
    result
}

/// Check if a path is already covered by a previously chosen glob pattern
fn is_covered_by_patterns(path: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if pattern.ends_with("/**") {
            let prefix = &pattern[..pattern.len() - 3];
            if path.starts_with(prefix) {
                return true;
            }
        } else if pattern == path {
            return true;
        }
    }
    false
}

/// Group file accesses by their topmost directory (e.g. /etc, /usr, /home, etc.)
fn group_by_top_dir(file_accesses: &[FileAccessInfo]) -> Vec<(String, Vec<&FileAccessInfo>)> {
    let mut groups: HashMap<String, Vec<&FileAccessInfo>> = HashMap::new();

    for info in file_accesses {
        // Find top-level directory (first component after root)
        let top = match Path::new(&info.path).components().nth(1) {
            Some(c) => format!("/{}", c.as_os_str().to_string_lossy()),
            None => "/".to_string(), // path is "/" itself
        };
        groups.entry(top).or_default().push(info);
    }

    let mut result: Vec<(String, Vec<&FileAccessInfo>)> = groups.into_iter().collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Collect all access rights from a group of file accesses
fn collect_group_rights(group: &[&FileAccessInfo], is_directory_rule: bool) -> Vec<String> {
    let all_syscalls: Vec<String> = group
        .iter()
        .flat_map(|info| info.syscall_names.iter().cloned())
        .collect();
    infer_access_rights(&all_syscalls, is_directory_rule)
}

/// Process file paths interactively with per-path subtree choices
fn process_file_paths(policy: &mut YamlPolicy, file_accesses: &[FileAccessInfo]) -> Result<()> {
    println!(
        "Found {} unique file paths",
        file_accesses.len()
    );
    println!();

    // First show a summary of all paths so the user has context
    println!("{}", style("All captured file paths:").bold());
    for info in file_accesses {
        let syscall_list = info.syscall_names.join(", ");
        println!(
            "  {} ({}, {}x)",
            info.path,
            style(&syscall_list).dim(),
            info.count,
        );
    }
    println!();

    // Group paths by top-level directory for a more efficient UX
    let groups = group_by_top_dir(file_accesses);

    // Track chosen patterns to skip already-covered paths
    let mut chosen_patterns: Vec<String> = Vec::new();

    for (top_dir, group) in &groups {
        // Check if already covered by a broader pattern
        if is_covered_by_patterns(top_dir, &chosen_patterns) {
            println!(
                "  {} {}",
                style(format!("{}/ ({} paths)", top_dir, group.len())).dim(),
                style("(already covered)").dim()
            );
            continue;
        }

        println!(
            "{}",
            style(format!("Directory: {} ({} paths)", top_dir, group.len())).bold().cyan()
        );

        // Show all paths in this group
        for info in group {
            let syscall_list = info.syscall_names.join(", ");
            println!(
                "    {} ({}, {}x)",
                info.path,
                style(&syscall_list).dim(),
                info.count,
            );
        }

        // If there's only one path and it equals the top dir (i.e. "/"), or
        // the group has many paths, offer group-level choices first
        if group.len() > 1 {
            // Offer a group-level choice first
            let group_choices = if top_dir == "/" {
                vec![
                    ("Allow access to all listed root-level paths individually".to_string(), "INDIVIDUAL"),
                    ("Allow access to everything under /** (full filesystem)".to_string(), "GLOB"),
                    ("Custom pattern...".to_string(), "CUSTOM"),
                    ("Skip all".to_string(), "SKIP"),
                ]
            } else {
                vec![
                    ("Review each path individually".to_string(), "INDIVIDUAL"),
                    (format!("Allow access to everything under {}/**", top_dir), "GLOB"),
                    ("Custom pattern...".to_string(), "CUSTOM"),
                    ("Skip all".to_string(), "SKIP"),
                ]
            };

            let display_items: Vec<&str> = group_choices.iter().map(|(label, _)| label.as_str()).collect();

            let selection = Select::new()
                .with_prompt("How to handle this group?")
                .items(&display_items)
                .default(0)
                .interact()?;

            let action = group_choices[selection].1;

            match action {
                "GLOB" => {
                    let pattern = if top_dir == "/" {
                        "/**".to_string()
                    } else {
                        format!("{}/**", top_dir)
                    };
                    let access = collect_group_rights(group, true);
                    policy.filesystem.rules.push(FilesystemRule {
                        path: pattern.clone(),
                        access,
                    });
                    chosen_patterns.push(pattern);
                    println!();
                    continue;
                }
                "CUSTOM" => {
                    let custom: String = Input::new()
                        .with_prompt("Enter pattern (use * for wildcard, ** for recursive)")
                        .interact_text()?;
                    let is_dir = custom.contains("**") || custom.ends_with("/*");
                    let access = collect_group_rights(group, is_dir);
                    policy.filesystem.rules.push(FilesystemRule {
                        path: custom.clone(),
                        access,
                    });
                    chosen_patterns.push(custom);
                    println!();
                    continue;
                }
                "SKIP" => {
                    println!();
                    continue;
                }
                _ => {
                    // Fall through to individual path processing
                }
            }
        }

        // Process individual paths in this group
        for info in group {
            if is_covered_by_patterns(&info.path, &chosen_patterns) {
                println!(
                    "    {} {}",
                    style(&info.path).dim(),
                    style("(already covered)").dim()
                );
                continue;
            }

            let syscall_list = info.syscall_names.join(", ");
            println!(
                "  {} ({}, {}x)",
                style(&info.path).bold(),
                style(&syscall_list).dim(),
                info.count,
            );

            let choices = build_subtree_choices(&info.path);
            let display_items: Vec<&str> = choices.iter().map(|(label, _)| label.as_str()).collect();

            let selection = Select::new()
                .with_prompt("Choose access scope")
                .items(&display_items)
                .default(0)
                .interact()?;

            let (_, ref pattern) = choices[selection];

            if pattern == "SKIP" {
                continue;
            }

            let final_pattern = if pattern == "CUSTOM" {
                let custom: String = Input::new()
                    .with_prompt("Enter pattern (use * for wildcard, ** for recursive)")
                    .interact_text()?;
                custom
            } else {
                pattern.clone()
            };

            let is_dir = final_pattern.contains("**") || final_pattern.ends_with("/*");
            let access = infer_access_rights(&info.syscall_names, is_dir);

            policy.filesystem.rules.push(FilesystemRule {
                path: final_pattern.clone(),
                access,
            });
            chosen_patterns.push(final_pattern);
        }

        println!();
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
