//! Interactive CLI for policy extraction

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;
use console::style;
use dialoguer::{Input, MultiSelect, Select};

use scmm_common::{
    capture::CaptureMetadata,
    categories::x86_64 as syscalls,
    policy::{
        landlock_access, Action, FilesystemRule, FilesystemRules, NetworkRule, NetworkRules,
        OnMissing, PolicyMetadata, PolicySettings, RunAs, SyscallRule, YamlPolicy,
    },
    ArgType, SyscallCategory, MAX_ARG_STR_LEN,
};

/// A network connection observed in the capture.
struct NetworkConnection {
    /// Socket address family (AF_INET=2, AF_INET6=10)
    family: u32,
    /// Port number
    port: u16,
    /// Address string (destination for connect, bind address for bind)
    addr: String,
    /// Protocol ("tcp" or "udp")
    proto: String,
    /// true = outbound (connect), false = inbound (bind)
    outbound: bool,
}

use crate::parser::ParsedCapture;

/// Strategy for handling files that may not exist at enforcement time
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MissingFilesStrategy {
    Precreate,
    Parentdir,
    Skip,
    /// Prompt the user interactively for each rule
    Ask,
}

const ON_MISSING_CHOICES: &[&str] = &[
    "precreate  — enforcer pre-creates the file for precise Landlock targeting",
    "parentdir  — grant restricted rights on parent directory",
    "skip       — silently drop the rule",
];

fn prompt_on_missing(path: &str) -> Result<OnMissing> {
    let selection = Select::new()
        .with_prompt(format!("on_missing strategy for {}", path))
        .items(ON_MISSING_CHOICES)
        .default(0)
        .interact()?;
    Ok(match selection {
        0 => OnMissing::Precreate,
        1 => OnMissing::Parentdir,
        _ => OnMissing::Skip,
    })
}

/// Determine the on_missing strategy for a rule.
///
/// Uses `created_files` for paths with create intent (`make_reg`),
/// `missing_files` for read-only paths.  `Ask` triggers an interactive prompt.
///
/// Returns `None` to signal that the path should be excluded from the policy
/// (e.g. `--created-files skip` for create-intent paths).
fn resolve_on_missing(
    access: &[String],
    path: &str,
    missing_files: Option<MissingFilesStrategy>,
    created_files: Option<MissingFilesStrategy>,
) -> Result<Option<OnMissing>> {
    let is_create = access.contains(&landlock_access::MAKE_REG.to_string());
    let strategy = if is_create {
        created_files
    } else {
        missing_files
    };

    match strategy {
        Some(MissingFilesStrategy::Precreate) => Ok(Some(OnMissing::Precreate)),
        Some(MissingFilesStrategy::Parentdir) => Ok(Some(OnMissing::Parentdir)),
        Some(MissingFilesStrategy::Skip) => {
            if is_create {
                // Created files with skip → exclude from policy entirely
                // (they don't exist yet, so on_missing:skip at enforcement would always drop them)
                Ok(None)
            } else {
                Ok(Some(OnMissing::Skip))
            }
        }
        Some(MissingFilesStrategy::Ask) => prompt_on_missing(path).map(Some),
        None => {
            // Default: precreate for create-intent, skip for read-only
            if is_create {
                Ok(Some(OnMissing::Precreate))
            } else {
                Ok(Some(OnMissing::Skip))
            }
        }
    }
}

/// Build a RunAs from the capture metadata's uid/gid, if present.
fn run_as_from_metadata(meta: &CaptureMetadata) -> Option<RunAs> {
    let uid = meta.uid?;
    let gid = meta.gid?;
    Some(RunAs {
        uid: Some(uid),
        gid: Some(gid),
    })
}

/// Run non-interactive extraction with sensible defaults.
///
/// Auto-selects: deny-by-default, allow all observed syscalls,
/// exact paths for each observed file, auto-detected capabilities only.
pub fn run_non_interactive_extraction(
    capture: &ParsedCapture,
    policy_name: &str,
    missing_files: Option<MissingFilesStrategy>,
    created_files: Option<MissingFilesStrategy>,
) -> Result<YamlPolicy> {
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
        capabilities: Vec::new(),
        filesystem: FilesystemRules::default(),
        network: NetworkRules::default(),
        syscalls: Vec::new(),
    };

    policy.settings.default_action = Action::Deny;
    policy.settings.run_as = run_as_from_metadata(&capture.metadata);

    println!("Non-interactive extraction (auto-selecting defaults)");
    println!();

    // Allow all observed syscalls
    let syscall_counts = analyze_syscalls(capture);
    for &nr in syscall_counts.keys() {
        policy.syscalls.push(SyscallRule {
            name: syscalls::get_name(nr).to_string(),
            action: Action::Allow,
            constraints: Vec::new(),
        });
    }
    println!("Allowed {} observed syscalls", syscall_counts.len());

    // Add path rules for each observed file.
    // For created files (make_reg) with parentdir strategy, resolve to the parent
    // directory immediately and merge access rights — the exact file paths are
    // ephemeral (e.g. random temp names) and won't match on subsequent runs.
    let file_accesses = extract_file_paths(capture, missing_files);
    let mut created_parentdir_merged: HashMap<String, Vec<String>> = HashMap::new();
    for info in &file_accesses {
        let access = infer_access_rights_with_flags(
            &info.syscall_names,
            false,
            &info.path,
            info.has_write_open,
            info.has_create_open,
            info.has_trunc_open,
        );
        let is_create = access.contains(&landlock_access::MAKE_REG.to_string());
        match resolve_on_missing(&access, &info.path, missing_files, created_files)? {
            Some(OnMissing::Parentdir) if is_create => {
                let parent = Path::new(&info.path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let entry = created_parentdir_merged.entry(parent).or_default();
                for a in &access {
                    if !entry.contains(a) {
                        entry.push(a.clone());
                    }
                }
            }
            Some(on_missing) => {
                policy.filesystem.rules.push(FilesystemRule {
                    path: info.path.clone(),
                    access,
                    on_missing,
                });
            }
            None => {}
        }
    }
    for (parent_path, access) in created_parentdir_merged {
        policy.filesystem.rules.push(FilesystemRule {
            path: parent_path,
            access,
            on_missing: OnMissing::Skip,
        });
    }
    println!("Added {} filesystem rules", policy.filesystem.rules.len());

    // Analyze network connections and binds.
    // All observed TCP ports get Landlock rules — Landlock restricts port-level
    // access regardless of address (loopback or not).
    let connections = extract_network_connections(capture);
    if connections.is_empty() {
        println!("No network connections found in capture.");
    } else {
        // Collect unique TCP ports keyed by (port, family), split by direction.
        // Also accumulate observed destination addresses per port for documentation.
        let mut seen_out: std::collections::HashMap<(u16, u32), (&str, Vec<String>)> =
            std::collections::HashMap::new();
        let mut seen_in: std::collections::HashMap<(u16, u32), (&str, Vec<String>)> =
            std::collections::HashMap::new();
        for conn in &connections {
            if conn.proto != "tcp" || conn.port == 0 {
                continue;
            }
            let cidr = if conn.family == 10 {
                "::/0"
            } else {
                "0.0.0.0/0"
            };
            let map = if conn.outbound {
                &mut seen_out
            } else {
                &mut seen_in
            };
            let entry = map
                .entry((conn.port, conn.family))
                .or_insert_with(|| (cidr, Vec::new()));
            if !conn.addr.is_empty() && !entry.1.contains(&conn.addr) {
                entry.1.push(conn.addr.clone());
            }
        }
        for ((port, _family), (cidr, observed)) in seen_out {
            policy.network.tcp.outbound.push(NetworkRule {
                protocol: "tcp".to_string(),
                addresses: vec![cidr.to_string()],
                ports: vec![port],
                observed_addresses: observed,
            });
        }
        for ((port, _family), (cidr, observed)) in seen_in {
            policy.network.tcp.inbound.push(NetworkRule {
                protocol: "tcp".to_string(),
                addresses: vec![cidr.to_string()],
                ports: vec![port],
                observed_addresses: observed,
            });
        }
        println!(
            "Found {} network event(s): {} outbound rule(s), {} inbound (bind) rule(s).",
            connections.len(),
            policy.network.tcp.outbound.len(),
            policy.network.tcp.inbound.len(),
        );
    }

    // Auto-detect capabilities
    let detected_caps = detect_file_capabilities(capture);
    if !detected_caps.is_empty() {
        println!("Detected capabilities: {}", detected_caps.join(", "));
        policy.capabilities.extend(detected_caps);
    }

    Ok(policy)
}

/// Run interactive extraction
pub fn run_interactive_extraction(
    capture: &ParsedCapture,
    policy_name: &str,
    missing_files: Option<MissingFilesStrategy>,
    created_files: Option<MissingFilesStrategy>,
) -> Result<YamlPolicy> {
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
        capabilities: Vec::new(),
        filesystem: FilesystemRules::default(),
        network: NetworkRules::default(),
    };

    policy.settings.run_as = run_as_from_metadata(&capture.metadata);

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
        for &nr in syscall_counts.keys() {
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

    let file_accesses = extract_file_paths(capture, missing_files);
    if !file_accesses.is_empty() {
        process_file_paths(&mut policy, &file_accesses, missing_files, created_files)?;
    } else {
        println!("No file paths found in capture.");
    }

    // Analyze network connections
    println!();
    println!("{}", style("Analyzing network connections...").bold());

    let connections = extract_network_connections(capture);
    if connections.is_empty() {
        println!("No network connections found in capture.");
    } else {
        process_network(&mut policy, &connections)?;
    }

    // Detect capabilities from the target binary
    println!();
    println!("{}", style("Analyzing capabilities...").bold());

    let detected_caps = detect_file_capabilities(capture);
    if !detected_caps.is_empty() {
        println!(
            "Detected file capabilities on target binary: {}",
            style(detected_caps.join(", ")).green()
        );
        println!("These will be included in the policy so the enforcer can grant them.");
        policy.capabilities.extend(detected_caps);
    } else {
        println!("No file capabilities detected on target binary.");
    }

    // Offer manual capability selection for anything not auto-detected
    let common_caps = vec![
        ("CAP_NET_RAW", "Raw sockets (ping, net tools)"),
        ("CAP_NET_ADMIN", "Network configuration"),
        ("CAP_SYS_ADMIN", "System administration (mount, etc)"),
        ("CAP_SYS_PTRACE", "Ptrace (debugging)"),
        ("CAP_DAC_OVERRIDE", "Bypass file permission checks"),
        ("CAP_CHOWN", "Change file ownership"),
        ("CAP_SETUID", "Set user ID"),
        ("CAP_SETGID", "Set group ID"),
        ("CAP_KILL", "Send signals to other processes"),
    ];

    // Filter out already-detected caps
    let remaining_caps: Vec<_> = common_caps
        .iter()
        .filter(|(cap, _)| !policy.capabilities.contains(&cap.to_string()))
        .collect();

    if !remaining_caps.is_empty() {
        let items: Vec<String> = remaining_caps
            .iter()
            .map(|(cap, desc)| format!("{} - {}", cap, desc))
            .collect();

        let selection = MultiSelect::new()
            .with_prompt(
                "Select additional capabilities to grant (SPACE to select, ENTER to confirm)",
            )
            .items(&items)
            .interact()?;

        for idx in selection {
            policy.capabilities.push(remaining_caps[idx].0.to_string());
        }
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
    /// Whether any openat/open call used write flags (O_WRONLY, O_RDWR)
    has_write_open: bool,
    /// Whether any openat/open call used O_CREAT
    has_create_open: bool,
    /// Whether any openat/open call used O_TRUNC
    has_trunc_open: bool,
}

/// Normalize a path by resolving `.` and `..` components without touching the filesystem.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if path.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// Open flag constants (x86_64)
const O_WRONLY: u64 = 0x1;
const O_RDWR: u64 = 0x2;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;

/// Syscalls that inherently create filesystem entries (independent of open flags).
const CREATE_INTENT_SYSCALLS: &[&str] = &[
    "creat",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
];

/// Extract file paths from capture events.
///
/// All-failed read-only paths (where every access returned ret_val < 0 and there
/// was no create intent) are excluded unless the user explicitly asked to include
/// them via `--missing-files precreate` or `--missing-files parentdir`.
fn extract_file_paths(
    capture: &ParsedCapture,
    missing_files: Option<MissingFilesStrategy>,
) -> Vec<FileAccessInfo> {
    // Exclude all-failed read-only paths unless user explicitly asked to include them
    let exclude_failed = !matches!(
        missing_files,
        Some(MissingFilesStrategy::Precreate) | Some(MissingFilesStrategy::Parentdir)
    );
    // Collect (path, syscall_nr) -> (count, has_write_open, has_create_open, has_trunc_open)
    let mut path_map: HashMap<(String, u32), (usize, bool, bool, bool)> = HashMap::new();

    // Per-path tracking: has any successful access OR any create-intent access?
    // (has_success, has_create_intent)
    let mut path_relevance: HashMap<String, (bool, bool)> = HashMap::new();

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

                    // Detect open flags for openat/open/openat2
                    // openat: arg0=dirfd, arg1=path, arg2=flags
                    // open:   arg0=path, arg1=flags
                    let name = syscalls::get_name(event.syscall_nr);
                    let flags_val = match name {
                        "openat" | "openat2" => event.args[2].raw_value,
                        "open" => event.args[1].raw_value,
                        _ => 0,
                    };
                    let is_write = (flags_val & O_WRONLY) != 0 || (flags_val & O_RDWR) != 0;
                    let is_create = (flags_val & O_CREAT) != 0;
                    let is_trunc = (flags_val & O_TRUNC) != 0;

                    // Track per-path relevance for failed-path filtering
                    let relevance = path_relevance
                        .entry(normalized.clone())
                        .or_insert((false, false));
                    if event.ret_val >= 0 {
                        relevance.0 = true; // has_success
                    }
                    if is_create || CREATE_INTENT_SYSCALLS.contains(&name) {
                        relevance.1 = true; // has_create_intent
                    }

                    let entry = path_map
                        .entry((normalized, event.syscall_nr))
                        .or_insert((0, false, false, false));
                    entry.0 += 1;
                    entry.1 |= is_write;
                    entry.2 |= is_create;
                    entry.3 |= is_trunc;
                }
            }
        }
    }

    // Group by path
    let mut by_path: HashMap<String, (Vec<String>, usize, bool, bool, bool)> = HashMap::new();
    for ((path, nr), (count, write_open, create_open, trunc_open)) in path_map {
        let entry = by_path
            .entry(path)
            .or_insert_with(|| (Vec::new(), 0, false, false, false));
        let name = syscalls::get_name(nr).to_string();
        if !entry.0.contains(&name) {
            entry.0.push(name);
        }
        entry.1 += count;
        entry.2 |= write_open;
        entry.3 |= create_open;
        entry.4 |= trunc_open;
    }

    // Filter out paths that only have failed non-creating accesses
    let total_before = by_path.len();
    if exclude_failed {
        by_path.retain(|path, _| {
            let (has_success, has_create_intent) =
                path_relevance.get(path).copied().unwrap_or((false, false));
            has_success || has_create_intent
        });
        let excluded = total_before - by_path.len();
        if excluded > 0 {
            println!(
                "Excluded {} path(s) with only failed non-creating accesses",
                excluded
            );
        }
    }

    let mut results: Vec<FileAccessInfo> = by_path
        .into_iter()
        .map(
            |(path, (syscall_names, count, has_write_open, has_create_open, has_trunc_open))| {
                FileAccessInfo {
                    path,
                    syscall_names,
                    count,
                    has_write_open,
                    has_create_open,
                    has_trunc_open,
                }
            },
        )
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

/// Infer Landlock access rights from observed syscall names, path, and open flags.
fn infer_access_rights_with_flags(
    syscall_names: &[String],
    is_directory_rule: bool,
    path: &str,
    has_write_open: bool,
    has_create_open: bool,
    has_trunc_open: bool,
) -> Vec<String> {
    let mut rights = std::collections::HashSet::new();

    for name in syscall_names {
        match name.as_str() {
            "open" | "openat" | "openat2" => {
                rights.insert(landlock_access::READ_FILE);
            }
            "stat" | "lstat" | "newfstatat" | "statx" | "statfs" | "access" | "faccessat"
            | "faccessat2" => {
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
            "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" | "sendfile" | "fallocate"
            | "ftruncate" => {
                rights.insert(landlock_access::WRITE_FILE);
            }
            "utimensat" | "futimesat" | "utime" | "utimes" => {
                rights.insert(landlock_access::WRITE_FILE);
            }
            "chmod" | "fchmodat" | "chown" | "lchown" | "fchownat" => {
                rights.insert(landlock_access::WRITE_FILE);
            }
            "truncate" => {
                rights.insert(landlock_access::TRUNCATE);
            }
            "execve" | "execveat" => {
                rights.insert(landlock_access::EXECUTE);
                rights.insert(landlock_access::READ_FILE);
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

    // If openat/open was called with write or create flags, grant
    // write_file / make_reg so Landlock allows the operation.
    if has_write_open {
        rights.insert(landlock_access::WRITE_FILE);
    }
    if has_create_open {
        rights.insert(landlock_access::MAKE_REG);
        rights.insert(landlock_access::WRITE_FILE);
    }
    if has_trunc_open {
        rights.insert(landlock_access::TRUNCATE);
    }

    // Directory rules (glob patterns like /foo/**) need read_dir, execute,
    // and make_reg so that the kernel allows traversal and file creation.
    if is_directory_rule {
        rights.insert(landlock_access::READ_DIR);
        rights.insert(landlock_access::EXECUTE);
        rights.insert(landlock_access::MAKE_REG);
    }

    // Shared libraries need execute access because the dynamic linker
    // mmap's them with PROT_EXEC. The mmap syscall uses an fd (not a path),
    // so the path-based capture can't see that — we infer it from the filename.
    if path.contains(".so") {
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
fn collect_group_rights(
    group: &[&FileAccessInfo],
    is_directory_rule: bool,
    pattern: &str,
) -> Vec<String> {
    let all_syscalls: Vec<String> = group
        .iter()
        .flat_map(|info| info.syscall_names.iter().cloned())
        .collect();
    let has_write = group.iter().any(|info| info.has_write_open);
    let has_create = group.iter().any(|info| info.has_create_open);
    let has_trunc = group.iter().any(|info| info.has_trunc_open);
    infer_access_rights_with_flags(
        &all_syscalls,
        is_directory_rule,
        pattern,
        has_write,
        has_create,
        has_trunc,
    )
}

/// Process file paths interactively with per-path subtree choices
fn process_file_paths(
    policy: &mut YamlPolicy,
    file_accesses: &[FileAccessInfo],
    missing_files: Option<MissingFilesStrategy>,
    created_files: Option<MissingFilesStrategy>,
) -> Result<()> {
    println!("Found {} unique file paths", file_accesses.len());
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
            style(format!("Directory: {} ({} paths)", top_dir, group.len()))
                .bold()
                .cyan()
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
                    (
                        "Allow access to all listed root-level paths individually".to_string(),
                        "INDIVIDUAL",
                    ),
                    (
                        "Allow access to everything under /** (full filesystem)".to_string(),
                        "GLOB",
                    ),
                    ("Custom pattern...".to_string(), "CUSTOM"),
                    ("Skip all".to_string(), "SKIP"),
                ]
            } else {
                vec![
                    ("Review each path individually".to_string(), "INDIVIDUAL"),
                    (
                        format!("Allow access to everything under {}/**", top_dir),
                        "GLOB",
                    ),
                    ("Custom pattern...".to_string(), "CUSTOM"),
                    ("Skip all".to_string(), "SKIP"),
                ]
            };

            let display_items: Vec<&str> = group_choices
                .iter()
                .map(|(label, _)| label.as_str())
                .collect();

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
                    let access = collect_group_rights(group, true, &pattern);
                    if let Some(on_missing) =
                        resolve_on_missing(&access, &pattern, missing_files, created_files)?
                    {
                        policy.filesystem.rules.push(FilesystemRule {
                            path: pattern.clone(),
                            access,
                            on_missing,
                        });
                    }
                    chosen_patterns.push(pattern);
                    println!();
                    continue;
                }
                "CUSTOM" => {
                    let custom: String = Input::new()
                        .with_prompt("Enter pattern (use * for wildcard, ** for recursive)")
                        .interact_text()?;
                    let is_dir = custom.contains("**") || custom.ends_with("/*");
                    let access = collect_group_rights(group, is_dir, &custom);
                    if let Some(on_missing) =
                        resolve_on_missing(&access, &custom, missing_files, created_files)?
                    {
                        policy.filesystem.rules.push(FilesystemRule {
                            path: custom.clone(),
                            access,
                            on_missing,
                        });
                    }
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
            let display_items: Vec<&str> =
                choices.iter().map(|(label, _)| label.as_str()).collect();

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
            let access = infer_access_rights_with_flags(
                &info.syscall_names,
                is_dir,
                &final_pattern,
                info.has_write_open,
                info.has_create_open,
                info.has_trunc_open,
            );

            if let Some(on_missing) =
                resolve_on_missing(&access, &final_pattern, missing_files, created_files)?
            {
                policy.filesystem.rules.push(FilesystemRule {
                    path: final_pattern.clone(),
                    access,
                    on_missing,
                });
            }
            chosen_patterns.push(final_pattern);
        }

        println!();
    }

    Ok(())
}

/// Extract network connections and binds from capture.
///
/// Handles:
/// - `connect` (nr=42): outbound connections (ret=0 or EINPROGRESS=-115)
/// - `bind`    (nr=49): inbound binds (ret=0)
///
/// Skips AF_UNIX (family=1) — those are filesystem sockets.
fn extract_network_connections(capture: &ParsedCapture) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();

    // Build a map of (pid, fd) → (proto, family) from socket() calls.
    // socket(family, type, protocol) — nr=41, arg0=family, arg1=type
    // SOCK_STREAM=1 → TCP, SOCK_DGRAM=2 → UDP
    let mut socket_type_map: HashMap<(u32, u64), (&str, u32)> = HashMap::new();
    for event in &capture.events {
        if event.syscall_nr == 41 && event.ret_val >= 0 {
            let family = event.args[0].raw_value as u32;
            // arg1 low bits: SOCK_STREAM=1, SOCK_DGRAM=2 (mask off SOCK_CLOEXEC etc.)
            let sock_type = (event.args[1].raw_value & 0xf) as u32;
            let proto = if sock_type == 2 { "udp" } else { "tcp" };
            let fd = event.ret_val as u64;
            socket_type_map.insert((event.pid, fd), (proto, family));
        }
    }

    for event in &capture.events {
        // connect(fd, sockaddr, addrlen) — nr=42  (outbound)
        // bind(fd, sockaddr, addrlen)    — nr=49  (inbound)
        let is_connect = event.syscall_nr == 42;
        let is_bind = event.syscall_nr == 49;
        if !is_connect && !is_bind {
            continue;
        }

        // Accept any connect/bind attempt — the application issued the call,
        // so the policy should allow it regardless of whether it succeeded.
        // (Landlock will enforce port-level restrictions; here we just record
        // which ports were attempted.)

        // arg1 must be Sockaddr type (set by strace parser)
        if event.args[1].arg_type != ArgType::Sockaddr {
            continue;
        }

        let raw = event.args[1].raw_value;
        let family = (raw >> 16) as u32;
        let port = (raw & 0xffff) as u16;

        // Skip AF_UNIX — those are filesystem sockets
        if family == 1 || family == 0 {
            continue;
        }

        let addr = {
            let len = event.args[1].str_len as usize;
            let len = len.min(MAX_ARG_STR_LEN);
            String::from_utf8_lossy(&event.args[1].str_data[..len]).to_string()
        };

        // Look up the socket type from the socket() call
        let fd = event.args[0].raw_value;
        let proto = socket_type_map
            .get(&(event.pid, fd))
            .map(|(p, _)| *p)
            .unwrap_or("tcp")
            .to_string();

        connections.push(NetworkConnection {
            family,
            port,
            addr,
            proto,
            outbound: is_connect,
        });
    }

    connections
}

/// Process network connections interactively
fn process_network(policy: &mut YamlPolicy, connections: &[NetworkConnection]) -> Result<()> {
    println!("Found {} unique network connections", connections.len());

    // Group outbound connections by port (all addresses, including loopback —
    // Landlock restricts by port regardless of address).
    let mut by_port: HashMap<u16, Vec<String>> = HashMap::new();
    for conn in connections {
        if conn.outbound && conn.proto == "tcp" && conn.port != 0 {
            by_port
                .entry(conn.port)
                .or_default()
                .push(conn.addr.clone());
        }
    }

    // Handle bind rules separately — always add them.
    for conn in connections {
        if !conn.outbound && conn.proto == "tcp" && conn.port != 0 {
            let observed = if conn.addr.is_empty() {
                Vec::new()
            } else {
                vec![conn.addr.clone()]
            };
            policy.network.tcp.inbound.push(NetworkRule {
                protocol: "tcp".to_string(),
                addresses: vec!["0.0.0.0/0".to_string()],
                ports: vec![conn.port],
                observed_addresses: observed,
            });
        }
    }

    if by_port.is_empty() {
        return Ok(());
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
                policy.network.tcp.outbound.push(NetworkRule {
                    protocol: "tcp".to_string(),
                    addresses: vec!["0.0.0.0/0".to_string()],
                    ports: vec![port],
                    observed_addresses: addrs.clone(),
                });
            }
            1 => {
                // User chose specific addresses — store them as both the enforced
                // addresses and the observed addresses (no wildcard needed).
                policy.network.tcp.outbound.push(NetworkRule {
                    protocol: "tcp".to_string(),
                    addresses: addrs.clone(),
                    ports: vec![port],
                    observed_addresses: Vec::new(),
                });
            }
            _ => {} // Skip
        }
    }

    Ok(())
}

/// Detect file capabilities on the target binary.
///
/// Resolves the target executable from the capture metadata (using execve paths
/// or `which`), then runs `getcap` to read its file capabilities.
/// Returns a list of capability names like `["CAP_NET_RAW"]`.
fn detect_file_capabilities(capture: &ParsedCapture) -> Vec<String> {
    let binaries = find_all_exec_binaries(capture);
    if binaries.is_empty() {
        println!("  Could not determine any target binary paths.");
        return Vec::new();
    }

    let mut all_caps = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for path in &binaries {
        // Run getcap to read file capabilities
        let output = match std::process::Command::new("getcap").arg(path).output() {
            Ok(o) => o,
            Err(_) => continue,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            println!("  {} has capabilities: {}", path, stdout.trim());
            for cap in parse_getcap_output(&stdout) {
                if seen.insert(cap.clone()) {
                    all_caps.push(cap);
                }
            }
        }
    }

    all_caps
}

/// Find all unique resolved paths of binaries exec'd during the capture.
fn find_all_exec_binaries(capture: &ParsedCapture) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for event in &capture.events {
        let name = syscalls::get_name(event.syscall_nr);
        if (name == "execve" || name == "execveat") && event.ret_val == 0 {
            let arg = &event.args[0];
            if arg.arg_type == ArgType::Path && arg.str_len > 0 {
                if let Ok(path) = std::str::from_utf8(&arg.str_data[..arg.str_len as usize]) {
                    if path.starts_with('/') && seen.insert(path.to_string()) {
                        paths.push(path.to_string());
                    }
                }
            }
        }
    }

    // Fall back: resolve the command name from metadata via which
    if paths.is_empty() {
        if let Some(cmd) = capture.metadata.command.first() {
            if let Ok(output) = std::process::Command::new("which").arg(cmd).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        paths.push(path);
                    }
                }
            }
        }
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use scmm_common::capture::CaptureMetadata;
    use scmm_common::{SyscallArg, SyscallEvent, MAX_ARG_STR_LEN};

    /// Helper: create a SyscallEvent with a path argument.
    fn make_event(syscall_nr: u32, path: &str, ret_val: i64, flags: u64) -> SyscallEvent {
        let mut event = SyscallEvent::default();
        event.syscall_nr = syscall_nr;
        event.ret_val = ret_val;

        // For openat (257): arg0=dirfd, arg1=path, arg2=flags
        let path_arg_idx: usize;
        let flags_arg_idx: usize;
        match syscall_nr {
            257 => {
                // openat
                path_arg_idx = 1;
                flags_arg_idx = 2;
            }
            _ => {
                // stat(4), access(21), execve(59): arg0=path
                path_arg_idx = 0;
                flags_arg_idx = usize::MAX;
            }
        }

        // Set path argument
        let mut arg = SyscallArg::default();
        arg.arg_type = ArgType::Path;
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_ARG_STR_LEN);
        arg.str_data[..len].copy_from_slice(&bytes[..len]);
        arg.str_len = len as u16;
        event.args[path_arg_idx] = arg;

        // Set flags argument for openat
        if flags_arg_idx < 6 {
            event.args[flags_arg_idx].raw_value = flags;
        }

        event
    }

    fn make_capture(events: Vec<SyscallEvent>) -> ParsedCapture {
        ParsedCapture {
            metadata: CaptureMetadata {
                hostname: String::new(),
                kernel_release: String::new(),
                command: vec!["test".into()],
                working_dir: "/tmp".into(),
                environment: Vec::new(),
                root_pid: 1,
                uid: None,
                gid: None,
                attached: false,
                processes: Vec::new(),
            },
            events,
        }
    }

    #[test]
    fn default_skips_failed_accesses() {
        // Simulate PATH lookup: multiple failed execve, then one success
        let events = vec![
            make_event(59, "/home/user/.cargo/bin/touch", -2, 0), // ENOENT
            make_event(59, "/usr/local/bin/touch", -2, 0),        // ENOENT
            make_event(59, "/usr/bin/touch", 0, 0),               // success
        ];
        let capture = make_capture(events);

        // Default (None / skip): only the successful path
        let filtered = extract_file_paths(&capture, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/usr/bin/touch");

        // With precreate: all 3 paths present (all-failed included)
        let all = extract_file_paths(&capture, Some(MissingFilesStrategy::Precreate));
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn keeps_create_intent_files() {
        // touch creates a file: openat with O_CREAT that might fail first (ENOENT on stat)
        // then succeed on openat with O_CREAT
        let events = vec![
            make_event(4, "/tmp/newfile", -2, 0), // stat fails (ENOENT)
            make_event(257, "/tmp/newfile", 0, O_CREAT), // openat with O_CREAT succeeds
        ];
        let capture = make_capture(events);

        let filtered = extract_file_paths(&capture, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/tmp/newfile");
    }

    #[test]
    fn keeps_create_intent_even_if_all_fail() {
        // File that the app tries to create but all attempts fail (e.g., permission denied)
        let events = vec![
            make_event(257, "/root/protected", -13, O_CREAT | O_WRONLY), // EACCES
        ];
        let capture = make_capture(events);

        let filtered = extract_file_paths(&capture, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/root/protected");
    }

    #[test]
    fn keeps_mkdir_even_if_failed() {
        // mkdir is inherently a create-intent syscall (nr 83)
        let events = vec![
            make_event(83, "/tmp/newdir", -13, 0), // EACCES
        ];
        let capture = make_capture(events);

        let filtered = extract_file_paths(&capture, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/tmp/newdir");
    }

    #[test]
    fn drops_pure_read_failures() {
        // cat tries to read a file that doesn't exist
        let events = vec![
            make_event(257, "/tmp/nonexistent", -2, 0), // openat O_RDONLY, ENOENT
            make_event(4, "/tmp/nonexistent", -2, 0),   // stat, ENOENT
        ];
        let capture = make_capture(events);

        let filtered = extract_file_paths(&capture, None);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn keeps_path_if_later_success() {
        // File initially fails stat but is later opened successfully
        let events = vec![
            make_event(4, "/etc/config", -2, 0),  // stat fails
            make_event(257, "/etc/config", 0, 0), // openat succeeds later
        ];
        let capture = make_capture(events);

        let filtered = extract_file_paths(&capture, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/etc/config");
    }

    #[test]
    fn precreate_includes_all_failed_paths() {
        let events = vec![
            make_event(4, "/tmp/gone", -2, 0),
            make_event(257, "/tmp/also_gone", -2, 0),
        ];
        let capture = make_capture(events);

        let all = extract_file_paths(&capture, Some(MissingFilesStrategy::Precreate));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn parentdir_includes_all_failed_paths() {
        let events = vec![
            make_event(4, "/tmp/gone", -2, 0),
            make_event(257, "/tmp/also_gone", -2, 0),
        ];
        let capture = make_capture(events);

        let all = extract_file_paths(&capture, Some(MissingFilesStrategy::Parentdir));
        assert_eq!(all.len(), 2);
    }
}

/// Parse `getcap` output into a list of capability names.
///
/// Input format: `/usr/bin/ping cap_net_raw=ep`
/// or: `/usr/bin/ping cap_net_raw,cap_sys_admin=eip`
fn parse_getcap_output(output: &str) -> Vec<String> {
    let mut caps = Vec::new();

    for line in output.lines() {
        // Format: "<path> <cap_list>=<flags>"
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }

        let cap_part = parts[1].trim().trim_start_matches("= ");

        // Split on '=' to get the cap names before the flags
        if let Some(names_part) = cap_part.split('=').next() {
            for cap_name in names_part.split(',') {
                let cap_name = cap_name.trim();
                if !cap_name.is_empty() {
                    let upper = cap_name.to_uppercase();
                    let normalized = if upper.starts_with("CAP_") {
                        upper
                    } else {
                        format!("CAP_{}", upper)
                    };
                    caps.push(normalized);
                }
            }
        }
    }

    caps
}
