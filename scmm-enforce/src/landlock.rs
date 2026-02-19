//! Landlock enforcement

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use scmm_common::policy::landlock_net_access;
use tracing::{debug, info, warn};

use crate::loader::LoadedPolicy;

/// Format access flags as a human-readable string
fn format_access(access: BitFlags<AccessFs>) -> String {
    let mut names = Vec::new();
    if access.contains(AccessFs::Execute) {
        names.push("execute");
    }
    if access.contains(AccessFs::WriteFile) {
        names.push("write_file");
    }
    if access.contains(AccessFs::ReadFile) {
        names.push("read_file");
    }
    if access.contains(AccessFs::ReadDir) {
        names.push("read_dir");
    }
    if access.contains(AccessFs::RemoveDir) {
        names.push("remove_dir");
    }
    if access.contains(AccessFs::RemoveFile) {
        names.push("remove_file");
    }
    if access.contains(AccessFs::MakeChar) {
        names.push("make_char");
    }
    if access.contains(AccessFs::MakeDir) {
        names.push("make_dir");
    }
    if access.contains(AccessFs::MakeReg) {
        names.push("make_reg");
    }
    if access.contains(AccessFs::MakeSock) {
        names.push("make_sock");
    }
    if access.contains(AccessFs::MakeFifo) {
        names.push("make_fifo");
    }
    if access.contains(AccessFs::MakeBlock) {
        names.push("make_block");
    }
    if access.contains(AccessFs::MakeSym) {
        names.push("make_sym");
    }
    if access.contains(AccessFs::Refer) {
        names.push("refer");
    }
    if access.contains(AccessFs::Truncate) {
        names.push("truncate");
    }
    names.join(", ")
}

/// Apply Landlock rules from policy
pub fn apply(policy: &LoadedPolicy, has_run_as: bool) -> Result<()> {
    if policy.landlock_rules.is_empty() {
        info!("No Landlock rules in policy, skipping Landlock enforcement");
        return Ok(());
    }

    let abi = ABI::V5;

    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .context("Failed to handle filesystem access")?
        .handle_access(AccessNet::from_all(ABI::V4))
        .context("Failed to handle network access")?;

    let mut ruleset_created = ruleset
        .create()
        .context("Failed to create Landlock ruleset")?;

    // Phase 1: Collect all expanded paths to compute ancestor directories
    let mut ancestor_dirs: HashSet<String> = HashSet::new();
    for rule in policy.landlock_rules.iter() {
        if rule.rule_type != 1 {
            continue;
        }
        if let Some(path) = policy.paths.get(rule.path_or_port as usize) {
            let expanded = expand_path(path);
            // Collect all ancestor directories for directory traversal
            let p = Path::new(&expanded);
            let mut current = p.parent();
            while let Some(dir) = current {
                let dir_str = dir.to_string_lossy().to_string();
                if dir_str.is_empty() || !ancestor_dirs.insert(dir_str) {
                    break; // Already processed this ancestor
                }
                current = dir.parent();
            }
        }
    }

    // Phase 2: Add directory traversal rules for all ancestor directories
    // Landlock requires execute (search) access on directories to traverse them
    let traverse_access = AccessFs::Execute | AccessFs::ReadDir;
    let mut sorted_ancestors: Vec<&str> = ancestor_dirs.iter().map(|s| s.as_str()).collect();
    sorted_ancestors.sort();
    if !sorted_ancestors.is_empty() {
        info!("Adding directory traversal rules:");
        for dir in &sorted_ancestors {
            match PathFd::new(dir) {
                Ok(path_fd) => {
                    match (&mut ruleset_created).add_rule(
                        PathBeneath::new(path_fd, traverse_access)
                            .set_compatibility(CompatLevel::BestEffort),
                    ) {
                        Ok(_) => debug!("  traverse {}", dir),
                        Err(e) => warn!("  FAIL traverse {}: {}", dir, e),
                    }
                }
                Err(_) => debug!("  skip traverse {} (does not exist)", dir),
            }
        }
    }

    // Phase 2b: Add implicit rules for the ELF interpreter (dynamic linker).
    // When execve runs a dynamically-linked binary, the kernel internally opens
    // the ELF interpreter (e.g. /lib64/ld-linux-x86-64.so.2). This access is
    // invisible to the eBPF recorder but checked by Landlock. Without this rule,
    // execve returns EACCES even though the binary itself is allowed.
    let elf_interp_access = AccessFs::Execute | AccessFs::ReadFile;
    for interp_path in &[
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ] {
        if let Ok(real) = std::fs::canonicalize(interp_path) {
            let real_str = real.to_string_lossy();
            if let Ok(path_fd) = PathFd::new(real_str.as_ref()) {
                match (&mut ruleset_created).add_rule(
                    PathBeneath::new(path_fd, elf_interp_access)
                        .set_compatibility(CompatLevel::BestEffort),
                ) {
                    Ok(_) => {
                        info!(
                            "  implicit: allow {} [execute, read_file] (ELF interpreter)",
                            real_str
                        );
                        // Also add traversal for the interpreter's directory
                        if let Some(parent) = real.parent() {
                            if let Ok(dir_fd) = PathFd::new(&*parent.to_string_lossy()) {
                                let _ = (&mut ruleset_created).add_rule(
                                    PathBeneath::new(dir_fd, traverse_access)
                                        .set_compatibility(CompatLevel::BestEffort),
                                );
                            }
                        }
                    }
                    Err(e) => warn!("  FAIL implicit {}: {}", real_str, e),
                }
                break; // Only need to add it once (all paths resolve to the same file)
            }
        }
    }

    // Phase 2c: When run_as is used, add implicit read access for NSS files
    // so the enforcer can look up the target user after Landlock is in effect.
    if has_run_as {
        let nss_read = AccessFs::ReadFile;
        for nss_path in &["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"] {
            if let Ok(path_fd) = PathFd::new(*nss_path) {
                match (&mut ruleset_created).add_rule(
                    PathBeneath::new(path_fd, nss_read).set_compatibility(CompatLevel::BestEffort),
                ) {
                    Ok(_) => info!("  implicit: allow {} [read_file] (run_as)", nss_path),
                    Err(e) => warn!("  FAIL implicit {}: {}", nss_path, e),
                }
            }
        }
    }

    // Phase 3: Apply the actual policy rules
    let fs_count = policy
        .landlock_rules
        .iter()
        .filter(|r| r.rule_type == 1)
        .count();
    let net_count = policy
        .landlock_rules
        .iter()
        .filter(|r| r.rule_type == 2)
        .count();
    info!(
        "Applying {} Landlock rule(s) ({} filesystem, {} network):",
        policy.landlock_rules.len(),
        fs_count,
        net_count,
    );
    for rule in policy.landlock_rules.iter() {
        match rule.rule_type {
            1 => {
                let path = match policy.paths.get(rule.path_or_port as usize) {
                    Some(p) => p,
                    None => {
                        warn!("  Path index {} out of bounds", rule.path_or_port);
                        continue;
                    }
                };

                let access = bitmap_to_access_fs(rule.access);
                let expanded = expand_path(path);
                let access_str = format_access(access);
                let on_missing = rule.on_missing;

                match add_path_rule(&mut ruleset_created, path, access, on_missing) {
                    Ok(true) => {
                        if expanded == *path {
                            info!("  allow {} [{}]", path, access_str);
                        } else {
                            info!("  allow {} -> {} [{}]", path, expanded, access_str);
                        }
                    }
                    Ok(false) => {
                        warn!("  skip  {} (path does not exist)", expanded);
                    }
                    Err(e) => warn!("  FAIL  {}: {}", path, e),
                }
            }
            2 => {
                let port = rule.path_or_port as u16;
                let mut net_access = BitFlags::<AccessNet>::empty();
                if rule.access & landlock_net_access::BIND_TCP != 0 {
                    net_access |= AccessNet::BindTcp;
                }
                if rule.access & landlock_net_access::CONNECT_TCP != 0 {
                    net_access |= AccessNet::ConnectTcp;
                }
                if net_access.is_empty() {
                    warn!(
                        "  Port rule for port {} has no recognized access bits",
                        port
                    );
                    continue;
                }
                match (&mut ruleset_created).add_rule(
                    NetPort::new(port, net_access).set_compatibility(CompatLevel::BestEffort),
                ) {
                    Ok(_) => info!("  allow port {} [connect_tcp]", port),
                    Err(e) => warn!("  FAIL port {}: {}", port, e),
                }
            }
            _ => {
                warn!("  Unknown rule_type {} — skipped", rule.rule_type);
            }
        }
    }

    let status = ruleset_created
        .restrict_self()
        .context("Failed to enforce Landlock ruleset")?;

    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {
            info!("Landlock fully enforced");
        }
        landlock::RulesetStatus::PartiallyEnforced => {
            info!("Landlock partially enforced (some access types unsupported by kernel ABI)");
        }
        landlock::RulesetStatus::NotEnforced => {
            warn!("Landlock not enforced - kernel may be too old");
        }
    }

    Ok(())
}

/// Access rights that Landlock checks on the parent directory, not the file itself.
/// For example, unlink() requires REMOVE_FILE on the parent, creat() requires MAKE_REG
/// on the parent. When a policy grants these on a specific file path, we must also
/// grant them on the parent directory.
const PARENT_DIR_RIGHTS: &[AccessFs] = &[
    AccessFs::RemoveFile,
    AccessFs::RemoveDir,
    AccessFs::MakeReg,
    AccessFs::MakeDir,
    AccessFs::MakeSock,
    AccessFs::MakeFifo,
    AccessFs::MakeBlock,
    AccessFs::MakeChar,
    AccessFs::MakeSym,
    AccessFs::Refer,
];

/// on_missing strategy constants (matching OnMissing repr values)
const ON_MISSING_PRECREATE: u8 = 0;
const ON_MISSING_PARENTDIR: u8 = 1;
const ON_MISSING_SKIP: u8 = 2;

fn add_path_rule(
    ruleset: &mut landlock::RulesetCreated,
    path: &str,
    access: BitFlags<AccessFs>,
    on_missing: u8,
) -> Result<bool> {
    let expanded_path = expand_path(path);

    // Collect rights that need to be granted on the parent directory
    let mut parent_rights = BitFlags::<AccessFs>::empty();
    for &right in PARENT_DIR_RIGHTS {
        if access.contains(right) {
            parent_rights |= right;
        }
    }

    // Try the exact path first
    match PathFd::new(&expanded_path) {
        Ok(path_fd) => {
            ruleset
                .add_rule(
                    PathBeneath::new(path_fd, access).set_compatibility(CompatLevel::BestEffort),
                )
                .context("Failed to add path rule")?;

            // Grant parent-directory rights on the parent if needed
            if !parent_rights.is_empty() {
                let p = Path::new(&expanded_path);
                if let Some(parent) = p.parent() {
                    if let Ok(parent_fd) = PathFd::new(&*parent.to_string_lossy()) {
                        let _ = ruleset.add_rule(
                            PathBeneath::new(parent_fd, parent_rights)
                                .set_compatibility(CompatLevel::BestEffort),
                        );
                    }
                }
            }

            Ok(true)
        }
        Err(_) => {
            // Path doesn't exist — apply the on_missing strategy
            match on_missing {
                ON_MISSING_PRECREATE => {
                    // Create missing parent directories and the file itself
                    let p = Path::new(&expanded_path);
                    if let Some(parent) = p.parent() {
                        if !parent.exists() {
                            std::fs::create_dir_all(parent).with_context(|| {
                                format!("Failed to create parent dirs for {}", expanded_path)
                            })?;
                        }
                    }
                    std::fs::File::create(&expanded_path)
                        .with_context(|| format!("Failed to pre-create {}", expanded_path))?;
                    info!("  pre-created {}", expanded_path);

                    // Now the file exists — apply the precise rule
                    let path_fd = PathFd::new(&expanded_path)
                        .map_err(|e| anyhow::anyhow!("PathFd after pre-create: {}", e))?;
                    ruleset
                        .add_rule(
                            PathBeneath::new(path_fd, access)
                                .set_compatibility(CompatLevel::BestEffort),
                        )
                        .context("Failed to add path rule after pre-create")?;

                    // Grant parent-directory rights if needed
                    if !parent_rights.is_empty() {
                        let p = Path::new(&expanded_path);
                        if let Some(parent) = p.parent() {
                            if let Ok(parent_fd) = PathFd::new(&*parent.to_string_lossy()) {
                                let _ = ruleset.add_rule(
                                    PathBeneath::new(parent_fd, parent_rights)
                                        .set_compatibility(CompatLevel::BestEffort),
                                );
                            }
                        }
                    }
                    Ok(true)
                }
                ON_MISSING_PARENTDIR => {
                    // Apply restricted rights on immediate parent directory.
                    // Grant parent-dir rights + WriteFile + Truncate on the parent.
                    // When the rule has make_reg (file creation intent), also grant
                    // ReadFile — the process will need to read back files it creates.
                    let mut ancestor_access = parent_rights;
                    if access.contains(AccessFs::WriteFile) {
                        ancestor_access |= AccessFs::WriteFile;
                    }
                    if access.contains(AccessFs::Truncate) {
                        ancestor_access |= AccessFs::Truncate;
                    }
                    if access.contains(AccessFs::MakeReg) && access.contains(AccessFs::ReadFile) {
                        ancestor_access |= AccessFs::ReadFile;
                    }

                    if ancestor_access.is_empty() {
                        return Ok(false);
                    }

                    let p = Path::new(&expanded_path);
                    if let Some(parent) = p.parent() {
                        let parent_str = parent.to_string_lossy();
                        if parent.exists() {
                            if let Ok(path_fd) = PathFd::new(parent_str.as_ref()) {
                                let ancestor_str = format_access(ancestor_access);
                                ruleset
                                    .add_rule(
                                        PathBeneath::new(path_fd, ancestor_access)
                                            .set_compatibility(CompatLevel::BestEffort),
                                    )
                                    .context("Failed to add path rule on parent")?;
                                warn!(
                                    "  (path {} does not exist, applied [{}] on parent {})",
                                    expanded_path, ancestor_str, parent_str
                                );
                                return Ok(true);
                            }
                        }
                    }
                    Ok(false)
                }
                ON_MISSING_SKIP => {
                    // Skip the rule entirely
                    Ok(false)
                }
                _ => {
                    // Unknown strategy — treat as skip
                    Ok(false)
                }
            }
        }
    }
}

fn bitmap_to_access_fs(bitmap: u64) -> BitFlags<AccessFs> {
    let mut access = BitFlags::<AccessFs>::empty();

    for name in scmm_common::policy::landlock_access::bitmap_to_names(bitmap) {
        access |= match name {
            "execute" => AccessFs::Execute,
            "write_file" => AccessFs::WriteFile,
            "read_file" => AccessFs::ReadFile,
            "read_dir" => AccessFs::ReadDir,
            "remove_dir" => AccessFs::RemoveDir,
            "remove_file" => AccessFs::RemoveFile,
            "make_char" => AccessFs::MakeChar,
            "make_dir" => AccessFs::MakeDir,
            "make_reg" => AccessFs::MakeReg,
            "make_sock" => AccessFs::MakeSock,
            "make_fifo" => AccessFs::MakeFifo,
            "make_block" => AccessFs::MakeBlock,
            "make_sym" => AccessFs::MakeSym,
            "refer" => AccessFs::Refer,
            "truncate" => AccessFs::Truncate,
            _ => continue,
        };
    }

    if access.is_empty() {
        access = AccessFs::ReadFile | AccessFs::ReadDir;
    }

    access
}

fn expand_path(path: &str) -> String {
    let mut result = path.to_string();

    if result.contains("${USER}") {
        if let Ok(user) = std::env::var("USER") {
            result = result.replace("${USER}", &user);
        }
    }

    if result.contains("${HOME}") {
        if let Ok(home) = std::env::var("HOME") {
            result = result.replace("${HOME}", &home);
        }
    }

    if result.contains("**") {
        if let Some(idx) = result.find("**") {
            result.truncate(idx);
            result = result.trim_end_matches('/').to_string();
        }
    } else if result.ends_with("/*") {
        result.truncate(result.len() - 2);
    }

    // "/**" becomes empty after stripping — use root "/"
    if result.is_empty() {
        result = "/".to_string();
    }

    result
}
