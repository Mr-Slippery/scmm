//! Landlock enforcement

use std::path::Path;

use anyhow::{Context, Result};
use landlock::{
    Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, ABI,
};
use tracing::{debug, info, warn};

use crate::loader::LoadedPolicy;

/// Format access flags as a human-readable string
fn format_access(access: BitFlags<AccessFs>) -> String {
    let mut names = Vec::new();
    if access.contains(AccessFs::Execute) { names.push("execute"); }
    if access.contains(AccessFs::WriteFile) { names.push("write_file"); }
    if access.contains(AccessFs::ReadFile) { names.push("read_file"); }
    if access.contains(AccessFs::ReadDir) { names.push("read_dir"); }
    if access.contains(AccessFs::RemoveDir) { names.push("remove_dir"); }
    if access.contains(AccessFs::RemoveFile) { names.push("remove_file"); }
    if access.contains(AccessFs::MakeChar) { names.push("make_char"); }
    if access.contains(AccessFs::MakeDir) { names.push("make_dir"); }
    if access.contains(AccessFs::MakeReg) { names.push("make_reg"); }
    if access.contains(AccessFs::MakeSock) { names.push("make_sock"); }
    if access.contains(AccessFs::MakeFifo) { names.push("make_fifo"); }
    if access.contains(AccessFs::MakeBlock) { names.push("make_block"); }
    if access.contains(AccessFs::MakeSym) { names.push("make_sym"); }
    if access.contains(AccessFs::Refer) { names.push("refer"); }
    if access.contains(AccessFs::Truncate) { names.push("truncate"); }
    names.join(", ")
}

/// Apply Landlock rules from policy
pub fn apply(policy: &LoadedPolicy) -> Result<()> {
    if policy.landlock_rules.is_empty() {
        info!("No Landlock rules in policy, skipping Landlock enforcement");
        return Ok(());
    }

    let abi = ABI::V5;

    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .context("Failed to create Landlock ruleset")?;

    let mut ruleset_created = ruleset.create().context("Failed to create Landlock ruleset")?;

    info!("Applying {} Landlock filesystem rule(s):", policy.landlock_rules.len());
    for rule in policy.landlock_rules.iter() {
        if rule.rule_type != 1 {
            continue;
        }

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

        match add_path_rule(&mut ruleset_created, path, access) {
            Ok(true) => {
                if expanded == *path {
                    info!("  allow {} [{}]", path, access_str);
                } else {
                    info!("  allow {} -> {} [{}]", path, expanded, access_str);
                }
            }
            Ok(false) => {
                info!("  skip  {} (path does not exist)", expanded);
            }
            Err(e) => warn!("  FAIL  {}: {}", path, e),
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
            warn!("Landlock only partially enforced - some rules may not work");
        }
        landlock::RulesetStatus::NotEnforced => {
            warn!("Landlock not enforced - kernel may be too old");
        }
    }

    Ok(())
}

fn add_path_rule(
    ruleset: &mut landlock::RulesetCreated,
    path: &str,
    access: BitFlags<AccessFs>,
) -> Result<bool> {
    let expanded_path = expand_path(path);

    if !Path::new(&expanded_path).exists() {
        debug!("Path does not exist, skipping: {}", expanded_path);
        return Ok(false);
    }

    let path_fd = PathFd::new(&expanded_path).context("Failed to open path")?;

    ruleset
        .add_rule(PathBeneath::new(path_fd, access).set_compatibility(CompatLevel::BestEffort))
        .context("Failed to add path rule")?;

    Ok(true)
}

fn bitmap_to_access_fs(bitmap: u64) -> BitFlags<AccessFs> {
    let mut access = BitFlags::<AccessFs>::empty();

    if bitmap & (1 << 0) != 0 {
        access |= AccessFs::Execute;
    }
    if bitmap & (1 << 1) != 0 {
        access |= AccessFs::WriteFile;
    }
    if bitmap & (1 << 2) != 0 {
        access |= AccessFs::ReadFile;
    }
    if bitmap & (1 << 3) != 0 {
        access |= AccessFs::ReadDir;
    }
    if bitmap & (1 << 4) != 0 {
        access |= AccessFs::RemoveDir;
    }
    if bitmap & (1 << 5) != 0 {
        access |= AccessFs::RemoveFile;
    }
    if bitmap & (1 << 6) != 0 {
        access |= AccessFs::MakeChar;
    }
    if bitmap & (1 << 7) != 0 {
        access |= AccessFs::MakeDir;
    }
    if bitmap & (1 << 8) != 0 {
        access |= AccessFs::MakeReg;
    }
    if bitmap & (1 << 9) != 0 {
        access |= AccessFs::MakeSock;
    }
    if bitmap & (1 << 10) != 0 {
        access |= AccessFs::MakeFifo;
    }
    if bitmap & (1 << 11) != 0 {
        access |= AccessFs::MakeBlock;
    }
    if bitmap & (1 << 12) != 0 {
        access |= AccessFs::MakeSym;
    }
    if bitmap & (1 << 13) != 0 {
        access |= AccessFs::Refer;
    }
    if bitmap & (1 << 14) != 0 {
        access |= AccessFs::Truncate;
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
