//! SysCallMeMaybe Enforcer
//!
//! Launches a program with syscall policy enforcement.
//!
//! # Usage
//!
//! ```bash
//! scmm-enforce -p policy.scmm-pol -- ./my-program arg1 arg2
//! scmm-enforce --mode=strict -p policy.scmm-pol -- ./my-program
//! ```

use std::ffi::CString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use nix::unistd::{Gid, Uid};
use tracing::{info, warn, Level};

mod landlock;
mod loader;
mod seccomp;

use caps::{CapSet, CapsHashSet};

/// Enforcement mode
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum EnforcementMode {
    /// Seccomp + Landlock (if available), warn if Landlock missing
    #[default]
    Standard,
    /// Seccomp + Landlock required, fail if Landlock unavailable
    Strict,
    /// Seccomp only, maximum compatibility
    Seccomp,
}

/// SysCallMeMaybe (SCMM) - Syscall enforcer
///
/// Launches a program with syscall filtering and filesystem sandboxing
/// based on a compiled policy file.
#[derive(Parser, Debug)]
#[command(name = "scmm-enforce")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "SCMM stands for SysCallMeMaybe - a Linux syscall sandboxing suite.")]
struct Args {
    /// Compiled policy file
    #[arg(short, long)]
    policy: PathBuf,

    /// Enforcement mode
    #[arg(short, long, default_value = "standard")]
    mode: EnforcementMode,

    /// Filter only specific categories (comma-separated: files,network,process,memory,ipc)
    #[arg(long)]
    categories: Option<String>,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Command to execute
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Enforcer is silent by default (ERROR only) since it execs into the target
    // and any output would mix with the target's output.
    // -v = WARN, -vv = INFO, -vvv = DEBUG, -vvvv = TRACE
    scmm_common::init_tracing_with_base(args.verbose, Level::ERROR);

    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<ExitCode> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified");
    }

    info!("SysCallMeMaybe Enforcer");
    info!("Policy: {}", args.policy.display());
    info!("Mode: {:?}", args.mode);
    info!("Command: {}", args.command.join(" "));

    // Load policy
    let policy = loader::load_policy(&args.policy).context("Failed to load policy")?;

    // Detect system capabilities
    let caps = detect_capabilities();
    info!(
        "Capabilities: seccomp={}, landlock={}",
        caps.seccomp, caps.landlock
    );

    let has_run_as = policy.run_as_uid.is_some() || policy.run_as_gid.is_some();
    let has_caps = policy.capabilities != 0;
    info!(
        "run_as: uid={:?}, gid={:?}, has_run_as={}, has_caps={}",
        policy.run_as_uid, policy.run_as_gid, has_run_as, has_caps
    );

    // Apply capabilities if requested (requires root).
    // When combined with run_as, we set caps now (as root), then use PR_SET_KEEPCAPS
    // to retain them across the setuid transition, and re-raise ambient caps afterward.
    if has_caps {
        apply_capabilities(policy.capabilities)?;
    }

    // Apply enforcement based on mode.
    // Landlock must be applied BEFORE seccomp because the Landlock syscalls
    // (landlock_create_ruleset, landlock_add_rule, landlock_restrict_self)
    // would be blocked by the seccomp filter.
    // Landlock is also applied before drop_privileges so we can open any path as root.
    match args.mode {
        EnforcementMode::Strict => {
            if !caps.landlock {
                bail!(
                    "Landlock not available. Strict mode requires kernel 5.13+ with Landlock enabled."
                );
            }
            landlock::apply(&policy, has_run_as)?;
        }
        EnforcementMode::Standard => {
            if caps.landlock {
                landlock::apply(&policy, has_run_as)?;
            } else {
                warn!("Landlock not available - path-based restrictions will not be enforced");
                warn!("Consider upgrading to kernel 5.13+ for full protection");
            }
        }
        EnforcementMode::Seccomp => {}
    }

    // Drop privileges AFTER Landlock but BEFORE seccomp.
    // When capabilities are requested, PR_SET_KEEPCAPS preserves the Permitted
    // set across the setuid transition, then we re-raise Inheritable + Ambient.
    if has_run_as {
        let uid = policy
            .run_as_uid
            .unwrap_or_else(|| nix::unistd::getuid().as_raw());
        let gid = policy
            .run_as_gid
            .unwrap_or_else(|| nix::unistd::getgid().as_raw());
        drop_privileges(uid, gid, if has_caps { policy.capabilities } else { 0 })?;
    }

    // Set NO_NEW_PRIVS before applying seccomp (required by kernel unless we have CAP_SYS_ADMIN).
    // When capabilities are requested (with or without run_as), we skip NO_NEW_PRIVS
    // so ambient caps survive into execve. This requires CAP_SYS_ADMIN for seccomp loading.
    if has_caps {
        info!("Skipping NO_NEW_PRIVS to preserve Ambient capabilities across execve");
        if !caps::has_cap(None, CapSet::Effective, caps::Capability::CAP_SYS_ADMIN).unwrap_or(false)
        {
            warn!("CAP_SYS_ADMIN is missing. Seccomp filter loading will likely fail without NO_NEW_PRIVS.");
            warn!("Ensure scmm-enforce has file capability cap_sys_admin+ep or is run with sudo.");
        }
    } else {
        set_no_new_privs()?;
    }

    // All logging MUST happen before seccomp is applied. After the seccomp
    // filter is installed, write/writev may be blocked, so any tracing or
    // error reporting would crash the process.
    info!("Executing command...");
    apply_seccomp(&policy)?;

    // After this point, only execvp or _exit — no logging, no error formatting.
    exec_command(&args.command)
}

/// System capabilities
struct Capabilities {
    seccomp: bool,
    landlock: bool,
}

/// Detect available system capabilities
fn detect_capabilities() -> Capabilities {
    Capabilities {
        seccomp: check_seccomp(),
        landlock: check_landlock(),
    }
}

/// Check if seccomp is available
fn check_seccomp() -> bool {
    // Seccomp is available on all modern Linux kernels (3.5+)
    std::path::Path::new("/proc/sys/kernel/seccomp").exists()
        || std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail").is_ok()
}

/// Check if Landlock is available
fn check_landlock() -> bool {
    // Check if Landlock is enabled in the kernel
    if let Ok(lsm_list) = std::fs::read_to_string("/sys/kernel/security/lsm") {
        if lsm_list.contains("landlock") {
            return true;
        }
    }

    // Alternative: try to create a ruleset and see if it works
    // This is more reliable but involves a syscall
    false
}

/// Apply seccomp filter.
///
/// All logging happens BEFORE the filter is installed. After `apply_filter()`
/// returns, write/writev may be blocked so no further I/O is safe.
fn apply_seccomp(policy: &loader::LoadedPolicy) -> Result<()> {
    if policy.seccomp_filter.is_empty() {
        info!("No seccomp filter in policy");
        return Ok(());
    }

    let insn_count = policy.seccomp_filter.len() / 8;
    info!("Applying seccomp filter ({} instructions)", insn_count);
    seccomp::apply_filter(&policy.seccomp_filter)?;
    // NO logging after this point — write() may be blocked
    Ok(())
}

/// Set PR_SET_NO_NEW_PRIVS
fn set_no_new_privs() -> Result<()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        anyhow::bail!(
            "Failed to set NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Drop privileges to the specified uid/gid.
///
/// If the target uid/gid already match the current process, this is a no-op
/// (avoids EPERM from setgroups/setgid/setuid which require CAP_SETGID/CAP_SETUID).
///
/// When `cap_mask != 0`, uses `PR_SET_KEEPCAPS` to retain the Permitted capability
/// set across the setuid transition, then re-raises Inheritable + Ambient caps.
/// Without this, the kernel clears all capability sets when transitioning from
/// uid 0 to non-zero.
///
/// Order: setgroups → setgid → PR_SET_KEEPCAPS → setuid → re-raise caps
fn drop_privileges(uid: u32, gid: u32, cap_mask: u64) -> Result<()> {
    let current_uid = nix::unistd::getuid().as_raw();
    let current_gid = nix::unistd::getgid().as_raw();
    let target_uid = Uid::from_raw(uid);
    let target_gid = Gid::from_raw(gid);

    if uid == current_uid && gid == current_gid {
        info!(
            "Already running as uid={}, gid={} — skipping privilege drop",
            uid, gid
        );
        return Ok(());
    }

    // Set supplementary groups and fix environment for the target user
    match nix::unistd::User::from_uid(target_uid) {
        Ok(Some(user)) => {
            let cname =
                CString::new(user.name.as_str()).context("Invalid username for getgrouplist")?;
            match nix::unistd::getgrouplist(&cname, target_gid) {
                Ok(groups) => {
                    nix::unistd::setgroups(&groups).context("setgroups failed")?;
                }
                Err(e) => {
                    warn!(
                        "Could not get supplementary groups: {}, using only primary gid",
                        e
                    );
                    nix::unistd::setgroups(&[target_gid]).context("setgroups failed")?;
                }
            }
            // Update environment so child processes see the correct HOME/USER.
            // Without this, programs run under sudo still see HOME=/root.
            std::env::set_var("HOME", &user.dir);
            std::env::set_var("USER", &user.name);
            info!("Set HOME={}, USER={}", user.dir.display(), user.name);
        }
        Ok(None) => {
            warn!("No passwd entry for uid={}, cannot set HOME/USER", uid);
            nix::unistd::setgroups(&[target_gid]).context("setgroups failed")?;
        }
        Err(e) => {
            warn!("Failed to look up uid={}: {}, cannot set HOME/USER", uid, e);
            nix::unistd::setgroups(&[target_gid]).context("setgroups failed")?;
        }
    }

    nix::unistd::setgid(target_gid).context("setgid failed")?;

    // If we need to preserve capabilities across the UID transition, set KEEPCAPS.
    // Without this, the kernel clears Permitted/Effective/Ambient when going from
    // root (uid 0) to non-root.
    if cap_mask != 0 && current_uid == 0 && uid != 0 {
        info!("Setting PR_SET_KEEPCAPS to preserve capabilities across setuid");
        let ret = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
        if ret != 0 {
            anyhow::bail!(
                "Failed to set PR_SET_KEEPCAPS: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    nix::unistd::setuid(target_uid).context("setuid failed")?;
    info!("Dropped privileges to uid={}, gid={}", uid, gid);

    // After setuid with KEEPCAPS, the Permitted set is retained but Effective and
    // Ambient are cleared. Re-raise the requested caps in all three sets.
    if cap_mask != 0 && current_uid == 0 && uid != 0 {
        info!("Re-raising capabilities after privilege drop");
        apply_capabilities(cap_mask).context("Failed to re-raise capabilities after setuid")?;
    }

    Ok(())
}

/// Execute the command (replaces current process)
fn exec_command(command: &[String]) -> Result<ExitCode> {
    let program = CString::new(command[0].as_bytes())?;
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();

    // Use execvp to search PATH
    let err = nix::unistd::execvp(&program, &args);

    // If we get here, exec failed
    Err(anyhow::anyhow!(
        "Failed to execute {}: {:?}",
        command[0],
        err
    ))
}

/// Apply requested capabilities to the Effective, Inheritable, and Ambient sets.
///
/// After PR_SET_KEEPCAPS + setuid, only the Permitted set is retained.
/// This function raises the requested caps in Effective (needed to raise
/// Inheritable/Ambient), then Inheritable, then Ambient.
fn apply_capabilities(mask: u64) -> Result<()> {
    if mask == 0 {
        return Ok(());
    }

    info!("Applying capabilities (mask: {:#x})", mask);

    let mut to_raise = CapsHashSet::new();
    for cap in caps::all() {
        if (mask & (1 << cap.index())) != 0 {
            to_raise.insert(cap);
        }
    }

    if to_raise.is_empty() {
        return Ok(());
    }

    info!("Requested capabilities: {:?}", to_raise);

    // 1. Verify caps are in the Permitted set
    let permitted = caps::read(None, CapSet::Permitted)?;
    let missing: CapsHashSet = to_raise.difference(&permitted).cloned().collect();

    if !missing.is_empty() {
        warn!(
            "Missing permitted capabilities: {:?}. scmm-enforce should be run as root or with appropriate file caps.",
            missing
        );
    }

    // 2. Raise in Effective set (needed to modify Inheritable/Ambient)
    let mut effective = caps::read(None, CapSet::Effective)?;
    effective.extend(to_raise.iter().cloned());
    caps::set(None, CapSet::Effective, &effective)
        .context("Failed to set Effective capabilities")?;

    // 3. Add to Inheritable
    let mut inheritable = caps::read(None, CapSet::Inheritable)?;
    inheritable.extend(to_raise.iter().cloned());
    caps::set(None, CapSet::Inheritable, &inheritable)
        .context("Failed to set Inheritable capabilities")?;

    // 4. Add to Ambient (each must be raised individually)
    for cap in to_raise {
        if let Err(e) = caps::raise(None, CapSet::Ambient, cap) {
            warn!("Failed to raise ambient capability {:?}: {}", cap, e);
            warn!("Ensure you are running a kernel with Ambient Capabilities support (4.3+)");
            return Err(e.into());
        }
    }

    info!("Ambient capabilities set successfully");
    Ok(())
}
