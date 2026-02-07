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

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::{info, warn};

mod landlock;
mod loader;
mod seccomp;

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

    scmm_common::init_tracing(args.verbose);

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

    // Set NO_NEW_PRIVS before applying seccomp (required by kernel)
    set_no_new_privs()?;

    // Apply enforcement based on mode.
    // Landlock must be applied BEFORE seccomp because the Landlock syscalls
    // (landlock_create_ruleset, landlock_add_rule, landlock_restrict_self)
    // would be blocked by the seccomp filter.
    match args.mode {
        EnforcementMode::Strict => {
            if !caps.landlock {
                anyhow::bail!(
                    "Landlock not available. Strict mode requires kernel 5.13+ with Landlock enabled."
                );
            }
            landlock::apply(&policy)?;
            apply_seccomp(&policy)?;
        }
        EnforcementMode::Standard => {
            if caps.landlock {
                landlock::apply(&policy)?;
            } else {
                warn!("Landlock not available - path-based restrictions will not be enforced");
                warn!("Consider upgrading to kernel 5.13+ for full protection");
            }
            apply_seccomp(&policy)?;
        }
        EnforcementMode::Seccomp => {
            apply_seccomp(&policy)?;
        }
    }

    // Execute the command
    info!("Executing command...");
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

/// Apply seccomp filter
fn apply_seccomp(policy: &loader::LoadedPolicy) -> Result<()> {
    if policy.seccomp_filter.is_empty() {
        info!("No seccomp filter in policy");
        return Ok(());
    }

    seccomp::apply_filter(&policy.seccomp_filter)?;
    info!("Seccomp filter applied");
    Ok(())
}

/// Set PR_SET_NO_NEW_PRIVS
fn set_no_new_privs() -> Result<()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        anyhow::bail!("Failed to set NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
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
    Err(anyhow::anyhow!("Failed to execute {}: {:?}", command[0], err))
}
