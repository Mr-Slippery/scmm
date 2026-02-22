//! SysCallMeMaybe Recorder
//!
//! Records syscalls of a process using eBPF tracepoints.
//!
//! # Usage
//!
//! ```bash
//! scmm-record -o capture.scmm-cap -- ./my-program arg1 arg2
//! scmm-record --files --network -o capture.scmm-cap -- ./my-program
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

mod capture;
mod loader;

use scmm_common::CategoryFilter;

/// SysCallMeMaybe (SCMM) - Syscall recorder using eBPF
///
/// Records all syscalls made by a process into a capture file for later
/// analysis and policy generation.
#[derive(Parser, Debug)]
#[command(name = "scmm-record")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "SCMM stands for SysCallMeMaybe - a Linux syscall sandboxing suite.")]
struct Args {
    /// Output capture file path
    #[arg(short, long, default_value = "capture.scmm-cap")]
    output: PathBuf,

    /// Record file-related syscalls (open, read, write, etc.)
    #[arg(long)]
    files: bool,

    /// Record network-related syscalls (socket, connect, etc.)
    #[arg(long)]
    network: bool,

    /// Record process-related syscalls (fork, exec, etc.)
    #[arg(long)]
    process: bool,

    /// Record memory-related syscalls (mmap, mprotect, etc.)
    #[arg(long)]
    memory: bool,

    /// Record IPC-related syscalls (pipe, shm, etc.)
    #[arg(long)]
    ipc: bool,

    /// Record all syscalls (default if no category specified)
    #[arg(long)]
    all: bool,

    /// Follow child processes (fork/clone) [default: true]
    #[arg(short = 'f', long, default_value_t = true)]
    follow_forks: bool,

    /// Attach to an existing process by PID (mutually exclusive with command)
    #[arg(short = 'p', long)]
    pid: Option<u32>,

    /// Run the traced command as this user:group (e.g. "nobody:nogroup", "1000:1000").
    /// Useful when recording with sudo so the child doesn't run as root.
    #[arg(long, value_name = "USER:GROUP")]
    user: Option<String>,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Command to execute and trace
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

impl Args {
    /// Get the category filter based on command line arguments
    fn category_filter(&self) -> CategoryFilter {
        // If no specific category is set, or --all is specified, record everything
        if self.all || (!self.files && !self.network && !self.process && !self.memory && !self.ipc)
        {
            return CategoryFilter::ALL;
        }

        let mut filter = CategoryFilter::NONE;
        if self.files {
            filter |= CategoryFilter::FILES;
        }
        if self.network {
            filter |= CategoryFilter::NETWORK;
        }
        if self.process {
            filter |= CategoryFilter::PROCESS;
        }
        if self.memory {
            filter |= CategoryFilter::MEMORY;
        }
        if self.ipc {
            filter |= CategoryFilter::IPC;
        }
        // Always include time and signal for context
        filter |= CategoryFilter::TIME;
        filter |= CategoryFilter::SIGNAL;
        filter |= CategoryFilter::OTHER;

        filter
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    scmm_common::init_tracing(args.verbose);

    // Set up signal handlers for graceful shutdown.
    // We intercept SIGINT, SIGTERM, SIGHUP, and SIGQUIT so we can:
    //   1. Forward the signal to the child process being recorded.
    //   2. Flush the capture file cleanly.
    //   3. Re-raise the signal on ourselves so the shell sees the correct
    //      "killed by signal" exit status.
    let running = Arc::new(AtomicBool::new(true));
    let signal_num = Arc::new(AtomicI32::new(0));

    {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])
            .expect("Error setting signal handlers");
        let r = running.clone();
        let s = signal_num.clone();
        thread::spawn(move || {
            // Block until the first signal arrives; store the signal number
            // and clear the running flag so the main loop can react.
            if let Some(sig) = signals.into_iter().next() {
                info!("Received signal {}, stopping...", sig);
                s.store(sig, Ordering::SeqCst);
                r.store(false, Ordering::SeqCst);
            }
        });
    }

    // Run the recorder
    match run(args, running, signal_num) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

/// Parse a "user:group" specification into (uid, gid).
/// Accepts names or numeric IDs: "v:v", "1000:1000", "v:1000".
fn parse_user_spec(spec: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Expected USER:GROUP format, got {:?}", spec);
    }

    let uid = match parts[0].parse::<u32>() {
        Ok(id) => id,
        Err(_) => {
            let user = nix::unistd::User::from_name(parts[0])?
                .ok_or_else(|| anyhow::anyhow!("Unknown user: {}", parts[0]))?;
            user.uid.as_raw()
        }
    };

    let gid = match parts[1].parse::<u32>() {
        Ok(id) => id,
        Err(_) => {
            let group = nix::unistd::Group::from_name(parts[1])?
                .ok_or_else(|| anyhow::anyhow!("Unknown group: {}", parts[1]))?;
            group.gid.as_raw()
        }
    };

    Ok((uid, gid))
}

/// If running under sudo, return the original user's uid/gid from
/// SUDO_UID and SUDO_GID environment variables.
fn resolve_sudo_user() -> Option<(u32, u32)> {
    let uid = std::env::var("SUDO_UID").ok()?.parse::<u32>().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse::<u32>().ok()?;
    Some((uid, gid))
}

fn run(args: Args, running: Arc<AtomicBool>, signal_num: Arc<AtomicI32>) -> Result<()> {
    // Validate: exactly one of --pid or command must be provided
    let attach_pid = args.pid;
    let has_command = !args.command.is_empty();

    match (attach_pid, has_command) {
        (Some(_), true) => anyhow::bail!("Cannot specify both --pid and a command"),
        (None, false) => anyhow::bail!("Must specify either --pid or a command to run"),
        _ => {}
    }

    info!(
        "SysCallMeMaybe recorder starting - tracing: {}",
        if let Some(pid) = attach_pid {
            format!("PID {}", pid)
        } else {
            args.command.join(" ")
        }
    );
    info!("Output: {}", args.output.display());
    info!(
        "Categories: {}",
        if args.category_filter() == CategoryFilter::ALL {
            "all".to_string()
        } else {
            let mut cats = Vec::new();
            let filter = args.category_filter();
            if (filter.0 & CategoryFilter::FILES.0) != 0 {
                cats.push("files");
            }
            if (filter.0 & CategoryFilter::NETWORK.0) != 0 {
                cats.push("network");
            }
            if (filter.0 & CategoryFilter::PROCESS.0) != 0 {
                cats.push("process");
            }
            if (filter.0 & CategoryFilter::MEMORY.0) != 0 {
                cats.push("memory");
            }
            if (filter.0 & CategoryFilter::IPC.0) != 0 {
                cats.push("ipc");
            }
            cats.join(", ")
        }
    );

    // Check for root or CAP_BPF
    if !nix::unistd::geteuid().is_root()
        && !caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_BPF).unwrap_or(false)
    {
        warn!("Running without root or CAP_BPF - eBPF loading may fail");
        warn!("Consider running with sudo or: setcap cap_bpf,cap_perfmon,cap_dac_read_search=ep <binary>");
    }

    // Load eBPF programs and start recording
    let mut recorder =
        loader::Recorder::new(&args.output, args.category_filter(), args.follow_forks)
            .context("Failed to initialize recorder")?;

    let root_pid = if let Some(pid) = attach_pid {
        if args.user.is_some() {
            warn!("--user is ignored when attaching to an existing process");
        }

        recorder
            .attach_pid(pid)
            .context("Failed to attach to process")?;

        info!("Attached to process with PID {}", pid);
        pid
    } else {
        // Determine uid/gid for the child process.
        // If --user is given, use that. Otherwise, if running under sudo,
        // default to SUDO_UID:SUDO_GID so the child runs as the invoking user.
        let run_as = if let Some(ref spec) = args.user {
            Some(parse_user_spec(spec).context("Invalid --user value")?)
        } else {
            resolve_sudo_user()
        };

        if let Some((uid, gid)) = run_as {
            info!("Child will run as uid={}, gid={}", uid, gid);
        }

        let child_pid = recorder
            .spawn_command(&args.command, run_as)
            .context("Failed to spawn command")?;

        info!("Started process with PID {}", child_pid);
        child_pid
    };

    // Event processing loop
    recorder.run(running, signal_num.clone(), root_pid)?;

    // Finalize capture file
    recorder.finalize()?;

    info!("Recording complete");

    // Re-raise the signal on ourselves so the shell sees "killed by signal X"
    // rather than a plain exit code. This mirrors the standard behaviour of
    // programs that catch a signal, do cleanup, and then die from it.
    let sig = signal_num.load(Ordering::SeqCst);
    if sig != 0 {
        use nix::sys::signal::{self, SigHandler, Signal};
        if let Ok(signal) = Signal::try_from(sig) {
            // Reset to the default handler so the raise actually terminates us.
            let _ = unsafe { signal::signal(signal, SigHandler::SigDfl) };
            let _ = signal::raise(signal);
        }
    }

    Ok(())
}
