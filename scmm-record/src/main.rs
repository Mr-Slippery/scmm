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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

    /// Follow child processes (fork/clone)
    #[arg(short = 'f', long)]
    follow_forks: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Command to execute and trace
    #[arg(trailing_var_arg = true, required = true)]
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

    // Set up signal handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        info!("Received interrupt signal, stopping...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    // Run the recorder
    match run(args, running) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args, running: Arc<AtomicBool>) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified");
    }

    info!(
        "SysCallMeMaybe recorder starting - tracing: {}",
        args.command.join(" ")
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
    let mut recorder = loader::Recorder::new(&args.output, args.category_filter(), args.follow_forks)
        .context("Failed to initialize recorder")?;

    // Spawn the target process
    let child_pid = recorder
        .spawn_command(&args.command)
        .context("Failed to spawn command")?;

    info!("Started process with PID {}", child_pid);

    // Event processing loop
    recorder.run(running, child_pid)?;

    // Finalize capture file
    recorder.finalize()?;

    info!("Recording complete");
    Ok(())
}
