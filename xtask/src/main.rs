//! Build tasks for SysCallMeMaybe
//!
//! Usage:
//!   cargo xtask build-ebpf      # Build eBPF programs
//!   cargo xtask build           # Build everything
//!   cargo xtask test            # Run tests

use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build tasks for SysCallMeMaybe")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF programs
    BuildEbpf {
        /// Build profile (dev or release)
        #[arg(long, default_value = "release")]
        profile: String,
    },
    /// Build all userspace tools
    Build {
        /// Release build
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + userspace)
    BuildAll {
        /// Release build
        #[arg(long)]
        release: bool,
    },
    /// Run tests
    Test,
    /// Install tools to /usr/local/bin
    Install,
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<()> {
    match args.command {
        Commands::BuildEbpf { profile } => build_ebpf(&profile),
        Commands::Build { release } => build_userspace(release),
        Commands::BuildAll { release } => {
            build_ebpf(if release { "release" } else { "dev" })?;
            build_userspace(release)
        }
        Commands::Test => run_tests(),
        Commands::Install => install(),
    }
}

fn build_ebpf(profile: &str) -> Result<()> {
    println!("Building eBPF programs...");

    // Check for bpf-linker
    let linker_check = Command::new("cargo")
        .args(["install", "--list"])
        .output()
        .context("Failed to check installed tools")?;

    if !String::from_utf8_lossy(&linker_check.stdout).contains("bpf-linker") {
        println!("Installing bpf-linker...");
        let status = Command::new("cargo")
            .args(["install", "bpf-linker"])
            .status()
            .context("Failed to install bpf-linker")?;

        if !status.success() {
            anyhow::bail!("Failed to install bpf-linker");
        }
    }

    // Build eBPF programs
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly-2026-01-15",
        "build",
        "--package",
        "scmm-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to build eBPF programs")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    println!("eBPF programs built successfully");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    println!("Building userspace tools...");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--workspace", "--exclude", "scmm-ebpf"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to build userspace tools")?;

    if !status.success() {
        anyhow::bail!("Userspace build failed");
    }

    println!("Userspace tools built successfully");
    Ok(())
}

fn run_tests() -> Result<()> {
    println!("Running tests...");

    let status = Command::new("cargo")
        .args(["test", "--workspace", "--exclude", "scmm-ebpf"])
        .status()
        .context("Failed to run tests")?;

    if !status.success() {
        anyhow::bail!("Tests failed");
    }

    println!("All tests passed");
    Ok(())
}

fn install() -> Result<()> {
    println!("Installing SysCallMeMaybe tools...");

    // Build release first
    build_userspace(true)?;

    let tools = ["scmm-record", "scmm-extract", "scmm-compile", "scmm-enforce"];
    let install_dir = "/usr/local/bin";

    for tool in &tools {
        let src = format!("target/release/{}", tool);
        let dst = format!("{}/{}", install_dir, tool);

        println!("Installing {} to {}", tool, dst);

        let status = Command::new("sudo")
            .args(["cp", &src, &dst])
            .status()
            .context(format!("Failed to install {}", tool))?;

        if !status.success() {
            anyhow::bail!("Failed to install {}", tool);
        }
    }

    println!("Installation complete!");
    println!();
    println!("Usage:");
    println!("  scmm-record -o capture.scmm-cap -- ./my-program");
    println!("  scmm-extract -i capture.scmm-cap -o policy.scmm.yaml");
    println!("  scmm-compile -i policy.scmm.yaml -o policy.scmm-pol");
    println!("  scmm-enforce -p policy.scmm-pol -- ./my-program");

    Ok(())
}
