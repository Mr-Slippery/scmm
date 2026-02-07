//! SysCallMeMaybe Policy Compiler
//!
//! Compiles YAML policy files into binary format for efficient enforcement.
//!
//! # Usage
//!
//! ```bash
//! scmm-compile -i policy.scmm.yaml -o policy.scmm-pol
//! ```

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

mod codegen;
mod validator;

use scmm_common::policy::YamlPolicy;

/// SysCallMeMaybe (SCMM) - Policy compiler
///
/// Compiles YAML policies into binary format for efficient loading and enforcement.
#[derive(Parser, Debug)]
#[command(name = "scmm-compile")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "SCMM stands for SysCallMeMaybe - a Linux syscall sandboxing suite.")]
struct Args {
    /// Input YAML policy file
    #[arg(short, long)]
    input: PathBuf,

    /// Output compiled policy file
    #[arg(short, long, default_value = "policy.scmm-pol")]
    output: PathBuf,

    /// Target architecture (x86_64, aarch64)
    #[arg(long, default_value = "x86_64")]
    arch: String,

    /// Skip validation (not recommended)
    #[arg(long)]
    no_validate: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    let args = Args::parse();

    scmm_common::init_tracing(args.verbose);

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<()> {
    info!("SysCallMeMaybe Policy Compiler");

    // Read YAML policy
    info!("Reading policy from: {}", args.input.display());
    let mut file = File::open(&args.input).context("Failed to open policy file")?;
    let mut yaml_content = String::new();
    file.read_to_string(&mut yaml_content)?;

    let policy: YamlPolicy =
        serde_yaml::from_str(&yaml_content).context("Failed to parse YAML policy")?;

    info!("Policy name: {}", policy.metadata.name);
    info!("Syscall rules: {}", policy.syscalls.len());
    info!("Filesystem rules: {}", policy.filesystem.rules.len());

    // Validate policy
    if !args.no_validate {
        info!("Validating policy...");
        let warnings = validator::validate(&policy, &args.arch)?;
        for warning in warnings {
            warn!("{}", warning);
        }
    }

    // Compile policy
    info!("Compiling policy...");
    let compiled = codegen::compile(&policy, &args.arch)?;

    // Write output
    info!("Writing compiled policy to: {}", args.output.display());
    let mut out_file = File::create(&args.output).context("Failed to create output file")?;
    out_file.write_all(&compiled)?;

    info!(
        "Compilation complete: {} bytes",
        compiled.len()
    );
    println!("Policy compiled successfully: {}", args.output.display());
    println!("Use 'scmm-enforce' to run a program with this policy.");

    Ok(())
}
