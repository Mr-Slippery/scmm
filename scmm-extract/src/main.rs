//! SysCallMeMaybe Policy Extractor
//!
//! Extracts syscall rules from capture files with interactive user guidance
//! for generalizing access patterns.
//!
//! # Usage
//!
//! ```bash
//! scmm-extract -i capture.scmm-cap -o policy.scmm.yaml
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod generalize;
mod interactive;
mod parser;
mod yaml;

/// SysCallMeMaybe (SCMM) - Policy extractor
///
/// Extracts syscall rules from capture files and generates YAML policies
/// with interactive guidance for path and network generalization.
#[derive(Parser, Debug)]
#[command(name = "scmm-extract")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "SCMM stands for SysCallMeMaybe - a Linux syscall sandboxing suite.")]
struct Args {
    /// Input capture file
    #[arg(short, long)]
    input: PathBuf,

    /// Output YAML policy file
    #[arg(short, long, default_value = "policy.scmm.yaml")]
    output: PathBuf,

    /// Policy name
    #[arg(long)]
    name: Option<String>,

    /// Extract only specific categories (comma-separated: files,network,process,memory,ipc)
    #[arg(long)]
    categories: Option<String>,

    /// Show statistics without generating policy
    #[arg(long)]
    stats_only: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Set up logging
    let level = match args.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<()> {
    println!("SysCallMeMaybe Policy Extractor");
    println!("================================");
    println!();

    // Parse capture file
    println!("Loading capture file: {}", args.input.display());
    let capture = parser::parse_capture(&args.input).context("Failed to parse capture file")?;

    println!("Loaded {} events from capture", capture.events.len());
    println!();

    // Show statistics
    if args.stats_only {
        parser::print_statistics(&capture);
        return Ok(());
    }

    // Run interactive extraction
    let policy_name = args
        .name
        .unwrap_or_else(|| args.input.file_stem().unwrap().to_string_lossy().to_string());

    let policy = interactive::run_interactive_extraction(&capture, &policy_name)?;

    // Write YAML policy
    yaml::write_policy(&args.output, &policy)?;

    println!();
    println!("Policy written to: {}", args.output.display());
    println!("Use 'scmm-compile' to compile this policy for enforcement.");

    Ok(())
}
