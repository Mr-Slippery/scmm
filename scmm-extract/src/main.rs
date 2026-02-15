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
use clap::{Parser, ValueEnum};

use scmm_common::policy::OnMissing;

mod interactive;
mod parser;
mod strace_parser;
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

    /// Default strategy for files that may not exist at enforcement time.
    /// Controls what the enforcer does when a path in the policy doesn't exist:
    ///   precreate  - enforcer pre-creates the file for precise Landlock targeting
    ///   parentdir  - grant restricted rights on parent directory (no read_file)
    ///   skip       - silently drop the rule
    #[arg(long, value_enum)]
    missing_files: Option<MissingFilesStrategy>,

    /// Show statistics without generating policy
    #[arg(long)]
    stats_only: bool,

    /// Non-interactive mode: auto-select defaults without prompting.
    /// Uses deny-by-default, allows all observed syscalls, exact file paths.
    #[arg(long)]
    non_interactive: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// Strategy for handling missing files at enforcement time
#[derive(Debug, Clone, Copy, ValueEnum)]
enum MissingFilesStrategy {
    Precreate,
    Parentdir,
    Skip,
}

impl MissingFilesStrategy {
    fn to_on_missing(self) -> OnMissing {
        match self {
            MissingFilesStrategy::Precreate => OnMissing::Precreate,
            MissingFilesStrategy::Parentdir => OnMissing::Parentdir,
            MissingFilesStrategy::Skip => OnMissing::Skip,
        }
    }
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
    let policy_name = args.name.unwrap_or_else(|| {
        args.input
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string()
    });

    let missing_files_override = args.missing_files.map(|s| s.to_on_missing());
    let policy = if args.non_interactive {
        interactive::run_non_interactive_extraction(&capture, &policy_name, missing_files_override)?
    } else {
        interactive::run_interactive_extraction(&capture, &policy_name, missing_files_override)?
    };

    // Write YAML policy
    yaml::write_policy(&args.output, &policy)?;

    println!();
    println!("Policy written to: {}", args.output.display());
    println!("Use 'scmm-compile' to compile this policy for enforcement.");

    Ok(())
}
