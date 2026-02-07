//! SysCallMeMaybe (SCMM) - Shared types and definitions
//!
//! This crate contains types shared between the eBPF kernel programs
//! and userspace tools.

#![cfg_attr(feature = "no_std", no_std)]

pub mod syscall;
pub mod capture;
pub mod policy;
pub mod categories;

pub use syscall::*;
pub use capture::*;
pub use policy::*;
pub use categories::*;

/// Maximum path length we capture from syscall arguments
pub const MAX_PATH_LEN: usize = 256;

/// Maximum string argument length (matches MAX_PATH_LEN for full path capture)
pub const MAX_ARG_STR_LEN: usize = 256;

/// Maximum number of syscall arguments
pub const MAX_ARGS: usize = 6;

/// Magic bytes for capture files
pub const CAPTURE_MAGIC: &[u8; 8] = b"SCMMCAP\0";

/// Magic bytes for compiled policy files
pub const POLICY_MAGIC: &[u8; 8] = b"SCMMPOL\0";

/// Current format version for capture files
pub const CAPTURE_VERSION: u16 = 1;

/// Current format version for policy files
pub const POLICY_VERSION: u16 = 1;
