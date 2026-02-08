//! SysCallMeMaybe (SCMM) - Shared types and definitions
//!
//! This crate contains types shared between the eBPF kernel programs
//! and userspace tools.

#![cfg_attr(feature = "no_std", no_std)]

pub mod syscall;
pub mod capture;
pub mod policy;
pub mod categories;
#[cfg(not(feature = "no_std"))]
pub mod flags;

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

/// Initialize tracing/logging with the given verbosity level.
/// 0 = WARN, 1 = INFO, 2 = DEBUG, 3+ = TRACE.
#[cfg(not(feature = "no_std"))]
pub fn init_tracing(verbose: u8) {
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    let level = match verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
}

/// Convert a `#[repr(C)]` struct to a byte slice (for writing to files).
///
/// # Safety
/// The caller must ensure `T` is `#[repr(C)]` or `#[repr(C, packed)]` and
/// contains no padding with uninitialized bytes that would be UB to read.
pub unsafe fn struct_to_bytes<T: Copy>(val: &T) -> &[u8] {
    core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>())
}

/// Read a `#[repr(C)]` struct from a byte slice.
///
/// # Safety
/// The caller must ensure `bytes` contains a valid representation of `T`
/// and is at least `size_of::<T>()` bytes long.
pub unsafe fn bytes_to_struct<T: Copy>(bytes: &[u8]) -> T {
    core::ptr::read(bytes.as_ptr() as *const T)
}
