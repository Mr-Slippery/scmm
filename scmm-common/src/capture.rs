//! Capture file format definitions

#[cfg(not(feature = "no_std"))]
use serde::{Deserialize, Serialize};

use crate::{CAPTURE_MAGIC, CAPTURE_VERSION};

/// Architecture identifiers (matching AUDIT_ARCH_*)
pub mod arch {
    pub const X86_64: u32 = 0xc000003e;
    pub const AARCH64: u32 = 0xc00000b7;
    pub const RISCV64: u32 = 0xc00000f3;
}

/// File header for capture files
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct CaptureFileHeader {
    /// Magic bytes "SCMMCAP\0"
    pub magic: [u8; 8],
    /// Format version
    pub version: u16,
    /// Flags (compression, etc.)
    pub flags: u16,
    /// Target architecture (AUDIT_ARCH_*)
    pub arch: u32,
    /// Kernel version (LINUX_VERSION_CODE format)
    pub kernel_version: u32,
    /// Boot time in nanoseconds (for correlating timestamps)
    pub boot_time_ns: u64,
    /// Recording start time (wall clock, nanoseconds since epoch)
    pub start_time_ns: u64,
    /// Recording end time (filled on close)
    pub end_time_ns: u64,
    /// Total event count
    pub event_count: u64,
    /// Offset to metadata block
    pub metadata_offset: u64,
    /// Offset to index footer (0 if none)
    pub index_offset: u64,
}

impl Default for CaptureFileHeader {
    fn default() -> Self {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(CAPTURE_MAGIC);
        Self {
            magic,
            version: CAPTURE_VERSION,
            flags: 0,
            arch: 0,
            kernel_version: 0,
            boot_time_ns: 0,
            start_time_ns: 0,
            end_time_ns: 0,
            event_count: 0,
            metadata_offset: 0,
            index_offset: 0,
        }
    }
}

/// Capture file flags
pub mod capture_flags {
    /// Events are LZ4 compressed
    pub const LZ4_COMPRESSED: u16 = 1 << 0;
    /// File is little-endian
    pub const LITTLE_ENDIAN: u16 = 1 << 1;
    /// Contains argument strings (paths, etc.)
    pub const HAS_ARG_STRINGS: u16 = 1 << 2;
}

/// Metadata about the captured session
#[cfg(not(feature = "no_std"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CaptureMetadata {
    /// Hostname where capture was made
    pub hostname: String,
    /// Kernel release string
    pub kernel_release: String,
    /// Original command that was executed
    pub command: Vec<String>,
    /// Working directory at start
    pub working_dir: String,
    /// Environment variables (optional, may be filtered)
    pub environment: Vec<(String, String)>,
    /// Root process ID
    pub root_pid: u32,
    /// Process tree (all observed PIDs and their relationships)
    pub processes: Vec<ProcessInfo>,
}

/// Information about a process
#[cfg(not(feature = "no_std"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name (comm)
    pub comm: String,
    /// Executable path (if known)
    pub exe: Option<String>,
    /// Start time (monotonic ns)
    pub start_time: u64,
    /// Exit time (monotonic ns, 0 if still running)
    pub exit_time: u64,
    /// Exit code (if exited)
    pub exit_code: Option<i32>,
}

/// Block header for event blocks in the capture file
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventBlockHeader {
    /// Block type identifier
    pub block_type: u32,
    /// Compressed size (0 if uncompressed)
    pub compressed_size: u32,
    /// Uncompressed size
    pub uncompressed_size: u32,
    /// Number of events in this block
    pub event_count: u32,
    /// First event timestamp (for seeking)
    pub first_timestamp: u64,
    /// Last event timestamp
    pub last_timestamp: u64,
}

/// Block types
pub mod block_type {
    /// Syscall events
    pub const SYSCALL_EVENTS: u32 = 1;
    /// Process events (exec, exit)
    pub const PROCESS_EVENTS: u32 = 2;
    /// Metadata block
    pub const METADATA: u32 = 3;
    /// Index block
    pub const INDEX: u32 = 4;
}

/// Serialized syscall event in capture file
/// This is a more compact representation than the ring buffer event
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SerializedEvent {
    /// Delta from previous timestamp (varint in actual file)
    pub timestamp_delta: u32,
    /// Event flags
    pub flags: u16,
    /// Syscall number
    pub syscall_nr: u16,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Return value
    pub ret_val: i64,
    /// Number of arguments with data
    pub arg_count: u8,
    /// Reserved
    pub _reserved: [u8; 7],
    // Followed by variable-length argument data
}
