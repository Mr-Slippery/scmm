//! Syscall event definitions shared between eBPF and userspace

use crate::{MAX_ARG_STR_LEN, MAX_ARGS, MAX_PATH_LEN};

#[cfg(not(feature = "no_std"))]
use serde::{Deserialize, Serialize};

/// Type of syscall argument
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "no_std"), derive(Serialize, Deserialize))]
pub enum ArgType {
    /// Unknown or unhandled type
    Unknown = 0,
    /// Integer value (includes pointers we don't dereference)
    Integer = 1,
    /// Raw pointer value (not dereferenced)
    Pointer = 2,
    /// Null-terminated string
    String = 3,
    /// File path
    Path = 4,
    /// Binary buffer (truncated)
    Buffer = 5,
    /// File descriptor
    Fd = 6,
    /// Bitmask flags (e.g., O_RDONLY | O_CLOEXEC)
    Flags = 7,
    /// Socket address (struct sockaddr)
    Sockaddr = 8,
    /// Signal number
    Signal = 9,
    /// Process ID
    Pid = 10,
}

impl Default for ArgType {
    fn default() -> Self {
        ArgType::Unknown
    }
}

/// A single syscall argument with its type and value
#[repr(C)]
#[derive(Clone)]
pub struct SyscallArg {
    /// Type of this argument
    pub arg_type: ArgType,
    /// Raw 64-bit value (register content)
    pub raw_value: u64,
    /// String/path data if applicable (null-terminated)
    pub str_data: [u8; MAX_ARG_STR_LEN],
    /// Length of string data (excluding null terminator)
    pub str_len: u16,
}

impl Default for SyscallArg {
    fn default() -> Self {
        Self {
            arg_type: ArgType::Unknown,
            raw_value: 0,
            str_data: [0u8; MAX_ARG_STR_LEN],
            str_len: 0,
        }
    }
}

impl core::fmt::Debug for SyscallArg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.arg_type {
            ArgType::Path | ArgType::String => {
                let s = core::str::from_utf8(&self.str_data[..self.str_len as usize])
                    .unwrap_or("<invalid utf8>");
                f.debug_struct("SyscallArg")
                    .field("type", &self.arg_type)
                    .field("value", &s)
                    .finish()
            }
            ArgType::Fd => f
                .debug_struct("SyscallArg")
                .field("type", &self.arg_type)
                .field("fd", &(self.raw_value as i32))
                .finish(),
            ArgType::Flags => f
                .debug_struct("SyscallArg")
                .field("type", &self.arg_type)
                .field("flags", &format_args!("0x{:x}", self.raw_value))
                .finish(),
            _ => f
                .debug_struct("SyscallArg")
                .field("type", &self.arg_type)
                .field("value", &self.raw_value)
                .finish(),
        }
    }
}

/// Complete syscall event captured by eBPF
#[repr(C)]
#[derive(Clone)]
pub struct SyscallEvent {
    /// Monotonic timestamp in nanoseconds
    pub timestamp_ns: u64,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Syscall number
    pub syscall_nr: u32,
    /// CPU architecture (AUDIT_ARCH_*)
    pub arch: u32,
    /// Return value (from sys_exit, 0 if entry-only)
    pub ret_val: i64,
    /// Syscall arguments
    pub args: [SyscallArg; MAX_ARGS],
    /// Process name (comm)
    pub comm: [u8; 16],
    /// Parent process ID
    pub ppid: u32,
    /// Event flags
    pub flags: u32,
}

impl Default for SyscallEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            syscall_nr: 0,
            arch: 0,
            ret_val: 0,
            args: Default::default(),
            comm: [0u8; 16],
            ppid: 0,
            flags: 0,
        }
    }
}

impl core::fmt::Debug for SyscallEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let comm = core::str::from_utf8(&self.comm)
            .unwrap_or("<invalid>")
            .trim_end_matches('\0');
        f.debug_struct("SyscallEvent")
            .field("timestamp_ns", &self.timestamp_ns)
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("comm", &comm)
            .field("syscall_nr", &self.syscall_nr)
            .field("ret_val", &self.ret_val)
            .field("args", &self.args)
            .finish()
    }
}

/// Event flags
pub mod event_flags {
    /// This is a sys_enter event
    pub const ENTRY: u32 = 1 << 0;
    /// This is a sys_exit event
    pub const EXIT: u32 = 1 << 1;
    /// Event was truncated (string too long, etc.)
    pub const TRUNCATED: u32 = 1 << 2;
    /// Failed to read some argument
    pub const READ_ERROR: u32 = 1 << 3;
}

/// Lightweight event for ring buffer (minimal size for eBPF)
/// This is what gets sent from kernel to userspace
#[repr(C)]
#[derive(Clone)]
pub struct RingBufEvent {
    /// Event type (entry/exit)
    pub event_type: u8,
    /// Padding
    pub _pad: [u8; 3],
    /// Syscall number
    pub syscall_nr: u32,
    /// Monotonic timestamp
    pub timestamp_ns: u64,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Return value (only valid for exit events)
    pub ret_val: i64,
    /// Raw argument values
    pub args: [u64; MAX_ARGS],
    /// Which argument index contains a captured path string (255 = none)
    pub path_arg_index: u8,
    /// Padding for alignment
    pub _pad2: u8,
    /// Length of the captured path string (0 = no string)
    pub path_str_len: u16,
    /// Path string data (only valid up to path_str_len bytes)
    pub path_data: [u8; MAX_PATH_LEN],
}

impl Default for RingBufEvent {
    fn default() -> Self {
        Self {
            event_type: 0,
            _pad: [0; 3],
            syscall_nr: 0,
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            ret_val: 0,
            args: [0u64; MAX_ARGS],
            path_arg_index: 255,
            _pad2: 0,
            path_str_len: 0,
            path_data: [0u8; MAX_PATH_LEN],
        }
    }
}

impl core::fmt::Debug for RingBufEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingBufEvent")
            .field("event_type", &self.event_type)
            .field("syscall_nr", &self.syscall_nr)
            .field("timestamp_ns", &self.timestamp_ns)
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("ret_val", &self.ret_val)
            .field("args", &self.args)
            .field("path_arg_index", &self.path_arg_index)
            .field("path_str_len", &self.path_str_len)
            .finish()
    }
}

/// Ring buffer event types
pub mod ring_event_type {
    pub const SYSCALL_ENTRY: u8 = 1;
    pub const SYSCALL_EXIT: u8 = 2;
    pub const PROCESS_EXEC: u8 = 3;
    pub const PROCESS_EXIT: u8 = 4;
}

/// Socket address data (parsed from struct sockaddr)
#[repr(C)]
#[derive(Clone, Debug)]
pub struct SockaddrInfo {
    /// Address family (AF_INET, AF_INET6, AF_UNIX, etc.)
    pub family: u16,
    /// Port number (for INET/INET6)
    pub port: u16,
    /// IPv4 address bytes
    pub ipv4: [u8; 4],
    /// IPv6 address bytes
    pub ipv6: [u8; 16],
    /// Unix socket path (not serialized due to size)
    pub unix_path: [u8; 108],
}

impl Default for SockaddrInfo {
    fn default() -> Self {
        Self {
            family: 0,
            port: 0,
            ipv4: [0; 4],
            ipv6: [0; 16],
            unix_path: [0; 108],
        }
    }
}
