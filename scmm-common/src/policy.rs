//! Policy definitions for syscall filtering

#[cfg(not(feature = "no_std"))]
use serde::{Deserialize, Serialize};

use crate::{POLICY_MAGIC, POLICY_VERSION};

/// Action to take when a rule matches
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(not(feature = "no_std"), derive(Serialize, Deserialize))]
#[cfg_attr(not(feature = "no_std"), serde(rename_all = "lowercase"))]
pub enum Action {
    /// Allow the syscall
    Allow = 0,
    /// Deny the syscall (EPERM)
    #[default]
    Deny = 1,
    /// Log but allow
    Log = 2,
    /// Kill the process
    Kill = 3,
    /// Trap to userspace handler (SECCOMP_RET_TRAP)
    Trap = 4,
}

/// Compiled policy file header
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct CompiledPolicyHeader {
    /// Magic bytes "SCMMPOL\0"
    pub magic: [u8; 8],
    /// Format version
    pub version: u16,
    /// Target architecture
    pub arch: u32,
    /// Feature flags
    pub flags: u32,
    /// Offset to seccomp BPF filter
    pub seccomp_filter_offset: u32,
    /// Length of seccomp BPF filter (bytes)
    pub seccomp_filter_len: u32,
    /// Offset to Landlock rules
    pub landlock_rules_offset: u32,
    /// Length of Landlock rules (bytes)
    pub landlock_rules_len: u32,
    /// Offset to path string table
    pub path_table_offset: u32,
    /// Length of path string table
    pub path_table_len: u32,
    /// Offset to capabilities list (u64 bitmask)
    pub capabilities_offset: u32,
    /// Length of capabilities list (bytes)
    pub capabilities_len: u32,
    /// Reserved for future use
    pub _reserved: [u8; 16],
}

impl Default for CompiledPolicyHeader {
    fn default() -> Self {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(POLICY_MAGIC);
        Self {
            magic,
            version: POLICY_VERSION,
            arch: 0,
            flags: 0,
            seccomp_filter_offset: 0,
            seccomp_filter_len: 0,
            landlock_rules_offset: 0,
            landlock_rules_len: 0,
            path_table_offset: 0,
            path_table_len: 0,
            capabilities_offset: 0,
            capabilities_len: 0,
            _reserved: [0; 16],
        }
    }
}

/// Policy file flags
pub mod policy_flags {
    /// Has seccomp BPF filter
    pub const HAS_SECCOMP: u32 = 1 << 0;
    /// Has Landlock rules
    pub const HAS_LANDLOCK: u32 = 1 << 1;
    /// Has LSM BPF programs
    pub const HAS_LSM_BPF: u32 = 1 << 2;
    /// Default action is allow (vs deny)
    pub const DEFAULT_ALLOW: u32 = 1 << 3;
    /// Log all denials
    pub const LOG_DENIALS: u32 = 1 << 4;
}

/// YAML policy structure (for scmm-extract output and scmm-compile input)
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YamlPolicy {
    /// Policy format version
    pub version: String,
    /// Policy metadata
    #[serde(default)]
    pub metadata: PolicyMetadata,
    /// Global settings
    #[serde(default)]
    pub settings: PolicySettings,
    /// Syscall rules
    #[serde(default)]
    pub syscalls: Vec<SyscallRule>,
    /// Capabilities to raise (in ambient set)
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Filesystem rules (for Landlock)
    #[serde(default)]
    pub filesystem: FilesystemRules,
    /// Network rules
    #[serde(default)]
    pub network: NetworkRules,
}

/// Policy metadata
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Policy name
    #[serde(default)]
    pub name: String,
    /// Description
    #[serde(default)]
    pub description: String,
    /// Source capture file (if generated)
    #[serde(default)]
    pub generated_from: Option<String>,
    /// Target executable
    #[serde(default)]
    pub target_executable: Option<String>,
    /// Generation timestamp
    #[serde(default)]
    pub generated_at: Option<String>,
}

/// Global policy settings
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    /// Default action for unmatched syscalls
    #[serde(default)]
    pub default_action: Action,
    /// Log all denied syscalls
    #[serde(default)]
    pub log_denials: bool,
    /// Target architecture
    #[serde(default = "default_arch")]
    pub arch: String,
}

#[cfg(not(feature = "no_std"))]
fn default_arch() -> String {
    "x86_64".to_string()
}

#[cfg(not(feature = "no_std"))]
impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            default_action: Action::Deny,
            log_denials: true,
            arch: default_arch(),
        }
    }
}

/// A single syscall rule
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRule {
    /// Syscall name
    pub name: String,
    /// Action to take
    pub action: Action,
    /// Optional constraints on arguments
    #[serde(default)]
    pub constraints: Vec<ArgConstraint>,
}

/// Constraint on a syscall argument
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgConstraint {
    /// Argument name or index
    pub arg: String,
    /// Argument type for matching
    #[serde(rename = "type")]
    pub arg_type: String,
    /// Match patterns
    #[serde(default)]
    pub r#match: Vec<MatchPattern>,
    /// Allowed flag values (for flags type)
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Denied flag values (for flags type)
    #[serde(default)]
    pub denied: Vec<String>,
}

/// A match pattern
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPattern {
    /// Pattern string
    pub pattern: String,
    /// Pattern type: exact, glob, regex, template
    #[serde(rename = "type", default = "default_pattern_type")]
    pub pattern_type: String,
}

#[cfg(not(feature = "no_std"))]
fn default_pattern_type() -> String {
    "exact".to_string()
}

/// Filesystem access rules (for Landlock)
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemRules {
    /// Individual path rules
    #[serde(default)]
    pub rules: Vec<FilesystemRule>,
}

/// A single filesystem rule
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemRule {
    /// Path or pattern
    pub path: String,
    /// Allowed access types
    pub access: Vec<String>,
}

/// Network rules
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkRules {
    /// Allow loopback connections
    #[serde(default = "default_true")]
    pub allow_loopback: bool,
    /// Outbound connection rules
    #[serde(default)]
    pub outbound: Vec<NetworkRule>,
    /// Inbound connection rules
    #[serde(default)]
    pub inbound: Vec<NetworkRule>,
}

#[cfg(not(feature = "no_std"))]
fn default_true() -> bool {
    true
}

/// A single network rule
#[cfg(not(feature = "no_std"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Protocol (tcp, udp)
    pub protocol: String,
    /// Allowed addresses (CIDR notation or "any")
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Allowed ports
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Landlock access rights (for filesystem rules)
#[cfg(not(feature = "no_std"))]
pub mod landlock_access {
    pub const EXECUTE: &str = "execute";
    pub const WRITE_FILE: &str = "write_file";
    pub const READ_FILE: &str = "read_file";
    pub const READ_DIR: &str = "read_dir";
    pub const REMOVE_DIR: &str = "remove_dir";
    pub const REMOVE_FILE: &str = "remove_file";
    pub const MAKE_CHAR: &str = "make_char";
    pub const MAKE_DIR: &str = "make_dir";
    pub const MAKE_REG: &str = "make_reg";
    pub const MAKE_SOCK: &str = "make_sock";
    pub const MAKE_FIFO: &str = "make_fifo";
    pub const MAKE_BLOCK: &str = "make_block";
    pub const MAKE_SYM: &str = "make_sym";
    pub const REFER: &str = "refer";
    pub const TRUNCATE: &str = "truncate";

    /// All access rights in bitmap order (bit 0 = execute, bit 1 = write_file, etc.)
    const ALL_RIGHTS: &[&str] = &[
        EXECUTE,
        WRITE_FILE,
        READ_FILE,
        READ_DIR,
        REMOVE_DIR,
        REMOVE_FILE,
        MAKE_CHAR,
        MAKE_DIR,
        MAKE_REG,
        MAKE_SOCK,
        MAKE_FIFO,
        MAKE_BLOCK,
        MAKE_SYM,
        REFER,
        TRUNCATE,
    ];

    /// Convert an access right name to its bitmap bit value.
    /// Returns 0 for unknown names.
    pub fn name_to_bit(name: &str) -> u64 {
        for (i, &right) in ALL_RIGHTS.iter().enumerate() {
            if name == right {
                return 1 << i;
            }
        }
        0
    }

    /// Convert a bitmap to a list of access right names.
    pub fn bitmap_to_names(bitmap: u64) -> Vec<&'static str> {
        let mut names = Vec::new();
        for (i, &right) in ALL_RIGHTS.iter().enumerate() {
            if bitmap & (1 << i) != 0 {
                names.push(right);
            }
        }
        names
    }
}
