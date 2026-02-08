//! Policy file loader

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};

use scmm_common::{policy::CompiledPolicyHeader, POLICY_MAGIC};

/// Loaded policy data
pub struct LoadedPolicy {
    /// Seccomp BPF filter bytecode
    pub seccomp_filter: Vec<u8>,
    /// Landlock rules
    pub landlock_rules: Vec<LandlockRule>,
    /// Path strings
    pub paths: Vec<String>,
    /// Capabilities bitmask
    pub capabilities: u64,
}

/// Landlock rule
#[derive(Debug)]
pub struct LandlockRule {
    /// Rule type (1 = path, 2 = port)
    pub rule_type: u8,
    /// Access rights bitmap
    pub access: u64,
    /// Path index (for path rules) or port (for port rules)
    pub path_or_port: u16,
}

/// Load a compiled policy file
pub fn load_policy(path: &Path) -> Result<LoadedPolicy> {
    let mut file = File::open(path).context("Failed to open policy file")?;

    // Read header
    let mut header_bytes = [0u8; std::mem::size_of::<CompiledPolicyHeader>()];
    file.read_exact(&mut header_bytes)?;

    let header: CompiledPolicyHeader = unsafe { scmm_common::bytes_to_struct(&header_bytes) };

    // Verify magic
    if &header.magic != POLICY_MAGIC {
        bail!("Invalid policy file: bad magic number");
    }

    // Read seccomp filter
    let mut seccomp_filter = vec![0u8; header.seccomp_filter_len as usize];
    if !seccomp_filter.is_empty() {
        file.read_exact(&mut seccomp_filter)?;
    }

    // Read Landlock rules
    let mut landlock_data = vec![0u8; header.landlock_rules_len as usize];
    if !landlock_data.is_empty() {
        file.read_exact(&mut landlock_data)?;
    }

    let landlock_rules = parse_landlock_rules(&landlock_data)?;

    // Read path table
    let mut path_data = vec![0u8; header.path_table_len as usize];
    if !path_data.is_empty() {
        file.read_exact(&mut path_data)?;
    }

    let paths = parse_path_table(&path_data)?;

    // Read capabilities
    let mut caps_data = vec![0u8; header.capabilities_len as usize];
    if !caps_data.is_empty() {
        file.read_exact(&mut caps_data)?;
    }
    let capabilities = if caps_data.len() >= 8 {
        std::io::Cursor::new(caps_data).read_u64::<LittleEndian>()?
    } else {
        0
    };

    Ok(LoadedPolicy {
        seccomp_filter,
        landlock_rules,
        paths,
        capabilities,
    })
}

/// Parse Landlock rules from binary data
fn parse_landlock_rules(data: &[u8]) -> Result<Vec<LandlockRule>> {
    let mut rules = Vec::new();
    let mut cursor = std::io::Cursor::new(data);

    while cursor.position() < data.len() as u64 {
        let rule_type = cursor.read_u8()?;
        let access = cursor.read_u64::<LittleEndian>()?;
        let path_or_port = cursor.read_u16::<LittleEndian>()?;

        rules.push(LandlockRule {
            rule_type,
            access,
            path_or_port,
        });
    }

    Ok(rules)
}

/// Parse path table from binary data
fn parse_path_table(data: &[u8]) -> Result<Vec<String>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    let mut cursor = std::io::Cursor::new(data);

    let count = cursor.read_u16::<LittleEndian>()? as usize;

    for _ in 0..count {
        let len = cursor.read_u16::<LittleEndian>()? as usize;
        let mut path_bytes = vec![0u8; len];
        cursor.read_exact(&mut path_bytes)?;

        // Skip null terminator
        cursor.read_u8()?;

        let path = String::from_utf8(path_bytes).unwrap_or_default();
        paths.push(path);
    }

    Ok(paths)
}
