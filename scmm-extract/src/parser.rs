//! Capture file parser

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};

use scmm_common::{
    capture::{capture_flags, CaptureFileHeader, CaptureMetadata},
    categories::x86_64 as syscalls,
    SyscallCategory, SyscallEvent, CAPTURE_MAGIC, MAX_ARGS, MAX_ARG_STR_LEN,
};

/// Parsed capture file
#[derive(Debug)]
pub struct ParsedCapture {
    /// Metadata
    pub metadata: CaptureMetadata,
    /// All events
    pub events: Vec<SyscallEvent>,
}

/// Parse a capture file
pub fn parse_capture(path: &Path) -> Result<ParsedCapture> {
    let file = File::open(path).context("Failed to open capture file")?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header_bytes = [0u8; std::mem::size_of::<CaptureFileHeader>()];
    reader.read_exact(&mut header_bytes)?;

    let header: CaptureFileHeader = unsafe { scmm_common::bytes_to_struct(&header_bytes) };

    // Verify magic
    if &header.magic != CAPTURE_MAGIC {
        bail!("Invalid capture file: bad magic number");
    }

    // Check if capture has argument string data
    let has_arg_strings = (header.flags & capture_flags::HAS_ARG_STRINGS) != 0;

    // Read events
    let mut events = Vec::new();
    let mut prev_timestamp = 0u64;

    while let Ok(block_type) = reader.read_u32::<LittleEndian>() {
        let compressed_size = reader.read_u32::<LittleEndian>()?;
        let uncompressed_size = reader.read_u32::<LittleEndian>()?;
        let event_count = reader.read_u32::<LittleEndian>()?;
        let _first_timestamp = reader.read_u64::<LittleEndian>()?;
        let _last_timestamp = reader.read_u64::<LittleEndian>()?;

        match block_type {
            scmm_common::capture::block_type::SYSCALL_EVENTS => {
                let mut data = vec![0u8; uncompressed_size as usize];
                reader.read_exact(&mut data)?;

                // Parse events from data
                let mut cursor = std::io::Cursor::new(&data);
                for _ in 0..event_count {
                    let event = parse_event(&mut cursor, &mut prev_timestamp, has_arg_strings)?;
                    events.push(event);
                }
            }
            scmm_common::capture::block_type::METADATA => {
                // Skip for now, read at end
                let mut data = vec![0u8; uncompressed_size as usize];
                reader.read_exact(&mut data)?;
            }
            _ => {
                // Skip unknown block
                let size = if compressed_size > 0 {
                    compressed_size
                } else {
                    uncompressed_size
                };
                reader.seek(SeekFrom::Current(size as i64))?;
            }
        }
    }

    // Read metadata if available
    let metadata = if header.metadata_offset > 0 {
        reader.seek(SeekFrom::Start(header.metadata_offset))?;

        // Skip block header
        reader.seek(SeekFrom::Current(32))?;

        let mut json_data = Vec::new();
        reader.read_to_end(&mut json_data)?;

        // Trim any trailing zeros
        if let Some(end) = json_data.iter().position(|&b| b == 0) {
            json_data.truncate(end);
        }

        serde_json::from_slice(&json_data).unwrap_or_default()
    } else {
        CaptureMetadata::default()
    };

    Ok(ParsedCapture { metadata, events })
}

/// Parse a single event from the data buffer
fn parse_event(
    cursor: &mut std::io::Cursor<&Vec<u8>>,
    prev_timestamp: &mut u64,
    has_arg_strings: bool,
) -> Result<SyscallEvent> {
    let mut event = SyscallEvent::default();

    // Timestamp delta
    let delta = cursor.read_u32::<LittleEndian>()? as u64;
    event.timestamp_ns = *prev_timestamp + delta;
    *prev_timestamp = event.timestamp_ns;

    // Flags
    event.flags = cursor.read_u16::<LittleEndian>()? as u32;

    // Syscall number
    event.syscall_nr = cursor.read_u16::<LittleEndian>()? as u32;

    // PID
    event.pid = cursor.read_u32::<LittleEndian>()?;

    // TID
    event.tid = cursor.read_u32::<LittleEndian>()?;

    // Return value
    event.ret_val = cursor.read_i64::<LittleEndian>()?;

    // Arguments
    for arg in &mut event.args {
        arg.raw_value = cursor.read_u64::<LittleEndian>()?;
    }

    // Read argument string data if present
    if has_arg_strings {
        let arg_info_count = cursor.read_u8()?;
        for _ in 0..arg_info_count {
            let arg_index = cursor.read_u8()? as usize;
            let arg_type_byte = cursor.read_u8()?;
            let str_len = cursor.read_u16::<LittleEndian>()? as usize;

            if arg_index < MAX_ARGS && str_len <= MAX_ARG_STR_LEN {
                event.args[arg_index].arg_type = match arg_type_byte {
                    3 => scmm_common::ArgType::String,
                    4 => scmm_common::ArgType::Path,
                    _ => scmm_common::ArgType::Unknown,
                };
                event.args[arg_index].str_len = str_len as u16;
                cursor.read_exact(&mut event.args[arg_index].str_data[..str_len])?;
            } else {
                // Skip invalid/oversized data
                let mut skip_buf = vec![0u8; str_len];
                cursor.read_exact(&mut skip_buf)?;
            }
        }
    }

    Ok(event)
}

/// Print statistics about the capture
pub fn print_statistics(capture: &ParsedCapture) {
    println!("Capture Statistics");
    println!("==================");
    println!();

    // Basic info
    println!("Total events: {}", capture.events.len());
    println!("Hostname: {}", capture.metadata.hostname);
    println!("Kernel: {}", capture.metadata.kernel_release);
    if !capture.metadata.command.is_empty() {
        println!("Command: {}", capture.metadata.command.join(" "));
    }
    println!();

    // Syscall counts by category
    let mut by_category: HashMap<SyscallCategory, usize> = HashMap::new();
    let mut by_syscall: HashMap<u32, usize> = HashMap::new();

    for event in &capture.events {
        let category = syscalls::get_category(event.syscall_nr);
        *by_category.entry(category).or_insert(0) += 1;
        *by_syscall.entry(event.syscall_nr).or_insert(0) += 1;
    }

    println!("Events by category:");
    let mut categories: Vec<_> = by_category.iter().collect();
    categories.sort_by(|a, b| b.1.cmp(a.1));
    for (category, count) in categories {
        println!("  {:?}: {}", category, count);
    }
    println!();

    println!("Top 20 syscalls:");
    let mut syscall_counts: Vec<_> = by_syscall.iter().collect();
    syscall_counts.sort_by(|a, b| b.1.cmp(a.1));
    for (nr, count) in syscall_counts.iter().take(20) {
        println!("  {} ({}): {}", syscalls::get_name(**nr), nr, count);
    }
    println!();

    // Unique PIDs
    let unique_pids: std::collections::HashSet<_> = capture.events.iter().map(|e| e.pid).collect();
    println!("Unique PIDs: {}", unique_pids.len());
    println!();

    // File paths
    let mut path_counts: HashMap<String, usize> = HashMap::new();
    for event in &capture.events {
        for arg in &event.args {
            if arg.arg_type == scmm_common::ArgType::Path && arg.str_len > 0 {
                if let Ok(path_str) = std::str::from_utf8(&arg.str_data[..arg.str_len as usize]) {
                    *path_counts.entry(path_str.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    if !path_counts.is_empty() {
        println!("Captured file paths: {} unique", path_counts.len());
        let mut sorted_paths: Vec<_> = path_counts.iter().collect();
        sorted_paths.sort_by(|a, b| b.1.cmp(a.1));
        for (path, count) in sorted_paths.iter().take(20) {
            println!("  {} ({})", path, count);
        }
        if sorted_paths.len() > 20 {
            println!("  ... and {} more", sorted_paths.len() - 20);
        }
    } else {
        println!("No file paths captured.");
    }
}
