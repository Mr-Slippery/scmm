//! Capture file writer

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};

use scmm_common::{
    capture::{capture_flags, CaptureFileHeader, CaptureMetadata},
    SyscallEvent,
};

/// Writer for capture files
pub struct CaptureWriter {
    /// Output file
    file: BufWriter<File>,
    /// File header (will be updated on finalize)
    header: CaptureFileHeader,
    /// Metadata
    metadata: CaptureMetadata,
    /// Current file position
    position: u64,
    /// Event buffer for compression
    event_buffer: Vec<u8>,
    /// Number of events in current buffer
    buffer_event_count: u32,
    /// First timestamp in buffer
    buffer_first_timestamp: u64,
    /// Last timestamp in buffer
    buffer_last_timestamp: u64,
    /// Previous timestamp for delta encoding
    prev_timestamp: u64,
}

impl CaptureWriter {
    /// Create a new capture writer
    pub fn new(path: &Path, arch: u32) -> Result<Self> {
        let file = File::create(path).context("Failed to create capture file")?;
        let mut file = BufWriter::new(file);

        // Initialize header
        let header = CaptureFileHeader {
            arch,
            flags: capture_flags::LITTLE_ENDIAN | capture_flags::HAS_ARG_STRINGS,
            start_time_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            ..Default::default()
        };

        // Write placeholder header (will be updated on finalize)
        let header_bytes = unsafe { scmm_common::struct_to_bytes(&header) };
        file.write_all(header_bytes)?;
        file.flush()?; // Ensure header is written immediately

        let position = std::mem::size_of::<CaptureFileHeader>() as u64;

        // Initialize metadata
        let metadata = CaptureMetadata {
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            kernel_release: get_kernel_release(),
            working_dir: std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            ..Default::default()
        };

        Ok(Self {
            file,
            header,
            metadata,
            position,
            event_buffer: Vec::with_capacity(64 * 1024),
            buffer_event_count: 0,
            buffer_first_timestamp: 0,
            buffer_last_timestamp: 0,
            prev_timestamp: 0,
        })
    }

    /// Set the command that was executed
    pub fn set_command(&mut self, command: Vec<String>) {
        self.metadata.command = command;
    }

    /// Set the target process UID/GID
    pub fn set_uid_gid(&mut self, uid: u32, gid: u32) {
        self.metadata.uid = Some(uid);
        self.metadata.gid = Some(gid);
    }

    /// Mark this capture as attached to an existing process
    pub fn set_attached(&mut self, pid: u32) {
        self.metadata.attached = true;
        self.metadata.root_pid = pid;
    }

    /// Write a syscall event
    pub fn write_event(&mut self, event: &SyscallEvent) -> Result<()> {
        // Update timestamps
        if self.buffer_event_count == 0 {
            self.buffer_first_timestamp = event.timestamp_ns;
        }
        self.buffer_last_timestamp = event.timestamp_ns;

        // Calculate timestamp delta
        let delta = if self.prev_timestamp == 0 {
            0
        } else {
            event.timestamp_ns.saturating_sub(self.prev_timestamp)
        };
        self.prev_timestamp = event.timestamp_ns;

        // Serialize event to buffer
        self.serialize_event(event, delta)?;
        self.buffer_event_count += 1;

        // Flush if buffer is large enough
        if self.event_buffer.len() >= 32 * 1024 {
            self.flush_buffer()?;
        }

        Ok(())
    }

    /// Serialize an event to the buffer
    fn serialize_event(&mut self, event: &SyscallEvent, delta: u64) -> Result<()> {
        // Simple binary format for now
        // In production, we'd use varint encoding and LZ4 compression

        // Timestamp delta (4 bytes, clamped)
        self.event_buffer
            .write_u32::<LittleEndian>(delta.min(u32::MAX as u64) as u32)?;

        // Flags (2 bytes)
        self.event_buffer
            .write_u16::<LittleEndian>(event.flags as u16)?;

        // Syscall number (2 bytes)
        self.event_buffer
            .write_u16::<LittleEndian>(event.syscall_nr as u16)?;

        // PID (4 bytes)
        self.event_buffer.write_u32::<LittleEndian>(event.pid)?;

        // TID (4 bytes)
        self.event_buffer.write_u32::<LittleEndian>(event.tid)?;

        // Return value (8 bytes)
        self.event_buffer.write_i64::<LittleEndian>(event.ret_val)?;

        // Arguments (6 * 8 bytes = 48 bytes)
        for arg in &event.args {
            self.event_buffer.write_u64::<LittleEndian>(arg.raw_value)?;
        }

        // Argument string data (variable length)
        // Serialized for Path, String, and Sockaddr args (all carry str_data).
        let mut arg_info_count: u8 = 0;
        for arg in &event.args {
            if arg.str_len > 0
                && matches!(
                    arg.arg_type,
                    scmm_common::ArgType::Path
                        | scmm_common::ArgType::String
                        | scmm_common::ArgType::Sockaddr
                )
            {
                arg_info_count += 1;
            }
        }
        self.event_buffer.write_u8(arg_info_count)?;

        for (i, arg) in event.args.iter().enumerate() {
            if arg.str_len > 0
                && matches!(
                    arg.arg_type,
                    scmm_common::ArgType::Path
                        | scmm_common::ArgType::String
                        | scmm_common::ArgType::Sockaddr
                )
            {
                self.event_buffer.write_u8(i as u8)?;
                self.event_buffer.write_u8(arg.arg_type as u8)?;
                self.event_buffer.write_u16::<LittleEndian>(arg.str_len)?;
                self.event_buffer
                    .write_all(&arg.str_data[..arg.str_len as usize])?;
            }
        }

        Ok(())
    }

    /// Flush the event buffer to disk
    fn flush_buffer(&mut self) -> Result<()> {
        if self.event_buffer.is_empty() {
            return Ok(());
        }

        // Write block header
        let block_type: u32 = scmm_common::capture::block_type::SYSCALL_EVENTS;
        let compressed_size: u32 = 0; // Not compressed for now
        let uncompressed_size: u32 = self.event_buffer.len() as u32;

        self.file.write_u32::<LittleEndian>(block_type)?;
        self.file.write_u32::<LittleEndian>(compressed_size)?;
        self.file.write_u32::<LittleEndian>(uncompressed_size)?;
        self.file
            .write_u32::<LittleEndian>(self.buffer_event_count)?;
        self.file
            .write_u64::<LittleEndian>(self.buffer_first_timestamp)?;
        self.file
            .write_u64::<LittleEndian>(self.buffer_last_timestamp)?;

        // Write data
        self.file.write_all(&self.event_buffer)?;

        // Update position
        self.position += 32 + self.event_buffer.len() as u64;

        // Clear buffer
        self.event_buffer.clear();
        self.buffer_event_count = 0;
        self.buffer_first_timestamp = 0;
        self.buffer_last_timestamp = 0;

        Ok(())
    }

    /// Finalize the capture file
    pub fn finalize(&mut self, total_events: u64) -> Result<()> {
        // Flush remaining events
        self.flush_buffer()?;

        // Write metadata block
        let metadata_offset = self.position;
        let metadata_json = serde_json::to_vec(&self.metadata)?;

        let block_type: u32 = scmm_common::capture::block_type::METADATA;
        self.file.write_u32::<LittleEndian>(block_type)?;
        self.file.write_u32::<LittleEndian>(0)?; // compressed size
        self.file
            .write_u32::<LittleEndian>(metadata_json.len() as u32)?;
        self.file.write_u32::<LittleEndian>(0)?; // event count
        self.file.write_u64::<LittleEndian>(0)?; // first timestamp
        self.file.write_u64::<LittleEndian>(0)?; // last timestamp
        self.file.write_all(&metadata_json)?;

        // Update header
        self.header.event_count = total_events;
        self.header.end_time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.header.metadata_offset = metadata_offset;

        // Seek to beginning and rewrite header
        self.file.flush()?;
        let file = self.file.get_mut();

        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;

        let header_bytes = unsafe { scmm_common::struct_to_bytes(&self.header) };
        file.write_all(header_bytes)?;
        file.flush()?;

        Ok(())
    }
}

/// Get kernel release string
fn get_kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}
