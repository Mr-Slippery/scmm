//! eBPF program loader and event handler

use std::collections::HashMap;
use std::ffi::CString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(debug_assertions)]
use aya::include_bytes_aligned;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, RingBuf};
use aya::programs::TracePoint;
use aya::Bpf;
use tracing::{debug, info, trace, warn};

use scmm_common::{
    capture::arch, categories::x86_64 as syscalls, ring_event_type, CategoryFilter, RingBufEvent,
    SyscallEvent,
};

use crate::capture::CaptureWriter;

/// Check if a PID is still running (standalone function to avoid borrow issues)
/// Uses waitpid with WNOHANG to properly detect exited/zombie processes
fn check_child_status(pid: u32) -> ChildStatus {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    match waitpid(
        nix::unistd::Pid::from_raw(pid as i32),
        Some(WaitPidFlag::WNOHANG),
    ) {
        Ok(WaitStatus::StillAlive) => ChildStatus::Running,
        Ok(WaitStatus::Exited(_, code)) => ChildStatus::Exited(code),
        Ok(WaitStatus::Signaled(_, sig, _)) => ChildStatus::Signaled(sig as i32),
        Ok(_) => ChildStatus::Running, // Other states (stopped, continued) mean still alive
        Err(nix::errno::Errno::ECHILD) => ChildStatus::Exited(0), // Already reaped
        Err(_) => ChildStatus::Exited(-1), // Error, assume exited
    }
}

#[derive(Debug, Clone, Copy)]
enum ChildStatus {
    Running,
    Exited(i32),
    Signaled(i32),
}

/// Recorder manages eBPF programs and event collection
pub struct Recorder {
    /// Loaded eBPF programs
    bpf: Bpf,
    /// Capture file writer
    writer: CaptureWriter,
    /// Category filter
    category_filter: CategoryFilter,
    /// Follow forks flag
    follow_forks: bool,
    /// Tracked PIDs
    tracked_pids: HashMap<u32, bool>,
    /// Event count
    event_count: u64,
    /// Pending entry events (pid,tid -> event) for matching with exits
    pending_entries: HashMap<(u32, u32, u32), RingBufEvent>,
    /// Child PID (kept for reaping)
    child_pid: Option<u32>,
}

impl Recorder {
    /// Create a new recorder
    pub fn new(output: &Path, category_filter: CategoryFilter, follow_forks: bool) -> Result<Self> {
        // Load eBPF bytecode
        // For now, we'll use a placeholder - in production this would be the compiled eBPF
        #[cfg(debug_assertions)]
        let bpf = Bpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/scmm-ebpf"
        )))?;

        #[cfg(not(debug_assertions))]
        let bpf = {
            // Try to load from standard locations
            let ebpf_paths = [
                "/usr/lib/scmm/scmm-ebpf",
                "/usr/local/lib/scmm/scmm-ebpf",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../target/bpfel-unknown-none/release/scmm-ebpf"
                ),
            ];

            let mut loaded = None;
            for path in &ebpf_paths {
                if let Ok(data) = std::fs::read(path) {
                    if let Ok(bpf) = Bpf::load(&data) {
                        loaded = Some(bpf);
                        info!("Loaded eBPF from {}", path);
                        break;
                    }
                }
            }

            loaded.ok_or_else(|| {
                anyhow::anyhow!("Could not find eBPF program. Build with: cargo xtask build-ebpf")
            })?
        };

        // Create capture writer
        let writer = CaptureWriter::new(output, arch::X86_64)?;

        Ok(Self {
            bpf,
            writer,
            category_filter,
            follow_forks,
            tracked_pids: HashMap::new(),
            event_count: 0,
            pending_entries: HashMap::new(),
            child_pid: None,
        })
    }

    /// Spawn a command and start tracing it
    ///
    /// Uses manual fork+exec instead of std::process::Command to avoid a hang:
    /// Rust's Command::spawn() has an internal error-reporting pipe that blocks
    /// until the child either execs or reports an error. If the child stops
    /// (SIGSTOP) before exec, the pipe stays open and spawn() hangs forever.
    ///
    /// With manual fork: child raises SIGSTOP, parent waitpid(WUNTRACED) sees
    /// the stop, adds PID to TARGET_PIDS, then SIGCONT resumes the child into
    /// execvp. This guarantees the eBPF tracer sees the execve syscall.
    /// Optional (uid, gid) to drop privileges to in the child before exec.
    pub fn spawn_command(&mut self, command: &[String], run_as: Option<(u32, u32)>) -> Result<u32> {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        use nix::unistd::{execvp, fork, ForkResult};

        // Set follow-forks config in eBPF before attaching
        self.set_config()?;

        // Attach tracepoints before spawning
        self.attach_tracepoints()?;

        // Prepare C strings for execvp before forking
        let c_args: Vec<CString> = command
            .iter()
            .map(|s| CString::new(s.as_str()).context("Invalid argument string"))
            .collect::<Result<Vec<_>>>()?;
        let c_arg_refs: Vec<&std::ffi::CStr> = c_args.iter().map(|s| s.as_c_str()).collect();

        // SAFETY: Between fork and exec in the child, only async-signal-safe
        // functions are called (raise, setgid, setuid, execvp, _exit).
        match unsafe { fork() }.context("fork() failed")? {
            ForkResult::Child => {
                // Stop ourselves BEFORE execve so parent can add our PID to
                // TARGET_PIDS. Parent will SIGCONT us once tracing is set up.
                let _ = nix::sys::signal::raise(nix::sys::signal::Signal::SIGSTOP);

                // Drop privileges if requested (setgid before setuid)
                if let Some((uid, gid)) = run_as {
                    unsafe {
                        libc::setgid(gid);
                        libc::setuid(uid);
                    }
                }

                // Now exec the target command
                let _ = execvp(c_arg_refs[0], &c_arg_refs);

                // If exec failed, exit immediately (async-signal-safe)
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child: nix_pid } => {
                let pid = nix_pid.as_raw() as u32;

                // Wait for the child to stop (it raised SIGSTOP before exec)
                match waitpid(nix_pid, Some(WaitPidFlag::WUNTRACED)) {
                    Ok(WaitStatus::Stopped(_, _)) => {
                        debug!("Child {} stopped before exec, setting up tracing", pid);
                    }
                    Ok(status) => {
                        warn!("Unexpected wait status for child {}: {:?}", pid, status);
                    }
                    Err(e) => {
                        warn!("waitpid error for child {}: {}", pid, e);
                    }
                }

                // Add PID to tracking map BEFORE resuming the child.
                // Now when the child runs execve, the eBPF will see it.
                self.add_pid(pid)?;
                self.tracked_pids.insert(pid, true);

                // Store command in capture metadata
                self.writer.set_command(command.to_vec());

                // Store child PID for reaping
                self.child_pid = Some(pid);

                // Resume the child - it will now call execve with tracing active
                nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGCONT)?;

                Ok(pid)
            }
        }
    }

    /// Set eBPF configuration (follow_forks flag)
    fn set_config(&mut self) -> Result<()> {
        let map = self
            .bpf
            .map_mut("CONFIG")
            .ok_or_else(|| anyhow::anyhow!("CONFIG map not found"))?;
        let mut config: AyaArray<_, u32> = AyaArray::try_from(map)?;
        let val: u32 = if self.follow_forks { 1 } else { 0 };
        config.set(0, val, 0)?;
        info!("eBPF config: follow_forks={}", self.follow_forks);
        Ok(())
    }

    /// Attach to tracepoints
    fn attach_tracepoints(&mut self) -> Result<()> {
        // Attach sys_enter
        let program: &mut TracePoint = self
            .bpf
            .program_mut("sys_enter")
            .ok_or_else(|| anyhow::anyhow!("sys_enter program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("raw_syscalls", "sys_enter")?;
        info!("Attached to raw_syscalls:sys_enter");

        // Attach sys_exit
        let program: &mut TracePoint = self
            .bpf
            .program_mut("sys_exit")
            .ok_or_else(|| anyhow::anyhow!("sys_exit program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("raw_syscalls", "sys_exit")?;
        info!("Attached to raw_syscalls:sys_exit");

        Ok(())
    }

    /// Add a PID to the tracking map
    fn add_pid(&mut self, pid: u32) -> Result<()> {
        let map = self
            .bpf
            .map_mut("TARGET_PIDS")
            .ok_or_else(|| anyhow::anyhow!("TARGET_PIDS map not found"))?;
        let mut target_pids: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(map)?;
        target_pids.insert(pid, 1, 0)?;
        debug!("Added PID {} to tracking", pid);
        Ok(())
    }

    /// Main event processing loop
    pub fn run(&mut self, running: Arc<AtomicBool>, root_pid: u32) -> Result<()> {
        info!("Starting event collection loop");

        // Take the ring buffer map out of bpf so we own it - this avoids
        // borrowing self.bpf in the loop (which would conflict with &mut self
        // for handle_event). More importantly, creating a RingBuf once and
        // reusing it preserves the consumer position; recreating it each
        // iteration resets the position and re-reads old events forever.
        let events_map = self
            .bpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS ring buffer map not found"))?;
        let mut ring_buf = RingBuf::try_from(events_map)?;

        let mut process_exited = false;

        while running.load(Ordering::SeqCst) {
            // Collect events from ring buffer first (before checking exit status)
            let events = Self::collect_events(&mut ring_buf);
            let event_count = events.len();

            // Process collected events
            for event in events {
                self.handle_event(&event)?;
            }

            if event_count > 0 {
                debug!("Processed {} events in this iteration", event_count);
            }

            // Check if root process is still running
            if !process_exited {
                match check_child_status(root_pid) {
                    ChildStatus::Running => {}
                    ChildStatus::Exited(code) => {
                        info!("Root process {} exited with code {}", root_pid, code);
                        process_exited = true;
                    }
                    ChildStatus::Signaled(sig) => {
                        info!("Root process {} killed by signal {}", root_pid, sig);
                        process_exited = true;
                    }
                }
            }

            if process_exited {
                // Process exited — drain remaining events from the ring buffer.
                // The kernel may still be committing events after the process
                // exits, so do multiple drain passes with small delays.
                for drain_pass in 0..5 {
                    std::thread::sleep(Duration::from_millis(5));
                    let events = Self::collect_events(&mut ring_buf);
                    if !events.is_empty() {
                        debug!(
                            "Post-exit drain pass {}: {} events",
                            drain_pass,
                            events.len()
                        );
                        for event in events {
                            self.handle_event(&event)?;
                        }
                    }
                }
                break;
            }

            // Small sleep to avoid busy-waiting
            std::thread::sleep(Duration::from_millis(1));
        }

        // Final drain of remaining events
        let events = Self::collect_events(&mut ring_buf);
        if !events.is_empty() {
            debug!("Final drain: {} events", events.len());
            for event in events {
                self.handle_event(&event)?;
            }
        }

        info!("Collected {} events", self.event_count);
        Ok(())
    }

    /// Collect events from ring buffer into a Vec
    fn collect_events<T: std::borrow::Borrow<aya::maps::MapData>>(
        ring_buf: &mut RingBuf<T>,
    ) -> Vec<RingBufEvent> {
        let mut events = Vec::new();

        while let Some(item) = ring_buf.next() {
            let event = unsafe { &*(item.as_ptr() as *const RingBufEvent) };
            events.push(event.clone());
        }

        events
    }

    /// Handle a single event from the ring buffer
    fn handle_event(&mut self, event: &RingBufEvent) -> Result<()> {
        // Skip bogus syscall numbers. The kernel can emit sys_exit with id=-1
        // (cast to u32 = 0xFFFFFFFF or 0xFFFF) for interrupted/restarted syscalls.
        if event.syscall_nr > 1000 {
            return Ok(());
        }

        // Check category filter
        let category = syscalls::get_category(event.syscall_nr);
        if !self.category_filter.contains(category) {
            return Ok(());
        }

        // Handle fork/clone for follow-forks
        if self.follow_forks && event.event_type == ring_event_type::SYSCALL_EXIT {
            match event.syscall_nr {
                56 | 57 | 58 | 435 => {
                    // clone, fork, vfork, clone3
                    if event.ret_val > 0 {
                        let child_pid = event.ret_val as u32;
                        if let Err(e) = self.add_pid(child_pid) {
                            warn!("Failed to add child PID {}: {}", child_pid, e);
                        } else {
                            self.tracked_pids.insert(child_pid, true);
                            debug!("Following fork to PID {}", child_pid);
                        }
                    }
                }
                _ => {}
            }
        }

        // Convert to full event and write
        if event.event_type == ring_event_type::SYSCALL_ENTRY {
            // Store entry for later matching with exit
            self.pending_entries
                .insert((event.pid, event.tid, event.syscall_nr), event.clone());
        } else if event.event_type == ring_event_type::SYSCALL_EXIT {
            // Try to match with entry
            let key = (event.pid, event.tid, event.syscall_nr);
            let entry = self.pending_entries.remove(&key);

            let full_event = self.build_full_event(event, entry.as_ref());
            self.writer.write_event(&full_event)?;
            self.event_count += 1;

            if self.event_count.is_multiple_of(10000) {
                trace!("Processed {} events", self.event_count);

                // Prune stale pending entries: remove entries whose timestamp
                // is more than 5 seconds older than the current event. These
                // are orphaned SYSCALL_ENTRY events whose matching EXIT was
                // lost (e.g. process killed mid-syscall, ring buffer overflow).
                let cutoff_ns = event.timestamp_ns.saturating_sub(5_000_000_000);
                let before = self.pending_entries.len();
                self.pending_entries
                    .retain(|_, e| e.timestamp_ns >= cutoff_ns);
                let pruned = before - self.pending_entries.len();
                if pruned > 0 {
                    debug!("Pruned {} stale pending entries", pruned);
                }
            }
        }

        Ok(())
    }

    /// Build a full SyscallEvent from ring buffer event
    fn build_full_event(&self, exit: &RingBufEvent, entry: Option<&RingBufEvent>) -> SyscallEvent {
        let mut event = SyscallEvent {
            timestamp_ns: exit.timestamp_ns,
            pid: exit.pid,
            tid: exit.tid,
            syscall_nr: exit.syscall_nr,
            ret_val: exit.ret_val,
            arch: arch::X86_64,
            ..Default::default()
        };

        // Copy arguments from entry if available
        if let Some(entry) = entry {
            for (i, &arg) in entry.args.iter().enumerate() {
                event.args[i].raw_value = arg;
                event.args[i].arg_type = scmm_common::ArgType::Integer;
            }

            // Copy captured path string data
            if entry.path_arg_index != 255 && entry.path_str_len > 0 {
                let idx = entry.path_arg_index as usize;
                if idx < scmm_common::MAX_ARGS {
                    let len = (entry.path_str_len as usize).min(scmm_common::MAX_ARG_STR_LEN);
                    event.args[idx].arg_type = scmm_common::ArgType::Path;
                    event.args[idx].str_data[..len].copy_from_slice(&entry.path_data[..len]);
                    event.args[idx].str_len = len as u16;
                }
            }
        }

        event
    }

    /// Finalize the capture file
    pub fn finalize(&mut self) -> Result<()> {
        self.writer.finalize(self.event_count)?;
        Ok(())
    }
}
