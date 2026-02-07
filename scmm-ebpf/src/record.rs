//! Syscall recording eBPF handlers

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::map,
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use scmm_common::{RingBufEvent, ring_event_type, MAX_ARGS};

/// Ring buffer for sending events to userspace
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Map of PIDs we're tracing (key: pid, value: 1 if active)
#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Category filter bitmask (set by userspace)
#[map]
static CATEGORY_FILTER: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

/// Follow child processes flag
#[map]
static FOLLOW_FORKS: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Handle sys_enter tracepoint
pub fn handle_sys_enter(ctx: TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Check if we're tracing this PID
    if unsafe { TARGET_PIDS.get(&pid).is_none() } {
        return Ok(());
    }

    // Read syscall number from tracepoint context
    // ctx points to the start of the tracepoint struct including the common header:
    //   common_type(0, 2), common_flags(2, 1), common_preempt_count(3, 1), common_pid(4, 4)
    // sys_enter user fields: id @ offset 8, args[6] @ offset 16
    let syscall_nr: i64 = unsafe { ctx.read_at(8).map_err(|_| 1i64)? };

    // Read arguments (offset 16 = after common header + id field)
    let args: [u64; 6] = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    // Build the event
    let event = RingBufEvent {
        event_type: ring_event_type::SYSCALL_ENTRY,
        _pad: [0; 3],
        syscall_nr: syscall_nr as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        ret_val: 0,
        args,
    };

    // Reserve space and write to ring buffer
    if let Some(mut entry) = EVENTS.reserve::<RingBufEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(())
}

/// Handle sys_exit tracepoint
pub fn handle_sys_exit(ctx: TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Check if we're tracing this PID
    if unsafe { TARGET_PIDS.get(&pid).is_none() } {
        return Ok(());
    }

    // Read syscall number and return value
    // ctx points to the start of the tracepoint struct including the common header:
    //   common_type(0, 2), common_flags(2, 1), common_preempt_count(3, 1), common_pid(4, 4)
    // sys_exit user fields: id @ offset 8, ret @ offset 16
    let syscall_nr: i64 = unsafe { ctx.read_at(8).map_err(|_| 1i64)? };
    let ret_val: i64 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    // Build the event
    let event = RingBufEvent {
        event_type: ring_event_type::SYSCALL_EXIT,
        _pad: [0; 3],
        syscall_nr: syscall_nr as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        tid,
        ret_val,
        args: [0u64; MAX_ARGS],
    };

    // Reserve space and write to ring buffer
    if let Some(mut entry) = EVENTS.reserve::<RingBufEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(())
}
