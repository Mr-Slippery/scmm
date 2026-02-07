//! SysCallMeMaybe eBPF programs
//!
//! This crate contains the eBPF programs that run in kernel space
//! to trace syscalls.

#![no_std]
#![no_main]

mod record;

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

/// Entry point for raw_syscalls:sys_enter tracepoint
#[tracepoint]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    match record::handle_sys_enter(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Entry point for raw_syscalls:sys_exit tracepoint
#[tracepoint]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    match record::handle_sys_exit(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
