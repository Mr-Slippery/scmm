//! Syscall recording eBPF handlers

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::map,
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use scmm_common::{ring_event_type, RingBufEvent, MAX_ARGS, MAX_SOCKADDR_LEN};

/// Ring buffer for sending events to userspace (1 MB to accommodate larger events with path data)
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Map of PIDs we're tracing (key: pid, value: 1 if active)
#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Configuration array: index 0 = follow_forks (0 or 1)
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

/// Returns the argument index (0-5) that contains a path pointer for this syscall,
/// or 255 if no path argument. x86_64 syscall numbers.
#[inline(always)]
fn path_arg_index(syscall_nr: u32) -> u8 {
    match syscall_nr {
        2 => 0,     // open(pathname, flags, mode)
        4 => 0,     // stat(pathname, statbuf)
        6 => 0,     // lstat(pathname, statbuf)
        21 => 0,    // access(pathname, mode)
        59 => 0,    // execve(pathname, argv, envp)
        76 => 0,    // truncate(path, length)
        80 => 0,    // chdir(path)
        82 => 0,    // rename(old, new) -- capture old path
        83 => 0,    // mkdir(pathname, mode)
        84 => 0,    // rmdir(pathname)
        85 => 0,    // creat(pathname, mode)
        86 => 0,    // link(oldpath, newpath)
        87 => 0,    // unlink(pathname)
        88 => 0,    // symlink(target, linkpath)
        89 => 0,    // readlink(pathname, buf, bufsiz)
        90 => 0,    // chmod(pathname, mode)
        92 => 0,    // chown(pathname, owner, group)
        94 => 0,    // lchown(pathname, owner, group)
        137 => 0,   // statfs(path, buf)
        161 => 0,   // chroot(path)
        257 => 1,   // openat(dirfd, pathname, flags, mode)
        258 => 1,   // mkdirat(dirfd, pathname, mode)
        259 => 1,   // mknodat(dirfd, pathname, dev, mode)
        260 => 1,   // fchownat(dirfd, pathname, owner, group, flags)
        262 => 1,   // newfstatat(dirfd, pathname, statbuf, flags)
        263 => 1,   // unlinkat(dirfd, pathname, flags)
        264 => 1,   // renameat(olddirfd, oldpath, newdirfd, newpath)
        265 => 1,   // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        266 => 2,   // symlinkat(target, newdirfd, linkpath) -- target is arg[0] but linkpath at arg[2]
        267 => 1,   // readlinkat(dirfd, pathname, buf, bufsiz)
        268 => 1,   // fchmodat(dirfd, pathname, mode)
        269 => 1,   // faccessat(dirfd, pathname, mode)
        322 => 1,   // execveat(dirfd, pathname, argv, envp, flags)
        332 => 1,   // statx(dirfd, pathname, flags, mask, statxbuf)
        437 => 1,   // openat2(dirfd, pathname, how, size)
        439 => 1,   // faccessat2(dirfd, pathname, mode, flags)
        _ => 255,
    }
}

/// Returns the argument index (0-5) that contains a sockaddr pointer for this syscall,
/// or 255 if no sockaddr argument. x86_64 syscall numbers.
///
/// connect(fd, sockaddr, addrlen) — nr=42, sockaddr at arg1
/// bind(fd, sockaddr, addrlen)    — nr=49, sockaddr at arg1
#[inline(always)]
fn sockaddr_arg_index(syscall_nr: u32) -> u8 {
    match syscall_nr {
        42 => 1, // connect
        49 => 1, // bind
        _ => 255,
    }
}

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

    let nr = syscall_nr as u32;
    let pai = path_arg_index(nr);
    let sai = sockaddr_arg_index(nr);

    // Write directly into ring buffer reserved slot (struct is too large for eBPF stack)
    if let Some(mut entry) = EVENTS.reserve::<RingBufEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).event_type = ring_event_type::SYSCALL_ENTRY;
            (*ptr)._pad = [0; 3];
            (*ptr).syscall_nr = nr;
            (*ptr).timestamp_ns = bpf_ktime_get_ns();
            (*ptr).pid = pid;
            (*ptr).tid = tid;
            (*ptr).ret_val = 0;
            (*ptr).args = args;
            (*ptr).path_arg_index = pai;
            (*ptr).sockaddr_arg_index = sai;
            (*ptr).path_str_len = 0;

            // Read path string from userspace if this syscall has a path argument
            if pai != 255 && (pai as usize) < MAX_ARGS {
                let user_ptr = args[pai as usize] as *const u8;
                if !user_ptr.is_null() {
                    match bpf_probe_read_user_str_bytes(user_ptr, &mut (*ptr).path_data) {
                        Ok(slice) => {
                            (*ptr).path_str_len = slice.len() as u16;
                        }
                        Err(_) => {
                            // Read failed, leave path_str_len = 0
                        }
                    }
                }
            }

            // Read sockaddr bytes from userspace (binary struct, not string)
            if sai != 255 && (sai as usize) < MAX_ARGS {
                let user_ptr = args[sai as usize] as *const u8;
                if !user_ptr.is_null() {
                    // Read up to MAX_SOCKADDR_LEN bytes; ignore errors (partial reads are ok)
                    let dest: &mut [u8; MAX_SOCKADDR_LEN] = &mut (*ptr).sockaddr_data;
                    let _ = bpf_probe_read_user_buf(user_ptr, dest);
                }
            }
        }
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

    let nr = syscall_nr as u32;

    // Kernel-side fork following: when a tracked process calls clone/fork/vfork/clone3,
    // immediately add the child PID to TARGET_PIDS so its very first syscalls are captured.
    // This eliminates the race condition of userspace adding the PID too late.
    if ret_val > 0 && (nr == 56 || nr == 57 || nr == 58 || nr == 435) {
        // clone=56, fork=57, vfork=58, clone3=435
        let follow = CONFIG.get(0);
        if let Some(&val) = follow {
            if val != 0 {
                let child_pid = ret_val as u32;
                let _ = TARGET_PIDS.insert(&child_pid, &1u8, 0);
            }
        }
    }

    // Write directly into ring buffer reserved slot
    if let Some(mut entry) = EVENTS.reserve::<RingBufEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).event_type = ring_event_type::SYSCALL_EXIT;
            (*ptr)._pad = [0; 3];
            (*ptr).syscall_nr = nr;
            (*ptr).timestamp_ns = bpf_ktime_get_ns();
            (*ptr).pid = pid;
            (*ptr).tid = tid;
            (*ptr).ret_val = ret_val;
            (*ptr).args = [0u64; MAX_ARGS];
            (*ptr).path_arg_index = 255;
            (*ptr).sockaddr_arg_index = 255;
            (*ptr).path_str_len = 0;
        }
        entry.submit(0);
    }

    Ok(())
}
