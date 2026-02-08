//! Seccomp filter application

use anyhow::{bail, Result};

/// sock_filter structure for BPF
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// sock_fprog structure for seccomp
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Apply a seccomp BPF filter
pub fn apply_filter(filter_data: &[u8]) -> Result<()> {
    if filter_data.is_empty() {
        return Ok(());
    }

    // Each sock_filter is 8 bytes
    if !filter_data.len().is_multiple_of(8) {
        bail!(
            "Invalid filter size: {} bytes (must be multiple of 8)",
            filter_data.len()
        );
    }

    let filter_count = filter_data.len() / 8;
    if filter_count > u16::MAX as usize {
        bail!("Filter too large: {} instructions", filter_count);
    }

    // Create sock_fprog
    let prog = SockFprog {
        len: filter_count as u16,
        filter: filter_data.as_ptr() as *const SockFilter,
    };

    // Apply filter using seccomp syscall
    // SECCOMP_SET_MODE_FILTER = 1
    // SECCOMP_FILTER_FLAG_TSYNC = 1 (sync all threads)
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1, // SECCOMP_SET_MODE_FILTER
            0, // flags (no TSYNC for now - single threaded at this point)
            &prog as *const SockFprog,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        bail!("Failed to apply seccomp filter: {}", err);
    }

    Ok(())
}
