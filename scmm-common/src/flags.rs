//! Syscall flag name → numeric value resolution (x86_64).
//!
//! Used by the policy compiler to convert human-readable flag names
//! (e.g. `O_WRONLY`, `PROT_EXEC`) into the numeric values needed
//! for seccomp BPF argument checks.

/// Resolve a flag name to its numeric value (x86_64).
/// Returns `None` for unrecognized names.
pub fn resolve(name: &str) -> Option<u64> {
    Some(match name {
        // open(2) access modes (bits 0-1 of flags arg)
        "O_RDONLY" => 0x0000,
        "O_WRONLY" => 0x0001,
        "O_RDWR" => 0x0002,

        // open(2) flags
        "O_CREAT" => 0x0040,
        "O_EXCL" => 0x0080,
        "O_NOCTTY" => 0x0100,
        "O_TRUNC" => 0x0200,
        "O_APPEND" => 0x0400,
        "O_NONBLOCK" => 0x0800,
        "O_DSYNC" => 0x1000,
        "O_SYNC" => 0x101000,
        "O_DIRECTORY" => 0x10000,
        "O_NOFOLLOW" => 0x20000,
        "O_CLOEXEC" => 0x80000,
        "O_TMPFILE" => 0x410000,
        "O_PATH" => 0x200000,
        "O_NOATIME" => 0x40000,

        // mmap / mprotect protection flags
        "PROT_NONE" => 0x0,
        "PROT_READ" => 0x1,
        "PROT_WRITE" => 0x2,
        "PROT_EXEC" => 0x4,

        // mmap flags
        "MAP_SHARED" => 0x01,
        "MAP_PRIVATE" => 0x02,
        "MAP_FIXED" => 0x10,
        "MAP_ANONYMOUS" => 0x20,
        "MAP_POPULATE" => 0x8000,
        "MAP_HUGETLB" => 0x40000,
        "MAP_STACK" => 0x20000,
        "MAP_NORESERVE" => 0x4000,

        // Socket address families
        "AF_UNSPEC" => 0,
        "AF_UNIX" => 1,
        "AF_INET" => 2,
        "AF_INET6" => 10,
        "AF_NETLINK" => 16,
        "AF_PACKET" => 17,
        "AF_VSOCK" => 40,

        // Socket types
        "SOCK_STREAM" => 1,
        "SOCK_DGRAM" => 2,
        "SOCK_RAW" => 3,
        "SOCK_SEQPACKET" => 5,
        "SOCK_NONBLOCK" => 0x800,
        "SOCK_CLOEXEC" => 0x80000,

        // clone flags
        "CLONE_VM" => 0x00000100,
        "CLONE_FS" => 0x00000200,
        "CLONE_FILES" => 0x00000400,
        "CLONE_SIGHAND" => 0x00000800,
        "CLONE_THREAD" => 0x00010000,
        "CLONE_NEWNS" => 0x00020000,
        "CLONE_SYSVSEM" => 0x00040000,
        "CLONE_NEWUSER" => 0x10000000,
        "CLONE_NEWPID" => 0x20000000,
        "CLONE_NEWNET" => 0x40000000,

        // prctl operations
        "PR_SET_NO_NEW_PRIVS" => 38,
        "PR_SET_SECCOMP" => 22,
        "PR_SET_DUMPABLE" => 4,
        "PR_GET_DUMPABLE" => 3,

        // fcntl commands
        "F_DUPFD" => 0,
        "F_GETFD" => 1,
        "F_SETFD" => 2,
        "F_GETFL" => 3,
        "F_SETFL" => 4,
        "F_DUPFD_CLOEXEC" => 0x406,

        // ioctl common requests
        "TCGETS" => 0x5401,
        "TIOCGWINSZ" => 0x5413,
        "FIONREAD" => 0x541B,

        _ => return None,
    })
}
