//! Syscall category definitions for filtering

#[cfg(not(feature = "no_std"))]
use serde::{Deserialize, Serialize};

/// Categories of syscalls for filtering
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "no_std"), derive(Serialize, Deserialize))]
pub enum SyscallCategory {
    /// File operations: open, read, write, close, stat, etc.
    Files = 1,
    /// Network operations: socket, connect, bind, accept, etc.
    Network = 2,
    /// Process operations: fork, clone, execve, wait, kill, etc.
    Process = 3,
    /// Memory operations: mmap, mprotect, brk, etc.
    Memory = 4,
    /// IPC operations: pipe, shmget, semget, msgget, etc.
    Ipc = 5,
    /// Time operations: clock_gettime, nanosleep, etc.
    Time = 6,
    /// Signal operations: rt_sigaction, rt_sigprocmask, etc.
    Signal = 7,
    /// Other/uncategorized syscalls
    Other = 255,
}

/// Bitmask for category filtering
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(not(feature = "no_std"), derive(Serialize, Deserialize))]
pub struct CategoryFilter(pub u32);

impl CategoryFilter {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(0xFFFFFFFF);
    pub const FILES: Self = Self(1 << 0);
    pub const NETWORK: Self = Self(1 << 1);
    pub const PROCESS: Self = Self(1 << 2);
    pub const MEMORY: Self = Self(1 << 3);
    pub const IPC: Self = Self(1 << 4);
    pub const TIME: Self = Self(1 << 5);
    pub const SIGNAL: Self = Self(1 << 6);
    pub const OTHER: Self = Self(1 << 7);

    pub fn contains(&self, category: SyscallCategory) -> bool {
        let bit = match category {
            SyscallCategory::Files => Self::FILES.0,
            SyscallCategory::Network => Self::NETWORK.0,
            SyscallCategory::Process => Self::PROCESS.0,
            SyscallCategory::Memory => Self::MEMORY.0,
            SyscallCategory::Ipc => Self::IPC.0,
            SyscallCategory::Time => Self::TIME.0,
            SyscallCategory::Signal => Self::SIGNAL.0,
            SyscallCategory::Other => Self::OTHER.0,
        };
        (self.0 & bit) != 0
    }

    pub fn add(&mut self, category: SyscallCategory) {
        let bit = match category {
            SyscallCategory::Files => Self::FILES.0,
            SyscallCategory::Network => Self::NETWORK.0,
            SyscallCategory::Process => Self::PROCESS.0,
            SyscallCategory::Memory => Self::MEMORY.0,
            SyscallCategory::Ipc => Self::IPC.0,
            SyscallCategory::Time => Self::TIME.0,
            SyscallCategory::Signal => Self::SIGNAL.0,
            SyscallCategory::Other => Self::OTHER.0,
        };
        self.0 |= bit;
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for CategoryFilter {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for CategoryFilter {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Complete x86_64 syscall definitions with categories and names
#[cfg(not(feature = "no_std"))]
pub mod x86_64 {
    use super::SyscallCategory;

    /// Get the category for a syscall number
    pub fn get_category(syscall_nr: u32) -> SyscallCategory {
        match syscall_nr {
            // File operations
            0 | 1 | 2 | 3 | 4 | 5 | 6 | 8  // read write open close stat fstat lstat lseek
            | 16 | 17 | 18 | 19 | 20 | 21   // ioctl pread64 pwrite64 readv writev access
            | 32 | 33 | 40                    // dup dup2 sendfile
            | 72 | 73 | 74 | 75 | 76 | 77    // fcntl flock fsync fdatasync truncate ftruncate
            | 78 | 79 | 80 | 81              // getdents getcwd chdir fchdir
            | 82 | 83 | 84 | 85              // rename mkdir rmdir creat
            | 86 | 87 | 88 | 89              // link unlink symlink readlink
            | 90 | 91 | 92 | 93 | 94 | 95    // chmod fchmod chown fchown lchown umask
            | 132 | 133 | 134                 // utime mknod uselib
            | 137 | 138 | 139                 // statfs fstatfs sysfs
            | 155 | 161 | 162                 // pivot_root chroot sync
            | 165 | 166                       // mount umount2
            | 187                             // readahead
            | 188 | 189 | 190                 // setxattr lsetxattr fsetxattr
            | 191 | 192 | 193                 // getxattr lgetxattr fgetxattr
            | 194 | 195 | 196                 // listxattr llistxattr flistxattr
            | 197 | 198 | 199                 // removexattr lremovexattr fremovexattr
            | 212                             // lookup_dcookie
            | 217                             // getdents64
            | 235                             // utimes
            | 253 | 254 | 255                 // inotify_init inotify_add_watch inotify_rm_watch
            | 257 | 258 | 259 | 260 | 261    // openat mkdirat mknodat fchownat futimesat
            | 262 | 263 | 264 | 265 | 266    // newfstatat unlinkat renameat linkat symlinkat
            | 267 | 268 | 269                 // readlinkat fchmodat faccessat
            | 275 | 276 | 277 | 278           // splice tee sync_file_range vmsplice
            | 280                             // utimensat
            | 285                             // fallocate
            | 291 | 292                        // epoll_create1 dup3
            | 294                             // inotify_init1
            | 295 | 296                       // preadv pwritev
            | 300 | 301                       // fanotify_init fanotify_mark
            | 303 | 304                       // name_to_handle_at open_by_handle_at
            | 306                             // syncfs
            | 316                             // renameat2
            | 319                             // memfd_create
            | 326                             // copy_file_range
            | 327 | 328                       // preadv2 pwritev2
            | 332                             // statx
            | 428 | 429 | 430 | 431 | 432 | 433  // open_tree move_mount fsopen fsconfig fsmount fspick
            | 436                             // close_range
            | 437                             // openat2
            | 439                             // faccessat2
            | 443                             // quotactl_fd
            | 451                             // cachestat
            | 452                             // fchmodat2
            | 457 | 458                       // statmount listmount
            => SyscallCategory::Files,

            // Network operations
            41 | 42 | 43 | 44 | 45 | 46 | 47  // socket connect accept sendto recvfrom sendmsg recvmsg
            | 48 | 49 | 50                     // shutdown bind listen
            | 51 | 52 | 53 | 54 | 55          // getsockname getpeername socketpair setsockopt getsockopt
            | 288                              // accept4
            | 299 | 307                        // recvmmsg sendmmsg
            => SyscallCategory::Network,

            // Process operations
            39                                 // getpid
            | 56 | 57 | 58 | 59 | 60 | 61 | 62  // clone fork vfork execve exit wait4 kill
            | 63                               // uname
            | 97 | 98 | 99 | 100               // getrlimit getrusage sysinfo times
            | 101                              // ptrace
            | 102 | 103 | 104 | 105 | 106     // getuid syslog getgid setuid setgid
            | 107 | 108 | 109 | 110 | 111     // geteuid getegid setpgid getppid getpgrp
            | 112 | 113 | 114 | 115 | 116     // setsid setreuid setregid getgroups setgroups
            | 117 | 118 | 119 | 120 | 121     // setresuid getresuid setresgid getresgid getpgid
            | 122 | 123 | 124                 // setfsuid setfsgid getsid
            | 125 | 126                       // capget capset
            | 135                              // personality
            | 153 | 154                        // vhangup modify_ldt
            | 156 | 157 | 158                  // _sysctl prctl arch_prctl
            | 160                              // setrlimit
            | 163 | 164                        // acct settimeofday
            | 167 | 168 | 169 | 170 | 171     // swapon swapoff reboot sethostname setdomainname
            | 172 | 173                        // iopl ioperm
            | 174 | 175 | 176 | 177 | 178 | 179  // create_module init_module delete_module get_kernel_syms query_module quotactl
            | 186                              // gettid
            | 200                              // tkill
            | 218                              // set_tid_address
            | 231                              // exit_group
            | 234                              // tgkill
            | 246                              // kexec_load
            | 247                              // waitid
            | 248 | 249 | 250                  // add_key request_key keyctl
            | 251 | 252                        // ioprio_set ioprio_get
            | 256                              // migrate_pages
            | 272                              // unshare
            | 273 | 274                        // set_robust_list get_robust_list
            | 279                              // move_pages
            | 298                              // perf_event_open
            | 302                              // prlimit64
            | 308                              // setns
            | 309                              // getcpu
            | 310 | 311                        // process_vm_readv process_vm_writev
            | 312 | 313                        // kcmp finit_module
            | 314 | 315                        // sched_setattr sched_getattr
            | 317                              // seccomp
            | 318                              // getrandom
            | 320                              // kexec_file_load
            | 321                              // bpf
            | 322                              // execveat
            | 323                              // userfaultfd
            | 324                              // membarrier
            | 334                              // rseq
            | 424                              // pidfd_send_signal
            | 434                              // pidfd_open
            | 435                              // clone3
            | 438                              // pidfd_getfd
            | 440                              // process_madvise
            | 444 | 445 | 446                  // landlock_create_ruleset landlock_add_rule landlock_restrict_self
            | 447                              // memfd_secret
            | 448                              // process_mrelease
            | 453                              // map_shadow_stack
            | 459 | 460 | 461                  // lsm_get_self_attr lsm_set_self_attr lsm_list_modules
            => SyscallCategory::Process,

            // Memory operations
            9 | 10 | 11 | 12                   // mmap mprotect munmap brk
            | 25 | 26 | 27 | 28               // mremap msync mincore madvise
            | 136                              // ustat
            | 149 | 150 | 151 | 152            // mlock munlock mlockall munlockall
            | 205 | 211                        // set_thread_area get_thread_area
            | 216                              // remap_file_pages
            | 237 | 238 | 239                  // mbind set_mempolicy get_mempolicy
            | 325                              // mlock2
            | 329 | 330 | 331                  // pkey_mprotect pkey_alloc pkey_free
            | 450                              // set_mempolicy_home_node
            => SyscallCategory::Memory,

            // IPC operations
            22                                 // pipe
            | 29 | 30 | 31                     // shmget shmat shmctl
            | 64 | 65 | 66                     // semget semop semctl
            | 67 | 68 | 69 | 70 | 71          // shmdt msgget msgsnd msgrcv msgctl
            | 220                              // semtimedop
            | 240 | 241 | 242 | 243 | 244 | 245  // mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr
            | 293                              // pipe2
            => SyscallCategory::Ipc,

            // Time operations
            35 | 36 | 37 | 38                  // nanosleep getitimer alarm setitimer
            | 96                               // gettimeofday
            | 159                              // adjtimex
            | 201                              // time
            | 222 | 223 | 224 | 225 | 226 | 227  // timer_create timer_settime timer_gettime timer_getoverrun timer_delete clock_settime
            | 228 | 229 | 230                  // clock_gettime clock_getres clock_nanosleep
            | 283 | 284                        // timerfd_create eventfd
            | 286 | 287                        // timerfd_settime timerfd_gettime
            | 289 | 290                        // signalfd4 eventfd2
            | 305                              // clock_adjtime
            => SyscallCategory::Time,

            // Signal operations
            13 | 14 | 15                       // rt_sigaction rt_sigprocmask rt_sigreturn
            | 34                               // pause
            | 127 | 128 | 129 | 130 | 131     // rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigsuspend sigaltstack
            | 282                              // signalfd
            | 297                              // rt_tgsigqueueinfo
            => SyscallCategory::Signal,

            // I/O multiplexing / polling (Files)
            7 | 23                             // poll select
            | 206 | 207 | 208 | 209 | 210     // io_setup io_destroy io_getevents io_submit io_cancel
            | 213 | 232 | 233                  // epoll_create epoll_wait epoll_ctl
            | 270 | 271                        // pselect6 ppoll
            | 281                              // epoll_pwait
            | 333                              // io_pgetevents
            | 425 | 426 | 427                  // io_uring_setup io_uring_enter io_uring_register
            | 441                              // epoll_pwait2
            | 442                              // mount_setattr
            => SyscallCategory::Files,

            // Futex operations (IPC/synchronization)
            202                                // futex
            | 449                              // futex_waitv
            | 454 | 455 | 456                  // futex_wake futex_wait futex_requeue
            => SyscallCategory::Ipc,

            // Scheduling (Process)
            142 | 143 | 144 | 145 | 146 | 147 | 148  // sched_*
            | 203 | 204                        // sched_setaffinity sched_getaffinity
            | 219                              // restart_syscall
            => SyscallCategory::Process,

            _ => SyscallCategory::Other,
        }
    }

    /// Get the name for a syscall number
    pub fn get_name(syscall_nr: u32) -> &'static str {
        match syscall_nr {
            0 => "read",
            1 => "write",
            2 => "open",
            3 => "close",
            4 => "stat",
            5 => "fstat",
            6 => "lstat",
            7 => "poll",
            8 => "lseek",
            9 => "mmap",
            10 => "mprotect",
            11 => "munmap",
            12 => "brk",
            13 => "rt_sigaction",
            14 => "rt_sigprocmask",
            15 => "rt_sigreturn",
            16 => "ioctl",
            17 => "pread64",
            18 => "pwrite64",
            19 => "readv",
            20 => "writev",
            21 => "access",
            22 => "pipe",
            23 => "select",
            24 => "sched_yield",
            25 => "mremap",
            26 => "msync",
            27 => "mincore",
            28 => "madvise",
            29 => "shmget",
            30 => "shmat",
            31 => "shmctl",
            32 => "dup",
            33 => "dup2",
            34 => "pause",
            35 => "nanosleep",
            36 => "getitimer",
            37 => "alarm",
            38 => "setitimer",
            39 => "getpid",
            40 => "sendfile",
            41 => "socket",
            42 => "connect",
            43 => "accept",
            44 => "sendto",
            45 => "recvfrom",
            46 => "sendmsg",
            47 => "recvmsg",
            48 => "shutdown",
            49 => "bind",
            50 => "listen",
            51 => "getsockname",
            52 => "getpeername",
            53 => "socketpair",
            54 => "setsockopt",
            55 => "getsockopt",
            56 => "clone",
            57 => "fork",
            58 => "vfork",
            59 => "execve",
            60 => "exit",
            61 => "wait4",
            62 => "kill",
            63 => "uname",
            64 => "semget",
            65 => "semop",
            66 => "semctl",
            67 => "shmdt",
            68 => "msgget",
            69 => "msgsnd",
            70 => "msgrcv",
            71 => "msgctl",
            72 => "fcntl",
            73 => "flock",
            74 => "fsync",
            75 => "fdatasync",
            76 => "truncate",
            77 => "ftruncate",
            78 => "getdents",
            79 => "getcwd",
            80 => "chdir",
            81 => "fchdir",
            82 => "rename",
            83 => "mkdir",
            84 => "rmdir",
            85 => "creat",
            86 => "link",
            87 => "unlink",
            88 => "symlink",
            89 => "readlink",
            90 => "chmod",
            91 => "fchmod",
            92 => "chown",
            93 => "fchown",
            94 => "lchown",
            95 => "umask",
            96 => "gettimeofday",
            97 => "getrlimit",
            98 => "getrusage",
            99 => "sysinfo",
            100 => "times",
            101 => "ptrace",
            102 => "getuid",
            103 => "syslog",
            104 => "getgid",
            105 => "setuid",
            106 => "setgid",
            107 => "geteuid",
            108 => "getegid",
            109 => "setpgid",
            110 => "getppid",
            111 => "getpgrp",
            112 => "setsid",
            113 => "setreuid",
            114 => "setregid",
            115 => "getgroups",
            116 => "setgroups",
            117 => "setresuid",
            118 => "getresuid",
            119 => "setresgid",
            120 => "getresgid",
            121 => "getpgid",
            122 => "setfsuid",
            123 => "setfsgid",
            124 => "getsid",
            125 => "capget",
            126 => "capset",
            127 => "rt_sigpending",
            128 => "rt_sigtimedwait",
            129 => "rt_sigqueueinfo",
            130 => "rt_sigsuspend",
            131 => "sigaltstack",
            132 => "utime",
            133 => "mknod",
            134 => "uselib",
            135 => "personality",
            136 => "ustat",
            137 => "statfs",
            138 => "fstatfs",
            139 => "sysfs",
            140 => "getpriority",
            141 => "setpriority",
            142 => "sched_setparam",
            143 => "sched_getparam",
            144 => "sched_setscheduler",
            145 => "sched_getscheduler",
            146 => "sched_get_priority_max",
            147 => "sched_get_priority_min",
            148 => "sched_rr_get_interval",
            149 => "mlock",
            150 => "munlock",
            151 => "mlockall",
            152 => "munlockall",
            153 => "vhangup",
            154 => "modify_ldt",
            155 => "pivot_root",
            156 => "_sysctl",
            157 => "prctl",
            158 => "arch_prctl",
            159 => "adjtimex",
            160 => "setrlimit",
            161 => "chroot",
            162 => "sync",
            163 => "acct",
            164 => "settimeofday",
            165 => "mount",
            166 => "umount2",
            167 => "swapon",
            168 => "swapoff",
            169 => "reboot",
            170 => "sethostname",
            171 => "setdomainname",
            172 => "iopl",
            173 => "ioperm",
            174 => "create_module",
            175 => "init_module",
            176 => "delete_module",
            177 => "get_kernel_syms",
            178 => "query_module",
            179 => "quotactl",
            180 => "nfsservctl",
            181 => "getpmsg",
            182 => "putpmsg",
            183 => "afs_syscall",
            184 => "tuxcall",
            185 => "security",
            186 => "gettid",
            187 => "readahead",
            188 => "setxattr",
            189 => "lsetxattr",
            190 => "fsetxattr",
            191 => "getxattr",
            192 => "lgetxattr",
            193 => "fgetxattr",
            194 => "listxattr",
            195 => "llistxattr",
            196 => "flistxattr",
            197 => "removexattr",
            198 => "lremovexattr",
            199 => "fremovexattr",
            200 => "tkill",
            201 => "time",
            202 => "futex",
            203 => "sched_setaffinity",
            204 => "sched_getaffinity",
            205 => "set_thread_area",
            206 => "io_setup",
            207 => "io_destroy",
            208 => "io_getevents",
            209 => "io_submit",
            210 => "io_cancel",
            211 => "get_thread_area",
            212 => "lookup_dcookie",
            213 => "epoll_create",
            214 => "epoll_ctl_old",
            215 => "epoll_wait_old",
            216 => "remap_file_pages",
            217 => "getdents64",
            218 => "set_tid_address",
            219 => "restart_syscall",
            220 => "semtimedop",
            221 => "fadvise64",
            222 => "timer_create",
            223 => "timer_settime",
            224 => "timer_gettime",
            225 => "timer_getoverrun",
            226 => "timer_delete",
            227 => "clock_settime",
            228 => "clock_gettime",
            229 => "clock_getres",
            230 => "clock_nanosleep",
            231 => "exit_group",
            232 => "epoll_wait",
            233 => "epoll_ctl",
            234 => "tgkill",
            235 => "utimes",
            236 => "vserver",
            237 => "mbind",
            238 => "set_mempolicy",
            239 => "get_mempolicy",
            240 => "mq_open",
            241 => "mq_unlink",
            242 => "mq_timedsend",
            243 => "mq_timedreceive",
            244 => "mq_notify",
            245 => "mq_getsetattr",
            246 => "kexec_load",
            247 => "waitid",
            248 => "add_key",
            249 => "request_key",
            250 => "keyctl",
            251 => "ioprio_set",
            252 => "ioprio_get",
            253 => "inotify_init",
            254 => "inotify_add_watch",
            255 => "inotify_rm_watch",
            256 => "migrate_pages",
            257 => "openat",
            258 => "mkdirat",
            259 => "mknodat",
            260 => "fchownat",
            261 => "futimesat",
            262 => "newfstatat",
            263 => "unlinkat",
            264 => "renameat",
            265 => "linkat",
            266 => "symlinkat",
            267 => "readlinkat",
            268 => "fchmodat",
            269 => "faccessat",
            270 => "pselect6",
            271 => "ppoll",
            272 => "unshare",
            273 => "set_robust_list",
            274 => "get_robust_list",
            275 => "splice",
            276 => "tee",
            277 => "sync_file_range",
            278 => "vmsplice",
            279 => "move_pages",
            280 => "utimensat",
            281 => "epoll_pwait",
            282 => "signalfd",
            283 => "timerfd_create",
            284 => "eventfd",
            285 => "fallocate",
            286 => "timerfd_settime",
            287 => "timerfd_gettime",
            288 => "accept4",
            289 => "signalfd4",
            290 => "eventfd2",
            291 => "epoll_create1",
            292 => "dup3",
            293 => "pipe2",
            294 => "inotify_init1",
            295 => "preadv",
            296 => "pwritev",
            297 => "rt_tgsigqueueinfo",
            298 => "perf_event_open",
            299 => "recvmmsg",
            300 => "fanotify_init",
            301 => "fanotify_mark",
            302 => "prlimit64",
            303 => "name_to_handle_at",
            304 => "open_by_handle_at",
            305 => "clock_adjtime",
            306 => "syncfs",
            307 => "sendmmsg",
            308 => "setns",
            309 => "getcpu",
            310 => "process_vm_readv",
            311 => "process_vm_writev",
            312 => "kcmp",
            313 => "finit_module",
            314 => "sched_setattr",
            315 => "sched_getattr",
            316 => "renameat2",
            317 => "seccomp",
            318 => "getrandom",
            319 => "memfd_create",
            320 => "kexec_file_load",
            321 => "bpf",
            322 => "execveat",
            323 => "userfaultfd",
            324 => "membarrier",
            325 => "mlock2",
            326 => "copy_file_range",
            327 => "preadv2",
            328 => "pwritev2",
            329 => "pkey_mprotect",
            330 => "pkey_alloc",
            331 => "pkey_free",
            332 => "statx",
            333 => "io_pgetevents",
            334 => "rseq",
            424 => "pidfd_send_signal",
            425 => "io_uring_setup",
            426 => "io_uring_enter",
            427 => "io_uring_register",
            428 => "open_tree",
            429 => "move_mount",
            430 => "fsopen",
            431 => "fsconfig",
            432 => "fsmount",
            433 => "fspick",
            434 => "pidfd_open",
            435 => "clone3",
            436 => "close_range",
            437 => "openat2",
            438 => "pidfd_getfd",
            439 => "faccessat2",
            440 => "process_madvise",
            441 => "epoll_pwait2",
            442 => "mount_setattr",
            443 => "quotactl_fd",
            444 => "landlock_create_ruleset",
            445 => "landlock_add_rule",
            446 => "landlock_restrict_self",
            447 => "memfd_secret",
            448 => "process_mrelease",
            449 => "futex_waitv",
            450 => "set_mempolicy_home_node",
            451 => "cachestat",
            452 => "fchmodat2",
            453 => "map_shadow_stack",
            454 => "futex_wake",
            455 => "futex_wait",
            456 => "futex_requeue",
            457 => "statmount",
            458 => "listmount",
            459 => "lsm_get_self_attr",
            460 => "lsm_set_self_attr",
            461 => "lsm_list_modules",
            _ => "unknown",
        }
    }

    /// Build a map from syscall name to syscall number (x86_64).
    pub fn build_name_to_nr_map() -> std::collections::HashMap<&'static str, u32> {
        let mut map = std::collections::HashMap::new();
        // x86_64 syscall numbers: 0-334, 424-461
        for nr in (0..=334).chain(424..=461) {
            let name = get_name(nr);
            if name != "unknown" {
                map.insert(name, nr);
            }
        }
        map
    }
}
