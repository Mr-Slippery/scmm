# SysCallMeMaybe (SCMM) - Architecture & Design

## Project Overview

SCMM is a Linux syscall sandboxing suite that:
1. Records syscalls of a process using eBPF
2. Extracts rules interactively with user-guided generalization
3. Compiles policies to efficient binary format
4. Enforces policies using Seccomp-BPF + Landlock

The name "scmm" stands for **SysCallMeMaybe**.

## Components

| Tool | Purpose | Key Files |
|------|---------|-----------|
| `scmm-record` | eBPF-based syscall recording | `scmm-record/src/{main,loader,capture}.rs` |
| `scmm-extract` | Interactive policy extraction | `scmm-extract/src/{main,interactive,generalize}.rs` |
| `scmm-compile` | YAML → binary policy compiler | `scmm-compile/src/{main,codegen,validator}.rs` |
| `scmm-enforce` | Policy enforcement at runtime | `scmm-enforce/src/{main,seccomp,landlock}.rs` |
| `scmm-common` | Shared types (eBPF ↔ userspace) | `scmm-common/src/*.rs` |
| `scmm-ebpf` | Kernel-space eBPF programs | `scmm-ebpf/src/{main,record}.rs` |

## Technology Choices

### Why Rust + Aya?
- **Self-contained binaries**: No libbpf/BCC dependencies at runtime
- **Shared types**: Same structs in kernel and userspace via `scmm-common`
- **Memory safety**: Critical for security tooling
- **Aya framework**: Pure Rust eBPF, supports BTF/CO-RE

### Why Tiered Enforcement?
Seccomp-BPF **cannot dereference pointers** (TOCTOU prevention), so:

| Layer | Technology | What It Can Do | Kernel |
|-------|------------|----------------|--------|
| 1 | Seccomp-BPF | Filter by syscall number, check raw arg values | 3.5+ |
| 2 | Landlock LSM | Path-based file access control | 5.13+ |

Seccomp alone can't check "is this openat() for /etc/passwd?" because the pathname is a pointer.

### Category Filtering
Users can record/enforce specific syscall categories:
- `--files` - open, read, write, stat, etc.
- `--network` - socket, connect, bind, etc.
- `--process` - fork, clone, execve, etc.
- `--memory` - mmap, mprotect, brk, etc.
- `--ipc` - pipe, shm, sem, msg, etc.

Defined in `scmm-common/src/categories.rs`.

## File Formats

### Capture File (.scmm-cap)
Binary format:
```
[64-byte header: magic, version, arch, timestamps, event count]
[Event blocks: compressed syscall events with delta timestamps]
[Metadata block: JSON with hostname, command, process tree]
```

### YAML Policy (.scmm.yaml)
```yaml
version: "1.0"
settings:
  default_action: deny
  arch: x86_64
syscalls:
  - name: openat
    action: allow
filesystem:
  rules:
    - path: "/etc"
      access: [read_file, read_dir]
network:
  outbound:
    - protocol: tcp
      ports: [80, 443]
```

### Compiled Policy (.scmm-pol)
Binary format:
```
[Header: magic, version, arch, offsets]
[Seccomp BPF bytecode]
[Landlock rule table]
[Path string table]
```

## Key Data Structures

### SyscallEvent (scmm-common/src/syscall.rs)
```rust
pub struct SyscallEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub syscall_nr: u32,
    pub ret_val: i64,
    pub args: [SyscallArg; 6],
    // ...
}
```

### RingBufEvent (eBPF → userspace)
Minimal struct sent via ring buffer, expanded to full SyscallEvent in userspace.

## Build System

### Building eBPF (requires nightly + bpf-linker)
```bash
# Install toolchain
rustup toolchain add nightly-2025-01-15 --profile minimal
rustup component add rust-src --toolchain nightly-2025-01-15
cargo +nightly-2025-01-15 install bpf-linker --locked

# Build
cargo xtask build-ebpf
```

### Building Userspace Only
```bash
cargo build --workspace --exclude scmm-ebpf --release
```

The `scmm-record` build.rs creates a placeholder eBPF file if the real one isn't built yet.

## Enforcement Modes

| Mode | Behavior |
|------|----------|
| `standard` | Seccomp + Landlock (warn if Landlock unavailable) |
| `strict` | Seccomp + Landlock (fail if Landlock unavailable) |
| `seccomp` | Seccomp only (maximum compatibility) |
| `permissive` | Log violations but don't block |

## Path Generalization (scmm-extract)

When extracting policies, users are prompted to generalize paths:
- **Exact**: `/home/alice/.bashrc`
- **Directory**: `/home/alice/*`
- **Recursive**: `/home/alice/**`
- **Template**: `/home/${USER}/.bashrc`

Known patterns auto-detected:
- `/home/<user>/` → `/home/${USER}/`
- `/tmp/<random>` → `/tmp/*`
- `/proc/<pid>/` → `/proc/self/`

## Security Considerations

### Dangerous Syscalls
Validator warns about: `ptrace`, `prctl`, `seccomp`, `bpf`, `mount`, `chroot`, etc.

### Privilege Requirements
| Tool | Privilege |
|------|-----------|
| scmm-record | CAP_BPF + CAP_PERFMON + CAP_DAC_READ_SEARCH (set by `build.sh`) |
| scmm-extract | None |
| scmm-compile | None |
| scmm-enforce | None (sets NO_NEW_PRIVS) |

## Current Status / TODOs

### Completed
- [x] Project structure and workspace
- [x] Shared types in scmm-common
- [x] Syscall category classification (x86_64)
- [x] Basic eBPF recording program structure
- [x] Capture file format
- [x] All CLI tools scaffolded
- [x] Interactive extraction with dialoguer
- [x] Seccomp BPF code generation
- [x] Landlock integration

### TODO - Phase 2 (Recording Enhancement)
- [ ] Capture syscall argument strings (paths, etc.) via `bpf_probe_read_user_str`
- [ ] Parse sockaddr structures for network info
- [ ] Fork/exec following with TARGET_PIDS map updates
- [ ] Process tree tracking in capture metadata

### TODO - Phase 3 (Polish)
- [ ] Better error messages
- [ ] Integration tests
- [ ] aarch64 syscall table
- [ ] More syscall argument type definitions

## Useful Commands

```bash
# Record a program
./target/release/scmm-record -o cap.scmm-cap -- ls -la

# Extract policy interactively
./target/release/scmm-extract -i cap.scmm-cap -o policy.yaml

# Compile policy
./target/release/scmm-compile -i policy.yaml -o policy.pol

# Run with enforcement
./target/release/scmm-enforce -p policy.pol -- ls -la
```

## References

- [Aya eBPF](https://aya-rs.dev/)
- [Landlock LSM](https://docs.kernel.org/userspace-api/landlock.html)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Linux syscall table (x86_64)](https://filippo.io/linux-syscall-table/)
