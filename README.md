# SysCallMeMaybe (SCMM)

A Linux syscall recording and sandboxing suite. Record what syscalls a program makes, interactively create a security policy, and then enforce that policy on future runs.

## Components

| Tool | Description |
|------|-------------|
| `scmm-record` | Records syscalls of a process using eBPF into a capture file |
| `scmm-extract` | Extracts rules from capture with interactive user guidance for generalization |
| `scmm-compile` | Converts YAML policy to efficient binary format |
| `scmm-enforce` | Launches a process with the compiled policy enforcing syscall restrictions |

## Quick Start

```bash
# 1. Record a program's syscalls
sudo scmm-record -o capture.scmm-cap -- ./my-program arg1 arg2

# 2. Interactively extract a policy
scmm-extract -i capture.scmm-cap -o policy.scmm.yaml

# 3. Compile the policy
scmm-compile -i policy.scmm.yaml -o policy.scmm-pol

# 4. Run the program with the policy enforced
scmm-enforce -p policy.scmm-pol -- ./my-program arg1 arg2
```

## Building

### Prerequisites

- Rust nightly (for eBPF compilation)
- Linux kernel 5.13+ (recommended, for Landlock support)
- Root access (for eBPF and recording)

### Build Commands

```bash
# Build eBPF programs (requires nightly)
cargo xtask build-ebpf

# Build userspace tools
cargo xtask build --release

# Or build everything at once
cargo xtask build-all --release

# Install to /usr/local/bin
cargo xtask install
```

## Tool Usage

### scmm-record

Records syscalls using eBPF tracepoints.

```bash
# Record all syscalls
sudo scmm-record -o capture.scmm-cap -- ./my-program

# Record only file and network syscalls
sudo scmm-record --files --network -o capture.scmm-cap -- ./my-program

# Follow child processes
sudo scmm-record -f -o capture.scmm-cap -- ./my-program

# Available category filters:
#   --files     File operations (open, read, write, etc.)
#   --network   Network operations (socket, connect, etc.)
#   --process   Process operations (fork, exec, etc.)
#   --memory    Memory operations (mmap, mprotect, etc.)
#   --ipc       IPC operations (pipe, shm, etc.)
#   --all       All syscalls (default)
```

### scmm-extract

Interactively extracts rules from a capture file.

```bash
# Basic extraction
scmm-extract -i capture.scmm-cap -o policy.scmm.yaml

# Show statistics only
scmm-extract -i capture.scmm-cap --stats-only

# Set policy name
scmm-extract -i capture.scmm-cap -o policy.yaml --name "my-app-policy"
```

During extraction, you'll be prompted to:
- Choose how to handle each syscall category
- Generalize file paths (exact, directory, recursive patterns)
- Generalize network connections (specific ports, any address, etc.)

### scmm-compile

Compiles YAML policies into binary format.

```bash
# Compile for x86_64 (default)
scmm-compile -i policy.scmm.yaml -o policy.scmm-pol

# Compile for ARM64
scmm-compile -i policy.scmm.yaml -o policy.scmm-pol --arch aarch64

# Skip validation (not recommended)
scmm-compile -i policy.scmm.yaml -o policy.scmm-pol --no-validate
```

### scmm-enforce

Runs a program with policy enforcement.

```bash
# Standard mode (Seccomp + Landlock if available)
scmm-enforce -p policy.scmm-pol -- ./my-program

# Strict mode (requires Landlock, fails if unavailable)
scmm-enforce -p policy.scmm-pol --mode strict -- ./my-program

# Seccomp only (maximum compatibility)
scmm-enforce -p policy.scmm-pol --mode seccomp -- ./my-program

# Permissive mode (log violations but don't block)
scmm-enforce -p policy.scmm-pol --mode permissive -- ./my-program
```

## Policy Format

Policies are written in YAML:

```yaml
version: "1.0"
metadata:
  name: "my-app-policy"
  description: "Policy for my application"

settings:
  default_action: deny
  log_denials: true
  arch: x86_64

syscalls:
  - name: read
    action: allow
  - name: write
    action: allow
  - name: openat
    action: allow
  - name: close
    action: allow
  # ... more syscalls

filesystem:
  rules:
    - path: "/etc"
      access: [read_file, read_dir]
    - path: "/usr"
      access: [read_file, read_dir, execute]
    - path: "/tmp"
      access: [read_file, write_file, read_dir, make_dir, remove]

network:
  allow_loopback: true
  outbound:
    - protocol: tcp
      addresses: ["0.0.0.0/0"]
      ports: [80, 443]
```

## How It Works

### Recording (scmm-record)

Uses eBPF tracepoints attached to `raw_syscalls:sys_enter` and `raw_syscalls:sys_exit` to capture all syscalls made by the target process. Events are sent to userspace via a ring buffer.

### Enforcement (scmm-enforce)

Uses a tiered approach because seccomp-BPF cannot dereference pointers (TOCTOU prevention):

| Layer | Technology | Capability | Kernel |
|-------|------------|------------|--------|
| 1 | Seccomp-BPF | Syscall number filtering | 3.5+ |
| 2 | Landlock LSM | Path-based file access control | 5.13+ |

## Requirements

- Linux kernel 3.5+ (for seccomp)
- Linux kernel 5.13+ (for Landlock, recommended)
- CAP_BPF + CAP_PERFMON (or root) for recording
- No special privileges for enforcement (uses NO_NEW_PRIVS)

## License

MIT OR Apache-2.0
