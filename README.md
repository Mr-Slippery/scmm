# SysCallMeMaybe (SCMM)

A Linux syscall recording and sandboxing suite. Record what syscalls a program makes, interactively create a security policy, and enforce it on future runs using Seccomp-BPF and Landlock LSM.

## How It Works

SCMM uses a four-step pipeline: **record** -> **extract** -> **compile** -> **enforce**, with an optional **merge** step for combining policies.

1. **Record** -- eBPF tracepoints capture every syscall the target process makes (spawn a command or attach to a running process). Alternatively, `strace` output can be used in place of eBPF recording.
2. **Extract** -- an interactive (or automatic) step turns raw captures into a human-readable YAML policy
3. **Merge** *(optional)* -- combine multiple policies into one (e.g. from different runs of the same binary)
4. **Compile** -- the YAML policy is compiled into a binary format with Seccomp BPF bytecode and Landlock rule tables
5. **Enforce** -- the compiled policy is loaded and the target is exec'd under the sandbox

Enforcement is tiered because seccomp-BPF cannot dereference pointers (TOCTOU prevention):

| Layer | Technology | What It Controls | Kernel |
|-------|------------|------------------|--------|
| 1 | Seccomp-BPF | Syscall numbers and raw argument values | 3.5+ |
| 2 | Landlock LSM | Path-based filesystem access | 5.13+ |

## Quick Start

```bash
# 1. Record a program's syscalls
scmm-record -f -o capture.scmm-cap -- ls -la /tmp

# 2. Interactively extract a policy
scmm-extract -i capture.scmm-cap -o policy.yaml

# 3. Compile the policy
scmm-compile -i policy.yaml -o policy.scmm-pol

# 4. Run the program under the sandbox (no root needed)
scmm-enforce -p policy.scmm-pol -- ls -la /tmp
```

You can also attach to an already-running process:

```bash
scmm-record -p <PID> -f -o capture.scmm-cap
```

Or merge policies from multiple recording sessions:

```bash
scmm-merge -i policy1.yaml -i policy2.yaml -o merged.yaml
```

## Building

### Prerequisites

- Rust nightly toolchain (for eBPF compilation)
- Linux kernel 5.13+ (for Landlock support)
- `CAP_BPF + CAP_PERFMON + CAP_DAC_READ_SEARCH` for recording (set automatically by `build.sh`)

### Build Commands

```bash
# Build everything (eBPF + userspace + set capabilities)
./build.sh

# Build userspace tools only (no nightly/bpf-linker needed)
cargo build --workspace --exclude scmm-ebpf --release

# Run checks (clippy + fmt)
./check.sh
```

`build.sh` installs the nightly toolchain and `bpf-linker` if needed, builds the eBPF programs and userspace tools in release mode, and sets `cap_bpf,cap_perfmon,cap_dac_read_search` on `scmm-record` so it can run without sudo. The userspace-only build is useful when you only need the extract/compile/enforce tools (e.g. when using strace for recording instead of eBPF).

## Tool Reference

### scmm-record

Records syscalls using eBPF tracepoints. Requires `CAP_BPF + CAP_PERFMON + CAP_DAC_READ_SEARCH` (set automatically by `build.sh`).

```
Usage: scmm-record [OPTIONS] [-- <COMMAND>...]

Options:
  -o, --output <PATH>          Output capture file [default: capture.scmm-cap]
  -f, --follow-forks           Follow child processes (fork/clone)
  -p, --pid <PID>              Attach to an existing process by PID (mutually exclusive with command)
      --user <USER:GROUP>      Run child as this user:group (e.g. "nobody:nogroup", "1000:1000")
      --files                  Record file-related syscalls only
      --network                Record network-related syscalls only
      --process                Record process-related syscalls only
      --memory                 Record memory-related syscalls only
      --ipc                    Record IPC-related syscalls only
      --all                    Record all syscalls (default if no category given)
  -v, --verbose                Increase verbosity (-v, -vv, -vvv)
```

You must specify either a command to spawn or `--pid` to attach to a running process (not both).

Examples:

```bash
# Record all syscalls, follow forks
scmm-record -f -o capture.scmm-cap -- ./my-program arg1 arg2

# Record only file and network syscalls
scmm-record --files --network -o capture.scmm-cap -- ./my-program

# Record as a specific user (useful in containers)
scmm-record --user nobody:nogroup -o capture.scmm-cap -- ./my-program

# Attach to an already-running process
scmm-record -p 1234 -o capture.scmm-cap

# Attach with fork following (captures child processes too)
scmm-record -p 1234 -f -o capture.scmm-cap
```

When attaching to a running process, recording starts from the attach point -- earlier syscalls are not captured. Recording stops automatically when the target process exits, or on Ctrl+C.

### scmm-extract

Extracts a YAML policy from a capture file or strace output. The input format is auto-detected: binary `.scmm-cap` files (from `scmm-record`) and text strace output (from `strace -f -o`) are both supported. By default runs interactively, prompting you to generalize paths and choose syscall handling per category.

```
Usage: scmm-extract [OPTIONS] -i <INPUT>

Options:
  -i, --input <PATH>           Input capture file (.scmm-cap) or strace output
  -o, --output <PATH>          Output YAML policy [default: policy.scmm.yaml]
      --name <NAME>            Policy name
      --non-interactive        Auto-select defaults without prompting
      --missing-files <STRATEGY>  Strategy for read-only paths: precreate, parentdir, skip, ask
      --created-files <STRATEGY>  Strategy for create-intent paths: precreate, parentdir, skip, ask
      --categories <LIST>      Extract specific categories (comma-separated)
      --stats-only             Show capture statistics without generating policy
  -v, --verbose                Increase verbosity
```

The `--missing-files` and `--created-files` flags control how the extractor handles paths that may not exist at enforcement time. The extractor classifies each observed path as either **read-only** (only stat/open/exec accesses) or **create-intent** (had `O_CREAT` flag or a create-type syscall like `mkdir`).

| Flag | Applies to | Default |
|------|-----------|---------|
| `--missing-files` | Read-only paths | `skip` |
| `--created-files` | Create-intent paths | `precreate` |

| Value | `--missing-files` behavior | `--created-files` behavior |
|-------|---------------------------|---------------------------|
| `skip` | Exclude all-failed paths from policy; successful paths get `on_missing: skip` | Exclude from policy entirely |
| `precreate` | Include all paths with `on_missing: precreate` | Include with `on_missing: precreate` |
| `parentdir` | Include all paths with `on_missing: parentdir` | Include with `on_missing: parentdir` |
| `ask` | Prompt interactively per rule | Prompt interactively per rule |

With the default `--missing-files skip`, failed PATH-lookup probes (e.g. `~/.cargo/bin/touch` returning ENOENT before finding `/usr/bin/touch`) are automatically excluded from the policy, keeping it clean.

Examples:

```bash
# Interactive extraction (default)
scmm-extract -i capture.scmm-cap -o policy.yaml

# Fully automatic extraction (for scripting/CI)
scmm-extract --non-interactive -i capture.scmm-cap -o policy.yaml

# Include all observed paths (even failed lookups)
scmm-extract --non-interactive --missing-files precreate -i capture.scmm-cap -o policy.yaml

# Use parentdir strategy for created files (sandbox creates the file, not enforcer)
scmm-extract --non-interactive --created-files parentdir -i capture.scmm-cap -o policy.yaml

# Just show what was captured
scmm-extract -i capture.scmm-cap --stats-only
```

During interactive extraction you are prompted to:
- Choose a default action (deny/allow/log/kill) for unmatched syscalls
- Allow or deny each observed syscall category
- Generalize file paths (exact, directory glob, recursive glob, template)
- Review auto-detected file capabilities

### scmm-merge

Merges multiple YAML policies into a single unified policy (union of all rules). Useful when you record the same program under different conditions and want a combined policy that covers all observed behavior.

```
Usage: scmm-merge [OPTIONS] -i <INPUT> -i <INPUT> [-i <INPUT>...]

Options:
  -i, --input <PATH>           Input YAML policy files (at least 2 required)
  -o, --output <PATH>          Output merged policy [default: merged-policy.yaml]
      --name <NAME>            Name for the merged policy
  -v, --verbose                Increase verbosity
```

Examples:

```bash
# Record the same program twice under different workloads
scmm-record -f -o cap1.scmm-cap -- ./my-server --mode a
scmm-record -f -o cap2.scmm-cap -- ./my-server --mode b

# Extract policies from each
scmm-extract --non-interactive -i cap1.scmm-cap -o policy1.yaml
scmm-extract --non-interactive -i cap2.scmm-cap -o policy2.yaml

# Merge into one policy that covers both workloads
scmm-merge -i policy1.yaml -i policy2.yaml -o merged.yaml --name my-server

# Compile and enforce as usual
scmm-compile -i merged.yaml -o policy.scmm-pol
scmm-enforce -p policy.scmm-pol -- ./my-server
```

The merge takes the union of syscall rules, filesystem rules, capabilities, and network rules from all input policies.

### scmm-compile

Compiles a YAML policy into a binary format containing Seccomp BPF bytecode and Landlock rule tables.

```
Usage: scmm-compile [OPTIONS] -i <INPUT>

Options:
  -i, --input <PATH>           Input YAML policy file
  -o, --output <PATH>          Output compiled policy [default: policy.scmm-pol]
      --arch <ARCH>            Target architecture [default: x86_64]
      --no-validate            Skip policy validation (not recommended)
  -v, --verbose                Increase verbosity
```

### scmm-enforce

Loads a compiled policy and exec's the target command under the sandbox. No root required.

The enforcer is silent by default -- only errors are printed. Use `-v` for warnings, `-vv` for info, `-vvv` for debug. This prevents log messages from mixing with the target program's stdout/stderr.

```
Usage: scmm-enforce [OPTIONS] -p <POLICY> -- <COMMAND>...

Options:
  -p, --policy <PATH>          Compiled policy file
  -m, --mode <MODE>            Enforcement mode [default: standard]
      --categories <LIST>      Enforce specific categories only (comma-separated: files,network,process,memory,ipc)
  -v, --verbose                Increase verbosity
```

Enforcement modes:

| Mode | Behavior |
|------|----------|
| `standard` | Seccomp + Landlock; warns if Landlock unavailable |
| `strict` | Seccomp + Landlock; fails if Landlock unavailable |
| `seccomp` | Seccomp only (maximum kernel compatibility) |

Examples:

```bash
# Standard enforcement
scmm-enforce -p policy.scmm-pol -- ./my-program

# Strict mode (require Landlock)
scmm-enforce -p policy.scmm-pol --mode strict -- ./my-program

# Verbose output for debugging policy denials
scmm-enforce -vv -p policy.scmm-pol -- ./my-program
```

## Policy Format

Policies are YAML files with these sections:

```yaml
version: "1.0"

metadata:
  name: my-app-policy
  description: "Sandbox policy for my application"
  target_executable: my-program
  generated_from: capture.scmm-cap  # source capture file (auto-set)
  generated_at: "2026-02-16T12:00:00Z"  # generation timestamp (auto-set)

settings:
  default_action: deny    # deny | allow | log | kill | trap
  log_denials: true
  arch: x86_64
  run_as:                  # optional: drop privileges before exec
    user: nobody
    group: nogroup
    uid: 65534             # numeric fallback if name resolution fails
    gid: 65534

syscalls:
  - name: read
    action: allow
  - name: write
    action: allow
  - name: openat
    action: allow
  - name: close
    action: allow

capabilities: []           # e.g. ["net_bind_service", "dac_override"]

filesystem:
  rules:
    - path: /etc/ld.so.cache
      access: [execute, read_file]
    - path: /usr/sbin/nginx
      access: [execute, read_file]
    - path: /tmp/app.pid
      access: [make_reg, write_file, truncate]
      on_missing: precreate    # precreate | parentdir | skip

network:
  allow_loopback: true
  outbound:
    - protocol: tcp
      addresses: ["0.0.0.0/0"]
      ports: [80, 443]
  inbound:
    - protocol: tcp
      ports: [8080]
```

### Filesystem access rights

| Right | Description |
|-------|-------------|
| `execute` | Execute a file |
| `read_file` | Read file contents |
| `write_file` | Write to a file |
| `read_dir` | List directory contents |
| `make_reg` | Create a regular file |
| `make_dir` | Create a directory |
| `make_char` | Create a character device |
| `make_block` | Create a block device |
| `make_sock` | Create a Unix socket |
| `make_fifo` | Create a FIFO |
| `make_sym` | Create a symbolic link |
| `remove_file` | Delete a file |
| `remove_dir` | Delete a directory |
| `truncate` | Truncate a file (Landlock ABI V3+) |
| `refer` | Link/rename across directories |

### Handling non-existent paths (`on_missing`)

When a path in the policy doesn't exist at enforcement time, Landlock can't attach a rule to it. The `on_missing` field controls what happens:

| Strategy | Behavior |
|----------|----------|
| `precreate` | The enforcer creates an empty file before applying the Landlock rule, giving precise access control. |
| `parentdir` | Grants restricted rights (write, no read) on the parent directory so the file can be created. |
| `skip` | Silently drops the rule. |

The extractor sets `on_missing` automatically based on the `--missing-files` and `--created-files` flags (see [scmm-extract](#scmm-extract)). Defaults: `precreate` for create-intent paths, `skip` for read-only paths.

## Using strace Instead of eBPF

If you don't have the kernel capabilities for eBPF recording (or prefer not to build the eBPF components), you can use `strace` to capture syscalls and feed the output directly to `scmm-extract`:

```bash
# Record with strace (use -f to follow forks)
strace -f -o trace.log -- ./my-program arg1 arg2

# Extract, compile, enforce as usual
scmm-extract -i trace.log -o policy.yaml --non-interactive
scmm-compile -i policy.yaml -o policy.scmm-pol
scmm-enforce -p policy.scmm-pol -- ./my-program arg1 arg2
```

The input format is auto-detected. Strace input supports:
- Single-process and multi-process (`-f`) output
- Unfinished/resumed syscall lines from concurrent threads
- Open flag parsing (`O_RDONLY|O_CREAT|O_TRUNC` etc.) for correct Landlock access inference

Limitations compared to eBPF recording:
- Timestamps are synthetic (1ms increments), not real
- No process tree or environment metadata in the capture
- `strace` itself adds overhead via ptrace (eBPF is lower overhead)

## Privilege Requirements

| Tool | Privilege |
|------|-----------|
| `scmm-record` | `CAP_BPF + CAP_PERFMON + CAP_DAC_READ_SEARCH` (set by `build.sh`) |
| `scmm-extract` | None |
| `scmm-merge` | None |
| `scmm-compile` | None |
| `scmm-enforce` | None (sets `NO_NEW_PRIVS` via `prctl`) |

When the policy includes `capabilities`, the enforcer raises them in the ambient set and skips `NO_NEW_PRIVS`. This requires `CAP_SYS_ADMIN` on the enforcer binary.

## Testing

Integration tests live in `tests/` and exercise the full pipeline (record -> extract -> compile -> enforce):

```bash
# Run all tests
./tests/run_all.sh

# Skip tests marked as local_only (e.g. nginx, which needs extra setup)
./tests/run_all.sh --skip-local
```

Tests marked `# local_only` at the top of the script are skipped with `--skip-local`. Use this in CI or environments where not all dependencies (nginx, specific sandbox configs) are available.

Test artifacts are kept in `tests/out_<name>/` for debugging failed runs.

## License

MIT OR Apache-2.0
