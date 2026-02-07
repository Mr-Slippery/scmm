# SCMM Build Status

## ✅ eBPF Build - COMPLETE

Built with:
```bash
cargo +nightly-2026-01-15 build --package scmm-ebpf --target bpfel-unknown-none -Z build-std=core --release
```

## ✅ Userspace Build - COMPLETE

Built with:
```bash
cargo build --workspace --exclude scmm-ebpf --release
```

## Binaries

All four binaries are built in `target/release/`:
- `scmm-record` - Records syscalls using eBPF
- `scmm-extract` - Extracts rules interactively from captures
- `scmm-compile` - Compiles YAML policy to binary format
- `scmm-enforce` - Enforces policy using Seccomp + Landlock

## Testing

To test the full pipeline:

```bash
# 1. Record a program's syscalls (requires root for eBPF)
sudo ./target/release/scmm-record -o capture.scmm-cap -- ls -la

# 2. Interactively extract a policy
./target/release/scmm-extract -i capture.scmm-cap -o policy.scmm.yaml

# 3. Compile the policy
./target/release/scmm-compile -i policy.scmm.yaml -o policy.scmm-pol

# 4. Run with enforcement
./target/release/scmm-enforce -p policy.scmm-pol -- ls -la
```

## Quick Build Commands

```bash
# Build eBPF
cargo xtask build-ebpf

# Build userspace
cargo xtask build --release

# Build everything
cargo xtask build-all --release

# Install to /usr/local/bin
sudo cargo xtask install
```
