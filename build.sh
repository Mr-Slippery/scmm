#!/usr/bin/env bash
set -euo pipefail

NIGHTLY="nightly-2026-01-15"

# Ensure nightly toolchain + rust-src are available
if ! rustup toolchain list | grep -q "$NIGHTLY"; then
    echo "Installing $NIGHTLY toolchain..."
    rustup toolchain add "$NIGHTLY" --profile minimal
    rustup component add rust-src --toolchain "$NIGHTLY"
fi

# Ensure bpf-linker is installed
if ! cargo install --list | grep -q '^bpf-linker'; then
    echo "Installing bpf-linker..."
    cargo +"$NIGHTLY" install bpf-linker --locked
fi

echo "=== Building eBPF programs ==="
cargo +"$NIGHTLY" build \
    --package scmm-ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

echo "=== Building userspace tools ==="
cargo build --workspace --exclude scmm-ebpf --release

echo "=== Setting capabilities for unprivileged eBPF ==="
if command -v setcap >/dev/null 2>&1; then
    sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search=ep target/release/scmm-record && \
        echo "Set cap_bpf,cap_perfmon,cap_dac_read_search on scmm-record (run without sudo)" || \
        echo "Warning: setcap failed - scmm-record will require sudo"
    # NOTE: scmm-enforce does NOT get cap_sys_admin — that would be a privilege
    # escalation vector. Policies with capabilities require 'sudo scmm-enforce'.
else
    echo "Warning: setcap not found - scmm-record will require sudo"
fi

echo "=== Done ==="
ls -lh target/release/scmm-{record,extract,compile,enforce} 2>/dev/null
