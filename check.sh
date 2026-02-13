#!/usr/bin/env bash
set -euxo pipefail

FMT_ARGS=""
if [ "${1:-}" = "--check" ]; then
    FMT_ARGS="--check"
fi

cargo clippy --workspace --exclude scmm-ebpf -- -D warnings
cargo fmt $FMT_ARGS --package scmm-common --package scmm-record --package scmm-extract --package scmm-compile --package scmm-enforce --package xtask
