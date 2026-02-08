#!/usr/bin/env bash
set -euxo pipefail

cargo clippy --workspace --exclude scmm-ebpf -- -D warnings
cargo fmt --package scmm-common --package scmm-record --package scmm-extract --package scmm-compile --package scmm-enforce --package xtask
