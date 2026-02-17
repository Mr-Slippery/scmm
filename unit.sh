#!/usr/bin/env bash
set -euo pipefail

cargo test --workspace --exclude scmm-ebpf
