#!/usr/bin/env bash
set -euo pipefail

./target/release/scmm-compile -i policy.yaml -o ls.policy.scmm-pol
