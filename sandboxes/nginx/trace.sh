#!/usr/bin/env bash
set -euxo pipefail

../../target/release/scmm-compile -i nginx.policy.yaml -o nginx.scmm-pol
strace -o trace.log -f -s 1500 ../../target/release/scmm-enforce -v -p nginx.scmm-pol nginx -p . -c nginx.conf
