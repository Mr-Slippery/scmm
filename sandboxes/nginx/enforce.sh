#!/usr/bin/env bash
set -euxo pipefail

../../target/release/scmm-compile -i nginx.policy.yaml -o nginx.scmm-pol
../../target/release/scmm-enforce -v -p nginx.scmm-pol nginx -p . -c nginx.conf
