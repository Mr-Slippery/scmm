#!/usr/bin/env bash
set -euox pipefail

CMD="$@"
./target/release/scmm-enforce -v -p ls.policy.scmm-pol -- ${CMD}
