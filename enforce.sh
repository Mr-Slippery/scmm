#!/usr/bin/env bash
set -euox pipefail

CMD="$@"
./target/release/scmm-enforce -p ls.policy.scmm-pol -- ${CMD}
