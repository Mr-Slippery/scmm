#!/usr/bin/env bash
set -euxo pipefail

CMD="$@"
rm -f capture.scmm-cap && ./target/release/scmm-record -v -o capture.scmm-cap -- ${CMD} 2>&1
./target/release/scmm-extract -i capture.scmm-cap -o policy.yaml
./target/release/scmm-compile -i policy.yaml -o ls.policy.scmm-pol
./target/release/scmm-enforce -p ls.policy.scmm-pol -- ${CMD}
