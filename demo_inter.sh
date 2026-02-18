#!/usr/bin/env bash
set -euxo pipefail

CMD="$@"
rm -f capture.scmm-cap && ./target/release/scmm-record -v -f -o capture.scmm-cap -- ${CMD} 2>&1
./target/release/scmm-extract -i capture.scmm-cap -o policy.yaml
./target/release/scmm-compile -i policy.yaml -o ls.policy.scmm-pol

# Use sudo for the enforcer if the policy requires capabilities
# (NO_NEW_PRIVS strips file caps, so CAP_SYS_ADMIN is needed to load seccomp without it)
if grep -q '^capabilities:' policy.yaml && ! grep -q '^capabilities: \[\]' policy.yaml; then
    sudo ./target/release/scmm-enforce -vv -p ls.policy.scmm-pol -- ${CMD}
else
    ./target/release/scmm-enforce -vv -p ls.policy.scmm-pol -- ${CMD}
fi
