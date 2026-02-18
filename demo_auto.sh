#!/usr/bin/env bash
set -euxo pipefail

CMD="$@"
rm -f capture.scmm-cap && ./target/release/scmm-record -v -f -o capture.scmm-cap -- ${CMD} 2>&1
./target/release/scmm-extract -i capture.scmm-cap -o policy.yaml --missing-files skip --created-files parentdir --non-interactive
./target/release/scmm-compile -i policy.yaml -o policy.scmm-pol

# Use sudo for the enforcer if the policy requires capabilities
# (NO_NEW_PRIVS strips file caps, so CAP_SYS_ADMIN is needed to load seccomp without it)
if grep -q '^capabilities:' policy.yaml && ! grep -q '^capabilities: \[\]' policy.yaml; then
    sudo -E ./target/release/scmm-enforce -vv -p policy.scmm-pol -- ${CMD}
else
    ./target/release/scmm-enforce -vv -p policy.scmm-pol -- ${CMD}
fi
