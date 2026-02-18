#!/usr/bin/env bash
set -euxo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

PATH_LEN=1500
CAP_FILE=strace-capture.log

CMD="$@"
rm -f "${CAP_FILE}" && strace -f -o "${CAP_FILE}" -s "${PATH_LEN}" -- ${CMD} 2>&1
"${SCRIPT_DIR}"/target/release/scmm-extract -i "${CAP_FILE}" -o policy.yaml --missing-files skip --created-files parentdir --non-interactive
"${SCRIPT_DIR}"/target/release/scmm-compile -i policy.yaml -o policy.scmm-pol

# Use sudo for the enforcer if the policy requires capabilities
# (NO_NEW_PRIVS strips file caps, so CAP_SYS_ADMIN is needed to load seccomp without it)
if grep -q '^capabilities:' policy.yaml && ! grep -q '^capabilities: \[\]' policy.yaml; then
    sudo -E "${SCRIPT_DIR}"/target/release/scmm-enforce -vv -p policy.scmm-pol -- ${CMD}
else
    "${SCRIPT_DIR}"/target/release/scmm-enforce -vv -p policy.scmm-pol -- ${CMD}
fi
