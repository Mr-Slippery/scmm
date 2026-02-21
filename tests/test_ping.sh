#!/usr/bin/env bash
# Test: record, extract, compile, enforce "ping -c 1 127.0.0.1"
# Validates that run_as + capabilities (CAP_NET_RAW) work together.
# The recorder captures the target UID/GID, the extractor populates run_as,
# and the enforcer uses PR_SET_KEEPCAPS to preserve ambient caps across setuid.
# Requires: sudo, ping
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_ping"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

CMD="ping -c 1 127.0.0.1"

echo "=== test_ping: $CMD ==="
uname -r

# 1. Record (needs CAP_BPF etc)
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture.scmm-cap" -- $CMD 2>"$WORKDIR/record.log"

# 2. Extract (non-interactive)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files skip \
    -i "$WORKDIR/capture.scmm-cap" -o "$WORKDIR/policy.yaml" 2>"$WORKDIR/extract.log"

cat "$WORKDIR/policy.yaml"

# 3. Compile
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy.yaml" -o "$WORKDIR/policy.pol" 2>"$WORKDIR/compile.log"

# 4. Enforce (needs sudo for run_as + capabilities)
enforce_log="$WORKDIR/enforce.log"
output=$(sudo "$ROOT/target/release/scmm-enforce" -vv -p "$WORKDIR/policy.pol" -- $CMD 2>"$enforce_log") || {
    echo "FAIL: test_ping — enforce exited with error"
    cat "$enforce_log"
    exit 1
}
cat "$enforce_log"

# 5. Verify — ping should succeed (check for "1 received" or "bytes from")
if echo "$output" | grep -q "1 received\|bytes from"; then
    echo "PASS: test_ping"
else
    echo "FAIL: test_ping — ping did not succeed under enforcement"
    echo "Output: $output"
    exit 1
fi
