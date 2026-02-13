#!/usr/bin/env bash
# Test: record, extract, compile, enforce "echo hello"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_echo"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

CMD="/bin/echo hello"

echo "=== test_echo: $CMD ==="

# 1. Record (child auto-drops to SUDO_UID:SUDO_GID)
sudo "$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture.scmm-cap" -- $CMD >/dev/null 2>&1

# 2. Extract (non-interactive)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files skip \
    -i "$WORKDIR/capture.scmm-cap" -o "$WORKDIR/policy.yaml" >/dev/null 2>&1

# 3. Compile
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy.yaml" -o "$WORKDIR/policy.pol" >/dev/null 2>&1

# 4. Enforce
output=$("$ROOT/target/release/scmm-enforce" -p "$WORKDIR/policy.pol" -- $CMD 2>/dev/null)

# 5. Verify
if [ "$output" = "hello" ]; then
    echo "PASS: test_echo"
else
    echo "FAIL: test_echo — expected 'hello', got '$output' (see $WORKDIR/policy.yaml)"
    exit 1
fi
