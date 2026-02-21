#!/usr/bin/env bash
# Test: record, extract, compile, enforce "ls -ali /tmp"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_ls"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

CMD="ls -ali /tmp"

echo "=== test_ls: $CMD ==="
uname -r

# 1. Record
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture.scmm-cap" -- $CMD 2>"$WORKDIR/record.log"

# 2. Extract (non-interactive)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files skip \
    -i "$WORKDIR/capture.scmm-cap" -o "$WORKDIR/policy.yaml" 2>"$WORKDIR/extract.log"

cat "$WORKDIR/policy.yaml"

# 3. Compile
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy.yaml" -o "$WORKDIR/policy.pol" 2>"$WORKDIR/compile.log"

# 4. Enforce
enforce_log="$WORKDIR/enforce.log"
output=$("$ROOT/target/release/scmm-enforce" -vv -p "$WORKDIR/policy.pol" -- $CMD 2>"$enforce_log") || {
    echo "FAIL: test_ls — enforce exited with error"
    cat "$enforce_log"
    exit 1
}
cat "$enforce_log"

# 5. Verify
if echo "$output" | grep -q '\.'; then
    echo "PASS: test_ls"
else
    echo "FAIL: test_ls — output missing expected entries"
    echo "$output"
    exit 1
fi
