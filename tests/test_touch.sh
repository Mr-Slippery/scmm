#!/usr/bin/env bash
# Test: record, extract, compile, enforce "touch <file>"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_touch"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

TESTFILE="$WORKDIR/testfile"
CMD="touch $TESTFILE"

echo "=== test_touch: $CMD ==="
uname -r

# 1. Record
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture.scmm-cap" -- $CMD 2>"$WORKDIR/record.log"

# 2. Extract (non-interactive)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files skip \
    -i "$WORKDIR/capture.scmm-cap" -o "$WORKDIR/policy.yaml" 2>"$WORKDIR/extract.log"

# Patch: set on_missing to parentdir for the test file so it can be created
python3 "$SCRIPT_DIR/patch_on_missing.py" "$WORKDIR/policy.yaml" "$TESTFILE" parentdir

cat "$WORKDIR/policy.yaml"

# 3. Compile
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy.yaml" -o "$WORKDIR/policy.pol" 2>"$WORKDIR/compile.log"

# Remove the file so enforce creates it fresh
rm -f "$TESTFILE"

# 4. Enforce
enforce_log="$WORKDIR/enforce.log"
if ! "$ROOT/target/release/scmm-enforce" -vv -p "$WORKDIR/policy.pol" -- $CMD 2>"$enforce_log"; then
    echo "FAIL: test_touch — enforce exited with error"
    cat "$enforce_log"
    exit 1
fi
cat "$enforce_log"

# 5. Verify
if [ -f "$TESTFILE" ]; then
    echo "PASS: test_touch"
else
    echo "FAIL: test_touch — file was not created"
    exit 1
fi
