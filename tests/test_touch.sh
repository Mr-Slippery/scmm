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

# 1. Record (child auto-drops to SUDO_UID:SUDO_GID)
sudo "$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture.scmm-cap" -- $CMD >/dev/null 2>&1

# 2. Extract (non-interactive)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files skip \
    -i "$WORKDIR/capture.scmm-cap" -o "$WORKDIR/policy.yaml" >/dev/null 2>&1

# Patch: set on_missing to parentdir for the test file so it can be created
python3 "$SCRIPT_DIR/patch_on_missing.py" "$WORKDIR/policy.yaml" "$TESTFILE" parentdir

# 3. Compile
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy.yaml" -o "$WORKDIR/policy.pol" >/dev/null 2>&1

# Remove the file so enforce creates it fresh
rm -f "$TESTFILE"

# 4. Enforce
if ! "$ROOT/target/release/scmm-enforce" -p "$WORKDIR/policy.pol" -- $CMD 2>/dev/null; then
    echo "FAIL: test_touch — enforce exited with error (see $WORKDIR/policy.yaml)"
    exit 1
fi

# 5. Verify
if [ -f "$TESTFILE" ]; then
    echo "PASS: test_touch"
else
    echo "FAIL: test_touch — file was not created (see $WORKDIR/policy.yaml)"
    exit 1
fi
