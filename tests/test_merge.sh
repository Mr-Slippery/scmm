#!/usr/bin/env bash
# Test: record two different "touch" invocations, extract policies,
#       merge them, compile, and enforce the merged policy on a third file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_merge"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/dir_a" "$WORKDIR/dir_b"

FILE_A="$WORKDIR/dir_a/file_a"
FILE_B="$WORKDIR/dir_b/file_b"

echo "=== test_merge ==="
uname -r

# --- Trace A: touch file_a (in dir_a) ---
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture_a.scmm-cap" -- touch "$FILE_A" 2>"$WORKDIR/record_a.log"

"$ROOT/target/release/scmm-extract" --non-interactive --missing-files parentdir \
    -i "$WORKDIR/capture_a.scmm-cap" -o "$WORKDIR/policy_a.yaml" 2>"$WORKDIR/extract_a.log"

# --- Trace B: touch file_b (in dir_b — different parent dir) ---
rm -f "$FILE_A"  # clean up so it doesn't pollute trace B
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture_b.scmm-cap" -- touch "$FILE_B" 2>"$WORKDIR/record_b.log"

"$ROOT/target/release/scmm-extract" --non-interactive --missing-files parentdir \
    -i "$WORKDIR/capture_b.scmm-cap" -o "$WORKDIR/policy_b.yaml" 2>"$WORKDIR/extract_b.log"

# --- Merge ---
"$ROOT/target/release/scmm-merge" \
    -i "$WORKDIR/policy_a.yaml" \
    -i "$WORKDIR/policy_b.yaml" \
    -o "$WORKDIR/merged.yaml" \
    --name "test-merge" 2>"$WORKDIR/merge.log"

# The merged policy should have filesystem rules from both policies.
# Verify the merge produced paths from both separate directories:
if ! grep -q "dir_a" "$WORKDIR/merged.yaml"; then
    echo "FAIL: test_merge — merged policy missing dir_a paths"
    exit 1
fi
if ! grep -q "dir_b" "$WORKDIR/merged.yaml"; then
    echo "FAIL: test_merge — merged policy missing dir_b paths"
    exit 1
fi

# --- Compile ---
cat "$WORKDIR/merged.yaml"
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/merged.yaml" -o "$WORKDIR/merged.pol" 2>"$WORKDIR/compile.log"

# --- Enforce: touch files in both dirs under the merged policy ---
# This proves the merge is needed: policy_a alone wouldn't cover dir_b,
# and policy_b alone wouldn't cover dir_a.
rm -f "$FILE_A" "$FILE_B"

if ! "$ROOT/target/release/scmm-enforce" -vv -p "$WORKDIR/merged.pol" -- touch "$FILE_A" 2>"$WORKDIR/enforce_a.log"; then
    echo "FAIL: test_merge — enforce on file_a (dir_a) failed"
    cat "$WORKDIR/enforce_a.log"
    exit 1
fi
cat "$WORKDIR/enforce_a.log"
if [ ! -f "$FILE_A" ]; then
    echo "FAIL: test_merge — file_a was not created under merged policy"
    exit 1
fi

if ! "$ROOT/target/release/scmm-enforce" -vv -p "$WORKDIR/merged.pol" -- touch "$FILE_B" 2>"$WORKDIR/enforce_b.log"; then
    echo "FAIL: test_merge — enforce on file_b (dir_b) failed"
    cat "$WORKDIR/enforce_b.log"
    exit 1
fi
cat "$WORKDIR/enforce_b.log"
if [ ! -f "$FILE_B" ]; then
    echo "FAIL: test_merge — file_b was not created under merged policy"
    exit 1
fi

echo "PASS: test_merge"
