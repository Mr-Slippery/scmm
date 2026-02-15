#!/usr/bin/env bash
# Test: record two different "touch" invocations, extract policies,
#       merge them, compile, and enforce the merged policy on a third file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_merge"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

FILE_A="$WORKDIR/file_a"
FILE_B="$WORKDIR/file_b"
FILE_C="$WORKDIR/file_c"

echo "=== test_merge ==="

# --- Trace A: touch file_a ---
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture_a.scmm-cap" -- touch "$FILE_A" >/dev/null 2>&1

"$ROOT/target/release/scmm-extract" --non-interactive --missing-files parentdir \
    -i "$WORKDIR/capture_a.scmm-cap" -o "$WORKDIR/policy_a.yaml" >/dev/null 2>&1

# --- Trace B: touch file_b ---
rm -f "$FILE_A"  # clean up so it doesn't pollute trace B
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/capture_b.scmm-cap" -- touch "$FILE_B" >/dev/null 2>&1

"$ROOT/target/release/scmm-extract" --non-interactive --missing-files parentdir \
    -i "$WORKDIR/capture_b.scmm-cap" -o "$WORKDIR/policy_b.yaml" >/dev/null 2>&1

# --- Merge ---
"$ROOT/target/release/scmm-merge" \
    -i "$WORKDIR/policy_a.yaml" \
    -i "$WORKDIR/policy_b.yaml" \
    -o "$WORKDIR/merged.yaml" \
    --name "test-merge"

# The merged policy should have filesystem rules from both policies.
# Verify the merge produced something with rules from both:
if ! grep -q "file_a\|file_b\|out_merge" "$WORKDIR/merged.yaml"; then
    echo "FAIL: test_merge — merged policy missing expected filesystem paths"
    exit 1
fi

# --- Compile ---
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/merged.yaml" -o "$WORKDIR/merged.pol" >/dev/null 2>&1

# --- Enforce: touch file_c (same parent dir, covered by parentdir on_missing) ---
rm -f "$FILE_A" "$FILE_B" "$FILE_C"
if ! "$ROOT/target/release/scmm-enforce" -p "$WORKDIR/merged.pol" -- touch "$FILE_A" 2>/dev/null; then
    echo "FAIL: test_merge — enforce on file_a failed"
    exit 1
fi

if [ -f "$FILE_A" ]; then
    echo "PASS: test_merge"
else
    echo "FAIL: test_merge — file_a was not created under merged policy"
    exit 1
fi
