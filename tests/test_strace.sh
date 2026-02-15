#!/usr/bin/env bash
# Test: use strace to record syscalls, then extract a policy from the strace output
set -euxo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_strace"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/allowed_dir"

echo "=== test_strace ==="

# Check that strace is available
if ! command -v strace &>/dev/null; then
    echo "SKIP: strace not found"
    exit 0
fi

# --- Step 1: Record with strace (follow forks) ---
# Use a subdirectory so the parentdir policy is specific to allowed_dir,
# not WORKDIR itself (which would also cover denied_dir).
TRACE_FILE="$WORKDIR/strace.log"
strace -f -o "$TRACE_FILE" -- touch "$WORKDIR/allowed_dir/testfile" 2>/dev/null

if [ ! -f "$TRACE_FILE" ]; then
    echo "FAIL: test_strace — strace output file not created"
    exit 1
fi

TRACE_SIZE=$(stat -c%s "$TRACE_FILE")
if [ "$TRACE_SIZE" -lt 100 ]; then
    echo "FAIL: test_strace — strace output too small ($TRACE_SIZE bytes)"
    exit 1
fi

# --- Step 2: Extract policy from strace output ---
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files parentdir \
    -i "$TRACE_FILE" -o "$WORKDIR/policy.yaml" >/dev/null 2>&1

if [ ! -f "$WORKDIR/policy.yaml" ]; then
    echo "FAIL: test_strace — policy extraction from strace output failed"
    exit 1
fi

# --- Step 3: Verify the policy has syscall rules ---
if ! grep -q "syscalls:" "$WORKDIR/policy.yaml"; then
    echo "FAIL: test_strace — policy missing syscalls section"
    exit 1
fi

# openat should appear (touch uses it)
if ! grep -q "openat" "$WORKDIR/policy.yaml"; then
    echo "FAIL: test_strace — policy missing openat syscall"
    exit 1
fi

# --- Step 4: Verify filesystem rules reference the allowed dir ---
if ! grep -q "allowed_dir" "$WORKDIR/policy.yaml"; then
    echo "FAIL: test_strace — policy missing allowed_dir path in filesystem rules"
    exit 1
fi

# --- Step 5: Test --stats-only with strace input ---
if ! "$ROOT/target/release/scmm-extract" --stats-only -i "$TRACE_FILE" >/dev/null 2>&1; then
    echo "FAIL: test_strace — --stats-only failed with strace input"
    exit 1
fi

# --- Step 6: Compile and enforce the strace-derived policy ---
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy.yaml" -o "$WORKDIR/policy.pol" >/dev/null 2>&1

# 6a. Positive test: touch in allowed_dir should succeed
rm -f "$WORKDIR/allowed_dir/testfile"
if ! "$ROOT/target/release/scmm-enforce" -p "$WORKDIR/policy.pol" -- touch "$WORKDIR/allowed_dir/testfile" 2>/dev/null; then
    echo "FAIL: test_strace — enforce on allowed_dir/testfile failed"
    exit 1
fi
if [ ! -f "$WORKDIR/allowed_dir/testfile" ]; then
    echo "FAIL: test_strace — testfile not created under strace-derived policy"
    exit 1
fi

# 6b. Negative test: touch in a different directory should be denied by Landlock.
#     The policy only covers allowed_dir (via parentdir), not denied_dir.
mkdir -p "$WORKDIR/denied_dir"
if "$ROOT/target/release/scmm-enforce" -p "$WORKDIR/policy.pol" -- touch "$WORKDIR/denied_dir/nope" 2>/dev/null; then
    # touch succeeded — check if the file was actually created (it shouldn't be)
    if [ -f "$WORKDIR/denied_dir/nope" ]; then
        echo "FAIL: test_strace — sandbox allowed creating file in denied_dir"
        exit 1
    fi
fi
# If enforce exited non-zero or file doesn't exist, the sandbox correctly denied it.

echo "PASS: test_strace"
