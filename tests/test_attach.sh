#!/usr/bin/env bash
# Test: attach to a running process by PID and record its syscalls
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_attach"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

echo "=== test_attach: record via --pid ==="
uname -r

# 1. Start a background process that does some syscalls
#    The loop writes to a file so we can verify it ran, and gives us time to attach.
OUTFILE="$WORKDIR/target_output"
(
    for i in $(seq 1 20); do
        echo "tick $i" >> "$OUTFILE"
        sleep 0.1
    done
) &
TARGET_PID=$!

# Give the process a moment to start
sleep 0.05

# 2. Record by attaching to the PID (record for ~1.5s, the target runs for ~2s)
"$ROOT/target/release/scmm-record" -f -p "$TARGET_PID" -o "$WORKDIR/capture.scmm-cap" 2>"$WORKDIR/record.log" &
RECORDER_PID=$!

# Wait for the target to finish — recorder should detect exit and stop
wait "$TARGET_PID" 2>/dev/null || true

# Wait for the recorder to finish (it should exit shortly after the target)
# Give it a generous timeout in case of slow CI
TIMEOUT=10
while kill -0 "$RECORDER_PID" 2>/dev/null; do
    TIMEOUT=$((TIMEOUT - 1))
    if [ "$TIMEOUT" -le 0 ]; then
        kill "$RECORDER_PID" 2>/dev/null || true
        echo "FAIL: test_attach — recorder did not stop after target exited"
        exit 1
    fi
    sleep 1
done
wait "$RECORDER_PID" 2>/dev/null || true

# 3. Verify capture file exists and has content
cat "$WORKDIR/record.log"

if [ ! -f "$WORKDIR/capture.scmm-cap" ]; then
    echo "FAIL: test_attach — capture file not created"
    exit 1
fi

CAP_SIZE=$(stat -c%s "$WORKDIR/capture.scmm-cap")
if [ "$CAP_SIZE" -lt 100 ]; then
    echo "FAIL: test_attach — capture file too small ($CAP_SIZE bytes)"
    exit 1
fi

# 4. Extract policy (non-interactive)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files skip \
    -i "$WORKDIR/capture.scmm-cap" -o "$WORKDIR/policy.yaml" 2>"$WORKDIR/extract.log"

if [ ! -f "$WORKDIR/policy.yaml" ]; then
    echo "FAIL: test_attach — policy extraction failed"
    exit 1
fi

# 5. Verify the target actually ran
if [ ! -f "$OUTFILE" ]; then
    echo "FAIL: test_attach — target process output file missing"
    exit 1
fi

LINES=$(wc -l < "$OUTFILE")
if [ "$LINES" -lt 10 ]; then
    echo "FAIL: test_attach — target produced too few lines ($LINES)"
    exit 1
fi

# 6. Test error cases
# 6a. Non-existent PID should fail
if "$ROOT/target/release/scmm-record" -p 999999999 -o /dev/null 2>/dev/null; then
    echo "FAIL: test_attach — should reject non-existent PID"
    exit 1
fi

# 6b. Both --pid and command should fail
if "$ROOT/target/release/scmm-record" -p 1 -o /dev/null -- /bin/true 2>/dev/null; then
    echo "FAIL: test_attach — should reject --pid with command"
    exit 1
fi

# 6c. Neither --pid nor command should fail
if "$ROOT/target/release/scmm-record" -o /dev/null 2>/dev/null; then
    echo "FAIL: test_attach — should reject missing --pid and command"
    exit 1
fi

echo "PASS: test_attach"
