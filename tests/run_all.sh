#!/usr/bin/env bash
# Run all SCMM integration tests and report results
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PASSED=0
FAILED=0
SKIPPED=0

run_test() {
    local test_script="$1"
    local name
    name=$(basename "$test_script" .sh)

    if output=$(bash "$test_script" 2>&1); then
        if echo "$output" | grep -q "^SKIP:"; then
            echo "  SKIP  $name"
            SKIPPED=$((SKIPPED + 1))
        else
            echo "  PASS  $name"
            PASSED=$((PASSED + 1))
        fi
    else
        echo "  FAIL  $name"
        echo "$output" | sed 's/^/        /'
        FAILED=$((FAILED + 1))
    fi
}

echo "SCMM Integration Tests"
echo "======================"
echo

for test_script in "$SCRIPT_DIR"/test_*.sh; do
    run_test "$test_script"
done

echo
echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
