#!/usr/bin/env bash
# Run all SCMM integration tests and report results
#
# Usage:
#   ./run_all.sh              Run all tests
#   ./run_all.sh --skip-local Skip tests marked "# local_only"
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKIP_LOCAL=false

for arg in "$@"; do
    case "$arg" in
        --skip-local) SKIP_LOCAL=true ;;
    esac
done

PASSED=0
FAILED=0
SKIPPED=0

run_test() {
    local test_script="$1"
    local name
    name=$(basename "$test_script" .sh)

    # Check for local_only marker
    if $SKIP_LOCAL && head -5 "$test_script" | grep -q '^# local_only'; then
        echo "  SKIP  $name (local_only)"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

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
