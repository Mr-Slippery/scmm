#!/usr/bin/env bash
# Test: default --missing-files (skip) filters noisy PATH-lookup misses from
# extraction and excludes failed read-only accesses while keeping create-intent
# paths.  Also tests --created-files parentdir for enforcement.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
WORKDIR="$SCRIPT_DIR/out_exclude_failed"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

TESTFILE="$WORKDIR/testfile"
MISSINGFILE="$WORKDIR/does_not_exist"

echo "=== test_exclude_failed ==="

# ── Part 1: touch (create-intent path should survive filtering) ──

CMD_TOUCH="touch $TESTFILE"

# Ensure at least one failed PATH lookup so the test works even with minimal PATH
export PATH="/nonexistent/bin:$PATH"

# Record touch
"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/cap_touch.scmm-cap" -- $CMD_TOUCH >/dev/null 2>&1

# Extract with --missing-files precreate (includes all-failed paths)
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files precreate \
    -i "$WORKDIR/cap_touch.scmm-cap" -o "$WORKDIR/policy_all.yaml" >/dev/null 2>&1

# Extract with default --missing-files (skip: excludes all-failed read-only paths)
# and --created-files parentdir so the enforcement test is meaningful
"$ROOT/target/release/scmm-extract" --non-interactive --created-files parentdir \
    -i "$WORKDIR/cap_touch.scmm-cap" -o "$WORKDIR/policy_filtered.yaml" >/dev/null 2>&1

# Filtered policy should have fewer rules (PATH lookups removed)
count_rules() {
    grep -c '^ *- path:' "$1"
}

RULES_ALL=$(count_rules "$WORKDIR/policy_all.yaml")
RULES_FILTERED=$(count_rules "$WORKDIR/policy_filtered.yaml")

if [ "$RULES_FILTERED" -ge "$RULES_ALL" ]; then
    echo "FAIL: touch — expected fewer rules with default missing-files ($RULES_FILTERED >= $RULES_ALL)"
    exit 1
fi

# The created file must still be in the filtered policy (create intent via O_CREAT)
if ! grep -q "$TESTFILE" "$WORKDIR/policy_filtered.yaml"; then
    echo "FAIL: touch — filtered policy is missing the created file $TESTFILE"
    exit 1
fi

# Compile and enforce the filtered policy
"$ROOT/target/release/scmm-compile" -i "$WORKDIR/policy_filtered.yaml" \
    -o "$WORKDIR/policy_filtered.pol" >/dev/null 2>&1

rm -f "$TESTFILE"

if ! "$ROOT/target/release/scmm-enforce" -p "$WORKDIR/policy_filtered.pol" -- $CMD_TOUCH 2>/dev/null; then
    echo "FAIL: touch — enforce with filtered policy failed"
    exit 1
fi

if [ ! -f "$TESTFILE" ]; then
    echo "FAIL: touch — file was not created under filtered policy"
    exit 1
fi

# ── Part 2: cat on nonexistent file (failed read should be excluded) ──

# cat will fail but we still record the attempt
CMD_CAT="cat $MISSINGFILE"

"$ROOT/target/release/scmm-record" -f -o "$WORKDIR/cap_cat.scmm-cap" -- $CMD_CAT >/dev/null 2>&1 || true

# Extract with default --missing-files (skip: excludes all-failed read-only paths)
"$ROOT/target/release/scmm-extract" --non-interactive \
    -i "$WORKDIR/cap_cat.scmm-cap" -o "$WORKDIR/policy_cat_filtered.yaml" >/dev/null 2>&1

# The nonexistent file must NOT appear as a filesystem rule in the filtered policy
# (pure failed read, no create intent). Match on "- path:" to avoid hitting metadata.
if grep -q "path: $MISSINGFILE" "$WORKDIR/policy_cat_filtered.yaml"; then
    echo "FAIL: cat — filtered policy should not contain rule for $MISSINGFILE (failed read, no create intent)"
    exit 1
fi

# With --missing-files precreate it SHOULD appear as a filesystem rule
"$ROOT/target/release/scmm-extract" --non-interactive --missing-files precreate \
    -i "$WORKDIR/cap_cat.scmm-cap" -o "$WORKDIR/policy_cat_all.yaml" >/dev/null 2>&1

if ! grep -q "path: $MISSINGFILE" "$WORKDIR/policy_cat_all.yaml"; then
    echo "FAIL: cat — precreate policy should contain rule for $MISSINGFILE"
    exit 1
fi

echo "PASS: test_exclude_failed (touch: all=$RULES_ALL filtered=$RULES_FILTERED, cat: missing file correctly excluded)"
