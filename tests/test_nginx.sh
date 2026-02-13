#!/usr/bin/env bash
# Test: compile and enforce nginx, verify Landlock restricts /noaccess
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
NGINX_DIR="$ROOT/sandboxes/nginx"
WORKDIR="$SCRIPT_DIR/out_nginx"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

trap '[ -n "${NGINX_PID:-}" ] && kill "$NGINX_PID" 2>/dev/null || true' EXIT

POLICY_YAML="$NGINX_DIR/nginx.policy.yaml"

echo "=== test_nginx ==="

if [ ! -f "$POLICY_YAML" ]; then
    echo "SKIP: test_nginx — $POLICY_YAML not found"
    exit 0
fi

if ! command -v nginx >/dev/null 2>&1; then
    echo "SKIP: test_nginx — nginx not installed"
    exit 0
fi

# 1. Compile
"$ROOT/target/release/scmm-compile" -i "$POLICY_YAML" -o "$WORKDIR/nginx.pol" >/dev/null 2>&1

# 2. Enforce in background (nginx runs in foreground with daemon off)
"$ROOT/target/release/scmm-enforce" -p "$WORKDIR/nginx.pol" -- \
    nginx -p "$NGINX_DIR" -c "$NGINX_DIR/nginx.conf" &
NGINX_PID=$!

# Wait for nginx to start listening
for i in $(seq 1 30); do
    if curl -s -o /dev/null http://localhost:8080/ 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# 3. Verify: index.html should be reachable
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/index.html)
if [ "$HTTP_CODE" != "200" ]; then
    echo "FAIL: test_nginx — GET /index.html returned $HTTP_CODE, expected 200"
    kill "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

# 4. Verify: /noaccess should be 403 (Landlock denies access to that directory)
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/noaccess/)
if [ "$HTTP_CODE" != "403" ]; then
    echo "FAIL: test_nginx — GET /noaccess/ returned $HTTP_CODE, expected 403"
    kill "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

# Cleanup
kill "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null || true

echo "PASS: test_nginx"
