#!/usr/bin/env bash
# local_only
# Test: record nginx with strace, extract+compile policy, enforce,
#       verify Landlock restricts /noaccess while allowing /index.html
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
NGINX_DIR="$ROOT/sandboxes/nginx"
PORT=8080

cleanup() {
    # Kill nginx first (via PID file), then strace will exit on its own
    [ -f "$NGINX_DIR/run/nginx.pid" ] && kill "$(cat "$NGINX_DIR/run/nginx.pid")" 2>/dev/null || true
    [ -n "${STRACE_PID:-}" ] && wait "$STRACE_PID" 2>/dev/null || true
    [ -n "${ENFORCE_PID:-}" ] && kill "$ENFORCE_PID" 2>/dev/null || true
    [ -n "${ENFORCE_PID:-}" ] && wait "$ENFORCE_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== test_nginx ==="

if ! command -v nginx >/dev/null 2>&1; then
    echo "SKIP: test_nginx — nginx not installed"
    exit 0
fi

# Clean up from previous runs
rm -f "$NGINX_DIR/run/nginx.pid" "$NGINX_DIR/logs/access.log" "$NGINX_DIR/logs/error.log"
rm -f "$NGINX_DIR/strace-capture.log" "$NGINX_DIR/policy.yaml" "$NGINX_DIR/policy.scmm-pol"

# 1. Record nginx startup + a request using strace
strace -f -o "$NGINX_DIR/strace-capture.log" -s 1500 -- \
    nginx -p "$NGINX_DIR" -c conf/nginx.conf &
STRACE_PID=$!

for _ in $(seq 1 30); do
    if curl -s -o /dev/null "http://localhost:$PORT/" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

curl -s -o /dev/null "http://localhost:$PORT/index.html"

# Stop nginx via its PID file (strace -f traces children, so killing strace
# itself can hang while it waits for traced children to exit)
if [ -f "$NGINX_DIR/run/nginx.pid" ]; then
    kill "$(cat "$NGINX_DIR/run/nginx.pid")" 2>/dev/null || true
fi
wait "$STRACE_PID" 2>/dev/null || true
STRACE_PID=""

# 2. Extract + compile
"$ROOT/target/release/scmm-extract" \
    -i "$NGINX_DIR/strace-capture.log" -o "$NGINX_DIR/policy.yaml" \
    --missing-files skip --created-files parentdir \
    --non-interactive >/dev/null 2>&1

"$ROOT/target/release/scmm-compile" \
    -i "$NGINX_DIR/policy.yaml" -o "$NGINX_DIR/policy.scmm-pol" >/dev/null 2>&1

# 3. Enforce
rm -f "$NGINX_DIR/run/nginx.pid" "$NGINX_DIR/logs/access.log" "$NGINX_DIR/logs/error.log"

"$ROOT/target/release/scmm-enforce" -p "$NGINX_DIR/policy.scmm-pol" -- \
    nginx -p "$NGINX_DIR" -c conf/nginx.conf &
ENFORCE_PID=$!

for _ in $(seq 1 30); do
    if curl -s -o /dev/null "http://localhost:$PORT/" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# 4. Verify: index.html should be reachable
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/index.html")
if [ "$HTTP_CODE" != "200" ]; then
    echo "FAIL: test_nginx — GET /index.html returned $HTTP_CODE, expected 200"
    exit 1
fi

# 5. Verify: /noaccess should be 403 (Landlock denies read access)
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/noaccess/")
if [ "$HTTP_CODE" != "403" ]; then
    echo "FAIL: test_nginx — GET /noaccess/ returned $HTTP_CODE, expected 403"
    exit 1
fi

echo "PASS: test_nginx"
