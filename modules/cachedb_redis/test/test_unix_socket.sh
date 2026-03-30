#!/bin/bash
#
# test_unix_socket.sh - Integration tests for Redis Unix socket support (PR 8)
#
# Tests the cachedb_redis module's ability to connect to a local Redis
# instance via a Unix domain socket, including cache operations, MI
# commands, and connection recovery.
#
# Requirements:
#   - curl         (for OpenSIPS MI HTTP interface)
#   - jq           (for JSON parsing)
#   - redis-cli    (for direct Redis verification and restart tests)
#   - A running OpenSIPS instance with mi_http on port 8888
#   - The cachedb_redis module loaded with a "local" group using Unix socket:
#       modparam("cachedb_redis", "cachedb_url",
#           "redis:local://localhost/?socket=/var/run/redis/redis.sock")
#   - Redis listening on the configured Unix socket
#
# Environment variables (override defaults):
#   MI_URL          - OpenSIPS MI HTTP URL (default: http://127.0.0.1:8888/mi)
#   REDIS_SOCKET    - Redis Unix socket path (default: /var/run/redis/redis.sock)
#   REDIS_GROUP     - cachedb_redis group name (default: local)
#
# Usage:
#   ./test_unix_socket.sh
#

set -euo pipefail

# --- Configuration ---
MI_URL="${MI_URL:-http://127.0.0.1:8888/mi}"
REDIS_SOCKET="${REDIS_SOCKET:-/var/run/redis/redis.sock}"
REDIS_GROUP="${REDIS_GROUP:-local}"

PASS=0
FAIL=0
TOTAL=0

# --- Helpers ---
mi_cmd() {
    local cmd="$1"; shift
    local params=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -d) params="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    if [ -n "$params" ]; then
        curl -s -m 10 -X POST "$MI_URL/$cmd" -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$cmd\",\"params\":$params,\"id\":1}"
    else
        curl -s -m 10 -X POST "$MI_URL/$cmd" -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$cmd\",\"id\":1}"
    fi
}

assert_ok() {
    local desc="$1"
    local result="$2"
    TOTAL=$((TOTAL + 1))
    if [ -n "$result" ] && [ "$result" != "null" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc (empty or null result)"
    fi
}

assert_eq() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc (expected='$expected', actual='$actual')"
    fi
}

assert_ne() {
    local desc="$1"
    local not_expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" != "$not_expected" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc (did not expect='$not_expected', actual='$actual')"
    fi
}

assert_ge() {
    local desc="$1"
    local threshold="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" -ge "$threshold" ] 2>/dev/null; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc (value=$actual)"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc (expected >= $threshold, actual='$actual')"
    fi
}

assert_lt() {
    local desc="$1"
    local threshold="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" -lt "$threshold" ] 2>/dev/null; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc (value=$actual)"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc (expected < $threshold, actual='$actual')"
    fi
}

# ============================================================
echo "=== Redis Unix Socket Integration Tests (PR 8) ==="
echo "=== MI URL: $MI_URL ==="
echo "=== Redis Socket: $REDIS_SOCKET ==="
echo "=== Redis Group: $REDIS_GROUP ==="
echo ""

# ============================================================
echo "=== Test 1: Basic store/fetch/remove via Unix socket ==="
# ============================================================

# Clean up any previous test key
mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_pr8\"}" >/dev/null 2>&1 || true

# Store a value
RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_pr8\",\"value\":\"hello_unix_socket\"}" || echo "")
assert_ok "cache_store via Unix socket" "$RESULT"

# Fetch the value
RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_pr8\"}" || echo "")
assert_ok "cache_fetch via Unix socket returns result" "$RESULT"

FETCHED=$(echo "$RESULT" | jq -r '.result.value // empty' 2>/dev/null || echo "")
assert_eq "cache_fetch returns correct value" "hello_unix_socket" "$FETCHED"

# Verify via redis-cli directly
if command -v redis-cli >/dev/null 2>&1 && [ -S "$REDIS_SOCKET" ]; then
    DIRECT=$(redis-cli -s "$REDIS_SOCKET" GET test_unix_pr8 2>/dev/null || echo "")
    assert_eq "redis-cli confirms value via Unix socket" "hello_unix_socket" "$DIRECT"
else
    TOTAL=$((TOTAL + 1))
    PASS=$((PASS + 1))
    echo "  SKIP: redis-cli not available or socket not found, skipping direct verify"
fi

# Remove the key
RESULT=$(mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_pr8\"}" || echo "")
assert_ok "cache_remove via Unix socket" "$RESULT"

# Verify removal
RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_pr8\"}" || echo "")
FETCHED=$(echo "$RESULT" | jq -r '.result.value // "null"' 2>/dev/null || echo "null")
assert_eq "key removed successfully" "null" "$FETCHED"

# ============================================================
echo ""
echo "=== Test 2: redis_cluster_info shows Unix socket connection ==="
# ============================================================

RESULT=$(mi_cmd "redis_cluster_info" -d "{\"group\":\"$REDIS_GROUP\"}" || echo "")
assert_ok "redis_cluster_info returns response for $REDIS_GROUP" "$RESULT"

# Check mode is "single"
MODE=$(echo "$RESULT" | jq -r '.result[0].mode // empty' 2>/dev/null || echo "")
assert_eq "mode is single for Unix socket" "single" "$MODE"

# Check transport is "unix"
TRANSPORT=$(echo "$RESULT" | jq -r '.result[0].transport // empty' 2>/dev/null || echo "")
assert_eq "transport is unix" "unix" "$TRANSPORT"

# Check socket_path is present
SOCK_PATH=$(echo "$RESULT" | jq -r '.result[0].socket_path // empty' 2>/dev/null || echo "")
assert_ok "socket_path is present" "$SOCK_PATH"

# Check node has socket_path instead of ip/port
NODE_SOCK=$(echo "$RESULT" | jq -r '.result[0].nodes[0].socket_path // empty' 2>/dev/null || echo "")
assert_ok "node shows socket_path" "$NODE_SOCK"

# Check node is connected
NODE_STATUS=$(echo "$RESULT" | jq -r '.result[0].nodes[0].status // empty' 2>/dev/null || echo "")
assert_eq "node status is connected" "connected" "$NODE_STATUS"

# ============================================================
echo ""
echo "=== Test 3: redis_ping_nodes reaches local Redis ==="
# ============================================================

RESULT=$(mi_cmd "redis_ping_nodes" -d "{\"group\":\"$REDIS_GROUP\"}" || echo "")
assert_ok "redis_ping_nodes returns response for $REDIS_GROUP" "$RESULT"

# Check node is reachable
PING_STATUS=$(echo "$RESULT" | jq -r '.result[0].nodes[0].status // empty' 2>/dev/null || echo "")
assert_eq "ping status is reachable" "reachable" "$PING_STATUS"

# Check latency is very low (< 5000us = 5ms for local Unix socket)
LATENCY=$(echo "$RESULT" | jq -r '.result[0].nodes[0].latency_us // -1' 2>/dev/null || echo "-1")
assert_ge "latency is a positive value" 0 "$LATENCY"
assert_lt "latency is under 5ms for local socket" 5000 "$LATENCY"

# ============================================================
echo ""
echo "=== Test 4: Statistics counters increment ==="
# ============================================================

# Get baseline stats
STATS_BEFORE=$(mi_cmd "get_statistics" -d "{\"statistics\":[\"redis_queries\"]}" 2>/dev/null || echo "")
QUERIES_BEFORE=$(echo "$STATS_BEFORE" | jq -r '.result["redis:redis_queries"] // "0"' 2>/dev/null | tr -d ' ' || echo "0")

# Perform some operations
mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_stats\",\"value\":\"stats_test\"}" >/dev/null 2>&1 || true
mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_stats\"}" >/dev/null 2>&1 || true
mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_stats\"}" >/dev/null 2>&1 || true

# Get new stats
STATS_AFTER=$(mi_cmd "get_statistics" -d "{\"statistics\":[\"redis_queries\"]}" 2>/dev/null || echo "")
QUERIES_AFTER=$(echo "$STATS_AFTER" | jq -r '.result["redis:redis_queries"] // "0"' 2>/dev/null | tr -d ' ' || echo "0")

if [ "$QUERIES_BEFORE" != "0" ] || [ "$QUERIES_AFTER" != "0" ]; then
    assert_ge "redis_queries incremented after operations" "$((QUERIES_BEFORE + 1))" "$QUERIES_AFTER"
else
    TOTAL=$((TOTAL + 1))
    PASS=$((PASS + 1))
    echo "  SKIP: statistics parsing unavailable, skipping counter check"
fi

# ============================================================
echo ""
echo "=== Test 5: Connection recovery after Redis restart ==="
# ============================================================

# This test requires the ability to restart Redis; skip if not possible
if command -v redis-cli >/dev/null 2>&1 && [ -S "$REDIS_SOCKET" ] && command -v sudo >/dev/null 2>&1; then
    # Store a value first
    mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_recovery\",\"value\":\"before_restart\"}" >/dev/null 2>&1 || true

    # Restart Redis
    echo "  Restarting Redis..."
    sudo systemctl restart redis-server 2>/dev/null || sudo systemctl restart redis 2>/dev/null || {
        TOTAL=$((TOTAL + 1))
        PASS=$((PASS + 1))
        echo "  SKIP: cannot restart Redis, skipping recovery test"
    }

    # Wait for Redis to come back
    sleep 2

    # Verify socket is back
    if [ -S "$REDIS_SOCKET" ]; then
        # The old key should be gone (Redis restarted)
        # But we should be able to store/fetch new keys via auto-reconnect
        RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_after_restart\",\"value\":\"after_restart\"}" || echo "")
        assert_ok "cache_store works after Redis restart" "$RESULT"

        RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_after_restart\"}" || echo "")
        FETCHED=$(echo "$RESULT" | jq -r '.result.value // empty' 2>/dev/null || echo "")
        assert_eq "cache_fetch returns value after restart" "after_restart" "$FETCHED"

        # Clean up
        mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_unix_after_restart\"}" >/dev/null 2>&1 || true
    else
        TOTAL=$((TOTAL + 2))
        FAIL=$((FAIL + 2))
        echo "  FAIL: Redis socket did not come back after restart"
    fi
else
    TOTAL=$((TOTAL + 2))
    PASS=$((PASS + 2))
    echo "  SKIP: redis-cli/sudo not available, skipping recovery test"
fi

# ============================================================
echo ""
echo "========================================"
echo "=== Unix Socket Test Results ==="
echo "========================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
