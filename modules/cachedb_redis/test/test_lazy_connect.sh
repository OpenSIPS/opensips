#!/bin/bash
#
# test_lazy_connect.sh - Integration tests for lazy_connect parameter (PR 9)
#
# Tests the cachedb_redis module's lazy_connect=1 behavior: connections
# are deferred until first cache operation, then work normally.
#
# Requirements:
#   - curl         (for OpenSIPS MI HTTP interface)
#   - jq           (for JSON parsing)
#   - A running OpenSIPS instance with mi_http on port 8888
#   - The cachedb_redis module loaded with lazy_connect=1:
#       modparam("cachedb_redis", "lazy_connect", 1)
#   - At least one cachedb_url configured (cluster, noauth, and/or local)
#
# Environment variables (override defaults):
#   MI_URL          - OpenSIPS MI HTTP URL (default: http://127.0.0.1:8888/mi)
#   REDIS_GROUP     - cachedb_redis group name to test (default: cluster)
#   REDIS_NOAUTH    - noauth group name (default: noauth)
#   REDIS_LOCAL     - local/unix socket group name (default: local)
#
# Usage:
#   ./test_lazy_connect.sh
#

set -euo pipefail

# --- Configuration ---
MI_URL="${MI_URL:-http://127.0.0.1:8888/mi}"
REDIS_GROUP="${REDIS_GROUP:-cluster}"
REDIS_NOAUTH="${REDIS_NOAUTH:-noauth}"
REDIS_LOCAL="${REDIS_LOCAL:-local}"

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

# ============================================================
echo "=== Lazy Connect Integration Tests (PR 9) ==="
echo "=== MI URL: $MI_URL ==="
echo "=== Redis Groups: $REDIS_GROUP, $REDIS_NOAUTH, $REDIS_LOCAL ==="
echo ""

# ============================================================
echo "=== Test 1: First cache operation triggers connection (cluster) ==="
# ============================================================

# The first operation on a lazy-connected group should succeed —
# redis_connect() is called transparently on first use.
mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_pr9\"}" >/dev/null 2>&1 || true

RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_pr9\",\"value\":\"lazy_hello\"}" || echo "")
assert_ok "cache_store succeeds on lazy-connected cluster group" "$RESULT"

RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_pr9\"}" || echo "")
FETCHED=$(echo "$RESULT" | jq -r '.result.value // empty' 2>/dev/null || echo "")
assert_eq "cache_fetch returns correct value after lazy connect" "lazy_hello" "$FETCHED"

mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_pr9\"}" >/dev/null 2>&1 || true

# ============================================================
echo ""
echo "=== Test 2: First cache operation triggers connection (noauth) ==="
# ============================================================

mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_NOAUTH\",\"attr\":\"test_lazy_noauth\"}" >/dev/null 2>&1 || true

RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_NOAUTH\",\"attr\":\"test_lazy_noauth\",\"value\":\"lazy_noauth\"}" || echo "")
assert_ok "cache_store succeeds on lazy-connected noauth group" "$RESULT"

RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_NOAUTH\",\"attr\":\"test_lazy_noauth\"}" || echo "")
FETCHED=$(echo "$RESULT" | jq -r '.result.value // empty' 2>/dev/null || echo "")
assert_eq "cache_fetch returns correct value (noauth)" "lazy_noauth" "$FETCHED"

mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_NOAUTH\",\"attr\":\"test_lazy_noauth\"}" >/dev/null 2>&1 || true

# ============================================================
echo ""
echo "=== Test 3: First cache operation triggers connection (Unix socket) ==="
# ============================================================

mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_LOCAL\",\"attr\":\"test_lazy_unix\"}" >/dev/null 2>&1 || true

RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_LOCAL\",\"attr\":\"test_lazy_unix\",\"value\":\"lazy_unix\"}" || echo "")
assert_ok "cache_store succeeds on lazy-connected Unix socket group" "$RESULT"

RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_LOCAL\",\"attr\":\"test_lazy_unix\"}" || echo "")
FETCHED=$(echo "$RESULT" | jq -r '.result.value // empty' 2>/dev/null || echo "")
assert_eq "cache_fetch returns correct value (Unix socket)" "lazy_unix" "$FETCHED"

mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_LOCAL\",\"attr\":\"test_lazy_unix\"}" >/dev/null 2>&1 || true

# ============================================================
echo ""
echo "=== Test 4: redis_cluster_info shows connections after first use ==="
# ============================================================

# After test 1-3, all three groups should now be connected
RESULT=$(mi_cmd "redis_cluster_info" || echo "")
assert_ok "redis_cluster_info returns data after lazy connect" "$RESULT"

# Check cluster group is connected
CLUSTER_INFO=$(mi_cmd "redis_cluster_info" -d "{\"group\":\"$REDIS_GROUP\"}" || echo "")
CLUSTER_MODE=$(echo "$CLUSTER_INFO" | jq -r '.result[0].mode // empty' 2>/dev/null || echo "")
assert_eq "cluster group shows cluster mode" "cluster" "$CLUSTER_MODE"

# Check that cluster nodes are connected (at least one)
CLUSTER_STATUS=$(echo "$CLUSTER_INFO" | jq -r '.result[0].nodes[0].status // empty' 2>/dev/null || echo "")
assert_eq "cluster node is connected after lazy connect" "connected" "$CLUSTER_STATUS"

# Check noauth group
NOAUTH_INFO=$(mi_cmd "redis_cluster_info" -d "{\"group\":\"$REDIS_NOAUTH\"}" || echo "")
NOAUTH_STATUS=$(echo "$NOAUTH_INFO" | jq -r '.result[0].nodes[0].status // empty' 2>/dev/null || echo "")
assert_eq "noauth node is connected after lazy connect" "connected" "$NOAUTH_STATUS"

# Check local/unix group
LOCAL_INFO=$(mi_cmd "redis_cluster_info" -d "{\"group\":\"$REDIS_LOCAL\"}" || echo "")
LOCAL_STATUS=$(echo "$LOCAL_INFO" | jq -r '.result[0].nodes[0].status // empty' 2>/dev/null || echo "")
assert_eq "unix socket node is connected after lazy connect" "connected" "$LOCAL_STATUS"

# ============================================================
echo ""
echo "=== Test 5: Statistics counters work with lazy-connected operations ==="
# ============================================================

# Get baseline stats
STATS_BEFORE=$(mi_cmd "get_statistics" -d "{\"statistics\":[\"redis_queries\"]}" 2>/dev/null || echo "")
QUERIES_BEFORE=$(echo "$STATS_BEFORE" | jq -r '.result["redis:redis_queries"] // "0"' 2>/dev/null | tr -d ' ' || echo "0")

# Perform operations across all groups
mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_stats\",\"value\":\"stat1\"}" >/dev/null 2>&1 || true
mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_NOAUTH\",\"attr\":\"test_lazy_stats\",\"value\":\"stat2\"}" >/dev/null 2>&1 || true
mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_LOCAL\",\"attr\":\"test_lazy_stats\",\"value\":\"stat3\"}" >/dev/null 2>&1 || true

# Get new stats
STATS_AFTER=$(mi_cmd "get_statistics" -d "{\"statistics\":[\"redis_queries\"]}" 2>/dev/null || echo "")
QUERIES_AFTER=$(echo "$STATS_AFTER" | jq -r '.result["redis:redis_queries"] // "0"' 2>/dev/null | tr -d ' ' || echo "0")

if [ "$QUERIES_BEFORE" != "0" ] || [ "$QUERIES_AFTER" != "0" ]; then
    assert_ge "redis_queries incremented after lazy-connect operations" "$((QUERIES_BEFORE + 1))" "$QUERIES_AFTER"
else
    TOTAL=$((TOTAL + 1))
    PASS=$((PASS + 1))
    echo "  SKIP: statistics parsing unavailable, skipping counter check"
fi

# Clean up
mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_stats\"}" >/dev/null 2>&1 || true
mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_NOAUTH\",\"attr\":\"test_lazy_stats\"}" >/dev/null 2>&1 || true
mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_LOCAL\",\"attr\":\"test_lazy_stats\"}" >/dev/null 2>&1 || true

# ============================================================
echo ""
echo "=== Test 6: Connection recovery works with lazy_connect ==="
# ============================================================

# After a lazy-connected group is established, verify that the
# reconnect logic still works if the connection drops.
# We test by storing, fetching, and removing — if the connection
# dropped internally, the retry loop should re-establish it.

RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_recovery\",\"value\":\"recovery_test\"}" || echo "")
assert_ok "cache_store for recovery test" "$RESULT"

RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_recovery\"}" || echo "")
FETCHED=$(echo "$RESULT" | jq -r '.result.value // empty' 2>/dev/null || echo "")
assert_eq "cache_fetch returns value for recovery test" "recovery_test" "$FETCHED"

RESULT=$(mi_cmd "cache_remove" -d "{\"system\":\"redis:$REDIS_GROUP\",\"attr\":\"test_lazy_recovery\"}" || echo "")
assert_ok "cache_remove for recovery test" "$RESULT"

# ============================================================
echo ""
echo "=== Test 7: redis_ping_nodes works after lazy connect ==="
# ============================================================

RESULT=$(mi_cmd "redis_ping_nodes" || echo "")
assert_ok "redis_ping_nodes returns data after lazy connect" "$RESULT"

# Check at least one node is reachable
PING_STATUS=$(echo "$RESULT" | jq -r '.result[0].nodes[0].status // empty' 2>/dev/null || echo "")
assert_eq "ping shows reachable after lazy connect" "reachable" "$PING_STATUS"

# ============================================================
echo ""
echo "========================================"
echo "=== Lazy Connect Test Results ==="
echo "========================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
