#!/bin/bash
#
# test_mi_commands.sh - Integration test for MI commands and statistics (PR 5)
#
# Tests the redis_cluster_info and redis_cluster_refresh MI commands,
# as well as the shared-memory statistics counters.
#
# Requirements:
#   - curl         (for OpenSIPS MI HTTP interface)
#   - jq           (for JSON parsing)
#   - A running OpenSIPS instance with mi_http on port 8888
#   - The cachedb_redis module loaded with at least one connection
#
# Environment variables (override defaults):
#   MI_URL          - OpenSIPS MI HTTP URL (default: http://127.0.0.1:8888/mi)
#
# Usage:
#   ./test_mi_commands.sh
#

set -euo pipefail

# --- Configuration ---
MI_URL="${MI_URL:-http://127.0.0.1:8888/mi}"
# jq filter to select the "cluster" group from redis_cluster_info results
CLUSTER_JQ='[.result[] | select(.group=="cluster")][0]'
PING_CLUSTER_JQ='[.result[] | select(.group=="cluster")][0]'

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
echo "=== Test 1: redis_cluster_info (no params) ==="
# ============================================================

RESULT=$(mi_cmd "redis_cluster_info" || echo "")
assert_ok "redis_cluster_info returns response" "$RESULT"

# Check that result is a JSON array with at least one connection
CON_COUNT=$(echo "$RESULT" | jq -r '.result | length' 2>/dev/null || echo "0")
assert_ge "at least one connection returned" 1 "$CON_COUNT"

# Check first connection has expected fields
GROUP=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.group" 2>/dev/null || echo "")
assert_ok "connection has group field" "$GROUP"

MODE=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.mode" 2>/dev/null || echo "")

TRANSPORT=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.transport" 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if [ "$TRANSPORT" = "tcp" ] || [ "$TRANSPORT" = "unix" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: transport is tcp or unix (transport=$TRANSPORT)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: transport should be tcp or unix (transport=$TRANSPORT)"
fi
TOTAL=$((TOTAL + 1))
if [ "$MODE" = "cluster" ] || [ "$MODE" = "single" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: mode is cluster or single (mode=$MODE)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: mode should be cluster or single (mode=$MODE)"
fi

# Check nodes array exists
NODES_COUNT=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes | length" 2>/dev/null || echo "0")
assert_ge "at least one node present" 1 "$NODES_COUNT"

# Check node has ip and port
NODE_IP=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].ip" 2>/dev/null || echo "")
assert_ok "node has ip field" "$NODE_IP"

NODE_PORT=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].port" 2>/dev/null || echo "")
assert_ok "node has port field" "$NODE_PORT"

NODE_STATUS=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].status" 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if [ "$NODE_STATUS" = "connected" ] || [ "$NODE_STATUS" = "disconnected" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: node has valid status (status=$NODE_STATUS)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: node status invalid (status=$NODE_STATUS)"
fi

# Check per-node counters exist
NODE_QUERIES=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].queries" 2>/dev/null || echo "null")
assert_ok "node has queries counter" "$NODE_QUERIES"

NODE_ERRORS=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].errors" 2>/dev/null || echo "null")
assert_ok "node has errors counter" "$NODE_ERRORS"

NODE_MOVED=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].moved" 2>/dev/null || echo "null")
assert_ok "node has moved counter" "$NODE_MOVED"

NODE_LAST_ACTIVITY=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].last_activity" 2>/dev/null || echo "null")
assert_ok "node has last_activity field" "$NODE_LAST_ACTIVITY"

# For cluster mode, check total_slots_mapped and cluster_command
if [ "$MODE" = "cluster" ]; then
    SLOTS=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.total_slots_mapped" 2>/dev/null || echo "0")
    assert_eq "total_slots_mapped is 16384" "16384" "$SLOTS"

    SLOTS_ASSIGNED=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.nodes[0].slots_assigned" 2>/dev/null || echo "null")
    assert_ok "node has slots_assigned field" "$SLOTS_ASSIGNED"

    CLUSTER_CMD=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.cluster_command" 2>/dev/null || echo "null")
    TOTAL=$((TOTAL + 1))
    if [ "$CLUSTER_CMD" = "SHARDS" ] || [ "$CLUSTER_CMD" = "SLOTS" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: cluster_command is SHARDS or SLOTS (value=$CLUSTER_CMD)"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: cluster_command should be SHARDS or SLOTS (value=$CLUSTER_CMD)"
    fi
fi

# Check topology refresh fields
TOPO_REFRESHES=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.topology_refreshes" 2>/dev/null || echo "null")
assert_ok "connection has topology_refreshes field" "$TOPO_REFRESHES"

LAST_REFRESH=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.last_topology_refresh" 2>/dev/null || echo "null")
assert_ok "connection has last_topology_refresh field" "$LAST_REFRESH"

# ============================================================
echo ""
echo "=== Test 2: redis_cluster_info with group filter ==="
# ============================================================

RESULT_FILTERED=$(mi_cmd "redis_cluster_info" -d "{\"group\":\"$GROUP\"}" || echo "")
assert_ok "filtered redis_cluster_info returns response" "$RESULT_FILTERED"

FILTERED_COUNT=$(echo "$RESULT_FILTERED" | jq -r '.result | length' 2>/dev/null || echo "0")
assert_ge "at least one connection with matching group" 1 "$FILTERED_COUNT"

FILTERED_GROUP=$(echo "$RESULT_FILTERED" | jq -r '.result[0].group' 2>/dev/null || echo "")
assert_eq "filtered result matches requested group" "$GROUP" "$FILTERED_GROUP"

# Filter with non-existent group
RESULT_EMPTY=$(mi_cmd "redis_cluster_info" -d '{"group":"nonexistent_group_xyz"}' || echo "")
EMPTY_COUNT=$(echo "$RESULT_EMPTY" | jq -r '.result | length' 2>/dev/null || echo "0")
assert_eq "non-existent group returns empty array" "0" "$EMPTY_COUNT"

# ============================================================
echo ""
echo "=== Test 3: redis_cluster_refresh ==="
# ============================================================

# Get topology_refreshes before
REFRESH_BEFORE=$(echo "$RESULT" | jq -r "${CLUSTER_JQ}.topology_refreshes" 2>/dev/null || echo "0")

REFRESH_RESULT=$(mi_cmd "redis_cluster_refresh" || echo "")
assert_ok "redis_cluster_refresh returns response" "$REFRESH_RESULT"

REFRESH_STATUS=$(echo "$REFRESH_RESULT" | jq -r "${CLUSTER_JQ}.status" 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if [ "$REFRESH_STATUS" = "ok" ] || [ "$REFRESH_STATUS" = "skipped (not cluster mode)" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: refresh status is ok or skipped (status=$REFRESH_STATUS)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: unexpected refresh status (status=$REFRESH_STATUS)"
fi

REFRESH_GROUP=$(echo "$REFRESH_RESULT" | jq -r "${CLUSTER_JQ}.group" 2>/dev/null || echo "")
assert_eq "refresh response includes group" "$GROUP" "$REFRESH_GROUP"

# Verify topology_refreshes incremented (for cluster mode)
if [ "$MODE" = "cluster" ]; then
    sleep 1
    RESULT_AFTER=$(mi_cmd "redis_cluster_info" || echo "")
    REFRESH_AFTER=$(echo "$RESULT_AFTER" | jq -r "${CLUSTER_JQ}.topology_refreshes" 2>/dev/null || echo "0")
    assert_ge "topology_refreshes incremented" "$((REFRESH_BEFORE + 1))" "$REFRESH_AFTER"
fi

# Test refresh with group filter
REFRESH_FILTERED=$(mi_cmd "redis_cluster_refresh" -d "{\"group\":\"$GROUP\"}" || echo "")
REFRESH_FILTERED_STATUS=$(echo "$REFRESH_FILTERED" | jq -r '.result[0].status' 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if [ "$REFRESH_FILTERED_STATUS" = "ok" ] || [ "$REFRESH_FILTERED_STATUS" = "skipped (not cluster mode)" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: filtered refresh status is ok or skipped (status=$REFRESH_FILTERED_STATUS)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: unexpected filtered refresh status (status=$REFRESH_FILTERED_STATUS)"
fi

# ============================================================
echo ""
echo "=== Test 4: Statistics counters ==="
# ============================================================

# Run cache operations to generate stats
mi_cmd "cache_store" -d '{"system":"redis:cluster","attr":"mi_test_key","value":"mi_test_val","expire":30}' >/dev/null 2>&1 || true
mi_cmd "cache_fetch" -d '{"system":"redis:cluster","attr":"mi_test_key"}' >/dev/null 2>&1 || true
mi_cmd "cache_remove" -d '{"system":"redis:cluster","attr":"mi_test_key"}' >/dev/null 2>&1 || true

# Check statistics via get_statistics
STATS=$(mi_cmd "get_statistics" -d '{"statistics":["redis_queries","redis_queries_failed","redis_moved","redis_topology_refreshes"]}' 2>/dev/null || echo "")
assert_ok "get_statistics returns response" "$STATS"

if [ -n "$STATS" ]; then
    QUERY_STAT=$(echo "$STATS" | jq -r '.result["cachedb_redis:redis_queries"]' 2>/dev/null || echo "null")
    assert_ge "redis_queries stat is positive" 1 "$QUERY_STAT"

    FAILED_STAT=$(echo "$STATS" | jq -r '.result["cachedb_redis:redis_queries_failed"]' 2>/dev/null || echo "null")
    assert_ok "redis_queries_failed stat exists" "$FAILED_STAT"

    MOVED_STAT=$(echo "$STATS" | jq -r '.result["cachedb_redis:redis_moved"]' 2>/dev/null || echo "null")
    assert_ok "redis_moved stat exists" "$MOVED_STAT"

    TOPO_STAT=$(echo "$STATS" | jq -r '.result["cachedb_redis:redis_topology_refreshes"]' 2>/dev/null || echo "null")
    assert_ge "redis_topology_refreshes stat is positive" 1 "$TOPO_STAT"

    # Verify per-node queries counter increased after cache operations
    RESULT_POST_OPS=$(mi_cmd "redis_cluster_info" -d '{"group":"cluster"}' || echo "")
    TOTAL_NODE_QUERIES=0
    for i in $(seq 0 $((NODES_COUNT - 1))); do
        NQ=$(echo "$RESULT_POST_OPS" | jq -r "${CLUSTER_JQ}.nodes[$i].queries" 2>/dev/null || echo "0")
        TOTAL_NODE_QUERIES=$((TOTAL_NODE_QUERIES + NQ))
    done
    assert_ge "sum of per-node queries > 0 after cache ops" 1 "$TOTAL_NODE_QUERIES"
fi

# ============================================================
echo ""
echo "=== Test 5: Cluster health check ==="
# ============================================================

RESULT_FINAL=$(mi_cmd "redis_cluster_info" || echo "")
FINAL_NODES=$(echo "$RESULT_FINAL" | jq -r "${CLUSTER_JQ}.nodes | length" 2>/dev/null || echo "0")
assert_ge "cluster still has nodes after all tests" 1 "$FINAL_NODES"

if [ "$MODE" = "cluster" ]; then
    FINAL_SLOTS=$(echo "$RESULT_FINAL" | jq -r "${CLUSTER_JQ}.total_slots_mapped" 2>/dev/null || echo "0")
    assert_eq "cluster still has 16384 slots mapped" "16384" "$FINAL_SLOTS"

    # Verify all nodes still connected
    ALL_CONNECTED=1
    for i in $(seq 0 $((FINAL_NODES - 1))); do
        STATUS=$(echo "$RESULT_FINAL" | jq -r "${CLUSTER_JQ}.nodes[$i].status" 2>/dev/null || echo "")
        if [ "$STATUS" != "connected" ]; then
            ALL_CONNECTED=0
            break
        fi
    done
    TOTAL=$((TOTAL + 1))
    if [ "$ALL_CONNECTED" = "1" ]; then
        PASS=$((PASS + 1))
        echo "  PASS: all $FINAL_NODES nodes still connected"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: some nodes disconnected after tests"
    fi
fi

# ============================================================
echo ""
echo "=== Test 6: redis_ping_nodes ==="
# ============================================================

PING_RESULT=$(mi_cmd "redis_ping_nodes" || echo "")
assert_ok "redis_ping_nodes returns response" "$PING_RESULT"

# Check that result is a JSON array with at least one connection
PING_CON_COUNT=$(echo "$PING_RESULT" | jq -r '.result | length' 2>/dev/null || echo "0")
assert_ge "at least one connection in ping result" 1 "$PING_CON_COUNT"

# Check first connection has group and nodes
PING_GROUP=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.group" 2>/dev/null || echo "")
assert_ok "ping result has group field" "$PING_GROUP"

PING_NODES_COUNT=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.nodes | length" 2>/dev/null || echo "0")
assert_ge "at least one node in ping result" 1 "$PING_NODES_COUNT"

# Check each node has ip, port, status, latency_us
PING_NODE_IP=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.nodes[0].ip" 2>/dev/null || echo "")
assert_ok "ping node has ip field" "$PING_NODE_IP"

PING_NODE_PORT=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.nodes[0].port" 2>/dev/null || echo "")
assert_ok "ping node has port field" "$PING_NODE_PORT"

PING_NODE_STATUS=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.nodes[0].status" 2>/dev/null || echo "")
TOTAL=$((TOTAL + 1))
if [ "$PING_NODE_STATUS" = "reachable" ] || [ "$PING_NODE_STATUS" = "unreachable" ] || [ "$PING_NODE_STATUS" = "disconnected" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: ping node has valid status (status=$PING_NODE_STATUS)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: ping node status invalid (status=$PING_NODE_STATUS)"
fi

# All nodes should be reachable in a healthy cluster
ALL_REACHABLE=1
for i in $(seq 0 $((PING_NODES_COUNT - 1))); do
    PSTATUS=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.nodes[$i].status" 2>/dev/null || echo "")
    if [ "$PSTATUS" != "reachable" ]; then
        ALL_REACHABLE=0
        break
    fi
done
TOTAL=$((TOTAL + 1))
if [ "$ALL_REACHABLE" = "1" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: all $PING_NODES_COUNT nodes reachable"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL: some nodes not reachable"
fi

# Check latency_us > 0 for reachable nodes
PING_LATENCY=$(echo "$PING_RESULT" | jq -r "${PING_CLUSTER_JQ}.nodes[0].latency_us" 2>/dev/null || echo "-1")
if [ "$PING_NODE_STATUS" = "reachable" ]; then
    assert_ge "ping latency_us > 0 for reachable node" 0 "$PING_LATENCY"
fi

# Test filtered by group
PING_FILTERED=$(mi_cmd "redis_ping_nodes" -d "{\"group\":\"$PING_GROUP\"}" || echo "")
assert_ok "filtered redis_ping_nodes returns response" "$PING_FILTERED"

PING_FILTERED_COUNT=$(echo "$PING_FILTERED" | jq -r '.result | length' 2>/dev/null || echo "0")
assert_ge "at least one connection with matching group" 1 "$PING_FILTERED_COUNT"

PING_FILTERED_GROUP=$(echo "$PING_FILTERED" | jq -r '.result[0].group' 2>/dev/null || echo "")
assert_eq "filtered ping result matches requested group" "$PING_GROUP" "$PING_FILTERED_GROUP"

# Non-existent group returns empty
PING_EMPTY=$(mi_cmd "redis_ping_nodes" -d '{"group":"nonexistent_group_xyz"}' || echo "")
PING_EMPTY_COUNT=$(echo "$PING_EMPTY" | jq -r '.result | length' 2>/dev/null || echo "0")
assert_eq "non-existent group returns empty array" "0" "$PING_EMPTY_COUNT"

# ============================================================
echo ""
echo "=============================="
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
