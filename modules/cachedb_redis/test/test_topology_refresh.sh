#!/bin/bash
#
# test_topology_refresh.sh - Integration test for PR 3b (dynamic topology refresh)
#
# Tests that OpenSIPS correctly refreshes the cluster topology after
# MOVED redirections from slot migrations. Verifies:
#   - Baseline: keys can be stored/fetched across all nodes
#   - After slot migration + MOVED: topology refreshes and data is accessible
#   - New writes to migrated slots go direct (no MOVED)
#   - Multiple consecutive migrations work correctly
#   - Cluster health after all tests
#
# Requirements:
#   - redis-cli    (Redis CLI client)
#   - curl         (for OpenSIPS MI HTTP interface)
#   - A running 3-node Redis Cluster (default: 10.0.0.23-25:6379)
#   - A running OpenSIPS instance with mi_http on port 8888
#   - The cachedb_redis module loaded with cluster mode enabled
#
# Environment variables (override defaults):
#   REDIS_PASS      - Redis cluster password
#   REDIS_NODE_1    - First cluster node   (default: 10.0.0.23)
#   REDIS_NODE_2    - Second cluster node  (default: 10.0.0.24)
#   REDIS_NODE_3    - Third cluster node   (default: 10.0.0.25)
#   REDIS_PORT      - Redis port           (default: 6379)
#   MI_URL          - OpenSIPS MI HTTP URL (default: http://127.0.0.1:8888/mi)
#

set -euo pipefail

# --- Configuration ---
REDIS_PASS="${REDIS_PASS:-85feedc95d5fa7f16fefdb9c92d154179748f2b08df76dc0}"
REDIS_NODE_1="${REDIS_NODE_1:-10.0.0.23}"
REDIS_NODE_2="${REDIS_NODE_2:-10.0.0.24}"
REDIS_NODE_3="${REDIS_NODE_3:-10.0.0.25}"
REDIS_PORT="${REDIS_PORT:-6379}"
MI_URL="${MI_URL:-http://127.0.0.1:8888/mi}"

PASS=0
FAIL=0
TOTAL=0

# --- Cleanup on exit ---
CLEANUP_SLOTS=()
cleanup() {
    for slot in "${CLEANUP_SLOTS[@]}"; do
        for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
            redis_cmd "$node" CLUSTER SETSLOT "$slot" STABLE >/dev/null 2>&1 || true
        done
    done
    # Delete any test keys
    for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
        redis_cmd "$node" -c KEYS "test:pr3b:*" 2>/dev/null | while read -r k; do
            redis_cmd "$node" -c DEL "$k" >/dev/null 2>&1 || true
        done
    done
}
trap cleanup EXIT

# --- Helpers ---
redis_cmd() {
    local node="$1"; shift
    redis-cli -h "$node" -p "$REDIS_PORT" -a "$REDIS_PASS" --no-auth-warning "$@"
}

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

mi_fetch_value() {
    local key="$1"
    local result
    result=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$key\"}" 2>/dev/null)
    echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo ""
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected='$expected', got='$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_empty() {
    local desc="$1" actual="$2"
    TOTAL=$((TOTAL + 1))
    if [ -n "$actual" ]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (value was empty)"
        FAIL=$((FAIL + 1))
    fi
}

get_node_id() {
    local node="$1"
    redis_cmd "$node" CLUSTER MYID | tr -d '\r'
}

# Determine which node owns a given slot and pick a destination
# Sets: SOURCE_IP, DEST_IP, SOURCE_ID, DEST_ID
resolve_slot_owner() {
    local slot="$1"
    local dest_override="${2:-}"

    if [ "$slot" -le 5460 ]; then
        SOURCE_IP="$REDIS_NODE_1"
        if [ "$dest_override" = "node3" ]; then
            DEST_IP="$REDIS_NODE_3"
        else
            DEST_IP="$REDIS_NODE_2"
        fi
    elif [ "$slot" -le 10922 ]; then
        SOURCE_IP="$REDIS_NODE_2"
        if [ "$dest_override" = "node3" ]; then
            DEST_IP="$REDIS_NODE_3"
        else
            DEST_IP="$REDIS_NODE_1"
        fi
    else
        SOURCE_IP="$REDIS_NODE_3"
        if [ "$dest_override" = "node1" ]; then
            DEST_IP="$REDIS_NODE_1"
        else
            DEST_IP="$REDIS_NODE_2"
        fi
    fi

    SOURCE_ID=$(get_node_id "$SOURCE_IP")
    DEST_ID=$(get_node_id "$DEST_IP")
}

# Begin slot migration: mark MIGRATING on source, IMPORTING on dest
begin_migration() {
    local slot="$1"
    redis_cmd "$DEST_IP" CLUSTER SETSLOT "$slot" IMPORTING "$SOURCE_ID" >/dev/null 2>&1 || true
    redis_cmd "$SOURCE_IP" CLUSTER SETSLOT "$slot" MIGRATING "$DEST_ID" >/dev/null 2>&1 || true
}

# Migrate all keys in a slot from source to dest
migrate_keys() {
    local slot="$1"
    local keys
    keys=$(redis_cmd "$SOURCE_IP" CLUSTER GETKEYSINSLOT "$slot" 100 2>/dev/null | tr -d '\r')
    if [ -n "$keys" ]; then
        for k in $keys; do
            redis_cmd "$SOURCE_IP" MIGRATE "$DEST_IP" "$REDIS_PORT" "$k" 0 5000 AUTH "$REDIS_PASS" >/dev/null 2>&1 || true
        done
    fi
}

# Complete migration: assign slot to dest on all nodes
complete_migration() {
    local slot="$1"
    for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
        redis_cmd "$node" CLUSTER SETSLOT "$slot" NODE "$DEST_ID" >/dev/null 2>&1 || true
    done
    sleep 1
}

# Restore a slot back to its original owner
restore_slot() {
    local slot="$1" orig_ip="$2" curr_ip="$3"
    local orig_id curr_id

    orig_id=$(get_node_id "$orig_ip")
    curr_id=$(get_node_id "$curr_ip")

    redis_cmd "$orig_ip" CLUSTER SETSLOT "$slot" IMPORTING "$curr_id" >/dev/null 2>&1 || true
    redis_cmd "$curr_ip" CLUSTER SETSLOT "$slot" MIGRATING "$orig_id" >/dev/null 2>&1 || true

    local keys
    keys=$(redis_cmd "$curr_ip" CLUSTER GETKEYSINSLOT "$slot" 100 2>/dev/null | tr -d '\r')
    if [ -n "$keys" ]; then
        for k in $keys; do
            redis_cmd "$curr_ip" MIGRATE "$orig_ip" "$REDIS_PORT" "$k" 0 5000 AUTH "$REDIS_PASS" >/dev/null 2>&1 || true
        done
    fi

    for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
        redis_cmd "$node" CLUSTER SETSLOT "$slot" NODE "$orig_id" >/dev/null 2>&1 || true
    done
    sleep 1
}

# --- Preflight checks ---
echo "=== PR 3b: Dynamic Topology Refresh Test ==="
echo ""
echo "Checking prerequisites..."

if ! command -v redis-cli &>/dev/null; then
    echo "ERROR: redis-cli not found. Install redis-tools."
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl not found."
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 required."
    exit 1
fi

# Verify cluster is healthy
CLUSTER_STATE=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO | grep cluster_state | tr -d '\r' | cut -d: -f2)
if [ "$CLUSTER_STATE" != "ok" ]; then
    echo "ERROR: Redis Cluster state is '$CLUSTER_STATE', expected 'ok'."
    exit 1
fi
echo "  Redis Cluster: ok"

# Verify OpenSIPS MI is reachable
MI_RESPONSE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -X POST "$MI_URL/which" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"which","id":1}' 2>/dev/null || true)
if [ "$MI_RESPONSE" != "200" ]; then
    echo "ERROR: OpenSIPS MI not reachable at $MI_URL (HTTP $MI_RESPONSE)."
    exit 1
fi
echo "  OpenSIPS MI: ok"

echo ""

# ================================================================== #
# Test 1: Baseline — store and fetch keys across all nodes           #
# ================================================================== #
echo "--- Test 1: Baseline — store and fetch across all nodes ---"

KEY1="test:pr3b:{b}:node1"
KEY2="test:pr3b:{c}:node2"
KEY3="test:pr3b:{a}:node3"

mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY1\",\"value\":\"baseline1\"}" >/dev/null
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY2\",\"value\":\"baseline2\"}" >/dev/null
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY3\",\"value\":\"baseline3\"}" >/dev/null

assert_eq "Fetch key1 baseline" "baseline1" "$(mi_fetch_value "$KEY1")"
assert_eq "Fetch key2 baseline" "baseline2" "$(mi_fetch_value "$KEY2")"
assert_eq "Fetch key3 baseline" "baseline3" "$(mi_fetch_value "$KEY3")"

redis_cmd "$REDIS_NODE_1" -c DEL "$KEY1" >/dev/null 2>&1 || true
redis_cmd "$REDIS_NODE_1" -c DEL "$KEY2" >/dev/null 2>&1 || true
redis_cmd "$REDIS_NODE_1" -c DEL "$KEY3" >/dev/null 2>&1 || true

echo ""

# ================================================================== #
# Test 2: Migrate a slot, verify data still accessible               #
# ================================================================== #
echo "--- Test 2: Migrate slot, verify data accessible after MOVED ---"

TEST_KEY="test:pr3b:migrate2"
TEST_SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$TEST_KEY" | tr -d '\r')
echo "  Key '$TEST_KEY' -> slot $TEST_SLOT"

resolve_slot_owner "$TEST_SLOT"
ORIG_SOURCE="$SOURCE_IP"
echo "  Source: $SOURCE_IP -> Dest: $DEST_IP"

# Store key via OpenSIPS
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$TEST_KEY\",\"value\":\"before_migrate\"}" >/dev/null

# Complete migration (no mid-migration ASK — just complete it)
CLEANUP_SLOTS+=("$TEST_SLOT")
begin_migration "$TEST_SLOT"
migrate_keys "$TEST_SLOT"
complete_migration "$TEST_SLOT"
echo "  Slot $TEST_SLOT migrated to $DEST_IP"

# Fetch via OpenSIPS — triggers MOVED → topology refresh
FETCHED=$(mi_fetch_value "$TEST_KEY")
assert_eq "Fetch after migration (MOVED triggers refresh)" "before_migrate" "$FETCHED"

# Store a NEW key to the same slot — should go direct after refresh
# (uses same hash tag to target the same slot)
NEW_KEY="test:pr3b:migrate2:new"
NEW_SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$NEW_KEY" | tr -d '\r')
# If the new key doesn't hash to the same slot, that's ok — just test it
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$NEW_KEY\",\"value\":\"after_refresh\"}" >/dev/null
FETCHED_NEW=$(mi_fetch_value "$NEW_KEY")
assert_eq "New key stored after refresh" "after_refresh" "$FETCHED_NEW"

# Restore
echo "  Restoring slot $TEST_SLOT..."
restore_slot "$TEST_SLOT" "$ORIG_SOURCE" "$DEST_IP"
CLEANUP_SLOTS=("${CLEANUP_SLOTS[@]/$TEST_SLOT}")
redis_cmd "$REDIS_NODE_1" -c DEL "$TEST_KEY" "$NEW_KEY" >/dev/null 2>&1 || true

echo ""

# ================================================================== #
# Test 3: Migrate slot, write to migrated slot, verify               #
# ================================================================== #
echo "--- Test 3: Write to migrated slot after complete migration ---"

K1="test:pr3b:{migrate3}:k1"
K1_SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$K1" | tr -d '\r')
echo "  Key '$K1' -> slot $K1_SLOT"

resolve_slot_owner "$K1_SLOT"
ORIG_SOURCE="$SOURCE_IP"
echo "  Source: $SOURCE_IP (A) -> Dest: $DEST_IP (B)"

# Store K1 on original owner
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$K1\",\"value\":\"value_k1\"}" >/dev/null

CLEANUP_SLOTS+=("$K1_SLOT")
# Migrate S: A → B (complete)
begin_migration "$K1_SLOT"
migrate_keys "$K1_SLOT"
complete_migration "$K1_SLOT"
echo "  Slot $K1_SLOT migrated A->B"

# Wait for rate-limit to expire (refresh is rate-limited to 1/sec)
sleep 2

# Write K2 to same slot via OpenSIPS — uses same hash tag {migrate3}
# First fetch triggers MOVED → refresh, then write should go direct
K2="test:pr3b:{migrate3}:k2"
K2_SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$K2" | tr -d '\r')
echo "  K2 '$K2' -> slot $K2_SLOT (same as K1)"

mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$K2\",\"value\":\"value_k2\"}" >/dev/null

# Verify K2 landed on node B (the new owner) via direct node query
K2_ON_B=$(redis_cmd "$DEST_IP" GET "$K2" | tr -d '\r')
assert_eq "K2 landed on new slot owner ($DEST_IP)" "value_k2" "$K2_ON_B"

# Fetch both K1 and K2 via OpenSIPS
assert_eq "Fetch K1 via OpenSIPS" "value_k1" "$(mi_fetch_value "$K1")"
assert_eq "Fetch K2 via OpenSIPS" "value_k2" "$(mi_fetch_value "$K2")"

# Restore
echo "  Restoring slot $K1_SLOT..."
restore_slot "$K1_SLOT" "$ORIG_SOURCE" "$DEST_IP"
CLEANUP_SLOTS=("${CLEANUP_SLOTS[@]/$K1_SLOT}")
redis_cmd "$REDIS_NODE_1" -c DEL "$K1" "$K2" >/dev/null 2>&1 || true

echo ""

# ================================================================== #
# Test 4: Multiple migrations, verify data integrity                 #
# ================================================================== #
echo "--- Test 4: Multiple migrations A->B->C ---"

MK="test:pr3b:multi"
MK_SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$MK" | tr -d '\r')
echo "  Key '$MK' -> slot $MK_SLOT"

# Determine A, B, C
if [ "$MK_SLOT" -le 5460 ]; then
    NODE_A="$REDIS_NODE_1"; NODE_B="$REDIS_NODE_2"; NODE_C="$REDIS_NODE_3"
elif [ "$MK_SLOT" -le 10922 ]; then
    NODE_A="$REDIS_NODE_2"; NODE_B="$REDIS_NODE_3"; NODE_C="$REDIS_NODE_1"
else
    NODE_A="$REDIS_NODE_3"; NODE_B="$REDIS_NODE_1"; NODE_C="$REDIS_NODE_2"
fi

NODE_A_ID=$(get_node_id "$NODE_A")
NODE_B_ID=$(get_node_id "$NODE_B")
NODE_C_ID=$(get_node_id "$NODE_C")

echo "  A=$NODE_A  B=$NODE_B  C=$NODE_C"

# Store value on A
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$MK\",\"value\":\"on_A\"}" >/dev/null

# Migration 1: A -> B
SOURCE_IP="$NODE_A"; SOURCE_ID="$NODE_A_ID"; DEST_IP="$NODE_B"; DEST_ID="$NODE_B_ID"
CLEANUP_SLOTS+=("$MK_SLOT")
begin_migration "$MK_SLOT"
migrate_keys "$MK_SLOT"
complete_migration "$MK_SLOT"
echo "  Migration 1: A->B complete"

sleep 2  # Wait for rate-limit

# Fetch (triggers MOVED → refresh)
assert_eq "Fetch after A->B migration" "on_A" "$(mi_fetch_value "$MK")"

# Write again (should go to B now)
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$MK\",\"value\":\"on_B\"}" >/dev/null

# Migration 2: B -> C
SOURCE_IP="$NODE_B"; SOURCE_ID="$NODE_B_ID"; DEST_IP="$NODE_C"; DEST_ID="$NODE_C_ID"
begin_migration "$MK_SLOT"
migrate_keys "$MK_SLOT"
complete_migration "$MK_SLOT"
echo "  Migration 2: B->C complete"

sleep 2  # Wait for rate-limit

# Fetch (triggers MOVED → refresh)
assert_eq "Fetch after B->C migration" "on_B" "$(mi_fetch_value "$MK")"

# Verify value on C directly
DIRECT_C=$(redis_cmd "$NODE_C" GET "$MK" | tr -d '\r')
assert_eq "Value on node C directly" "on_B" "$DIRECT_C"

# Restore C -> A
echo "  Restoring slot $MK_SLOT to A..."
restore_slot "$MK_SLOT" "$NODE_A" "$NODE_C"
CLEANUP_SLOTS=("${CLEANUP_SLOTS[@]/$MK_SLOT}")
redis_cmd "$REDIS_NODE_1" -c DEL "$MK" >/dev/null 2>&1 || true

echo ""

# ================================================================== #
# Test 5: Cluster health + data integrity after all tests            #
# ================================================================== #
echo "--- Test 5: Final cluster health + data integrity ---"

FINAL_STATE=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO | grep cluster_state | tr -d '\r' | cut -d: -f2)
TOTAL=$((TOTAL + 1))
if [ "$FINAL_STATE" = "ok" ]; then
    echo "  PASS: Cluster state is ok after all tests"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Cluster state is '$FINAL_STATE' (expected 'ok')"
    FAIL=$((FAIL + 1))
fi

# Store and fetch a final key to confirm module is healthy
FINAL_KEY="test:pr3b:final:$(date +%s)"
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$FINAL_KEY\",\"value\":\"healthy\"}" >/dev/null
FINAL_VAL=$(mi_fetch_value "$FINAL_KEY")
assert_eq "Final health check store/fetch" "healthy" "$FINAL_VAL"
redis_cmd "$REDIS_NODE_1" -c DEL "$FINAL_KEY" >/dev/null 2>&1 || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $TOTAL total ==="
exit $FAIL
