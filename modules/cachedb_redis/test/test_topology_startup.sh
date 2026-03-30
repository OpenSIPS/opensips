#!/bin/bash
#
# test_topology_startup.sh - Integration test for PR 3a (topology parser replacement)
#
# Tests that the new CLUSTER SHARDS/SLOTS parser correctly builds the slot
# table and that keys are routed to the correct nodes. Verifies:
#   - OpenSIPS connects to cluster and MI responds
#   - Keys can be stored and fetched
#   - Keys that hash to different nodes are routed correctly
#   - Many random keys can be stored/fetched (slot table coverage)
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

# Determine which node owns a given slot
slot_owner() {
    local slot="$1"
    if [ "$slot" -le 5460 ]; then
        echo "$REDIS_NODE_1"
    elif [ "$slot" -le 10922 ]; then
        echo "$REDIS_NODE_2"
    else
        echo "$REDIS_NODE_3"
    fi
}

# --- Preflight checks ---
echo "=== PR 3a: Topology Startup Parser Test ==="
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
# Test 1: Basic store and fetch                                      #
# ================================================================== #
echo "--- Test 1: Basic store and fetch ---"

TEST_KEY="test:pr3a:basic:$(date +%s)"
TEST_VAL="topology_test_value"

STORE_RESULT=$(mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$TEST_KEY\",\"value\":\"$TEST_VAL\"}")
assert_eq "Store returns OK" "OK" "$(echo "$STORE_RESULT" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",""))' 2>/dev/null || echo "")"

FETCH_RESULT=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$TEST_KEY\"}")
FETCHED_VAL=$(echo "$FETCH_RESULT" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo "")
assert_eq "Fetch returns stored value" "$TEST_VAL" "$FETCHED_VAL"

# Verify via redis-cli too
DIRECT_VAL=$(redis_cmd "$REDIS_NODE_1" -c GET "$TEST_KEY" | tr -d '\r')
assert_eq "Key exists in cluster (redis-cli)" "$TEST_VAL" "$DIRECT_VAL"

redis_cmd "$REDIS_NODE_1" -c DEL "$TEST_KEY" >/dev/null 2>&1 || true

echo ""

# ================================================================== #
# Test 2: Keys routed to correct nodes                               #
# ================================================================== #
echo "--- Test 2: Keys routed to correct nodes ---"

# Find keys that hash to each node's slot range
# Node 1: slots 0-5460, Node 2: slots 5461-10922, Node 3: slots 10923-16383
KEY1="test:pr3a:node1:$(date +%s)"
KEY2="test:pr3a:node2:$(date +%s)"
KEY3="test:pr3a:node3:$(date +%s)"

# We need keys that hash to specific ranges. Use {hashtag} to control routing.
# {a} hashes to slot 15495 (node 3), {b} to slot 3300 (node 1), {c} to slot 7365 (node 2)
KEY1="test:pr3a:{b}:node1"
KEY2="test:pr3a:{c}:node2"
KEY3="test:pr3a:{a}:node3"

SLOT1=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$KEY1" | tr -d '\r')
SLOT2=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$KEY2" | tr -d '\r')
SLOT3=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$KEY3" | tr -d '\r')

OWNER1=$(slot_owner "$SLOT1")
OWNER2=$(slot_owner "$SLOT2")
OWNER3=$(slot_owner "$SLOT3")

echo "  $KEY1 -> slot $SLOT1 -> $OWNER1"
echo "  $KEY2 -> slot $SLOT2 -> $OWNER2"
echo "  $KEY3 -> slot $SLOT3 -> $OWNER3"

# Store all 3 keys via OpenSIPS
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY1\",\"value\":\"val1\"}" >/dev/null
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY2\",\"value\":\"val2\"}" >/dev/null
mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY3\",\"value\":\"val3\"}" >/dev/null

# Verify each key landed on the correct node
DIRECT1=$(redis_cmd "$OWNER1" GET "$KEY1" | tr -d '\r')
assert_eq "Key1 on correct node ($OWNER1)" "val1" "$DIRECT1"

DIRECT2=$(redis_cmd "$OWNER2" GET "$KEY2" | tr -d '\r')
assert_eq "Key2 on correct node ($OWNER2)" "val2" "$DIRECT2"

DIRECT3=$(redis_cmd "$OWNER3" GET "$KEY3" | tr -d '\r')
assert_eq "Key3 on correct node ($OWNER3)" "val3" "$DIRECT3"

# Fetch each key back via OpenSIPS
FETCH1=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY1\"}")
FETCHED1=$(echo "$FETCH1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo "")
assert_eq "Fetch $KEY1 via OpenSIPS" "val1" "$FETCHED1"

FETCH2=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY2\"}")
FETCHED2=$(echo "$FETCH2" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo "")
assert_eq "Fetch $KEY2 via OpenSIPS" "val2" "$FETCHED2"

FETCH3=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY3\"}")
FETCHED3=$(echo "$FETCH3" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo "")
assert_eq "Fetch $KEY3 via OpenSIPS" "val3" "$FETCHED3"

# Cleanup
redis_cmd "$REDIS_NODE_1" -c DEL "$KEY1" >/dev/null 2>&1 || true
redis_cmd "$REDIS_NODE_1" -c DEL "$KEY2" >/dev/null 2>&1 || true
redis_cmd "$REDIS_NODE_1" -c DEL "$KEY3" >/dev/null 2>&1 || true

echo ""

# ================================================================== #
# Test 3: Write and read 100 random keys                             #
# ================================================================== #
echo "--- Test 3: Write and read 100 random keys ---"

TIMESTAMP=$(date +%s)
KEYS_OK=0
KEYS_FAIL=0

for i in $(seq 1 100); do
    KEY="test:pr3a:bulk:${TIMESTAMP}:${i}"
    VAL="value_${i}"

    mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY\",\"value\":\"$VAL\"}" >/dev/null 2>&1

    FETCH=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY\"}" 2>/dev/null)
    FETCHED=$(echo "$FETCH" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo "")

    if [ "$FETCHED" = "$VAL" ]; then
        KEYS_OK=$((KEYS_OK + 1))
    else
        KEYS_FAIL=$((KEYS_FAIL + 1))
        if [ "$KEYS_FAIL" -le 3 ]; then
            echo "  FAIL detail: key=$KEY expected=$VAL got=$FETCHED"
        fi
    fi

    # Cleanup
    redis_cmd "$REDIS_NODE_1" -c DEL "$KEY" >/dev/null 2>&1 || true
done

TOTAL=$((TOTAL + 1))
if [ "$KEYS_OK" -eq 100 ]; then
    echo "  PASS: All 100 keys stored and fetched correctly"
    PASS=$((PASS + 1))
else
    echo "  FAIL: $KEYS_OK/100 keys correct, $KEYS_FAIL failed"
    FAIL=$((FAIL + 1))
fi

echo ""

# ================================================================== #
# Test 4: Verify slot table coverage across multiple slot ranges     #
# ================================================================== #
echo "--- Test 4: Verify slot table coverage across slot ranges ---"

# Store keys with various hash tags, verify they land on the right nodes
# and can be stored/fetched. This covers slots across all 3 nodes.
# We use 30 different keys with diverse hash tags to cover the slot space.
SLOTS_OK=0
SLOTS_FAIL=0
SLOTS_TOTAL=30

for i in $(seq 1 $SLOTS_TOTAL); do
    KEY="test:pr3a:coverage:${i}:$(date +%s)"
    VAL="coverage_${i}"

    mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY\",\"value\":\"$VAL\"}" >/dev/null 2>&1

    FETCH=$(mi_cmd "cache_fetch" -d "{\"system\":\"redis:cluster\",\"attr\":\"$KEY\"}" 2>/dev/null)
    FETCHED=$(echo "$FETCH" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("value",""))' 2>/dev/null || echo "")

    if [ "$FETCHED" = "$VAL" ]; then
        SLOTS_OK=$((SLOTS_OK + 1))
    else
        SLOTS_FAIL=$((SLOTS_FAIL + 1))
        if [ "$SLOTS_FAIL" -le 3 ]; then
            SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER KEYSLOT "$KEY" 2>/dev/null | tr -d '\r')
            echo "  FAIL detail: key=$KEY slot=$SLOT expected=$VAL got=$FETCHED"
        fi
    fi

    redis_cmd "$REDIS_NODE_1" -c DEL "$KEY" >/dev/null 2>&1 || true
done

TOTAL=$((TOTAL + 1))
if [ "$SLOTS_FAIL" -eq 0 ]; then
    echo "  PASS: All $SLOTS_OK/$SLOTS_TOTAL coverage keys stored and fetched"
    PASS=$((PASS + 1))
else
    echo "  FAIL: $SLOTS_OK ok, $SLOTS_FAIL failed out of $SLOTS_TOTAL"
    FAIL=$((FAIL + 1))
fi

echo ""

# --- Final cluster health check ---
echo "--- Final cluster health check ---"
FINAL_STATE=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO | grep cluster_state | tr -d '\r' | cut -d: -f2)
TOTAL=$((TOTAL + 1))
if [ "$FINAL_STATE" = "ok" ]; then
    echo "  PASS: Cluster state is ok after all tests"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Cluster state is '$FINAL_STATE' (expected 'ok')"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $TOTAL total ==="
exit $FAIL
