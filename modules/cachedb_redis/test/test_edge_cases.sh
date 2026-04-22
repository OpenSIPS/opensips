#!/bin/bash
#
# test_edge_cases.sh - Edge case integration tests for cachedb_redis cluster
#
# Exercises two high-risk code paths uncovered by load testing analysis:
#   Test 1: MOVED to an unknown endpoint — new node joins cluster
#   Test 2: All nodes temporarily unreachable — complete outage + recovery
#
# Requirements:
#   - redis-cli, curl, python3
#   - 3-node Redis Cluster (10.0.0.23-25:6379)
#   - OpenSIPS with mi_http on port 8888
#   - SSH access to all 3 Redis nodes (10.0.0.23, 10.0.0.24, 10.0.0.25)
#
# Environment variables (override defaults):
#   REDIS_PASS      - Redis cluster password
#   REDIS_NODE_1    - First cluster node   (default: 10.0.0.23)
#   REDIS_NODE_2    - Second cluster node  (default: 10.0.0.24)
#   REDIS_NODE_3    - Third cluster node   (default: 10.0.0.25)
#   REDIS_PORT      - Redis port           (default: 6379)
#   MI_URL          - OpenSIPS MI HTTP URL (default: http://127.0.0.1:8888/mi)
#   LEAK_THRESHOLD  - Max allowed memory growth in bytes (default: 51200 = 50KB)
#

set -euo pipefail

# --- Configuration ---
REDIS_PASS="${REDIS_PASS:-85feedc95d5fa7f16fefdb9c92d154179748f2b08df76dc0}"
REDIS_NODE_1="${REDIS_NODE_1:-10.0.0.23}"
REDIS_NODE_2="${REDIS_NODE_2:-10.0.0.24}"
REDIS_NODE_3="${REDIS_NODE_3:-10.0.0.25}"
REDIS_PORT="${REDIS_PORT:-6379}"
MI_URL="${MI_URL:-http://127.0.0.1:8888/mi}"
LEAK_THRESHOLD="${LEAK_THRESHOLD:-51200}"

PASS=0
FAIL=0
TOTAL=0
TOTAL_OPS=0

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
        redis_cmd "$node" -c KEYS "test:edge:*" 2>/dev/null | while read -r k; do
            redis_cmd "$node" -c DEL "$k" >/dev/null 2>&1 || true
        done
    done
}
trap cleanup EXIT

# --- Helpers (shared with test_load.sh) ---

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

mi_store() {
    local key="$1" value="$2"
    local result
    result=$(mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$key\",\"value\":\"$value\"}" 2>/dev/null) || return 1
    echo "$result" | python3 -c 'import sys,json; r=json.load(sys.stdin); sys.exit(1 if "error" in r else 0)' 2>/dev/null
}

mi_remove() {
    local key="$1"
    mi_cmd "cache_remove" -d "{\"system\":\"redis:cluster\",\"attr\":\"$key\"}" >/dev/null 2>&1
}

mi_add() {
    local key="$1" value="$2"
    mi_cmd "cache_add" -d "{\"system\":\"redis:cluster\",\"attr\":\"$key\",\"value\":$value}" >/dev/null 2>&1
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        echo "    PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "    FAIL: $desc (expected='$expected', got='$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_empty() {
    local desc="$1" actual="$2"
    TOTAL=$((TOTAL + 1))
    if [ -n "$actual" ]; then
        echo "    PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "    FAIL: $desc (value was empty)"
        FAIL=$((FAIL + 1))
    fi
}

sample_memory() {
    local result
    result=$(mi_cmd "get_statistics" -d "{\"statistics\":[\"pkmem:\"]}" 2>/dev/null)
    local used real frags
    used=$(echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["pkmem:1-used_size"])' 2>/dev/null)
    real=$(echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["pkmem:1-real_used_size"])' 2>/dev/null)
    frags=$(echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["pkmem:1-fragments"])' 2>/dev/null)
    echo "$used $real $frags"
}

mem_used() {
    echo "$1" | awk '{print $1}'
}

mem_real() {
    echo "$1" | awk '{print $2}'
}

mem_frags() {
    echo "$1" | awk '{print $3}'
}

check_leak() {
    local desc="$1" baseline="$2" current="$3" threshold="$4"
    local delta=$((current - baseline))

    TOTAL=$((TOTAL + 1))
    if [ "$delta" -lt "$threshold" ]; then
        echo "    PASS: $desc (delta=$delta < threshold=$threshold)"
        PASS=$((PASS + 1))
        return 0
    else
        echo "    FAIL: $desc (delta=$delta >= threshold=$threshold)"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

run_cycle() {
    local key="$1" value="$2"
    local fetched

    mi_store "$key" "$value" || return 1
    fetched=$(mi_fetch_value "$key")
    if [ "$fetched" != "$value" ]; then
        return 1
    fi
    mi_remove "$key" || return 1
    TOTAL_OPS=$((TOTAL_OPS + 3))
    return 0
}

get_node_id() {
    local node="$1"
    redis_cmd "$node" CLUSTER MYID | tr -d '\r'
}

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

begin_migration() {
    local slot="$1"
    redis_cmd "$DEST_IP" CLUSTER SETSLOT "$slot" IMPORTING "$SOURCE_ID" >/dev/null 2>&1 || true
    redis_cmd "$SOURCE_IP" CLUSTER SETSLOT "$slot" MIGRATING "$DEST_ID" >/dev/null 2>&1 || true
}

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

complete_migration() {
    local slot="$1"
    for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
        redis_cmd "$node" CLUSTER SETSLOT "$slot" NODE "$DEST_ID" >/dev/null 2>&1 || true
    done
    sleep 1
}

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

# --- New helpers for edge case tests ---

# Run redis-cli commands on node 4 (separate VM at 10.0.0.28).
node4_cmd() {
    redis-cli -h "$NODE4_IP" -p "$NODE4_PORT" -a "$REDIS_PASS" --no-auth-warning "$@"
}

wait_cluster_ok() {
    local timeout="${1:-60}"
    local start=$SECONDS
    local state
    while [ $((SECONDS - start)) -lt "$timeout" ]; do
        state=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO 2>/dev/null | grep cluster_state | tr -d '\r' | cut -d: -f2)
        if [ "$state" = "ok" ]; then
            echo "$((SECONDS - start))"
            return 0
        fi
        sleep 1
    done
    echo "$timeout"
    return 1
}

# Hash tags for targeting specific nodes:
# {b} -> slot 3300 (node 1, slots 0-5460)
# {c} -> slot 7365 (node 2, slots 5461-10922)
# {a} -> slot 15495 (node 3, slots 10923-16383)
HASH_TAGS=("{b}" "{c}" "{a}")
NODE_IPS=("$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3")
MIGRATION_SLOTS=(3300 7365 15495)

# ================================================================== #
# Preflight checks                                                     #
# ================================================================== #
echo "=== cachedb_redis Edge Case Tests ==="
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
    echo "ERROR: python3 not found."
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

# Verify SSH access to all 3 redis nodes
SSH_OK=1
for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "$node" "true" 2>/dev/null; then
        echo "ERROR: SSH access to $node failed."
        SSH_OK=0
    fi
done
if [ "$SSH_OK" -eq 0 ]; then
    echo "ERROR: SSH access required to all 3 redis nodes."
    echo "  Deploy keys: see Prerequisites section in test plan."
    exit 1
fi
echo "  SSH to redis nodes: ok"

echo ""

# ================================================================== #
# Test 1: MOVED to unknown endpoint                                    #
# ================================================================== #
echo "--- Test 1: MOVED to unknown endpoint ---"

REDIS_NODE_4="${REDIS_NODE_4:-10.0.0.28}"
NODE4_IP="$REDIS_NODE_4"
NODE4_PORT="$REDIS_PORT"

# Phase 1a: Start 4th Redis, verify OpenSIPS doesn't know about it
echo "  Phase 1a: Starting 4th Redis on ${NODE4_IP}:${NODE4_PORT}"

# Ensure redis-4 is running with a clean cluster state (no prior cluster membership)
ssh -o ConnectTimeout=5 "$NODE4_IP" "sudo systemctl start redis-server 2>/dev/null; sleep 1; \
    redis-cli -a '$REDIS_PASS' --no-auth-warning FLUSHALL 2>/dev/null; \
    redis-cli -a '$REDIS_PASS' --no-auth-warning CLUSTER RESET HARD 2>/dev/null; \
    sudo systemctl stop redis-server 2>/dev/null; \
    sudo rm -f /var/lib/redis/nodes.conf; \
    sudo systemctl start redis-server" >/dev/null 2>&1 || true
sleep 2

# Join new node to cluster
redis_cmd "$REDIS_NODE_1" CLUSTER MEET "$NODE4_IP" "$NODE4_PORT" >/dev/null 2>&1

# Wait for cluster to recognize 4 nodes (poll CLUSTER NODES)
NODE4_JOINED=0
for attempt in $(seq 1 30); do
    NODE_COUNT=$(redis_cmd "$REDIS_NODE_1" CLUSTER NODES 2>/dev/null | grep -c "master\|slave" || echo "0")
    if [ "$NODE_COUNT" -ge 4 ]; then
        NODE4_JOINED=1
        break
    fi
    sleep 1
done

if [ "$NODE4_JOINED" -eq 0 ]; then
    echo "    ERROR: 4th node did not join cluster within 30 seconds. Skipping Test 1."
    # Cleanup — fully reset to avoid stale state on next run
    node4_cmd FLUSHALL >/dev/null 2>&1 || true
    node4_cmd CLUSTER RESET HARD >/dev/null 2>&1 || true
    ssh -o ConnectTimeout=5 "$NODE4_IP" "sudo systemctl stop redis-server; \
        sudo rm -f /var/lib/redis/nodes.conf" 2>/dev/null || true
else

NODE4_ID=$(node4_cmd CLUSTER MYID 2>/dev/null | tr -d '\r')

echo "    Cluster: $NODE_COUNT nodes, state ok"

# Store a key on slot 3300 (still on node 1) via OpenSIPS — baseline check
mi_store "test:edge:moved:{b}:before" "before_migration" || true
TOTAL_OPS=$((TOTAL_OPS + 1))
PRE_FETCH=$(mi_fetch_value "test:edge:moved:{b}:before")
TOTAL_OPS=$((TOTAL_OPS + 1))
assert_eq "Pre-migration fetch succeeds" "before_migration" "$PRE_FETCH"

# Phase 1b: Migrate slot 3300 to unknown node 4, trigger MOVED
echo "  Phase 1b: Migrate slot 3300 to unknown node"

NODE1_ID=$(get_node_id "$REDIS_NODE_1")

# Full migration: node 1 -> node 4
# Set IMPORTING on destination (node 4)
CLEANUP_SLOTS+=(3300)
node4_cmd CLUSTER SETSLOT 3300 IMPORTING "$NODE1_ID" >/dev/null 2>&1 || true

# Set MIGRATING on source (node 1)
redis_cmd "$REDIS_NODE_1" CLUSTER SETSLOT 3300 MIGRATING "$NODE4_ID" >/dev/null 2>&1 || true

# Migrate existing keys from node 1 to node 4
KEYS_IN_SLOT=$(redis_cmd "$REDIS_NODE_1" CLUSTER GETKEYSINSLOT 3300 100 2>/dev/null | tr -d '\r')
if [ -n "$KEYS_IN_SLOT" ]; then
    for k in $KEYS_IN_SLOT; do
        redis_cmd "$REDIS_NODE_1" MIGRATE "$NODE4_IP" "$NODE4_PORT" "$k" 0 5000 AUTH "$REDIS_PASS" >/dev/null 2>&1 || true
    done
fi

# Complete migration — notify all nodes (including node 4)
for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
    redis_cmd "$node" CLUSTER SETSLOT 3300 NODE "$NODE4_ID" >/dev/null 2>&1 || true
done
node4_cmd CLUSTER SETSLOT 3300 NODE "$NODE4_ID" >/dev/null 2>&1 || true
sleep 1

# Now store via OpenSIPS — its slot table says 3300 -> node 1, but node 1
# returns MOVED 3300 10.0.0.24:26379. OpenSIPS has never seen that endpoint,
# so get_redis_connection_by_endpoint returns NULL. After failover exhausts,
# NULL slot lookup triggers refresh_cluster_topology(), discovers node 4 via
# CLUSTER SHARDS, and subsequent operations route correctly.
#
# The first attempt may fail (triggering topology refresh). Retry a few
# times to give OpenSIPS time to discover the new node.
MOVED_STORED=0
for attempt in $(seq 1 5); do
    if mi_store "test:edge:moved:{b}:after" "after_migration" 2>/dev/null; then
        MOVED_STORED=1
        break
    fi
    sleep 2
done
TOTAL_OPS=$((TOTAL_OPS + 1))

POST_FETCH=$(mi_fetch_value "test:edge:moved:{b}:after")
TOTAL_OPS=$((TOTAL_OPS + 1))
assert_eq "Post-migration store+fetch via MOVED to new node" "after_migration" "$POST_FETCH"

# Phase 1c: Sustained operations on new node (100 operations)
echo "  Phase 1c: Sustained operations on new node (100 cycles)"

MOVED_BASELINE_MEM=$(sample_memory)
MOVED_BASELINE_USED=$(mem_used "$MOVED_BASELINE_MEM")

P2C_OK=0
P2C_FAIL=0
for i in $(seq 1 100); do
    key="test:edge:moved:{b}:sustained_${i}"
    value="moved_sustained_${i}"
    if run_cycle "$key" "$value"; then
        P2C_OK=$((P2C_OK + 1))
    else
        P2C_FAIL=$((P2C_FAIL + 1))
    fi
done

echo "    100 cycles: $P2C_OK ok, $P2C_FAIL errors"

TOTAL=$((TOTAL + 1))
if [ "$P2C_FAIL" -eq 0 ]; then
    echo "    PASS: All operations on new node succeeded"
    PASS=$((PASS + 1))
else
    echo "    FAIL: $P2C_FAIL operations on new node failed"
    FAIL=$((FAIL + 1))
fi

MOVED_FINAL_MEM=$(sample_memory)
MOVED_FINAL_USED=$(mem_used "$MOVED_FINAL_MEM")
check_leak "No memory leak" "$MOVED_BASELINE_USED" "$MOVED_FINAL_USED" "$LEAK_THRESHOLD" || true

# Phase 1d: Cleanup — migrate slot back, remove node 4
echo "  Phase 1d: Cleanup"

# Migrate slot 3300 back: node 4 -> node 1
redis_cmd "$REDIS_NODE_1" CLUSTER SETSLOT 3300 IMPORTING "$NODE4_ID" >/dev/null 2>&1 || true
node4_cmd CLUSTER SETSLOT 3300 MIGRATING "$NODE1_ID" >/dev/null 2>&1 || true

# Migrate keys back
KEYS_IN_SLOT=$(node4_cmd CLUSTER GETKEYSINSLOT 3300 100 2>/dev/null | tr -d '\r')
if [ -n "$KEYS_IN_SLOT" ]; then
    for k in $KEYS_IN_SLOT; do
        node4_cmd MIGRATE "$REDIS_NODE_1" "$REDIS_PORT" "$k" 0 5000 AUTH "$REDIS_PASS" >/dev/null 2>&1 || true
    done
fi

# Complete migration back
for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
    redis_cmd "$node" CLUSTER SETSLOT 3300 NODE "$NODE1_ID" >/dev/null 2>&1 || true
done
node4_cmd CLUSTER SETSLOT 3300 NODE "$NODE1_ID" >/dev/null 2>&1 || true
sleep 1

# Remove node 4 from cluster: CLUSTER FORGET on all 3 original nodes
for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
    redis_cmd "$node" CLUSTER FORGET "$NODE4_ID" >/dev/null 2>&1 || true
done

# Fully reset redis-4 so it doesn't auto-rejoin or retain stale state
node4_cmd FLUSHALL >/dev/null 2>&1 || true
node4_cmd CLUSTER RESET HARD >/dev/null 2>&1 || true
ssh -o ConnectTimeout=5 "$NODE4_IP" "sudo systemctl stop redis-server; \
    sudo rm -f /var/lib/redis/nodes.conf" 2>/dev/null || true
sleep 1
CLEANUP_SLOTS=("${CLEANUP_SLOTS[@]/3300}")

# Wait for cluster to stabilize (3 nodes, state ok)
CLEANUP_SECS=$(wait_cluster_ok 30) || true
echo "    Slot restored, node removed, cluster stable"

# Warm-up: first request on the {b} slot (3300) will hit the stale node 4
# connection, triggering a topology refresh. Absorb this expected failure.
mi_store "test:edge:moved:cleanup:{b}:warmup" "warmup" 2>/dev/null || true
sleep 2

# Verify OpenSIPS can route to all 3 original nodes
P2D_OK=0
P2D_FAIL=0
for tag_idx in 0 1 2; do
    tag="${HASH_TAGS[$tag_idx]}"
    key="test:edge:moved:cleanup:${tag}:verify"
    value="cleanup_verify_${tag_idx}"
    if run_cycle "$key" "$value"; then
        P2D_OK=$((P2D_OK + 1))
    else
        P2D_FAIL=$((P2D_FAIL + 1))
    fi
done

TOTAL=$((TOTAL + 1))
if [ "$P2D_OK" -eq 3 ]; then
    echo "    PASS: Post-cleanup operations on all original nodes"
    PASS=$((PASS + 1))
else
    echo "    FAIL: Post-cleanup operations failed ($P2D_OK/3 succeeded)"
    FAIL=$((FAIL + 1))
fi

fi  # end NODE4_JOINED check

echo ""

# ================================================================== #
# Test 2: All nodes temporarily unreachable                            #
# ================================================================== #
echo "--- Test 2: All nodes temporarily unreachable ---"

# Phase 2a: Baseline — store 10 keys across all 3 nodes
echo "  Phase 2a: Baseline (10 keys stored)"

for i in $(seq 1 10); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:edge:outage:${HASH_TAGS[$tag_idx]}:baseline_${i}"
    value="outage_baseline_${i}"
    mi_store "$key" "$value" || true
    TOTAL_OPS=$((TOTAL_OPS + 1))
done

# Verify all 10 baseline keys are readable
BASELINE_READS_OK=0
for i in $(seq 1 10); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:edge:outage:${HASH_TAGS[$tag_idx]}:baseline_${i}"
    fetched=$(mi_fetch_value "$key")
    TOTAL_OPS=$((TOTAL_OPS + 1))
    if [ "$fetched" = "outage_baseline_${i}" ]; then
        BASELINE_READS_OK=$((BASELINE_READS_OK + 1))
    fi
done

OUTAGE_BASELINE_MEM=$(sample_memory)
OUTAGE_BASELINE_USED=$(mem_used "$OUTAGE_BASELINE_MEM")

# Phase 2b: Stop all Redis nodes
echo "  Phase 2b: Stopping all Redis nodes..."

ssh -o ConnectTimeout=5 "$REDIS_NODE_3" "sudo systemctl stop redis-server" 2>/dev/null || true
sleep 1
ssh -o ConnectTimeout=5 "$REDIS_NODE_2" "sudo systemctl stop redis-server" 2>/dev/null || true
sleep 1
ssh -o ConnectTimeout=5 "$REDIS_NODE_1" "sudo systemctl stop redis-server" 2>/dev/null || true
sleep 3

# Phase 2c: Operations during outage
echo "  Phase 2c: Operations during outage"

P3C_OK=0
P3C_FAIL=0
for i in $(seq 1 50); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:edge:outage:${HASH_TAGS[$tag_idx]}:during_${i}"
    if mi_store "$key" "should_fail_${i}" 2>/dev/null; then
        P3C_OK=$((P3C_OK + 1))
    else
        P3C_FAIL=$((P3C_FAIL + 1))
    fi
    TOTAL_OPS=$((TOTAL_OPS + 1))
done

echo "    50 operations: $P3C_OK ok, $P3C_FAIL expected failures"

TOTAL=$((TOTAL + 1))
if [ "$P3C_FAIL" -eq 50 ]; then
    echo "    PASS: All outage operations failed (expected)"
    PASS=$((PASS + 1))
else
    echo "    FAIL: Expected 50 failures, got $P3C_FAIL (ok=$P3C_OK)"
    FAIL=$((FAIL + 1))
fi

# Verify MI is still responsive
MI_ALIVE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -X POST "$MI_URL/which" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"which","id":1}' 2>/dev/null || echo "000")

TOTAL=$((TOTAL + 1))
if [ "$MI_ALIVE" = "200" ]; then
    echo "    PASS: MI still responsive"
    PASS=$((PASS + 1))
else
    echo "    FAIL: MI not responsive (HTTP $MI_ALIVE)"
    FAIL=$((FAIL + 1))
fi

# Phase 2d: Restart all Redis nodes
echo "  Phase 2d: Restarting all Redis nodes..."

ssh -o ConnectTimeout=5 "$REDIS_NODE_1" "sudo systemctl start redis-server" 2>/dev/null || true
sleep 1
ssh -o ConnectTimeout=5 "$REDIS_NODE_2" "sudo systemctl start redis-server" 2>/dev/null || true
sleep 1
ssh -o ConnectTimeout=5 "$REDIS_NODE_3" "sudo systemctl start redis-server" 2>/dev/null || true
sleep 2

# Verify each node is up (poll PING)
for node in "$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3"; do
    for attempt in $(seq 1 15); do
        if redis_cmd "$node" PING 2>/dev/null | grep -q "PONG"; then
            break
        fi
        sleep 1
    done
done

# CLUSTER MEET between nodes in case they need help re-joining
redis_cmd "$REDIS_NODE_1" CLUSTER MEET "$REDIS_NODE_2" "$REDIS_PORT" >/dev/null 2>&1 || true
redis_cmd "$REDIS_NODE_1" CLUSTER MEET "$REDIS_NODE_3" "$REDIS_PORT" >/dev/null 2>&1 || true

# Wait for cluster state ok
RECOVERY_SECS=$(wait_cluster_ok 60) || true

CLUSTER_STATE_AFTER=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO 2>/dev/null | grep cluster_state | tr -d '\r' | cut -d: -f2)

echo "    Cluster recovery: $CLUSTER_STATE_AFTER (took $RECOVERY_SECS seconds)"

TOTAL=$((TOTAL + 1))
if [ "$CLUSTER_STATE_AFTER" = "ok" ]; then
    echo "    PASS: Cluster recovered"
    PASS=$((PASS + 1))
else
    echo "    FAIL: Cluster state is '$CLUSTER_STATE_AFTER' (expected 'ok')"
    FAIL=$((FAIL + 1))
fi

# Phase 2e: Recovery operations
echo "  Phase 2e: Recovery operations"

P3E_OK=0
P3E_FAIL=0
for i in $(seq 1 100); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:edge:outage:${HASH_TAGS[$tag_idx]}:recovery_${i}"
    value="recovery_${i}"
    if run_cycle "$key" "$value"; then
        P3E_OK=$((P3E_OK + 1))
    else
        P3E_FAIL=$((P3E_FAIL + 1))
    fi
done

echo "    100 operations: $P3E_OK ok, $P3E_FAIL errors"

TOTAL=$((TOTAL + 1))
if [ "$P3E_OK" -ge 90 ]; then
    echo "    PASS: Recovery succeeded ($P3E_OK/100 >= 90 threshold)"
    PASS=$((PASS + 1))
else
    echo "    FAIL: Recovery insufficient ($P3E_OK/100 < 90 threshold)"
    FAIL=$((FAIL + 1))
fi

# Verify pre-outage keys survived
SURVIVED=0
for i in $(seq 1 10); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:edge:outage:${HASH_TAGS[$tag_idx]}:baseline_${i}"
    fetched=$(mi_fetch_value "$key")
    TOTAL_OPS=$((TOTAL_OPS + 1))
    if [ "$fetched" = "outage_baseline_${i}" ]; then
        SURVIVED=$((SURVIVED + 1))
    fi
done

TOTAL=$((TOTAL + 1))
if [ "$SURVIVED" -eq 10 ]; then
    echo "    PASS: Pre-outage keys survived ($SURVIVED/10)"
    PASS=$((PASS + 1))
else
    echo "    FAIL: Pre-outage keys lost (only $SURVIVED/10 survived)"
    FAIL=$((FAIL + 1))
fi

# Phase 2f: Stability check
echo "  Phase 2f: Stability"

OUTAGE_FINAL_MEM=$(sample_memory)
OUTAGE_FINAL_USED=$(mem_used "$OUTAGE_FINAL_MEM")
OUTAGE_DELTA=$((OUTAGE_FINAL_USED - OUTAGE_BASELINE_USED))

echo "    Memory delta: $OUTAGE_DELTA bytes"
check_leak "No memory leak" "$OUTAGE_BASELINE_USED" "$OUTAGE_FINAL_USED" "$LEAK_THRESHOLD" || true

# Final 50 operations to confirm full recovery
P3F_OK=0
P3F_FAIL=0
for i in $(seq 1 50); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:edge:outage:${HASH_TAGS[$tag_idx]}:final_${i}"
    value="final_${i}"
    if run_cycle "$key" "$value"; then
        P3F_OK=$((P3F_OK + 1))
    else
        P3F_FAIL=$((P3F_FAIL + 1))
    fi
done

echo "    50 operations: $P3F_OK ok, $P3F_FAIL errors"

# Clean up baseline keys
for i in $(seq 1 10); do
    tag_idx=$(( (i - 1) % 3 ))
    mi_remove "test:edge:outage:${HASH_TAGS[$tag_idx]}:baseline_${i}" 2>/dev/null || true
done

echo ""

# ================================================================== #
# Summary                                                              #
# ================================================================== #
echo "=== Summary ==="
echo "  Assertions: $PASS passed, $FAIL failed, $TOTAL total"

if [ "$FAIL" -eq 0 ]; then
    echo "  PASS: All edge case tests passed"
else
    echo "  FAIL: $FAIL assertion(s) failed"
fi

echo ""
exit "$FAIL"
