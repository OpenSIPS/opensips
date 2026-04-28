#!/bin/bash
#
# test_load.sh - Load test for memory leak detection in cachedb_redis topology refresh
#
# Exercises the new CLUSTER SHARDS/SLOTS parser and dynamic topology refresh
# under sustained load with repeated topology changes, monitoring pkg memory
# for leaks.
#
# Phases:
#   0: Warmup + baseline (200 ops)
#   1: Sustained load without topology changes (500 ops)
#   2: Slot migration stress — 10 migration cycles (300 ops)
#   3: Node stop/start — failure + recovery path (170 ops)
#   4: Final soak (300 ops)
#
# Requirements:
#   - redis-cli, curl, python3
#   - 3-node Redis Cluster (10.0.0.23-25:6379)
#   - OpenSIPS with mi_http on port 8888
#   - SSH access to 10.0.0.25 (for node stop/start in Phase 3)
#   - cachedb_redis module loaded with cluster mode
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

# --- Helpers (reused from test_topology_refresh.sh) ---

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

# --- New helpers for load test ---

# Sample pkg memory for process 1 (HTTPD). Returns "used real fragments".
sample_memory() {
    local result
    result=$(mi_cmd "get_statistics" -d "{\"statistics\":[\"pkmem:\"]}" 2>/dev/null)
    local used real frags
    used=$(echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["pkmem:1-used_size"])' 2>/dev/null)
    real=$(echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["pkmem:1-real_used_size"])' 2>/dev/null)
    frags=$(echo "$result" | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["pkmem:1-fragments"])' 2>/dev/null)
    echo "$used $real $frags"
}

# Extract just used_size from sample_memory output
mem_used() {
    echo "$1" | awk '{print $1}'
}

# Extract just real_used_size from sample_memory output
mem_real() {
    echo "$1" | awk '{print $2}'
}

# Extract just fragments from sample_memory output
mem_frags() {
    echo "$1" | awk '{print $3}'
}

# Store a key via MI
mi_store() {
    local key="$1" value="$2"
    mi_cmd "cache_store" -d "{\"system\":\"redis:cluster\",\"attr\":\"$key\",\"value\":\"$value\"}" >/dev/null 2>&1
}

# Remove a key via MI
mi_remove() {
    local key="$1"
    mi_cmd "cache_remove" -d "{\"system\":\"redis:cluster\",\"attr\":\"$key\"}" >/dev/null 2>&1
}

# Check for memory leak. Args: description, baseline_used, current_used, threshold
# Returns 0 (pass) or 1 (fail). Prints result.
check_leak() {
    local desc="$1" baseline="$2" current="$3" threshold="$4"
    local delta=$((current - baseline))

    TOTAL=$((TOTAL + 1))
    if [ "$delta" -lt "$threshold" ]; then
        echo "  PASS: $desc (delta=$delta < threshold=$threshold)"
        PASS=$((PASS + 1))
        return 0
    else
        echo "  FAIL: $desc (delta=$delta >= threshold=$threshold)"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

# Check that memory samples don't show monotonic growth.
# Args: description, space-separated list of used_size values
# A sequence is "monotonic" if every value >= the previous one AND
# the last value is > the first.
check_no_monotonic_growth() {
    local desc="$1"; shift
    local samples=("$@")
    local n=${#samples[@]}

    if [ "$n" -lt 3 ]; then
        TOTAL=$((TOTAL + 1))
        echo "  PASS: $desc (too few samples to check monotonicity)"
        PASS=$((PASS + 1))
        return 0
    fi

    local monotonic=1
    local i
    for (( i=1; i<n; i++ )); do
        if [ "${samples[$i]}" -lt "${samples[$((i-1))]}" ]; then
            monotonic=0
            break
        fi
    done

    TOTAL=$((TOTAL + 1))
    if [ "$monotonic" -eq 1 ] && [ "${samples[$((n-1))]}" -gt "${samples[0]}" ]; then
        echo "  FAIL: $desc (monotonic growth: ${samples[0]} -> ${samples[$((n-1))]})"
        FAIL=$((FAIL + 1))
        return 1
    else
        echo "  PASS: $desc (no monotonic growth)"
        PASS=$((PASS + 1))
        return 0
    fi
}

# Run a store/fetch/remove cycle. Returns 0 on success, 1 on any failure.
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

# Hash tags for targeting specific nodes:
# {b} -> slot 3300 (node 1, slots 0-5460)
# {c} -> slot 7365 (node 2, slots 5461-10922)
# {a} -> slot 15495 (node 3, slots 10923-16383)
HASH_TAGS=("{b}" "{c}" "{a}")
NODE_IPS=("$REDIS_NODE_1" "$REDIS_NODE_2" "$REDIS_NODE_3")

# Slots used for migration cycles (one per node):
# slot 3300 (node 1), slot 7365 (node 2), slot 15495 (node 3)
MIGRATION_SLOTS=(3300 7365 15495)

# --- Preflight checks ---
echo "=== cachedb_redis Load Test (Memory Leak Detection) ==="
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

# Verify memory stats are available
TEST_MEM=$(sample_memory)
if [ -z "$(mem_used "$TEST_MEM")" ] || [ "$(mem_used "$TEST_MEM")" = "" ]; then
    echo "ERROR: Cannot read pkg memory statistics."
    exit 1
fi
echo "  Memory stats: ok (used=$(mem_used "$TEST_MEM"))"
echo "  Leak threshold: ${LEAK_THRESHOLD} bytes"
echo ""

# ================================================================== #
# Phase 0: Warmup + baseline                                         #
# ================================================================== #
echo "--- Phase 0: Warmup ---"

WARMUP_OK=0
WARMUP_FAIL=0
for i in $(seq 1 400); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:load:warmup:${HASH_TAGS[$tag_idx]}:${i}"
    if run_cycle "$key" "warmup_${i}"; then
        WARMUP_OK=$((WARMUP_OK + 1))
    else
        WARMUP_FAIL=$((WARMUP_FAIL + 1))
    fi
done

BASELINE_MEM=$(sample_memory)
BASELINE_USED=$(mem_used "$BASELINE_MEM")
BASELINE_REAL=$(mem_real "$BASELINE_MEM")
BASELINE_FRAGS=$(mem_frags "$BASELINE_MEM")

echo "  $((WARMUP_OK + WARMUP_FAIL)) operations completed ($WARMUP_OK ok, $WARMUP_FAIL errors)"
echo "  Baseline memory: used=$BASELINE_USED real=$BASELINE_REAL fragments=$BASELINE_FRAGS"
echo ""

# ================================================================== #
# Phase 1: Sustained load without topology changes                    #
# ================================================================== #
echo "--- Phase 1: Sustained load (no topology changes) ---"

P1_OK=0
P1_FAIL=0
P1_SAMPLES=()

for i in $(seq 1 1000); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:load:phase1:${HASH_TAGS[$tag_idx]}:${i}"
    if run_cycle "$key" "phase1_${i}"; then
        P1_OK=$((P1_OK + 1))
    else
        P1_FAIL=$((P1_FAIL + 1))
    fi

    # Sample every 200 operations
    if [ $((i % 200)) -eq 0 ]; then
        sample=$(sample_memory)
        P1_SAMPLES+=("$(mem_used "$sample")")
    fi
done

P1_FINAL_MEM=$(sample_memory)
P1_FINAL_USED=$(mem_used "$P1_FINAL_MEM")
P1_FINAL_REAL=$(mem_real "$P1_FINAL_MEM")
P1_FINAL_FRAGS=$(mem_frags "$P1_FINAL_MEM")
P1_DELTA=$((P1_FINAL_USED - BASELINE_USED))

echo "  1000 operations completed, $P1_FAIL errors"
echo "  Memory: used=$P1_FINAL_USED real=$P1_FINAL_REAL fragments=$P1_FINAL_FRAGS"
echo "  Delta from baseline: ${P1_DELTA} bytes"
check_leak "No leak in sustained load" "$BASELINE_USED" "$P1_FINAL_USED" "$LEAK_THRESHOLD" || true
echo ""

# ================================================================== #
# Phase 2: Slot migration stress (10 cycles)                         #
# ================================================================== #
echo "--- Phase 2: Slot migration stress (20 cycles) ---"

P2_TOTAL_OPS=0
P2_MIGRATIONS=0
P2_SAMPLES=()

for cycle in $(seq 1 20); do
    # Rotate through nodes: cycle 1->node1's slot, 2->node2's slot, etc.
    slot_idx=$(( (cycle - 1) % 3 ))
    slot=${MIGRATION_SLOTS[$slot_idx]}
    tag="${HASH_TAGS[$slot_idx]}"
    orig_ip="${NODE_IPS[$slot_idx]}"

    # Pick destination: next node in ring
    dest_idx=$(( (slot_idx + 1) % 3 ))
    dest_ip="${NODE_IPS[$dest_idx]}"

    # Set up SOURCE/DEST for migration helpers
    SOURCE_IP="$orig_ip"
    SOURCE_ID=$(get_node_id "$SOURCE_IP")
    DEST_IP="$dest_ip"
    DEST_ID=$(get_node_id "$DEST_IP")

    # Step 1: Store 40 keys in this slot
    for k in $(seq 1 40); do
        key="test:load:p2c${cycle}:${tag}:${k}"
        mi_store "$key" "p2c${cycle}v${k}"
        TOTAL_OPS=$((TOTAL_OPS + 1))
        P2_TOTAL_OPS=$((P2_TOTAL_OPS + 1))
    done

    # Step 2: Migrate the slot
    begin_migration "$slot"
    migrate_keys "$slot"
    complete_migration "$slot"
    P2_MIGRATIONS=$((P2_MIGRATIONS + 1))

    # Step 3: Fetch all 40 keys via OpenSIPS (triggers MOVED -> refresh)
    for k in $(seq 1 40); do
        key="test:load:p2c${cycle}:${tag}:${k}"
        fetched=$(mi_fetch_value "$key")
        TOTAL_OPS=$((TOTAL_OPS + 1))
        P2_TOTAL_OPS=$((P2_TOTAL_OPS + 1))
        if [ "$fetched" != "p2c${cycle}v${k}" ]; then
            echo "    WARNING: cycle $cycle key $k mismatch (expected='p2c${cycle}v${k}', got='$fetched')"
        fi
    done

    # Step 4: Store 20 more keys (should go direct after refresh)
    for k in $(seq 41 60); do
        key="test:load:p2c${cycle}:${tag}:${k}"
        mi_store "$key" "p2c${cycle}v${k}"
        TOTAL_OPS=$((TOTAL_OPS + 1))
        P2_TOTAL_OPS=$((P2_TOTAL_OPS + 1))
    done

    # Step 5: Fetch all 60 keys, verify values
    cycle_ok=0
    cycle_fail=0
    for k in $(seq 1 60); do
        key="test:load:p2c${cycle}:${tag}:${k}"
        fetched=$(mi_fetch_value "$key")
        TOTAL_OPS=$((TOTAL_OPS + 1))
        P2_TOTAL_OPS=$((P2_TOTAL_OPS + 1))
        if [ "$fetched" = "p2c${cycle}v${k}" ]; then
            cycle_ok=$((cycle_ok + 1))
        else
            cycle_fail=$((cycle_fail + 1))
        fi
    done

    # Step 6: Delete all keys
    for k in $(seq 1 60); do
        key="test:load:p2c${cycle}:${tag}:${k}"
        mi_remove "$key"
        TOTAL_OPS=$((TOTAL_OPS + 1))
        P2_TOTAL_OPS=$((P2_TOTAL_OPS + 1))
    done

    # Step 7: Restore slot to original owner
    restore_slot "$slot" "$orig_ip" "$dest_ip"

    # Step 8: Sample memory
    sample=$(sample_memory)
    sample_used=$(mem_used "$sample")
    P2_SAMPLES+=("$sample_used")

    echo "  Cycle $cycle: slot $slot, migrate $orig_ip -> $dest_ip, ${cycle_ok}/$((cycle_ok + cycle_fail)) ok, mem=$sample_used"

    # Step 9: Let rate limiter expire
    sleep 2
done

P2_FINAL_MEM=$(sample_memory)
P2_FINAL_USED=$(mem_used "$P2_FINAL_MEM")
P2_FINAL_REAL=$(mem_real "$P2_FINAL_MEM")
P2_FINAL_FRAGS=$(mem_frags "$P2_FINAL_MEM")
P2_DELTA=$((P2_FINAL_USED - BASELINE_USED))

echo "  $P2_TOTAL_OPS operations, $P2_MIGRATIONS migrations"
echo "  Memory: used=$P2_FINAL_USED real=$P2_FINAL_REAL fragments=$P2_FINAL_FRAGS"
echo "  Delta from baseline: ${P2_DELTA} bytes"
check_leak "No leak after migrations" "$BASELINE_USED" "$P2_FINAL_USED" "$LEAK_THRESHOLD" || true
check_no_monotonic_growth "No monotonic growth across migration cycles" "${P2_SAMPLES[@]}" || true
echo ""

# ================================================================== #
# Phase 3: Node stop/start (failure + recovery)                       #
# ================================================================== #
echo "--- Phase 3: Node failure and recovery ---"

P3_START_MEM=$(sample_memory)
P3_START_USED=$(mem_used "$P3_START_MEM")

# Stop Redis on node 3
echo "  Stopping redis on ${REDIS_NODE_3}..."
if ! ssh -o ConnectTimeout=5 "$REDIS_NODE_3" "sudo systemctl stop redis-server" 2>/dev/null; then
    echo "  WARNING: Could not stop redis on $REDIS_NODE_3 via SSH. Skipping Phase 3."
    echo "  (This phase requires SSH access to $REDIS_NODE_3)"
    SKIP_PHASE3=1
fi

if [ "${SKIP_PHASE3:-0}" -eq 0 ]; then
    # Wait for cluster to detect failure
    sleep 5

    # NOTE: With 3 masters and no replicas, stopping any node puts the
    # entire cluster in CLUSTERDOWN state. ALL operations will fail, not
    # just those targeting the stopped node's slots. This is expected.

    # Run 20 operations targeting the stopped node's slots — all should fail.
    # These trigger the reconnect failure -> refresh_cluster_topology path.
    # {a} -> slot 15495 (node 3)
    P3_FAIL_OK=0
    P3_FAIL_ERR=0
    for i in $(seq 1 40); do
        key="test:load:phase3:{a}:fail_${i}"
        mi_store "$key" "should_fail_${i}" 2>/dev/null || true
        TOTAL_OPS=$((TOTAL_OPS + 1))
        P3_FAIL_ERR=$((P3_FAIL_ERR + 1))
    done
    echo "  40 ops on stopped node's slots: $P3_FAIL_ERR expected failures"

    # Also try 40 ops on other nodes' slots — will also fail due to CLUSTERDOWN
    P3_CD_OK=0
    P3_CD_ERR=0
    for i in $(seq 1 40); do
        tag_idx=$(( (i - 1) % 2 ))
        if [ "$tag_idx" -eq 0 ]; then tag="{b}"; else tag="{c}"; fi
        key="test:load:phase3:${tag}:cd_${i}"
        if mi_store "$key" "clusterdown_${i}" 2>/dev/null; then
            fetched=$(mi_fetch_value "$key")
            if [ "$fetched" = "clusterdown_${i}" ]; then
                P3_CD_OK=$((P3_CD_OK + 1))
            else
                P3_CD_ERR=$((P3_CD_ERR + 1))
            fi
        else
            P3_CD_ERR=$((P3_CD_ERR + 1))
        fi
        TOTAL_OPS=$((TOTAL_OPS + 2))
    done
    echo "  40 ops on other nodes (CLUSTERDOWN): $P3_CD_OK ok, $P3_CD_ERR errors"

    # Verify OpenSIPS MI is still alive after the failures
    MI_ALIVE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -X POST "$MI_URL/which" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"which","id":1}' 2>/dev/null || echo "000")
    if [ "$MI_ALIVE" != "200" ]; then
        echo "  FAIL: OpenSIPS MI not responding after node failure (HTTP $MI_ALIVE)"
        echo "  OpenSIPS may have crashed. Aborting Phase 3."
        # Try to restart redis before bailing
        ssh -o ConnectTimeout=5 "$REDIS_NODE_3" "sudo systemctl start redis-server" 2>/dev/null || true
        sleep 5
        redis_cmd "$REDIS_NODE_1" CLUSTER MEET "$REDIS_NODE_3" "$REDIS_PORT" >/dev/null 2>&1 || true
        FAIL=$((FAIL + 1))
        TOTAL=$((TOTAL + 1))
    else
        echo "  OpenSIPS MI: still alive after failures"

        # Start Redis on node 3
        echo "  Starting redis on ${REDIS_NODE_3}..."
        ssh -o ConnectTimeout=5 "$REDIS_NODE_3" "sudo systemctl start redis-server" 2>/dev/null || true

        # Wait for cluster convergence
        sleep 5

        # Re-add node if needed
        redis_cmd "$REDIS_NODE_1" CLUSTER MEET "$REDIS_NODE_3" "$REDIS_PORT" >/dev/null 2>&1 || true

        # Poll for cluster state == ok (up to 30 seconds)
        P3_RECOVERY_START=$SECONDS
        P3_RECOVERED=0
        for attempt in $(seq 1 30); do
            state=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO 2>/dev/null | grep cluster_state | tr -d '\r' | cut -d: -f2)
            if [ "$state" = "ok" ]; then
                P3_RECOVERED=1
                break
            fi
            sleep 1
        done
        P3_RECOVERY_SECS=$((SECONDS - P3_RECOVERY_START))

        if [ "$P3_RECOVERED" -eq 1 ]; then
            echo "  Cluster recovery: ok (took ${P3_RECOVERY_SECS} seconds)"
        else
            echo "  WARNING: Cluster did not recover within 30 seconds"
        fi

        # Run 50 store/fetch operations across all 3 nodes — verify recovery
        # Topology refresh should pick up the recovered node
        P3_RECOVERY_OK=0
        P3_RECOVERY_FAIL=0
        for i in $(seq 1 100); do
            tag_idx=$(( (i - 1) % 3 ))
            key="test:load:phase3:recovery:${HASH_TAGS[$tag_idx]}:${i}"
            if run_cycle "$key" "recovery_${i}"; then
                P3_RECOVERY_OK=$((P3_RECOVERY_OK + 1))
            else
                P3_RECOVERY_FAIL=$((P3_RECOVERY_FAIL + 1))
            fi
        done
        echo "  100 ops across all nodes: $P3_RECOVERY_OK ok, $P3_RECOVERY_FAIL errors"

        P3_FINAL_MEM=$(sample_memory)
        P3_FINAL_USED=$(mem_used "$P3_FINAL_MEM")
        P3_FINAL_REAL=$(mem_real "$P3_FINAL_MEM")
        P3_FINAL_FRAGS=$(mem_frags "$P3_FINAL_MEM")
        P3_DELTA=$((P3_FINAL_USED - P3_START_USED))

        echo "  Memory: used=$P3_FINAL_USED real=$P3_FINAL_REAL fragments=$P3_FINAL_FRAGS"
        echo "  Delta from phase start: ${P3_DELTA} bytes"
        check_leak "No leak after node failure/recovery" "$P3_START_USED" "$P3_FINAL_USED" "$LEAK_THRESHOLD" || true
    fi

    # Clean up any leftover keys from failure tests (may exist if node came back)
    for i in $(seq 1 40); do
        mi_remove "test:load:phase3:{a}:fail_${i}" 2>/dev/null || true
        mi_remove "test:load:phase3:{b}:cd_${i}" 2>/dev/null || true
        mi_remove "test:load:phase3:{c}:cd_${i}" 2>/dev/null || true
    done
fi

echo ""

# ================================================================== #
# Phase 4: Final soak                                                 #
# ================================================================== #
echo "--- Phase 4: Final soak ---"

P4_OK=0
P4_FAIL=0
for i in $(seq 1 600); do
    tag_idx=$(( (i - 1) % 3 ))
    key="test:load:phase4:${HASH_TAGS[$tag_idx]}:${i}"
    if run_cycle "$key" "phase4_${i}"; then
        P4_OK=$((P4_OK + 1))
    else
        P4_FAIL=$((P4_FAIL + 1))
    fi
done

FINAL_MEM=$(sample_memory)
FINAL_USED=$(mem_used "$FINAL_MEM")
FINAL_REAL=$(mem_real "$FINAL_MEM")
FINAL_FRAGS=$(mem_frags "$FINAL_MEM")
FINAL_DELTA=$((FINAL_USED - BASELINE_USED))

echo "  600 operations completed, $P4_FAIL errors"
echo "  Memory: used=$FINAL_USED real=$FINAL_REAL fragments=$FINAL_FRAGS"
echo "  Overall delta from baseline: ${FINAL_DELTA} bytes"
check_leak "No memory leak (final vs baseline)" "$BASELINE_USED" "$FINAL_USED" "$LEAK_THRESHOLD" || true

# Final cluster health check
FINAL_STATE=$(redis_cmd "$REDIS_NODE_1" CLUSTER INFO | grep cluster_state | tr -d '\r' | cut -d: -f2)
TOTAL=$((TOTAL + 1))
if [ "$FINAL_STATE" = "ok" ]; then
    echo "  PASS: Cluster state is ok"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Cluster state is '$FINAL_STATE' (expected 'ok')"
    FAIL=$((FAIL + 1))
fi

echo ""

# ================================================================== #
# Summary                                                             #
# ================================================================== #
echo "=== Summary ==="
if [ "$FINAL_DELTA" -ge 0 ]; then
    DELTA_SIGN="+"
else
    DELTA_SIGN=""
fi
DELTA_PCT=$(python3 -c "print(f'{abs($FINAL_DELTA)/$BASELINE_USED*100:.2f}')" 2>/dev/null || echo "?")
echo "  Total operations: $TOTAL_OPS"
if [ "${SKIP_PHASE3:-0}" -eq 0 ]; then
    echo "  Topology refreshes: ${P2_MIGRATIONS}+ (migrations) + N (node failure)"
else
    echo "  Topology refreshes: ${P2_MIGRATIONS}+ (migrations), node failure skipped"
fi
echo "  Memory baseline: $BASELINE_USED"
echo "  Memory final:    $FINAL_USED"
echo "  Memory delta:    ${DELTA_SIGN}${FINAL_DELTA} bytes (${DELTA_PCT}%)"
echo ""
echo "  Assertions: $PASS passed, $FAIL failed, $TOTAL total"

if [ "$FAIL" -eq 0 ]; then
    echo "  PASS: No memory leak detected"
else
    echo "  FAIL: $FAIL assertion(s) failed"
fi

echo ""
exit "$FAIL"
