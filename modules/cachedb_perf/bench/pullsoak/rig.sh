#!/bin/sh
# Concurrent pull soak: the shape of test that would have caught the three
# defects found by reading the code (lock scope, per-sender dedupe, atomic
# counters).  Several workers on BOTH nodes pull at once, while writes race
# the pulls, so slots are contended and replies interleave.
D=${D:-/tmp/cachedb_perf_soak}
T=${T:-$(cd "$(dirname "$0")/../../../.." && pwd)}
KEYS=${KEYS:-500}
mkdir -p $D
pkill -f "soak/n[12].cfg" 2>/dev/null; sleep 1
rm -f $D/mi1.sock $D/mi2.sock $D/shared.db
sqlite3 $D/shared.db "CREATE TABLE cachedb_perf (collection TEXT, pkey TEXT, pvalue BLOB, expires INTEGER);"

for i in 1 2; do
cat > $D/n$i.cfg <<EOF
log_level=3
max_while_loops=1000000
stderror_enabled=yes
syslog_enabled=no
udp_workers=8
socket=udp:127.0.0.1:508$i
socket=bin:127.0.0.1:558$i
mpath="$T/modules/"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "db_sqlite.so"
loadmodule "clusterer.so"
loadmodule "mi_datagram.so"
loadmodule "cachedb_perf.so"
loadmodule "sl.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", $i)
modparam("clusterer", "my_node_info", "cluster_id=1, url=bin:127.0.0.1:558$i")
modparam("clusterer", "neighbor_node_info", "cluster_id=1, node_id=$((3-i)), url=bin:127.0.0.1:558$((3-i))")
modparam("mi_datagram", "socket_name", "$D/mi$i.sock")
modparam("cachedb_perf", "cache_collections", "sync=12")
modparam("cachedb_perf", "cachedb_url", "perf:///sync")
modparam("cachedb_perf", "db_url", "sqlite://$D/shared.db")
modparam("cachedb_perf", "sync_cluster_id", 1)
modparam("cachedb_perf", "replicate_collections", "sync")
modparam("cachedb_perf", "pull_timeout_ms", 200)
modparam("cachedb_perf", "pull_negative_ms", 50)
modparam("cachedb_perf", "pull_on_miss", 1)

route {
    # seed a band of keys owned by this node
    if (\$hdr(X-Seed) == "1") {
        \$var(i) = 0;
        while (\$var(i) < $KEYS) {
            cache_store("perf", "soak-\$var(i)", "\$var(i)", 600);
            \$var(i) = \$var(i) + 1;
        }
        sl_send_reply(200, "seeded");
        exit;
    }
    # hammer: fetch a slice of the key space, verify what comes back
    if (\$hdr(X-Hammer) == "1") {
        # header values are STRINGS - without the cast the loop counter
        # never increments and runs to max_while_loops
        \$var(i) = \$(hdr(X-From){s.int});
        \$var(end) = \$(hdr(X-To){s.int});
        \$var(hit) = 0;
        \$var(bad) = 0;
        while (\$var(i) < \$var(end)) {
            \$var(k) = \$var(i) % $KEYS;
            if (cache_fetch("perf", "soak-\$var(k)", \$var(v))) {
                \$var(hit) = \$var(hit) + 1;
                # the value IS the key's index, so a reply matched to the
                # wrong request shows up as a number that does not belong.
                # Compared numerically: a quoted string is only expanded in
                # a function argument, never in an assignment or a
                # comparison, so there is no way to build the expectation.
                if (\$(var(v){s.int}) != \$var(k))
                    \$var(bad) = \$var(bad) + 1;
            }
            \$var(i) = \$var(i) + 1;
        }
        sl_send_reply(200, "hit=\$var(hit) bad=\$var(bad)");
        exit;
    }
    # churn: overwrite keys while others are pulling them
    if (\$hdr(X-Churn) == "1") {
        \$var(i) = 0;
        while (\$var(i) < 200) {
            \$var(k) = \$var(i) % $KEYS;
            cache_store("perf", "soak-\$var(k)", "\$var(k)", 600);
            \$var(i) = \$var(i) + 1;
        }
        sl_send_reply(200, "churned");
        exit;
    }
    # ask for keys that exist nowhere - exercises the negative path
    if (\$hdr(X-Ghost) == "1") {
        \$var(i) = 0;
        \$var(found) = 0;
        while (\$var(i) < 200) {
            if (cache_fetch("perf", "ghost-\$var(i)", \$var(v)))
                \$var(found) = \$var(found) + 1;
            \$var(i) = \$var(i) + 1;
        }
        sl_send_reply(200, "ghostfound=\$var(found)");
        exit;
    }
    sl_send_reply(200, "ok");
    exit;
}
EOF
done
cd $T
./opensips -f $D/n1.cfg -F > $D/n1.log 2>&1 &
./opensips -f $D/n2.cfg -F > $D/n2.log 2>&1 &
sleep 7
grep -ahc "cross-node pull active" $D/n1.log $D/n2.log
