#!/bin/sh
# CP-15.14 async e2e: a burst of cross-node misses, handled two ways.
#   MODE=sync   pull_on_miss=1, script calls topology_hiding_match()
#               -> the lookup blocks the worker while the cluster answers
#   MODE=async  pull_on_miss=0, script calls async(topology_hiding_match())
#               -> the transaction suspends, the worker goes back to work
# Same workload, same node count, same worker count.
set -e
T=/dn/wt-cp15
D=/dn/e2e
MODE=${MODE:-async}
WORKERS=${WORKERS:-4}
mkdir -p $D
pkill -f "e2e/n[12].cfg" 2>/dev/null || true
sleep 1
for i in 1 2; do ip netns del e$i 2>/dev/null || true; ip link del y${i}p 2>/dev/null || true; done
ip link del br95 2>/dev/null || true
sleep 1
rm -f $D/mi1.sock $D/mi2.sock

if [ "$MODE" = "sync" ]; then ONMISS=1; else ONMISS=0; fi

ip link add br95 type bridge
ip link set br95 up
echo 0 > /sys/class/net/br95/bridge/multicast_snooping 2>/dev/null || true
for i in 1 2; do
  ip netns add e$i
  ip link add y$i type veth peer name y${i}p
  ip link set y$i netns e$i
  ip link set y${i}p master br95 up
  ip netns exec e$i ip link set lo up
  ip netns exec e$i ip addr add 10.95.0.$i/24 dev y$i
  ip netns exec e$i ip link set y$i up
  ip netns exec e$i ip route add 239.0.0.0/8 dev y$i

  cat > $D/n$i.cfg <<EOF
log_level=2
max_while_loops=100000
stderror_enabled=yes
syslog_enabled=no
udp_workers=$WORKERS
socket=udp:10.95.0.$i:5060
socket=bin:10.95.0.$i:5599
mpath="$T/modules/"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "clusterer.so"
loadmodule "clusterer_controller.so"
loadmodule "mi_datagram.so"
loadmodule "cachedb_perf.so"
loadmodule "tm.so"
loadmodule "sl.so"
loadmodule "signaling.so"
loadmodule "sipmsgops.so"
loadmodule "rr.so"
loadmodule "dialog.so"
loadmodule "topology_hiding.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", $i)
modparam("clusterer", "cluster_options", "cluster_id=3, use_controller=1")
modparam("clusterer_controller", "my_ip", "10.95.0.$i")
modparam("clusterer_controller", "password", "e2etest")
modparam("clusterer_controller", "cluster", "id=3,multicast=239.0.95.1:4488,bin_socket=bin:10.95.0.$i:5599")
modparam("mi_datagram", "socket_name", "$D/mi$i.sock")
modparam("cachedb_perf", "cache_collections", "th=12")
modparam("cachedb_perf", "cachedb_url", "perf:///th")
modparam("cachedb_perf", "sync_cluster_id", 3)
modparam("cachedb_perf", "replicate_collections", "th")
modparam("cachedb_perf", "pull_timeout_ms", 300)
modparam("cachedb_perf", "pull_on_miss", $ONMISS)
modparam("topology_hiding", "th_state_url", "perf:///th")
modparam("topology_hiding", "th_contact_encode_param", "tk")

route {
    if (\$hdr(X-Seed) == "1") {
        \$var(i) = 0;
        while (\$var(i) < 400) {
            cache_store("perf", "th:e2e-key-\$var(i)000000", "0:22:sip:uas@10.95.0.9:50993:10018:udp:10.95.0.1:5060", 600);
            \$var(i) = \$var(i) + 1;
        }
        sl_send_reply(200, "seeded");
        exit;
    }
    if (\$hdr(X-Match) == "1") {
EOF
  if [ "$MODE" = "sync" ]; then
    cat >> $D/n$i.cfg <<'EOF'
        if (topology_hiding_match())
            sl_send_reply(200, "m");
        else
            sl_send_reply(404, "n");
        exit;
    }
    sl_send_reply(200, "ok");
    exit;
}
EOF
  else
    cat >> $D/n$i.cfg <<'EOF'
        async(topology_hiding_match(), r);
        exit;
    }
    sl_send_reply(200, "ok");
    exit;
}
route[r] {
    if ($rc > 0) sl_send_reply(200, "m"); else sl_send_reply(404, "n");
    exit;
}
EOF
  fi
  ip netns exec e$i $T/opensips -f $D/n$i.cfg -F > $D/n$i.log 2>&1 &
done
sleep 14
grep -ahc "cross-node pull active" $D/n1.log $D/n2.log
