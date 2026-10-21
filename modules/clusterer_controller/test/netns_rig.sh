#!/bin/bash
# netns_rig.sh - helpers for netns_tests.sh: four network namespaces n1..n4
# on a private bridge, one OpenSIPS per namespace.  Nothing leaves the host.
# Needs root, iproute2, iptables and python3.
#
# Every node runs TWO controller clusters on the SAME port and different
# groups (741 on 239.0.74.1, 742 on 239.0.74.2), which is the shared-port
# case IP_MULTICAST_ALL=0 is for.
#
#   NEW      install prefix of the build under test (required)
#   OLD      install prefix of a wire-version-1 build (optional; T6 needs it)
#   RIG_DIR  scratch directory for configs, logs, sockets (wiped on setup)
#   RIG_NS_PREFIX  prefix for the namespace names (default none).  Namespace
#            names are global to the host, the bridge and links are not: two
#            runs at once need different prefixes and RIG_DIRs, each started
#            under its own "unshare -n".
set -u
: "${NEW:?set NEW to the install prefix of the build under test}"
OLD=${OLD:-}
R=${RIG_DIR:-/tmp/cl_ctr_rig}
RIG_TM=${RIG_TM:-0}     # 1: load tm with tm_replication_cluster=741
RIG_TAG_RELEASE=${RIG_TAG_RELEASE:-0}   # 1: release_tag_when_isolated=1
BR=br74
NSP=${RIG_NS_PREFIX:-}
PORT=3741
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

modpath() { if [ -d "$1/lib64/opensips/modules" ]; then echo "$1/lib64/opensips/modules/"; else echo "$1/lib/opensips/modules/"; fi; }

ip4() { echo "10.74.0.1$1"; }
# nx <i> <cmd...>: run a command in node i's namespace
nx() { local i=$1; shift; ip netns exec ${NSP}n$i "$@"; }
# dropped <i> <chain>: packets the DROP rules of that chain in node i have
# matched - read before deleting a cut, to prove the cut actually fired
dropped() { nx $1 iptables -L $2 -v -n -x | awk 'NR>2 && $3=="DROP" {s+=$1} END {print s+0}'; }

teardown() {
  for i in 1 2 3 4; do
    [ -f $R/n$i.pid ] && kill -9 -- -"$(ps -o pgid= -p "$(cat $R/n$i.pid)" 2>/dev/null | tr -d ' ')" 2>/dev/null
    ip netns del ${NSP}n$i 2>/dev/null
    ip link del v${i}p 2>/dev/null
  done
  ip link del $BR 2>/dev/null
}

setup() {
  teardown; sleep 1
  rm -rf $R; mkdir -p $R
  ip link add $BR type bridge
  echo 0 > /sys/class/net/$BR/bridge/multicast_snooping
  ip addr add 10.74.0.254/24 dev $BR
  ip link set $BR up
  for i in 1 2 3 4; do
    ip netns add ${NSP}n$i
    ip link add v$i type veth peer name v${i}p
    ip link set v$i netns ${NSP}n$i
    ip link set v${i}p master $BR up
    ip netns exec ${NSP}n$i ip link set lo up
    ip netns exec ${NSP}n$i ip addr add $(ip4 $i)/24 dev v$i
    ip netns exec ${NSP}n$i ip link set v$i up
    ip netns exec ${NSP}n$i ip route add 239.0.0.0/8 dev v$i
  done
}

# mkcfg <i> <prefix> [stickiness] [query_time] [uuid]
mkcfg() {
  local i=$1 P=$2 ST=${3:-1} QT=${4:-2} U=${5:-} IP; IP=$(ip4 $1)
  local UK=""; [ -n "$U" ] && UK=",uuid=$U"
  local TMMOD="" TMRT="" TRMOD=""
  # only when on: a build from before the parameter (PREV) refuses it
  [ "$RIG_TAG_RELEASE" != 0 ] && \
    TRMOD="modparam(\"clusterer_controller\", \"release_tag_when_isolated\", $RIG_TAG_RELEASE)"
  if [ "$RIG_TM" = 1 ]; then
    TMMOD='loadmodule "tm.so"
modparam("tm", "tm_replication_cluster", 741)'
    TMRT='if ($hdr(X-Relay) != NULL) { $du = "sip:10.74.0.254:5070"; t_relay(); exit; }'
  fi
  cat > $R/n$i.cfg <<EOF
log_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=2
auto_aliases=no
socket=udp:$IP:5060
socket=bin:$IP:5588
mpath="$(modpath $P)"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "sl.so"
loadmodule "mi_datagram.so"
loadmodule "clusterer.so"
loadmodule "clusterer_controller.so"
$TMMOD
modparam("mi_datagram", "socket_name", "$R/mi$i.sock")
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "cluster_options", "cluster_id=741, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=742, use_controller=1")
modparam("clusterer", "sharing_tag", "tag741/741=backup")
modparam("clusterer_controller", "my_ip", "$IP")
modparam("clusterer_controller", "password", "rig74-not-a-secret-9f3a1c")
modparam("clusterer_controller", "query_time", $QT)
modparam("clusterer_controller", "master_stickiness", $ST)
modparam("clusterer_controller", "on_config_mismatch", "reject")
modparam("clusterer_controller", "consumer_rate_limit", 4000)
$TRMOD
modparam("clusterer_controller", "cluster", "id=741,multicast=239.0.74.1:$PORT,bin_socket=bin:$IP:5588$UK")
modparam("clusterer_controller", "cluster", "id=742,multicast=239.0.74.2:$PORT,bin_socket=bin:$IP:5588$UK")

route {
    $TMRT
    if (\$hdr(X-Bcast) != NULL) {
        cl_ctr_broadcast_req(741, "\$hdr(X-Bcast)");
        sl_send_reply(200, "sent");
        exit;
    }
    sl_send_reply(200, "ok");
}
event_route[E_CL_CTR_REQ_RECEIVED] {
    xlog("L_NOTICE", "[RX] \$param(msg)\n");
}
EOF
}

# start <i> <prefix> [stickiness] [query_time] [uuid]
start() {
  local i=$1 P=$2
  mkcfg "$@"
  ip netns exec ${NSP}n$i $P/sbin/opensips -f $R/n$i.cfg -m 64 -M 16 -w $R \
     -P $R/n$i.pid 2>>$R/n$i.log
}
stop_graceful() { [ -f $R/n$1.pid ] && kill -TERM "$(cat $R/n$1.pid)"; sleep 2; }
stop_hard() {
  local pg; pg=$(ps -o pgid= -p "$(cat $R/n$1.pid)" 2>/dev/null | tr -d ' ')
  [ -n "$pg" ] && kill -9 -- -"$pg"; sleep 1
}
alive() { [ -f $R/n$1.pid ] && kill -0 "$(cat $R/n$1.pid)" 2>/dev/null; }
# pause / resume every process of node i (a VM pause, as the node sees it)
pause_node()  { kill -STOP -- -"$(ps -o pgid= -p "$(cat $R/n$1.pid)" | tr -d ' ')"; }
resume_node() { kill -CONT -- -"$(ps -o pgid= -p "$(cat $R/n$1.pid)" | tr -d ' ')"; }
# since <i> <mark>: node i's log lines written after line <mark>
since() { tail -n +$(($2 + 1)) $R/n$1.log; }

# mi <i> <method> [k=v ...]  -> JSON on stdout (integer values sent as numbers)
mi() {
  python3 - "$R" "$@" <<'PY'
import json, os, socket, sys
rd, node, meth = sys.argv[1], sys.argv[2], sys.argv[3]
srv = "%s/mi%s.sock" % (rd, node)
params = {}
for kv in sys.argv[4:]:
    k, v = kv.split("=", 1)
    params[k] = int(v) if v.lstrip("-").isdigit() else v
me = "%s/cli%d.sock" % (rd, os.getpid())
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(me); s.settimeout(5)
try:
    s.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":meth,"params":params or []}).encode(), srv)
    print(s.recv(65536).decode())
except Exception as e:
    print('{"error":"%s"}' % e)
finally:
    s.close(); os.unlink(me)
PY
}

# tap <i> <seconds> <out>  - record node i's controller datagrams (background it)
tap() { python3 "$HERE/wire_tap.py" capture v${1}p "$(ip4 $1)" $PORT "$2" "$3"; }
# replay <i> <file>  - send recorded datagrams again from inside node i's netns
replay() { ip netns exec ${NSP}n$1 python3 "$HERE/wire_tap.py" inject "$2" "$(ip4 $1)"; }

# bcast <i> <count> <tag>  - make node i broadcast <count> messages via SIP
bcast() {
  python3 - "$(ip4 $1)" "$2" "$3" <<'PY'
import socket, sys, time
ip, n, tag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0)); s.settimeout(1)
ok = 0
for k in range(n):
    m = ("OPTIONS sip:x@%s SIP/2.0\r\nVia: SIP/2.0/UDP 10.74.0.254:%d;branch=z9hG4bK%s%d\r\n"
         "From: <sip:t@10.74.0.254>;tag=1\r\nTo: <sip:x@%s>\r\nCall-ID: %s-%d\r\nCSeq: 1 OPTIONS\r\n"
         "X-Bcast: %s-%d\r\nContent-Length: 0\r\n\r\n") % (ip, s.getsockname()[1], tag, k, ip, tag, k, tag, k)
    s.sendto(m.encode(), (ip, 5060))
    try:
        s.recv(4096); ok += 1
    except socket.timeout:
        pass
    time.sleep(0.01)
print(ok)
PY
}
rx_count() { grep -ac "\[RX\] $2-" $R/n$1.log; }
