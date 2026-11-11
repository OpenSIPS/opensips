#!/bin/bash
# helpers for netns_tests.sh: namespaces n1..n4 on a private bridge, one OpenSIPS each,
# nothing leaves the host; needs root, iproute2, iptables, python3
set -u
: "${NEW:?set NEW to the install prefix of the build under test}"
OLD=${OLD:-}            # install prefix of a wire-version-1 build (T6)
R=${RIG_DIR:-/tmp/cl_ctr_rig}   # configs, logs, sockets; wiped on setup
RIG_TM=${RIG_TM:-0}     # 1: load tm with tm_replication_cluster=741
RIG_TAG_RELEASE=${RIG_TAG_RELEASE:-0}   # 1: release_tag_when_isolated=1
RIG_EVENTS=${RIG_EVENTS:-1}             # 0: no event routes (an older build has not these events)
RIG_PASSWORD=${RIG_PASSWORD:-rig74-not-a-secret-9f3a1c}   # the cluster password (T32 starts a node with another)
BR=br74
NSP=${RIG_NS_PREFIX:-}  # parallel runs: each its own prefix and RIG_DIR, under its own "unshare -n"
PORT=3741               # 741 (239.0.74.1) and 742 (239.0.74.2) share it: the IP_MULTICAST_ALL=0 case
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

modpath() { if [ -d "$1/lib64/opensips/modules" ]; then echo "$1/lib64/opensips/modules/"; else echo "$1/lib/opensips/modules/"; fi; }

ip4() { echo "10.74.0.1$1"; }
# nx <i> <cmd...>: run a command in node i's namespace
nx() { local i=$1; shift; ip netns exec ${NSP}n$i "$@"; }
# lb <prefix>: OpenSIPS unbuffers stderr, and glibc 2.37+ then writes a line in 128-byte
# pieces a node's processes interleave: a preloaded setbuf keeps it line-buffered
# (not for an ASan build, whose runtime refuses to load after a preload)
lb() {
  readelf -d "$1/sbin/opensips" 2>/dev/null | grep -q libasan && return
  [ -f $R/linebuf.so ] || cc -shared -fPIC -O2 -o $R/linebuf.so -x c - 2>/dev/null <<'C' || return
#include <stdio.h>
static char errbuf[16384];
void setbuf(FILE *f, char *buf)
{
	if (f == stderr && !buf)
		setvbuf(f, errbuf, _IOLBF, sizeof errbuf);
	else
		setvbuf(f, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}
C
  echo "env LD_PRELOAD=$R/linebuf.so"
}
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
  local TMMOD="" TMRT="" TRMOD="" EVRT=""
  # every cluster-state event logged as one "EVT" line; the master route also
  # reads $cl_ctr_role inside the route, which must not deadlock
  if [ "$RIG_EVENTS" = 1 ]; then
    EVRT='event_route[E_CL_CTR_ROLE] { xlog("EVT ROLE $param(cluster_id) $param(role) $param(old_role)\n"); }
event_route[E_CL_CTR_MASTER] { xlog("EVT MASTER $param(cluster_id) $param(master_ip) $param(node_id) now=$cl_ctr_role(741)\n"); }
event_route[E_CL_CTR_MEMBER] { xlog("EVT MEMBER $param(cluster_id) $param(node_id) $param(ip) $param(state) $param(reason)\n"); }
event_route[E_CL_CTR_REFUSED] { xlog("EVT REFUSED $param(cluster_id) $param(ip) $param(reason)\n"); }
event_route[E_CL_CTR_MERGE] { xlog("EVT MERGE $param(cluster_id) $param(master_ip) $param(was_master)\n"); }
event_route[E_CL_CTR_MAINTENANCE] { xlog("EVT MAINT $param(cluster_id) $param(node_id) $param(state)\n"); }
event_route[E_CL_CTR_ADMISSION] { xlog("EVT ADMISSION $param(cluster_id) $param(ip) $param(node_id) $param(state)\n"); }'
  fi
  # only when on: a build from before the parameter (PREV) refuses it
  [ "$RIG_TAG_RELEASE" != 0 ] && \
    TRMOD="modparam(\"clusterer\", \"release_tag_when_isolated\", $RIG_TAG_RELEASE)"
  [ -n "${RIG_NODE_ID:-}" ] && \
    TRMOD="$TRMOD
modparam(\"clusterer\", \"my_node_id\", $RIG_NODE_ID)"
  # RIG_NATIVE="<nodes>": also a member of the static cluster 900 of <nodes>
  # (RIG_NODE_ID must then be this node's number)
  local NATRT="" j
  if [ -n "${RIG_NATIVE:-}" ]; then
    TRMOD="$TRMOD
$(native900 $i $RIG_NATIVE)"
    NATRT='if ($hdr(X-Bcast900) != NULL) { cluster_broadcast_req(900, "$hdr(X-Bcast900)"); sl_send_reply(200, "sent"); exit; }'
  fi
  # RIG_BCAST=1: X-BcastB broadcasts on 741 with cluster_broadcast_req (the body
  # appended after ':' when there is one), logged as [RXB]; node events as [NODE]
  local BRT="" BEV=""
  if [ "${RIG_BCAST:-}" = 1 ]; then
    BRT='if ($hdr(X-BcastB) != NULL) { if ($rb != NULL) cluster_broadcast_req(741, "$hdr(X-BcastB):$rb"); else cluster_broadcast_req(741, "$hdr(X-BcastB)"); sl_send_reply(200, "sent"); exit; }'
    BEV='event_route[E_CLUSTERER_REQ_RECEIVED] { xlog("L_NOTICE", "[RXB] $param(src_id) $param(msg)\n"); }
event_route[E_CLUSTERER_NODE_STATE_CHANGED] { xlog("L_NOTICE", "[NODE] $param(cluster_id) $param(node_id) $param(new_state)\n"); }'
  fi
  [ -n "${RIG_MCAST:-}" ] && \
    TRMOD="$TRMOD
modparam(\"clusterer\", \"mcast_broadcasts\", $RIG_MCAST)"
  [ -n "${RIG_MCAST_WINDOW:-}" ] && \
    TRMOD="$TRMOD
modparam(\"clusterer\", \"mcast_window\", $RIG_MCAST_WINDOW)"
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
loadmodule "clusterer_controller.so"
$TMMOD
modparam("mi_datagram", "socket_name", "$R/mi$i.sock")
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "cluster_options", "cluster_id=741, use_controller=1")
modparam("clusterer", "cluster_options", "cluster_id=742, use_controller=1")
modparam("clusterer", "sharing_tag", "tag741/741=backup")
modparam("clusterer", "my_ip", "$IP")
modparam("clusterer", "password", "$RIG_PASSWORD")
modparam("clusterer", "query_time", $QT)
modparam("clusterer", "master_stickiness", $ST)
modparam("clusterer", "on_config_mismatch", "reject")
$TRMOD
modparam("clusterer", "cluster", "id=741,multicast=239.0.74.1:$PORT,bin_socket=bin:$IP:5588$UK")
modparam("clusterer", "cluster", "id=742,multicast=239.0.74.2:$PORT,bin_socket=bin:$IP:5588$UK")

route {
    $TMRT
    $NATRT
    $BRT
    sl_send_reply(200, "ok");
}
$EVRT
$BEV
EOF
}

# native900 <i> <nodes...>: node i's lines for the static cluster 900 of <nodes>,
# and an event route logging what it receives there as [RX900] <src> <msg>
native900() {
  local i=$1 j; shift
  echo "modparam(\"clusterer\", \"my_node_info\", \"cluster_id=900,url=bin:$(ip4 $i):5588\")"
  for j in "$@"; do [ "$j" != "$i" ] && \
    echo "modparam(\"clusterer\", \"neighbor_node_info\", \"cluster_id=900,node_id=$j,url=bin:$(ip4 $j):5588\")"; done
  echo 'event_route[E_CLUSTERER_REQ_RECEIVED] { xlog("L_NOTICE", "[RX900] $param(src_id) $param(msg)\n"); }'
}
# start_native <i> <prefix> <module .so> <nodes...>: node i (my_node_id i) in static cluster
# 900 only, on clusterer_controller.so or stock clusterer.so; X-Bcast broadcasts on 900
start_native() {
  local i=$1 P=$2 MOD=$3; shift 3
  cat > $R/n$i.cfg <<EOF
log_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=2
auto_aliases=no
socket=udp:$(ip4 $i):5060
socket=bin:$(ip4 $i):5588
mpath="$(modpath $P)"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "sl.so"
loadmodule "mi_datagram.so"
loadmodule "$MOD"
modparam("mi_datagram", "socket_name", "$R/mi$i.sock")
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", $i)
$(native900 $i "$@")
route {
    if (\$hdr(X-Bcast) != NULL) {
        cluster_broadcast_req(900, "\$hdr(X-Bcast)");
        sl_send_reply(200, "sent");
        exit;
    }
    sl_send_reply(200, "ok");
}
EOF
  ip netns exec ${NSP}n$i $(lb $P) $P/sbin/opensips -f $R/n$i.cfg -m 64 -M 16 -w $R \
     -P $R/n$i.pid 2>>$R/n$i.log
}

# start <i> <prefix> [stickiness] [query_time] [uuid]
start() {
  local i=$1 P=$2
  mkcfg "$@"
  ip netns exec ${NSP}n$i $(lb $P) $P/sbin/opensips -f $R/n$i.cfg -m 64 -M 16 -w $R \
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
    params[k] = (json.loads(v) if v[:1] in "[{" else
                 int(v) if v.lstrip("-").isdigit() else v)
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
  python3 - "$(ip4 $1)" "$2" "$3" "${4:-X-Bcast}" <<'PY'
import socket, sys, time
ip, n, tag, hdr = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0)); s.settimeout(1)
ok = 0
for k in range(n):
    m = ("OPTIONS sip:x@%s SIP/2.0\r\nVia: SIP/2.0/UDP 10.74.0.254:%d;branch=z9hG4bK%s%d\r\n"
         "From: <sip:t@10.74.0.254>;tag=1\r\nTo: <sip:x@%s>\r\nCall-ID: %s-%d\r\nCSeq: 1 OPTIONS\r\n"
         "%s: %s-%d\r\nContent-Length: 0\r\n\r\n") % (ip, s.getsockname()[1], tag, k, ip, tag, k, hdr, tag, k)
    s.sendto(m.encode(), (ip, 5060))
    try:
        s.recv(4096); ok += 1
    except socket.timeout:
        pass
    time.sleep(0.01)
print(ok)
PY
}
rx900() { grep -ac "\[RX900\] [0-9]* $2-" $R/n$1.log; }
