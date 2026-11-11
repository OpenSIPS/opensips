#!/bin/bash
# NEW=<prefix> [OLD=<wire-1 build> (T6)] [PREV=<-DCL_CTR_CAPS_MINE=0 build> (T27)] [GROUP=1..11] ./netns_tests.sh, as root
# GROUP runs one group on a fresh rig; checks assert effects, log lines only where the line is the behaviour
. "$(dirname "$0")/netns_rig.sh"
trap 'tc qdisc del dev v1p root 2>/dev/null; teardown' EXIT
PASS=0; FAIL=0; SKIPN=0; SKIPL=""
check() { if [ "$2" = 1 ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1  ($3)"; FAIL=$((FAIL+1)); fi; }
# skip <test> <why>: the test did not run; counted, never a failure
skip() { echo "  SKIP  $1  ($2)"; SKIPN=$((SKIPN+1)); SKIPL="$SKIPL${SKIPL:+, }$1 ($2)"; }
members() {  # members <node> <cluster> -> "ip:status:id ..." sorted
  mi $1 clusterer:list_members | python3 -c '
import json,sys
r=json.load(sys.stdin).get("result",[])
for c in r:
    if c.get("cluster_id")==int(sys.argv[1]):
        print(" ".join(sorted("%s:%s:%s"%(m["ip"],m["status"],m["node_id"]) for m in c["members"])))' $2
}
tagst() {  # tagst <node> -> state of the cluster-741 sharing tag on that node
  mi $1 clusterer:list_shtags | python3 -c '
import json,sys
try: d=json.load(sys.stdin).get("result",[])
except Exception: sys.exit()
print(" ".join(sorted(set(t["State"] for t in d if t.get("Cluster")==741))))'; }
cfgval() { mi $1 clusterer:list_config | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c["cluster_id"]==int(sys.argv[1]): print(c.get(sys.argv[2]))' $2 $3; }
nid() { members $1 741 | tr ' ' '\n' | grep "^$(ip4 $2):" | cut -d: -f3; }
# maint <node> <ip> -> that member's maintenance state as <node> sees it
maint() { mi $1 clusterer:list_members | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741:
        for m in c["members"]:
            if m["ip"]==sys.argv[1]: print(m.get("maintenance"))' $2; }
# admission <node> <ip> -> connecting/online as <node> sees that member, empty if unlisted
admission() { mi $1 clusterer:list_members | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741:
        for m in c["members"]:
            if m["ip"]==sys.argv[1]: print(m.get("admission"))' $2; }
role_of() { members $1 741 | tr ' ' '\n' | grep "^$2:" | cut -d: -f2; }
# stats <node> -> "name=value ..." of the clusterer_controller group
stats() { mi $1 statistics:get 'statistics=["clusterer_controller:"]' | python3 -c '
import json,sys
try: d=json.load(sys.stdin).get("result",{})
except Exception: d={}
print(" ".join("%s=%s" % (k.split(":",1)[1], v) for k,v in sorted(d.items()) if k.startswith("clusterer_controller:")))'; }
cstat() { stats $1 | tr ' ' '\n' | grep "^$2=" | cut -d= -f2; }
# rstat <node> -> its replays_refused-741, empty if the node is down or the build has none
rstat() { cstat $1 replays_refused-741; }
# rf_mark: the closing check counts that statistic from here; rf_growth: its growth since, on
# the nodes that report it (a lower value is a restarted node, counted from 0), else empty
rf_mark() { local i v; for i in 1 2 3 4; do v=$(rstat $i); eval RF$i=\${v:-0}; done; }
rf_growth() {
  local i v b n=""
  for i in 1 2 3 4; do
    v=$(rstat $i); [ -n "$v" ] || continue
    eval b=\${RF$i:-0}
    if [ "$v" -ge "$b" ] 2>/dev/null; then n=$(( ${n:-0} + v - b )); else n=$(( ${n:-0} + v )); fi
  done
  echo "$n"
}

GROUP=${GROUP:-}
grp() { [ -z "$GROUP" ] || [ "$GROUP" = "$1" ]; }
# boot <nodes> [start args]: with GROUP, the group's own cluster as the tests
# before it leave one - n1..n3 elect (n3 master), then n4 joins if <nodes> is 4
boot() {
  local n=$1 i; shift
  [ -n "$GROUP" ] || return 0
  for i in 1 2 3; do start $i $NEW "$@"; done; sleep 12
  [ "$n" = 4 ] && { start 4 $NEW "$@"; sleep 8; }
  U1=$(cfgval 1 741 cluster_uuid)
  for i in 1 2 3 4; do eval RP$i=$([ -f $R/n$i.log ] && wc -l < $R/n$i.log || echo 0); done
  rf_mark
}

setup
if grp 1; then
echo "=== T1 cold start, 3 nodes, two clusters on one port ==="
for i in 1 2 3; do start $i $NEW; done
sleep 12
M1=$(members 1 741); M3=$(members 3 742)
echo "    741 @n1: $M1"; echo "    742 @n3: $M3"
check "741: 3 members, n3 master" $([ "$(echo $M1 | wc -w)" = 3 ] && echo "$M1" | grep -q "10.74.0.13:master" && echo 1 || echo 0) "$M1"
check "742: 3 members, n3 master" $([ "$(echo $M3 | wc -w)" = 3 ] && echo "$M3" | grep -q "10.74.0.13:master" && echo 1 || echo 0) "$M3"
T=$(cfgval 1 741 term); check "term reported and >= 1" $([ "${T:-0}" -ge 1 ] 2>/dev/null && echo 1 || echo 0) "term=$T"
U1=$(cfgval 1 741 cluster_uuid); U2=$(cfgval 2 741 cluster_uuid); U3=$(cfgval 3 741 cluster_uuid)
echo "    741 uuid: n1=$U1 n2=$U2 n3=$U3 ($(cfgval 1 741 cluster_uuid_state))"
check "one cluster uuid on all three nodes" $([ -n "$U1" ] && [ "$U1" = "$U2" ] && [ "$U2" = "$U3" ] && echo 1 || echo 0) "$U1/$U2/$U3"
check "741 and 742 founded different uuids" $([ "$U1" != "$(cfgval 1 742 cluster_uuid)" ] && echo 1 || echo 0) ""
# a leaked datagram is handed to its own cluster's worker, which has it already
X=$(cat $R/n?.log | grep -ac "already accepted, dropping\|speaks wire version")
check "no cross-cluster multicast leakage (IP_MULTICAST_ALL)" $([ "$X" = 0 ] && echo 1 || echo 0) "$X lines"

echo "=== T3 SIGKILL restart of member n1 ==="
ID1=$(nid 3 1)
stop_hard 1; rm -f $R/n1.pid
start 1 $NEW; sleep 10
check "n2 logged n1's restart by incarnation" $(grep -aq "10.74.0.11 restarted (incarnation" $R/n2.log && echo 1 || echo 0) ""
check "n1 kept node_id $ID1" $([ "$(nid 3 1)" = "$ID1" ] && echo 1 || echo 0) "now $(nid 3 1)"
check "restarted n1 adopted the running cluster's uuid" $([ "$(cfgval 1 741 cluster_uuid)" = "$U1" ] && echo 1 || echo 0) "$(cfgval 1 741 cluster_uuid)"

echo "=== T4 node_id held for a node that left cleanly ==="
ID2=$(nid 3 2)
stop_graceful 2; rm -f $R/n2.pid; sleep 2
start 4 $NEW; sleep 8
ID4=$(nid 3 4)
check "newcomer n4 did NOT take n2's id $ID2" $([ -n "$ID4" ] && [ "$ID4" != "$ID2" ] && echo 1 || echo 0) "n4=$ID4"
start 2 $NEW; sleep 8
check "n2 came back with its old id $ID2" $([ "$(nid 3 2)" = "$ID2" ] && echo 1 || echo 0) "now $(nid 3 2)"
check "n3 logged giving the id back" $(grep -aq "10.74.0.12 rejoined - giving it back node_id $ID2" $R/n3.log && echo 1 || echo 0) ""
fi

if grp 2; then
boot 3
echo "=== T5 partition heal between masters with DIFFERENT settings ==="
stop_graceful 4; rm -f $R/n4.pid; sleep 2
nx 4 iptables -I INPUT -p udp --dport $PORT ! -s 10.74.0.14 -j DROP
start 4 $NEW 0          # master_stickiness=0 - differs from the cluster
sleep 12
check "isolated n4 self-promoted" $(members 4 741 | grep -q "10.74.0.14:master" && echo 1 || echo 0) "$(members 4 741)"
nx 4 iptables -D INPUT -p udp --dport $PORT ! -s 10.74.0.14 -j DROP
sleep 16
A=0; for i in 1 2 3 4; do alive $i && A=$((A+1)); done
check "nobody exited after the heal (4/4 alive)" $([ $A = 4 ] && echo 1 || echo 0) "$A alive"
check "n4 warned it will NOT merge" $(grep -aq "NOT merging" $R/n4.log && echo 1 || echo 0) ""
# n3's id is established by now, so it may refuse n4 at the identity filter
# before the beacon's settings are even compared - either refusal is right
check "n3 refused the merge (settings or identity)" $(grep -aq "NOT merging\|10.74.0.14 belongs to another cluster" $R/n3.log && echo 1 || echo 0) ""
MM=$(members 3 741)
check "main partition intact: 3 members, n3 master" $([ "$(echo $MM | wc -w)" = 3 ] && echo "$MM" | grep -q "10.74.0.13:master" && echo 1 || echo 0) "$MM"

echo "=== T6 a wire-version-1 node on the group ==="
stop_graceful 4; rm -f $R/n4.pid; sleep 2
if [ -n "$OLD" ]; then
RIG_EVENTS=0 start 4 $OLD; sleep 10
check "new nodes name the v1 peer" $(grep -aq "10.74.0.14 speaks wire version 1, this node speaks 5" $R/n3.log && echo 1 || echo 0) ""
MM=$(members 3 741)
check "main partition unaffected: 3 members" $([ "$(echo $MM | wc -w)" = 3 ] && echo 1 || echo 0) "$MM"
else
skip T6 "OLD, a wire-version-1 build, not given"
fi

echo "=== T7 independent deployment, SAME settings, same group/password/cluster_id ==="
stop_graceful 4; rm -f $R/n4.pid; sleep 2
nx 4 iptables -I INPUT -p udp --dport $PORT ! -s 10.74.0.14 -j DROP
start 4 $NEW
sleep 36            # founds alone, and its uuid outlives the 30 s grace
check "isolated n4 founded its own, established uuid" $([ "$(cfgval 4 741 cluster_uuid_state)" = established ] && [ "$(cfgval 4 741 cluster_uuid)" != "$U1" ] && echo 1 || echo 0) "$(cfgval 4 741 cluster_uuid_state) $(cfgval 4 741 cluster_uuid)"
nx 4 iptables -D INPUT -p udp --dport $PORT ! -s 10.74.0.14 -j DROP
sleep 16
MM=$(members 3 741)
check "main cluster did NOT absorb n4: 3 members, n3 master" $([ "$(echo $MM | wc -w)" = 3 ] && echo "$MM" | grep -q "10.74.0.13:master" && echo 1 || echo 0) "$MM"
check "n4 still alone, master of its own" $(members 4 741 | grep -q "^10.74.0.14:master" && [ "$(members 4 741 | wc -w)" = 1 ] && echo 1 || echo 0) "$(members 4 741)"
check "n3 logged the foreign cluster" $(grep -aq "10.74.0.14 belongs to another cluster" $R/n3.log && echo 1 || echo 0) ""
check "n4 logged the foreign cluster" $(grep -aq "belongs to another cluster" $R/n4.log && echo 1 || echo 0) ""
FC=$(cfgval 3 741 foreign_clusters); U4=$(cfgval 4 741 cluster_uuid)
check "n3 lists n4's cluster in foreign_clusters" $(echo "$FC" | grep -q "$U4" && echo "$FC" | grep -q "10.74.0.14" && echo 1 || echo 0) "$FC"
A=0; for i in 1 2 3 4; do alive $i && A=$((A+1)); done
check "nobody exited (4/4 alive)" $([ $A = 4 ] && echo 1 || echo 0) "$A alive"
stop_graceful 4; rm -f $R/n4.pid

echo "=== T8 a partition of the SAME cluster still heals ==="
nx 2 iptables -I INPUT -p udp --dport $PORT -j DROP
nx 2 iptables -I OUTPUT -p udp --dport $PORT -j DROP
sleep 14
check "isolated n2 elected itself (same uuid)" $(members 2 741 | grep -q "10.74.0.12:master" && [ "$(cfgval 2 741 cluster_uuid)" = "$U1" ] && echo 1 || echo 0) "$(members 2 741) $(cfgval 2 741 cluster_uuid)"
check "the T8 cut fired ($(dropped 2 INPUT) in, $(dropped 2 OUTPUT) out dropped)" $([ "$(dropped 2 INPUT)" -gt 0 ] && [ "$(dropped 2 OUTPUT)" -gt 0 ] && echo 1 || echo 0) ""
nx 2 iptables -D INPUT -p udp --dport $PORT -j DROP
nx 2 iptables -D OUTPUT -p udp --dport $PORT -j DROP
sleep 20
MM=$(members 3 741); M2=$(members 2 741)
check "healed: n3 sees 3 members with one master" $([ "$(echo $MM | wc -w)" = 3 ] && [ "$(echo $MM | tr ' ' '\n' | grep -c ':master:')" = 1 ] && echo 1 || echo 0) "$MM"
# masters rank on the members they hear now: on its table, isolated n2 (still listing
# unpurged peers) could tie the majority and win on term
H3=$(echo "$MM" | tr ' ' '\n' | grep ':master:' | cut -d: -f1); H2=$(echo "$M2" | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
check "healed: n2 follows the majority's master" $([ -n "$H3" ] && [ "$H3" = "$H2" ] && [ "$H3" != "$(ip4 2)" ] && echo 1 || echo 0) "n3: $H3, n2: $H2"

echo "=== T9 pinned uuid, whole-cluster restart ==="
for i in 1 2 3; do stop_graceful $i; rm -f $R/n$i.pid; done; sleep 2
for i in 1 2 3; do start $i $NEW 1 2 fleet-a; done; sleep 10
EXP=$(python3 -c '
import hashlib
b=bytearray(hashlib.blake2b(b"fleet-a",digest_size=16,key=b"cl_ctr_cluster_uuid").digest())
b[6]=(b[6]&0x0F)|0x80; b[8]=(b[8]&0x3F)|0x80; h=b.hex()
print("%s-%s-%s-%s-%s"%(h[:8],h[8:12],h[12:16],h[16:20],h[20:]))')
P1=$(cfgval 1 741 cluster_uuid); P3=$(cfgval 3 742 cluster_uuid)
echo "    expected $EXP, n1/741=$P1 n3/742=$P3"
check "pinned: every node, both clusters, the name's v8 uuid" $([ "$P1" = "$EXP" ] && [ "$P3" = "$EXP" ] && echo 1 || echo 0) ""
check "pinned state reported" $([ "$(cfgval 2 741 cluster_uuid_state)" = pinned ] && echo 1 || echo 0) "$(cfgval 2 741 cluster_uuid_state)"
MM=$(members 1 741)
check "pinned cluster formed: 3 members" $([ "$(echo $MM | wc -w)" = 3 ] && echo 1 || echo 0) "$MM"
fi

if grp 3; then
boot 3 1 2 fleet-a
echo "=== T11 an older MEMBER_LIST arriving late does not undo a newer one ==="
# n2 misses L1 (tag on n1), gets L2 (tag on n2), then L1 replayed: unseen by its replay window,
# only the list's own stamp can order it
I1=$(nid 3 1); I2=$(nid 3 2); N11=$(members 3 741 | wc -w)
nx 2 iptables -I INPUT -p udp -s $(ip4 3) --dport $PORT -j DROP
tap 3 6 $R/t11.json >/dev/null & TP=$!
sleep 0.5; M11=$(wc -l < $R/n3.log); T11F=$(date +%s.%N)
mi 3 clusterer:shtag_force cluster_id=741 node_id=$I1 >/dev/null
# a pin is said in four lists, one at once and three with the next keepalives: n2 misses all
for k in $(seq 1 40); do [ "$(since 3 $M11 | grep -ac "cluster 741\] sent MEMBER_LIST ([0-9]* members)$")" -ge 4 ] && break; sleep 0.5; done
wait $TP
CUT11=$(dropped 2 INPUT)
nx 2 iptables -D INPUT -p udp -s $(ip4 3) --dport $PORT -j DROP
check "the T11 cut fired ($CUT11 dropped)" $([ "$CUT11" -gt 0 ] && echo 1 || echo 0) ""
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' $R/t11.json)
# a list of N11 members is 89 + 17 x N11 bytes, as nothing else the master sends to the group
NL1=$(python3 "$HERE/wire_tap.py" count $R/t11.json 239.0.74.1 $((89 + 17 * N11)) $T11F)
check "recorded the master's datagrams ($N), L1 among them ($NL1 member lists sent after the pin)" $([ "${NL1:-0}" -gt 0 ] && echo 1 || echo 0) "$N datagrams, $NL1 lists of $N11 members"
check "n2 missed L1 (still auto)" $([ "$(cfgval 2 741 shtag_mode)" = auto ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
mi 3 clusterer:shtag_force cluster_id=741 node_id=$I2 >/dev/null; sleep 2
check "n2 applied L2 (override:$I2)" $([ "$(cfgval 2 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
replay 3 $R/t11.json >/dev/null; sleep 2
check "after the late L1: n2 still override:$I2" $([ "$(cfgval 2 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
check "after the late L1: n1 still override:$I2" $([ "$(cfgval 1 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 1 741 shtag_mode)"
mi 3 clusterer:shtag_auto cluster_id=741 >/dev/null; sleep 1

echo "=== T12 tm anycast Via cid: absent until the node has an id, then the live id ==="
# a sink records the top Via of each request n4 relays; n4's controller traffic is held 1.2 s
# (under query_time, so it founds no cluster) so the first ones leave before it has an id
python3 - $R/t12.json <<'PY' & SK=$!
import json, re, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 5070)); s.settimeout(0.5)
seen, end = {}, time.time() + 14
while time.time() < end:
    try: d = s.recv(65535).decode("latin-1")
    except socket.timeout: continue
    cid = re.search(r"^Call-ID:\s*(\S+)", d, re.M | re.I)
    via = re.search(r"^Via:[^\r\n]*", d, re.M | re.I)
    if cid and via and not d.startswith("SIP/2.0"):
        seen.setdefault(cid.group(1), via.group(0))
json.dump(seen, open(sys.argv[1], "w"))
PY
sleep 0.5
python3 - <<'PY' & SD=$!
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0))
for k in range(120):
    m = ("OPTIONS sip:x@10.74.0.14 SIP/2.0\r\nVia: SIP/2.0/UDP 10.74.0.254:%d;branch=z9hG4bKtm%d\r\n"
         "From: <sip:t@10.74.0.254>;tag=1\r\nTo: <sip:x@10.74.0.14>\r\nCall-ID: tm-%03d\r\n"
         "CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nX-Relay: 1\r\nContent-Length: 0\r\n\r\n") % (s.getsockname()[1], k, k)
    s.sendto(m.encode(), ("10.74.0.14", 5060)); time.sleep(0.1)
PY
nx 4 iptables -I INPUT -p udp --dport $PORT -j DROP
RIG_TM=1 start 4 $NEW 1 2 fleet-a
sleep 1.2
nx 4 iptables -D INPUT -p udp --dport $PORT -j DROP
wait $SD; wait $SK
I4=$(nid 3 4)
read -r TOT NOCID GOOD BAD <<<"$(python3 - $R/t12.json "$I4" <<'PY'
import json, re, sys
seen, me = json.load(open(sys.argv[1])), sys.argv[2]
order = [seen[k] for k in sorted(seen)]
cids = [re.search(r";cid=([^;,\s]*)", v) for v in order]
nocid = sum(1 for c in cids if not c)
good = sum(1 for c in cids if c and c.group(1) == me)
bad = sum(1 for c in cids if c and c.group(1) != me)
print(len(order), nocid, good, bad)
PY
)"
echo "    n4 node_id $I4: $TOT relayed, $NOCID without cid, $GOOD with cid=$I4, $BAD other"
check "requests relayed before n4 had an id carry no cid" $([ "${NOCID:-0}" -gt 0 ] && echo 1 || echo 0) "$NOCID"
check "requests relayed after the join carry cid=$I4" $([ -n "$I4" ] && [ "${GOOD:-0}" -gt 0 ] && echo 1 || echo 0) "$GOOD"
check "no request carried any other cid (-1, 0, stale)" $([ "${BAD:-1}" = 0 ] && echo 1 || echo 0) "$BAD"

# T11 replays packets on purpose; from here on no control packet may be
# refused as a replay - a node's sequence never restarts within its life
for i in 1 2 3 4; do eval RP$i=$(wc -l < $R/n$i.log); done
rf_mark

echo "=== T53 the tag pinned on the master, which then goes into maintenance: one holder, another node ==="
# n4 joined in T12: first every node online on the master
for k in $(seq 1 40); do
  MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
  [ -n "$MN" ] && [ "$(members $MN 741 | wc -w)" = 4 ] && [ "$(admission $MN $(ip4 4))" = online ] && break
  sleep 1
done
MID=$(nid $MN $MN)
mi $MN clusterer:shtag_force cluster_id=741 node_id=${MID:-0} >/dev/null
for k in $(seq 1 40); do V=""; for i in 1 2 3 4; do V="$V $(cfgval $i 741 shtag_mode)"; done; [ "$(echo $V | tr ' ' '\n' | sort -u)" = "override:$MID" ] && break; sleep 0.5; done
check "the pin on master n$MN (node $MID) is known to all four" $([ -n "$MID" ] && [ "$(echo $V | tr ' ' '\n' | sort -u)" = "override:$MID" ] && [ "$(tagst $MN)" = active ] && echo 1 || echo 0) "$V, n$MN $(tagst $MN)"
mi $MN clusterer:maintenance cluster_id=741 state=evicted >/dev/null
for k in $(seq 1 40); do
  sleep 1
  MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
  U=$(echo $MS | tr ' ' '\n' | sort -u)
  NA=0; for i in 1 2 3 4; do [ "$(tagst $i)" = active ] && NA=$((NA+1)); done
  [ "$(echo $MS | wc -w)" = 4 ] && [ "$(echo "$U" | wc -l)" = 1 ] && [ "$U" != "$MIP" ] && [ $NA = 1 ] && [ "$(tagst $MN)" != active ] && break
done
NM=$(echo $MS | cut -d' ' -f1); NN=${NM##*.}; NN=${NN#1}
check "the master in maintenance handed over: one new master ($NM), named by all four" $([ "$(echo $MS | wc -w)" = 4 ] && [ "$(echo "$U" | wc -l)" = 1 ] && [ -n "$NM" ] && [ "$NM" != "$MIP" ] && echo 1 || echo 0) "$MS"
check "exactly one node holds the tag: the new master, not n$MN in maintenance" $([ $NA = 1 ] && [ "$(tagst ${NN:-0})" = active ] && [ "$(tagst $MN)" != active ] && [ "$(maint $MN $MIP)" = evicted ] && echo 1 || echo 0) "$NA holder(s), n$NN $(tagst ${NN:-0}), n$MN $(tagst $MN) ($(maint $MN $MIP))"
for k in $(seq 1 40); do V=""; for i in 1 2 3 4; do V="$V $(cfgval $i 741 shtag_mode)"; done; [ "$(echo $V | tr ' ' '\n' | sort -u)" = auto ] && break; sleep 1; done
check "the pin left with it: automatic allocation on all four" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = auto ] && echo 1 || echo 0) "$V"
mi $MN clusterer:maintenance cluster_id=741 state=none >/dev/null
for k in $(seq 1 40); do V=""; for i in 1 2 3 4; do V="$V $(maint $i $MIP)"; done; [ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && break; sleep 0.5; done
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
NA=0; for i in 1 2 3 4; do [ "$(tagst $i)" = active ] && NA=$((NA+1)); done
check "n$MN back in service on every node; one master, one holder" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && [ "$(echo $MS | wc -w)" = 4 ] && [ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ $NA = 1 ] && echo 1 || echo 0) "$V / $MS / $NA holder(s)"

echo "=== T54 the tag pinned on a member that is then killed: the master takes the tag before the purge ==="
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
XID=$(nid $MN $x); QT54=$(cfgval $MN 741 query_time)
mi $MN clusterer:shtag_force cluster_id=741 node_id=${XID:-0} >/dev/null
for k in $(seq 1 40); do NA=0; for i in 1 2 3 4; do [ "$(tagst $i)" = active ] && NA=$((NA+1)); done; [ "$(tagst $x)" = active ] && [ $NA = 1 ] && break; sleep 0.5; done
check "pinned member n$x (node $XID) holds the tag, alone" $([ -n "$XID" ] && [ "$(tagst $x)" = active ] && [ $NA = 1 ] && echo 1 || echo 0) "n$x $(tagst $x), $NA holder(s)"
M54=$(wc -l < $R/n$MN.log)
stop_hard $x; rm -f $R/n$x.pid
# silent, it leaves the election window after 3 to 4 query periods (CL_CTR_ELECT_FACTOR, by
# whole periods) and the master's next ALIVE round lifts the pin; the purge is at 6 periods
for k in $(seq 1 $((5 * ${QT54:-2} + 30))); do sleep 1; [ "$(tagst $MN)" = active ] && break; done
S54=$k
NA=0; for i in 1 2 3 4; do [ $i = $x ] && continue; [ "$(tagst $i)" = active ] && NA=$((NA+1)); done
echo "    n$x killed: master n$MN held the tag $S54 s later (query_time $QT54; n$x still listed: $(members $MN 741 | tr ' ' '\n' | grep -c "^$(ip4 $x):"))"
check "another node holds the tag after n$x was killed: master n$MN, alone" $([ "$(tagst $MN)" = active ] && [ $NA = 1 ] && [ "$(cfgval $MN 741 shtag_mode)" = auto ] && echo 1 || echo 0) "n$MN $(tagst $MN), $NA holder(s), $(cfgval $MN 741 shtag_mode)"
check "the master lifted the pin when its node fell silent, not when it purged it" $(since $MN $M54 | grep -aq "cluster 741\] node $XID holding the forced sharing tag is silent or holds no role" && ! since $MN $M54 | grep -aq "cluster 741\] forced shtag node $XID timed out" && echo 1 || echo 0) "$(since $MN $M54 | grep -a "forced sh" | tail -1 | cut -c1-140)"
start $x $NEW 1 2 fleet-a
for k in $(seq 1 40); do sleep 1; [ "$(admission $MN $(ip4 $x))" = online ] && [ "$(members $x 741 | wc -w)" = 4 ] && break; done
NA=0; for i in 1 2 3 4; do [ "$(tagst $i)" = active ] && NA=$((NA+1)); done
check "n$x back and online on the master; one tag holder" $([ "$(admission $MN $(ip4 $x))" = online ] && [ $NA = 1 ] && echo 1 || echo 0) "n$x '$(admission $MN $(ip4 $x))', $NA holder(s)"

echo "=== T61 a joiner admitted and never heard: the master forgets it after 5 s, before it can hold the queue ==="
# a JOIN_REQ sealed with the password in the name of the bridge address, where no node runs,
# as a recorded request sent again to a master that never saw it: admitted, it stays silent
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
FIP=10.74.0.254; M61=$(wc -l < $R/n$MN.log)
for k in 1 2 3 4 5 6 7 8; do
  python3 $HERE/malformed_test.py joinreq $FIP 239.0.74.1 $PORT 741 239.0.74.1 $RIG_PASSWORD > $R/t61.json
  for j in 1 2 3 4; do since $MN $M61 | grep -aq "cluster 741\] admitting $FIP - CONNECTING" && break 2; sleep 0.5; done
done
check "the master admitted a JOIN_REQ in the name of $FIP, where no node runs (sent $k time(s))" $(since $MN $M61 | grep -aq "cluster 741\] admitting $FIP - CONNECTING" && echo 1 || echo 0) "$(cat $R/t61.json)"
for k in $(seq 1 60); do since $MN $M61 | grep -aq "cluster 741\] $FIP was admitted 5 s ago and has not been heard since - forgetting it" && break; sleep 0.5; done
for j in $(seq 1 20); do since $MN $M61 | grep -aq "EVT MEMBER 741 [0-9]* $FIP left dropped" && break; sleep 0.5; done
check "never heard, it is forgotten after 5 s: not listed, nobody CONNECTING, and no warning that it holds the queue" $(since $MN $M61 | grep -aq "cluster 741\] $FIP was admitted 5 s ago and has not been heard since - forgetting it" && ! since $MN $M61 | grep -aq "cluster 741\] $FIP is still CONNECTING after" && [ -z "$(admission $MN $FIP)" ] && [ "$(cstat $MN connecting-741)" = 0 ] && echo 1 || echo 0) "listed '$(admission $MN $FIP)', connecting-741 $(cstat $MN connecting-741)"
check "the master's events say so: its admission as connecting, then the member dropped" $(since $MN $M61 | grep -aq "EVT ADMISSION 741 $FIP [0-9]* connecting" && since $MN $M61 | grep -aq "EVT MEMBER 741 [0-9]* $FIP left dropped" && echo 1 || echo 0) "$(since $MN $M61 | grep -a "EVT [A-Z]* 741 .*$FIP" | tail -3 | tr '\n' ' ' | cut -c1-200)"
# the members learnt of it from its NODE_ASSIGN: they purge it once the master's relay left it out
for k in $(seq 1 60); do V=""; for i in 1 2 3 4; do V="$V $(members $i 741 | wc -w)"; done; [ "$(echo $V | tr ' ' '\n' | sort -u)" = 4 ] && break; sleep 1; done
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
NA=0; for i in 1 2 3 4; do [ "$(tagst $i)" = active ] && NA=$((NA+1)); done
check "every node lists the four members again; one master, one tag holder" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = 4 ] && [ "$(echo $MS | wc -w)" = 4 ] && [ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ $NA = 1 ] && echo 1 || echo 0) "$V / $MS / $NA holder(s)"
fi

if grp 4; then
boot 4 1 2 fleet-a
echo "=== T13 a member paused past every timeout wakes without electing itself ==="
# 15 s: past the watchdog (3 s), election window (6 s) and purge window (12 s); woken,
# n1 finds every timer expired and every peer stale although only it was gone
M1=$(wc -l < $R/n1.log)
pause_node 1; sleep 15; resume_node 1; sleep 10
check "woken n1 did not elect itself" $(since 1 $M1 | grep -aq "my role changed: [a-z]* -> master\|became master" && echo 0 || echo 1) "$(since 1 $M1 | grep -a 'became master' | head -1 | cut -c1-120)"
check "woken n1 did not purge its peers" $(since 1 $M1 | grep -aq "purging timed-out peer" && echo 0 || echo 1) "$(since 1 $M1 | grep -ac 'purging timed-out peer') purges"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "one master, and all four nodes name it" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"
echo "    n1 self_stalls: $(cfgval 1 741 self_stalls)"
MV=$(members $(echo $MS | cut -d' ' -f1 | sed 's/.*\.1//') 741)
check "the master still knows every member by node_id" $(echo "$MV" | tr ' ' '\n' | grep -q ':0$' && echo 0 || echo 1) "$MV"

echo "=== T14 the master paused past every timeout: one master after it wakes ==="
OLDM=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); OM=${OLDM##*.}; OM=${OM#1}
T0=$(cfgval 2 741 term); MO=$(wc -l < $R/n$OM.log)
pause_node $OM; sleep 15
NEWM=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
resume_node $OM; sleep 12
check "the others elected a new master while $OLDM was paused" $([ -n "$NEWM" ] && [ "$NEWM" != "$OLDM" ] && echo 1 || echo 0) "new=$NEWM"
check "woken $OLDM did not purge its peers" $(since $OM $MO | grep -aq "purging timed-out peer" && echo 0 || echo 1) "$(since $OM $MO | grep -ac 'purging timed-out peer') purges"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "one master afterwards, and all four nodes name it" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"
FM=$(echo $MS | cut -d' ' -f1)
echo "    master before $OLDM (term $T0), while paused $NEWM, after $FM (term $(cfgval 2 741 term))"
check "the master chosen meanwhile kept it - the woken one stood down" $([ "$FM" = "$NEWM" ] && since $OM $MO | grep -aq "stands down" && echo 1 || echo 0) "after=$FM"
MV=$(members $(echo $FM | sed 's/.*\.1//') 741)
check "the master knows every member by node_id" $(echo "$MV" | tr ' ' '\n' | grep -q ':0$' && echo 0 || echo 1) "$MV"

echo "=== T15 kernel drops on a full receive buffer are counted ==="
# paused n2's full receive buffer drops junk, counted via SO_RXQ_OVFL once it reads again;
# 741 and 742 share the port, so either socket may take the flood
drops2() { echo $(( $(cfgval 2 741 rx_kernel_drops) + $(cfgval 2 742 rx_kernel_drops) )); }
D0=$(drops2); B2=$(cfgval 2 741 rcvbuf_bytes)
pause_node 2
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0))
junk = b"\x55" * 1200          # 0x55: the magic of no wire version
for _ in range(4000):
    s.sendto(junk, ("10.74.0.12", 3741))
PY
sleep 1; resume_node 2; sleep 6
D1=$(drops2)
echo "    n2 rcvbuf_bytes $B2, rx_kernel_drops $D0 -> $D1"
check "rx_kernel_drops grew" $([ "${D1:-0}" -gt "${D0:-0}" ] 2>/dev/null && echo 1 || echo 0) "$D0 -> $D1"
check "n2 still a member after the flood" $(members 3 741 | grep -q "10.74.0.12:" && echo 1 || echo 0) "$(members 3 741)"

echo "=== T16 a member that alone stops hearing the master asks before electing ==="
# one-sided: only this member's input from the master is cut, its peers still hear it
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
for c in 1 2 3 4; do [ "$(ip4 $c)" != "$MIP" ] && break; done
H0=$(cfgval $c 741 election_holds); MC=$(wc -l < $R/n$c.log)
nx $c iptables -I INPUT -p udp -s $MIP --dport $PORT -j DROP
sleep 10
CUT16=$(dropped $c INPUT)
nx $c iptables -D INPUT -p udp -s $MIP --dport $PORT -j DROP
check "the T16 cut fired ($CUT16 dropped)" $([ "$CUT16" -gt 0 ] && echo 1 || echo 0) ""
sleep 4
echo "    n$c cut from master $MIP for 10 s; election_holds $H0 -> $(cfgval $c 741 election_holds)"
check "n$c did not re-elect while cut" $(since $c $MC | grep -aq "went silent .* re-electing" && echo 0 || echo 1) "$(since $c $MC | grep -a 're-electing' | head -1 | cut -c1-110)"
check "n$c held the election because peers still hear the master" $([ "$(cfgval $c 741 election_holds)" -gt "${H0:-0}" ] 2>/dev/null && echo 1 || echo 0) "$(cfgval $c 741 election_holds)"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "one master, still $MIP, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u)" = "$MIP" ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T17 maintenance: out of election and tags, handover from the master ==="
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
BIP=$(members 2 741 | tr ' ' '\n' | grep ':backup:' | cut -d: -f1)
BN=${BIP##*.}; BN=${BN#1}; MN=${MIP##*.}; MN=${MN#1}
echo "    master $MIP, backup $BIP"
mi $BN clusterer:maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $BIP)"; done
check "every node lists backup $BIP as evicted" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = evicted ] && echo 1 || echo 0) "$V"
RO=""; for i in 1 2 3 4; do RO="$RO $(role_of $i $BIP)"; done
check "no node names $BIP backup any more" $(echo "$RO" | grep -q backup && echo 0 || echo 1) "$RO"
BID=$(nid $MN $BN)
echo "    $BIP is node_id '$BID' in the master's view: $(members $MN 741)"
check "pinning the tag on a node in maintenance is refused" $(mi $MN clusterer:shtag_force cluster_id=741 node_id=${BID:-0} | grep -q "maintenance" && echo 1 || echo 0) "$(mi $MN clusterer:shtag_force cluster_id=741 node_id=${BID:-0} | cut -c1-120)"
check "$BIP lists itself as evicted" $([ "$(maint $BN $BIP)" = evicted ] && echo 1 || echo 0) ""
for i in 1 2 3 4; do eval L$i=$(wc -l < $R/n$i.log); done
mi $MN clusterer:maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
NM=$(echo $MS | cut -d' ' -f1)
check "the master in maintenance handed over: one new master, named by all" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && [ "$NM" != "$MIP" ] && [ "$NM" != "$BIP" ] && echo 1 || echo 0) "$MS"
WS=0; for i in 1 2 3 4; do eval m=\$L$i; WS=$((WS + $(since $i $m | grep -ac "went silent (its"))); done
check "the handover did not wait for the master watchdog (no master 'went silent')" $([ $WS = 0 ] && echo 1 || echo 0) "$WS"
NN=${NM##*.}; NN=${NN#1}
check "the active tag moved with it: $NM active, $MIP backup" $([ "$(tagst $NN)" = active ] && [ "$(tagst $MN)" = backup ] && echo 1 || echo 0) "new $(tagst $NN) old $(tagst $MN)"
mi $BN clusterer:maintenance cluster_id=741 state=none >/dev/null
mi $MN clusterer:maintenance cluster_id=741 state=none >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $BIP) $(maint $i $MIP)"; done
check "both back in service on every node" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && echo 1 || echo 0) "$V"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "still one master, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T18 one member cut off for 11, 12 and 13 s: the majority's master leads after each heal ==="
# near the purge window the isolated node (higher term) still lists unpurged members: a tie on
# table counts, 3 to 1 on members heard; the second depends on ALIVE/purge ticks, hence 3 lengths
for cut in 11 12 13; do
  MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
  for x in 4 3 2 1; do [ "$(ip4 $x)" != "$MIP" ] && break; done
  nx $x iptables -I INPUT -p udp --dport $PORT -j DROP
  nx $x iptables -I OUTPUT -p udp --dport $PORT -j DROP
  sleep $cut
  CUT18=$(( $(dropped $x INPUT) + $(dropped $x OUTPUT) ))
  nx $x iptables -D INPUT -p udp --dport $PORT -j DROP
  nx $x iptables -D OUTPUT -p udp --dport $PORT -j DROP
  sleep 14
  MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
  check "${cut} s cut of n$x ($CUT18 dropped): majority's master $MIP leads, named by all" $([ "$CUT18" -gt 0 ] && [ "$(echo $MS | tr ' ' '\n' | sort -u)" = "$MIP" ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"
done
echo "=== T19 a killed master is replaced within the learned timeout ==="
# steady link: watchdog at its 3 s floor; a SIGKILLed master (no GOODBYE) must be replaced
# within that plus one probe round and an election tick
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for o in 1 2 3 4; do [ $o != $MN ] && break; done
TO=$(cfgval $o 741 master_timeout_ms)
echo "    n$o's watchdog for master $MIP: ${TO} ms (mean $(cfgval $o 741 master_ka_mean_ms), dev $(cfgval $o 741 master_ka_dev_ms))"
check "a steady link keeps the watchdog at its 3 s floor" $([ "${TO:-0}" = 3000 ] && echo 1 || echo 0) "$TO"
for i in 1 2 3 4; do eval K$i=$(wc -l < $R/n$i.log); done
T0=$(date +%s.%N); stop_hard $MN; rm -f $R/n$MN.pid
NEWM=""; for k in $(seq 1 40); do
  MS=""; for i in 1 2 3 4; do [ $i = $MN ] && continue; MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
  U=$(echo $MS | tr ' ' '\n' | sort -u)
  if [ "$(echo $MS | wc -w)" = 3 ] && [ "$(echo "$U" | wc -l)" = 1 ] && [ "$U" != "$MIP" ]; then NEWM=$U; break; fi
  sleep 0.25
done
DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))")
check "the survivors agree on a new master within 8 s (took ${DT} s: $NEWM)" $([ -n "$NEWM" ] && python3 -c "import sys; sys.exit(0 if $DT <= 8 else 1)" && echo 1 || echo 0) "$MS"
CF=0; for i in 1 2 3 4; do [ $i = $MN ] && continue; eval m=\$K$i; CF=$((CF + $(since $i $m | grep -a "cluster 741\]" | grep -ac "confirm that master .* is silent - electing"))); done
check "survivors elected on their peers' confirmation, not a lone timeout" $([ $CF -gt 0 ] && echo 1 || echo 0) "$CF node(s)"
NN=${NEWM##*.}; NN=${NN#1}; TS=""; for k in 1 2 3 4; do TS=$(tagst $NN); [ "$TS" = active ] && break; sleep 0.25; done
LISTED=$(members $NN 741 | tr ' ' '
' | grep -c "^$MIP:")
check "the new master took the active tag at once, before purging $MIP (still listed: $LISTED)" $([ "$TS" = active ] && [ "$LISTED" = 1 ] && echo 1 || echo 0) "tag $TS, listed $LISTED"
start $MN $NEW 1 2 fleet-a; sleep 8

echo "=== T26 a killed master restarted at once survives the new master's first tag announcement ==="
# as Restart=always: it rejoins while still listed, and the new master announces the tag to
# it before it has an identity (a TCP receiver segfaulted on it)
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
RL=$(wc -l < $R/n$MN.log)
stop_hard $MN; rm -f $R/n$MN.pid
start $MN $NEW 1 2 fleet-a
PID=$(cat $R/n$MN.pid 2>/dev/null)
OK=""; for k in $(seq 1 60); do
  MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
  [ "$(echo $MS | wc -w)" = 4 ] && [ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && { OK=1; break; }
  sleep 0.25
done
sleep 3
check "n$MN restarted at once is still the same process ($PID)" $(alive $MN && [ "$(cat $R/n$MN.pid 2>/dev/null)" = "$PID" ] && echo 1 || echo 0) "alive=$(alive $MN && echo yes || echo no)"
check "no segfault on n$MN" $(since $MN $RL | grep -aqi 'segfault' && echo 0 || echo 1) "$(since $MN $RL | grep -ai 'segfault' | head -1 | cut -c1-120)"
NM=$(echo $MS | cut -d' ' -f1); NN=${NM##*.}; NN=${NN#1}
check "one master named by all four, holding the active tag ($NM)" $([ -n "$OK" ] && [ "$(tagst $NN)" = active ] && echo 1 || echo 0) "$MS tag $(tagst $NN)"
alive $MN || { start $MN $NEW 1 2 fleet-a; sleep 8; }
fi

if grp 5; then
boot 4 1 2 fleet-a
echo "=== T20 a lossy, jittery link into one member: patience, not an election ==="
# keepalive gaps of 2-4 s become routine: n1 must learn a longer wait; once clean it shrinks
# back towards 3 s over minutes - patience is meant to outlast one burst of loss
x=1; MX=$(wc -l < $R/n$x.log); PEAK=0
# nothing changes in this test: the member lists the master still sends to the group are its
# refresh, one every 30 keepalives - its datagrams are recorded for 115 s and the lists counted
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}; N20=$(members $MN 741 | wc -w)
tap $MN 115 $R/t20.json >/dev/null & TP=$!
tc qdisc add dev v${x}p root netem delay 300ms 300ms loss 25%
for k in 1 2 3 4 5 6 7 8 9; do sleep 10; T=$(cfgval $x 741 master_timeout_ms); [ "${T:-0}" -gt "$PEAK" ] 2>/dev/null && PEAK=$T; done
tc qdisc del dev v${x}p root
E=$(since $x $MX | grep -a "cluster 741\]" | grep -ac "went silent (its"); P=$(since $x $MX | grep -a "cluster 741\]" | grep -ac "asking .* peer")
echo "    n$x over 90 s: $P watchdog round(s), $E election(s), learned wait peaked at $PEAK ms, $(cfgval $x 741 master_false_suspicions) false suspicion(s)"
check "no election on the lossy member" $([ "$E" = 0 ] && echo 1 || echo 0) "$E"
check "it learned to wait longer than 3 s" $([ "$PEAK" -gt 3000 ] && echo 1 || echo 0) "$PEAK"
sleep 30
T=$(cfgval $x 741 master_timeout_ms)
check "the learned wait shrinks once the link is clean ($PEAK -> $T ms)" $([ "${T:-0}" -lt "$PEAK" ] && [ "${T:-0}" -ge 3000 ] && echo 1 || echo 0) "$T"
wait $TP
NL20=$(python3 "$HERE/wire_tap.py" count $R/t20.json 239.0.74.1 $((89 + 17 * N20)))
check "the master multicast its member list unasked, every 30 keepalives ($NL20 list(s) of $N20 members in 115 s)" $([ "${NL20:-0}" -ge 2 ] 2>/dev/null && echo 1 || echo 0) "$NL20"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "one master throughout, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T21 a member cut off in both directions suspects itself first ==="
# nobody answers its question: the likeliest fault, so it waits one more watchdog
# period before electing itself
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
for x in 1 2 3 4; do [ "$(ip4 $x)" != "$MIP" ] && break; done
MX=$(wc -l < $R/n$x.log)
nx $x iptables -I INPUT -p udp --dport $PORT -j DROP
nx $x iptables -I OUTPUT -p udp --dport $PORT -j DROP
sleep 14
CUT21=$(( $(dropped $x INPUT) + $(dropped $x OUTPUT) ))
nx $x iptables -D INPUT -p udp --dport $PORT -j DROP
nx $x iptables -D OUTPUT -p udp --dport $PORT -j DROP
L21=$(since $x $MX | grep -a "cluster 741\]")
W1=$(echo "$L21" | grep -an "may be the one cut off" | head -1 | cut -d: -f1)
E1=$(echo "$L21" | grep -an "my role changed: [a-z]* -> master" | head -1 | cut -d: -f1)
check "the T21 cut fired ($CUT21 dropped)" $([ "$CUT21" -gt 0 ] && echo 1 || echo 0) ""
check "isolated n$x suspected itself before electing itself" $([ -n "$W1" ] && { [ -z "$E1" ] || [ "$W1" -lt "$E1" ]; } && echo 1 || echo 0) "wait line $W1, election line $E1"
sleep 14
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "healed: $MIP leads, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u)" = "$MIP" ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T22 a member cut off for 25 s does not raise the term ==="
# nobody confirms the master is gone, so its self-election keeps the term (PreVote)
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 1 2 3 4; do [ "$(ip4 $x)" != "$MIP" ] && break; done
# wait until rested: after T21 its local health and margin stay raised, and a watchdog
# stretched past the 25 s cut would never reach electing itself
for k in $(seq 1 60); do
  [ "$(cfgval $x 741 local_health)" = 0 ] && [ "$(cfgval $x 741 master_timeout_ms)" -le 5000 ] 2>/dev/null && break
  sleep 2
done
echo "    n$x before the cut: local health $(cfgval $x 741 local_health), watchdog $(cfgval $x 741 master_timeout_ms) ms"
TB=$(cfgval $MN 741 term); MX=$(wc -l < $R/n$x.log)
nx $x iptables -I INPUT -p udp --dport $PORT -j DROP
nx $x iptables -I OUTPUT -p udp --dport $PORT -j DROP
sleep 25
CUT22=$(( $(dropped $x INPUT) + $(dropped $x OUTPUT) ))
TI=$(cfgval $x 741 term)
nx $x iptables -D INPUT -p udp --dport $PORT -j DROP
nx $x iptables -D OUTPUT -p udp --dport $PORT -j DROP
sleep 16
TA=$(cfgval $MN 741 term)
echo "    term before $TB, on isolated n$x during the cut $TI, after the heal $TA"
check "the T22 cut fired ($CUT22 dropped)" $([ "$CUT22" -gt 0 ] && echo 1 || echo 0) ""
check "isolated n$x elected itself unconfirmed, without raising the term" $(since $x $MX | grep -a "cluster 741\]" | grep -aq "unconfirmed - nobody confirmed" && [ "$TI" = "$TB" ] && echo 1 || echo 0) "term $TI vs $TB"
check "the cluster's term is unchanged by the partition" $([ "$TA" = "$TB" ] && echo 1 || echo 0) "$TB -> $TA"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "healed: $MIP leads, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u)" = "$MIP" ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T23 a stuttering member slows its own judgement (local health) ==="
# 1.3 s pauses stay under the stall threshold but keep its timers running late
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
for x in 1 2 3 4; do [ "$(ip4 $x)" != "$MIP" ] && break; done
MX=$(wc -l < $R/n$x.log); LH=0
for k in 1 2 3 4 5 6 7 8 9 10; do
  pause_node $x; sleep 1.3; resume_node $x; sleep 1
  v=$(cfgval $x 741 local_health); [ "${v:-0}" -gt "$LH" ] 2>/dev/null && LH=$v
done
echo "    n$x local_health peaked at $LH"
check "the stuttering member's local health rose" $([ "$LH" -ge 2 ] && echo 1 || echo 0) "$LH"
check "it did not elect itself" $(since $x $MX | grep -a "cluster 741\]" | grep -aq "my role changed: [a-z]* -> master" && echo 0 || echo 1) ""
check "it did not purge anyone" $(since $x $MX | grep -aq "purging timed-out peer" && echo 0 || echo 1) ""
sleep 25
V=$(cfgval $x 741 local_health)
check "healthy again 25 s after the stutter ends (local_health $V)" $([ "$V" = 0 ] && echo 1 || echo 0) "$V"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "one master throughout, $MIP, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u)" = "$MIP" ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"
fi

if grp 6; then
boot 4 1 2 fleet-a
echo "=== T24 release_tag_when_isolated: a cut-off master, or a member cut off alone, gives up the active tag ==="
check "with the option off, no tag was released anywhere" $(cat $R/n?.log | grep -aq "releasing the active sharing tag" && echo 0 || echo 1) ""
for i in 1 2 3 4; do stop_graceful $i; rm -f $R/n$i.pid; done; sleep 2
for i in 1 2 3 4; do RIG_TAG_RELEASE=1 start $i $NEW 1 2 fleet-a; done; sleep 16
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
check "the option is on everywhere" $([ "$(cfgval $MN 741 release_tag_when_isolated)" = 1 ] && echo 1 || echo 0) ""
# the master hears 3 of 4 and keeps the tag; the member, counting the 4 it knew, elects
# itself and releases it (~10 s to elect unconfirmed, then one election window)
for x in 1 2 3 4; do [ $x != $MN ] && break; done
MX=$(wc -l < $R/n$x.log)
nx $x iptables -I INPUT -p udp --dport $PORT -j DROP; nx $x iptables -I OUTPUT -p udp --dport $PORT -j DROP
sleep 25
XREL=$(cfgval $x 741 tag_released); XTAG=$(tagst $x); XROLE=$(members $x 741 | tr ' ' '\n' | grep "^$(ip4 $x):" | cut -d: -f2)
nx $x iptables -D INPUT -p udp --dport $PORT -j DROP; nx $x iptables -D OUTPUT -p udp --dport $PORT -j DROP
check "a member cut off: master $MIP (3 of 4) keeps the tag" $([ "$(cfgval $MN 741 tag_released)" = 0 ] && echo 1 || echo 0) "$(cfgval $MN 741 tag_released)"
check "the member cut off alone elected itself and released the tag" $([ "$XROLE" = master ] && [ "$XREL" = 1 ] && [ "$XTAG" = backup ] && since $x $MX | grep -aq "releasing the active sharing tag" && echo 1 || echo 0) "role $XROLE, tag_released $XREL, tag $XTAG"
sleep 16
check "healed: n$x a member again, holding no released state" $([ "$(cfgval $x 741 tag_released)" = 0 ] && [ "$(members $x 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)" = "$MIP" ] && echo 1 || echo 0) "released $(cfgval $x 741 tag_released), master $(members $x 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"
# the master cut off: it hears 1 of 4, releases the tag, the rest elect
MM=$(wc -l < $R/n$MN.log)
nx $MN iptables -I INPUT -p udp --dport $PORT -j DROP; nx $MN iptables -I OUTPUT -p udp --dport $PORT -j DROP
sleep 15
REL=$(cfgval $MN 741 tag_released)
NEWM=$(members $x 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
nx $MN iptables -D INPUT -p udp --dport $PORT -j DROP; nx $MN iptables -D OUTPUT -p udp --dport $PORT -j DROP
check "the cut-off master released the active tag" $([ "$REL" = 1 ] && since $MN $MM | grep -aq "releasing the active sharing tag" && echo 1 || echo 0) "tag_released=$REL"
check "the rest elected another master meanwhile" $([ -n "$NEWM" ] && [ "$NEWM" != "$MIP" ] && echo 1 || echo 0) "$NEWM"
sleep 16
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "healed: one master, named by all; the old master holds no released state" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && [ "$(cfgval $MN 741 tag_released)" = 0 ] && echo 1 || echo 0) "$MS released=$(cfgval $MN 741 tag_released)"

echo "=== T25 maintenance of another node, and the full level ==="
# cl_state <node> <node_id> -> enabled|disabled: that node as <node>'s clusterer has it
cl_state() { mi $1 clusterer:list | python3 -c '
import json,sys
try: d=json.load(sys.stdin).get("result",{})
except Exception: sys.exit()
for c in d.get("Clusters",[]):
    if c.get("cluster_id")==741:
        for n in c.get("Nodes",[]):
            if n.get("node_id")==int(sys.argv[1]): print(n.get("state"))' $2; }
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 1 2 3 4; do [ $x != $MN ] && break; done
for y in 1 2 3 4; do [ $y != $MN ] && [ $y != $x ] && break; done
XID=$(nid $y $x); XIP=$(ip4 $x)
echo "    from n$y: n$x ($XIP, node_id $XID) into full; master $MIP"
for i in 1 2 3 4; do eval F$i=$(wc -l < $R/n$i.log); done
mi $y clusterer:maintenance cluster_id=741 state=full node_id=${XID:-0} >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $XIP)"; done
check "every node lists n$x as full, asked from n$y" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = full ] && echo 1 || echo 0) "$V"
check "n$x applied it to itself on n$y's request" $(eval m=\$F$x; since $x $m | grep -aq "asks this node into maintenance state full" && echo 1 || echo 0) ""
D=""; for i in 1 2 3 4; do [ $i = $x ] && continue; D="$D $(cl_state $i $XID)"; done
check "the other nodes disabled n$x in their clusterer" $([ "$(echo $D | tr ' ' '\n' | sort -u)" = disabled ] && echo 1 || echo 0) "$D"
RO=""; for i in 1 2 3 4; do RO="$RO $(role_of $i $XIP)"; done
check "nobody names n$x master or backup" $(echo "$RO" | grep -q 'master\|backup' && echo 0 || echo 1) "$RO"
mi $y clusterer:maintenance cluster_id=741 state=none node_id=${XID:-0} >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $XIP)"; done
check "back in service on every node" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && echo 1 || echo 0) "$V"
D=""; for i in 1 2 3 4; do [ $i = $x ] && continue; D="$D $(cl_state $i $XID)"; done
check "the other nodes enabled n$x again" $([ "$(echo $D | tr ' ' '\n' | sort -u)" = enabled ] && echo 1 || echo 0) "$D"
check "a node_id outside the cluster is refused" $(mi $y clusterer:maintenance cluster_id=741 state=full node_id=999 | grep -q "not a member" && echo 1 || echo 0) "$(mi $y clusterer:maintenance cluster_id=741 state=full node_id=999 | cut -c1-100)"
fi

if grp 7; then
boot 4 1 2 fleet-a
echo "=== T27 a member advertising no capabilities: none shared, broadcasts by TCP, nothing else held back ==="
# one member on PREV (-DCL_CTR_CAPS_MINE=0); every build of this wire version has the other
# mechanisms, so only what needs every member's capability (multicast broadcasts) waits for it
if [ -z "${PREV:-}" ] || [ ! -x "$PREV/sbin/opensips" ]; then
  skip T27 "PREV, a build of this wire version advertising no capabilities, not given"
else
capsof() { mi $1 clusterer:list_members | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741:
        for m in c["members"]:
            if m["ip"]==sys.argv[1]: print(" ".join(m.get("capabilities",["(no field)"])))' $2; }
clcaps() { mi $1 clusterer:list_config | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741: print(" ".join(c.get("cluster_capabilities",["(no field)"])))'; }
ALL="probe maint_set maint_full admission heartbeat"   # mcast-data also needs a broadcast socket
nomc() { sed 's/ *mcast-data//'; }
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
for y in 1 2 3 4; do [ $y != $MN ] && [ $y != $x ] && break; done
XIP=$(ip4 $x); YIP=$(ip4 $y)
echo "    n$x on the previous build; asking from n$y; master $MIP"
stop_graceful $x; for i in 1 2 3 4; do eval W$i=$(wc -l < $R/n$i.log); done
RIG_EVENTS=0 start $x $PREV 1 2 fleet-a; sleep 10
check "n$x rejoined on the build advertising no capabilities" $(alive $x && members $y 741 | tr ' ' '\n' | grep -q "^$XIP:" && echo 1 || echo 0) "$(members $y 741)"
check "the master lists no capabilities for n$x, all for n$y" $([ -z "$(capsof $MN $XIP)" ] && [ "$(capsof $MN $YIP | nomc)" = "$ALL" ] && echo 1 || echo 0) "n$x '$(capsof $MN $XIP)' n$y '$(capsof $MN $YIP)'"
check "the cluster's shared capabilities are none while n$x runs it (master and n$y)" $([ -z "$(clcaps $MN)" ] && [ -z "$(clcaps $y)" ] && echo 1 || echo 0) "master '$(clcaps $MN)' n$y '$(clcaps $y)'"
eval m=\$W$MN
check "the master sends broadcasts by TCP while n$x is aboard" $(since $MN $m | grep -aq "cluster 741\] broadcasts now go by TCP" && echo 1 || echo 0) "$(since $MN $m | grep -a "broadcasts now go by" | tail -1)"
XID=$(nid $y $x)
R1=$(mi $y clusterer:maintenance cluster_id=741 state=evicted node_id=${XID:-0})
sleep 3
check "remote maintenance of n$x is applied all the same" $([ "$(maint $y $XIP)" = evicted ] && echo 1 || echo 0) "$(echo "$R1" | cut -c1-140) / $(maint $y $XIP)"
mi $y clusterer:maintenance cluster_id=741 state=none node_id=${XID:-0} >/dev/null
R2=$(mi $y clusterer:maintenance cluster_id=741 state=full)
sleep 3
check "the full level on n$y is applied all the same" $([ "$(maint $y $YIP)" = full ] && echo 1 || echo 0) "$(echo "$R2" | cut -c1-140) / $(maint $y $YIP)"
mi $y clusterer:maintenance cluster_id=741 state=none >/dev/null
sleep 3
if [ $MN != $x ]; then
  for i in 1 2 3 4; do eval Q$i=$(wc -l < $R/n$i.log); done
  T0=$(date +%s.%N); stop_hard $MN; rm -f $R/n$MN.pid
  # agreement among the survivors on this build (an older one may not
  # answer this MI command by its current name)
  NEWM=""; for k in $(seq 1 60); do
    MS=""; for i in 1 2 3 4; do [ $i = $MN ] || [ $i = $x ] && continue; MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
    U=$(echo $MS | tr ' ' '\n' | sort -u)
    if [ "$(echo $MS | wc -w)" = 2 ] && [ "$(echo "$U" | wc -l)" = 1 ] && [ "$U" != "$MIP" ]; then NEWM=$U; break; fi
    sleep 0.25
  done
  DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))")
  CO=0; for i in 1 2 3 4; do [ $i = $MN ] || [ $i = $x ] && continue; eval m=\$Q$i; CO=$((CO + $(since $i $m | grep -ac "may be the one cut off"))); done
  check "a master killed with n$x aboard: replaced within 8 s, no survivor suspecting itself (took ${DT} s: $NEWM)" $([ -n "$NEWM" ] && [ $CO = 0 ] && python3 -c "import sys; sys.exit(0 if $DT <= 8 else 1)" && echo 1 || echo 0) "cut-off waits $CO, $MS"
  start $MN $NEW 1 2 fleet-a
fi
stop_graceful $x; start $x $NEW 1 2 fleet-a; sleep 10
for i in 1 2 3 4; do eval ALLNEW$i=$(wc -l < $R/n$i.log); done   # T35: from here every node runs this build
check "all on this build again: the cluster shares every capability" $([ "$(clcaps $y | nomc)" = "$ALL" ] && echo 1 || echo 0) "'$(clcaps $y)'"
fi

echo "=== T28 statistics, one set per cluster ==="
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
N741=$(stats $MN | tr ' ' '\n' | grep -c -- '-741='); N742=$(stats $MN | tr ' ' '\n' | grep -c -- '-742=')
check "every statistic, once per cluster (38 each for 741 and 742)" $([ "$N741" = 38 ] && [ "$N742" = 38 ] && echo 1 || echo 0) "741: $N741, 742: $N742"
M=""; for i in 1 2 3 4; do M="$M $(cstat $i members-741)/$(cfgval $i 741 member_count)"; done
check "members-741 is the live count on every node" $(echo $M | tr ' ' '\n' | awk -F/ '$1!=4{b=1} END{print b?0:1}') "$M (stat/table)"
check "the master: role 2, is_master 1; n$x: is_master 0" $([ "$(cstat $MN role-741)" = 2 ] && [ "$(cstat $MN is_master-741)" = 1 ] && [ "$(cstat $x is_master-741)" = 0 ] && echo 1 || echo 0) "role $(cstat $MN role-741) is_master $(cstat $MN is_master-741) / $(cstat $x is_master-741)"
# the statistic is the highest term heard, list_config the master's own: a claimant
# that yielded at the cold start may have asserted a higher one
check "term-741 is at least the master's term in clusterer:list_config" $(S=$(cstat $MN term-741); C=$(cfgval $MN 741 term); [ -n "$S" ] && [ -n "$C" ] && [ "$C" -ge 1 ] && [ "$S" -ge "$C" ] && echo 1 || echo 0) "$(cstat $MN term-741) vs $(cfgval $MN 741 term)"
check "every node counted at least one master change" $(for i in 1 2 3 4; do [ "$(cstat $i master_changes-741)" -ge 1 ] 2>/dev/null || { echo 0; exit; }; done; echo 1) "$(for i in 1 2 3 4; do echo -n "$(cstat $i master_changes-741) "; done)"
J0=$(cstat $MN members_joined-741); L0=$(cstat $MN members_left-741)
stop_graceful $x; sleep 2; start $x $NEW 1 2 fleet-a; sleep 8
J1=$(cstat $MN members_joined-741); L1=$(cstat $MN members_left-741)
check "n$x restarted: the master counted it leaving and joining" $([ "${L1:-0}" -gt "${L0:-0}" ] && [ "${J1:-0}" -gt "${J0:-0}" ] && echo 1 || echo 0) "left $L0 -> $L1, joined $J0 -> $J1"

echo "=== T29 events: role, master, members, maintenance ==="
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for i in 1 2 3 4; do eval V$i=$(wc -l < $R/n$i.log); done
stop_hard $MN; rm -f $R/n$MN.pid
NEWM=""; for k in $(seq 1 60); do
  MS=""; for i in 1 2 3 4; do [ $i = $MN ] && continue; MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
  U=$(echo $MS | tr ' ' '\n' | sort -u)
  if [ "$(echo $MS | wc -w)" = 3 ] && [ "$(echo "$U" | wc -l)" = 1 ] && [ "$U" != "$MIP" ]; then NEWM=$U; break; fi
  sleep 0.25
done
NN=${NEWM##*.}; NN=${NN#1}; sleep 2
eval VN=\$V$NN
check "the new master raised E_CL_CTR_ROLE, to master" $(since $NN $VN | grep -aq "EVT ROLE 741 master " && echo 1 || echo 0) "$(since $NN $VN | grep -a 'EVT ROLE' | tail -1)"
EM=""; for i in 1 2 3 4; do [ $i = $MN ] && continue; eval m=\$V$i; EM="$EM $(since $i $m | grep -a "EVT MASTER 741 $NEWM " | grep -c .)"; done
check "every survivor raised E_CL_CTR_MASTER naming $NEWM" $(echo $EM | tr ' ' '\n' | awk '$1<1{b=1} END{print b?0:1}') "$EM"
check "the event route read \$cl_ctr_role while it ran - no deadlock" $(since $NN $VN | grep -aq "EVT MASTER 741 $NEWM [0-9]* now=master" && echo 1 || echo 0) "$(since $NN $VN | grep -a 'EVT MASTER' | tail -1)"
for k in $(seq 1 40); do since $NN $VN | grep -aq "EVT MEMBER 741 [0-9]* $MIP left timeout" && break; sleep 0.5; done
check "the new master raised E_CL_CTR_MEMBER for $MIP: left, timeout" $(since $NN $VN | grep -aq "EVT MEMBER 741 [0-9]* $MIP left timeout" && echo 1 || echo 0) "$(since $NN $VN | grep -a 'EVT MEMBER' | tail -2 | tr '\n' ' ')"
start $MN $NEW 1 2 fleet-a; sleep 8
check "... and for $MIP joining again" $(since $NN $VN | grep -aq "EVT MEMBER 741 0 $MIP joined new" && echo 1 || echo 0) ""
for x in 1 2 3 4; do [ $x != $NN ] && [ $x != $MN ] && break; done
for i in 1 2 3 4; do eval V$i=$(wc -l < $R/n$i.log); done
mi $x clusterer:maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
EV=""; for i in 1 2 3 4; do eval m=\$V$i; EV="$EV $(since $i $m | grep -a "EVT MAINT 741 [0-9]* evicted" | grep -c .)"; done
check "E_CL_CTR_MAINTENANCE on every node, n$x's own included" $(echo $EV | tr ' ' '\n' | awk '$1<1{b=1} END{print b?0:1}') "$EV"
mi $x clusterer:maintenance cluster_id=741 state=none >/dev/null; sleep 4
fi

if grp 8; then
boot 4 1 2 fleet-a
echo "=== T30 malformed datagrams: no crash, no change, a bounded log ==="
# malformed_test.py unsealed, then sealed with the password's key from non-members, a member and
# the master: the handshake and beacon parsers only (test.c feeds the session handlers)
MAL=$HERE/malformed_test.py; PW=$RIG_PASSWORD
view() { for i in 1 2 3 4; do echo "$(members $i 741) / $(members $i 742)"; done | sort -u; }
fuuids() { for i in 1 2 3 4; do for c in 741 742; do mi $i clusterer:list_config | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c["cluster_id"]==int(sys.argv[1]): print(" ".join(sorted(f["cluster_uuid"] for f in c.get("foreign_clusters") or [])))' $c; done; done | tr ' ' '\n' | sort -u | grep . | tr '\n' ' '; }
alive4() { local a=0 i; for i in 1 2 3 4; do alive $i && a=$((a+1)); done; echo $a; }
mark() { for i in 1 2 3 4; do eval L$i=$(wc -l < $R/n$i.log); done; }
lines() { local i m; for i in 1 2 3 4; do eval m=\$L$i; echo -n "$(since $i $m | wc -l) "; done; }
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
V0=$(view); TM0=$(cfgval $MN 741 term); FU0=$(fuuids); AF0=$(cstat $MN auth_failures-741)
mark; sleep 10; Q=$(lines | tr ' ' '\n' | sort -n | tail -1)    # 2Q: a quiet node's lines over the flood's 23 s
mark
python3 $MAL outsider 10.74.0.254 $(ip4 1),$(ip4 2),$(ip4 3),$(ip4 4),239.0.74.1,239.0.74.2 $PORT 741 742 20 > $R/mal1.json
sleep 3
echo "    no password: $(cat $R/mal1.json)"
check "no password: every node still running" $([ "$(alive4)" = 4 ] && echo 1 || echo 0) "$(alive4) of 4"
V1=$(view)
check "no password: every node's view unchanged" $([ "$V1" = "$V0" ] && [ "$(echo "$V1" | wc -l)" = 1 ] && echo 1 || echo 0) "$V1"
check "no password: term unchanged" $([ "$(cfgval $MN 741 term)" = "$TM0" ] && echo 1 || echo 0) "$TM0 -> $(cfgval $MN 741 term)"
LL=$(lines)
check "no password: a log line per kind of refusal, not per datagram (<= $((2 * Q + 30)) lines a node)" $(echo $LL | tr ' ' '\n' | awk -v b=$((2 * Q + 30)) '$1>b{x=1} END{print x?0:1}') "lines:$LL, quiet ${Q}"
FC=$(for i in 1 2 3 4; do eval m=\$L$i; since $i $m; done | grep -ac "another cluster")
check "random cluster uuids are not taken for another cluster" $([ "$(fuuids)" = "$FU0" ] && [ "$FC" = 0 ] && echo 1 || echo 0) "foreign uuids now: $(fuuids | wc -w) (were $(echo $FU0 | wc -w)), $FC log lines"
AF1=$(cstat $MN auth_failures-741)
check "the bodies that do not decrypt are counted as authentication failures" $([ "${AF1:-0}" -gt "${AF0:-0}" ] && echo 1 || echo 0) "auth_failures $AF0 -> $AF1"
SRC=""; for k in $(seq 100 119); do ip addr add 10.74.0.$k/24 dev $BR; SRC="$SRC,10.74.0.$k"; done; SRC=${SRC#,}
mark; AF2=$(cstat $MN auth_failures-741)
python3 $MAL sealed $SRC 239.0.74.1 $PORT 741 239.0.74.1 $PW 15 > $R/mal2.json
sleep 3
for k in $(seq 100 119); do ip addr del 10.74.0.$k/24 dev $BR; done
echo "    sealed with the bootstrap key, no member: $(cat $R/mal2.json)"
check "bootstrap key: the packets passed decryption (none failed it; the master named a sender's empty JOIN_REQ)" $([ "$(cstat $MN auth_failures-741)" = "$AF2" ] && eval m=\$L$MN && since $MN $m | grep -aq "JOIN_REQ from 10.74.0.1[01][0-9] names no valid address" && echo 1 || echo 0) "auth_failures $AF2 -> $(cstat $MN auth_failures-741)"
check "bootstrap key, no member (JOIN_REQ, beacon, KEY_GRANT, ACK, JOIN_REJECT, JOIN_WAIT; any other type dropped): every node still running" $([ "$(alive4)" = 4 ] && echo 1 || echo 0) "$(alive4) of 4"
V2=$(view)
check "bootstrap key, no member: every node's view unchanged" $([ "$V2" = "$V0" ] && [ "$(echo "$V2" | wc -l)" = 1 ] && echo 1 || echo 0) "$V2"
for x in 1 2 3 4; do [ $x != $MN ] && break; done
nx $x python3 $MAL sealed $(ip4 $x) 239.0.74.1 $PORT 741 239.0.74.1 $PW 8 lite > $R/mal3.json &
nx $MN python3 $MAL sealed $(ip4 $MN) 239.0.74.1 $PORT 741 239.0.74.1 $PW 8 lite > $R/mal4.json
wait; sleep 10
echo "    bootstrap key, from n$x: $(cat $R/mal3.json)"; echo "    bootstrap key, from master n$MN: $(cat $R/mal4.json)"
check "bootstrap key, from a member's and the master's address: every node still running" $([ "$(alive4)" = 4 ] && echo 1 || echo 0) "$(alive4) of 4"
V3=$(view)
check "bootstrap key, from a member's and the master's address: every node's view unchanged" $([ "$V3" = "$V0" ] && [ "$(echo "$V3" | wc -l)" = 1 ] && echo 1 || echo 0) "$V3"

echo "=== T31 several nodes joining at once ==="
# three members restarted at once x5 (stopped, then killed), then all four cold x3 with no
# pinned uuid: distinct ids, one master, one uuid each time
ids_ok() { local v; v=$(members $1 $2); [ "$(echo $v | wc -w)" = 4 ] && [ "$(echo $v | tr ' ' '\n' | grep -c ':master:')" = 1 ] && \
  [ "$(echo $v | tr ' ' '\n' | cut -d: -f3 | grep -v '^0$' | sort -u | wc -l)" = 4 ]; }
settled() { [ "$(view | wc -l)" = 1 ] && ids_ok 1 741 && ids_ok 1 742; }
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for r in 1 2 3 4 5; do
  for i in 1 2 3 4; do [ $i = $MN ] && continue
    if [ $r -le 3 ]; then kill -TERM "$(cat $R/n$i.pid)"; else stop_hard $i; fi; done
  sleep 3; for i in 1 2 3 4; do [ $i != $MN ] && rm -f $R/n$i.pid; done
  for i in 1 2 3 4; do [ $i != $MN ] && start $i $NEW 1 2 fleet-a & done; wait
  T0=$(date +%s.%N); OK=0
  for k in $(seq 1 80); do settled && { OK=1; break; }; sleep 0.25; done
  DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))"); sleep 3
  check "round $r ($([ $r -le 3 ] && echo stopped || echo killed)): three back at once in $DT s, distinct ids, master still $MIP" $([ $OK = 1 ] && settled && [ "$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)" = "$MIP" ] && echo 1 || echo 0) "$(view | tr '\n' '|')"
done
for r in 1 2 3; do
  for i in 1 2 3 4; do stop_hard $i; rm -f $R/n$i.pid; done; sleep 2
  for i in 1 2 3 4; do start $i $NEW & done; wait
  T0=$(date +%s.%N); OK=0
  for k in $(seq 1 160); do settled && { OK=1; break; }; sleep 0.25; done
  DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))")
  sleep 36            # past the uuid's grace: it must be established, and one
  UU=$(for i in 1 2 3 4; do echo "$(cfgval $i 741 cluster_uuid) $(cfgval $i 742 cluster_uuid)"; done | sort -u)
  ST=$(for i in 1 2 3 4; do echo "$(cfgval $i 741 cluster_uuid_state) $(cfgval $i 742 cluster_uuid_state)"; done | sort -u)
  check "cold round $r: four started at once settled in $DT s - one master, distinct ids, one view" $([ $OK = 1 ] && settled && echo 1 || echo 0) "$(view | tr '\n' '|')"
  check "cold round $r: one established uuid per cluster on all four" $([ "$(echo "$UU" | wc -l)" = 1 ] && [ "$ST" = "established established" ] && echo 1 || echo 0) "$(echo $UU) / $(echo $ST)"
done

echo "=== T58 a cold start while undecryptable datagrams keep arriving: no cluster is founded until they stop, then one ==="
# session-magic datagrams naming 741 that no key opens, five a second from the bridge to the
# group and to every node; 742 is sent none, and its founding meanwhile shows the nodes ran
for i in 1 2 3 4; do stop_hard $i; rm -f $R/n$i.pid; done; sleep 2
for i in 1 2 3 4; do eval J$i=$(wc -l < $R/n$i.log); nx $i iptables -I INPUT -p udp -s 10.74.0.254 --dport $PORT -j ACCEPT; done
python3 $MAL junk 10.74.0.254 $(ip4 1),$(ip4 2),$(ip4 3),$(ip4 4),239.0.74.1 $PORT 741 5 150 > $R/junk.json & JK=$!
sleep 1
for i in 1 2 3 4; do start $i $NEW; done
# held <node>: the one-second rounds in which it put its founding of 741 off for the junk
held() { local m; eval m=\$J$1; since $1 $m | grep -ac "cluster 741\] undecryptable traffic on cluster_id 741"; }
for k in $(seq 1 90); do sleep 1; H=""; for i in 1 2 3 4; do H="$H $(held $i)"; done; [ "$(echo $H | tr ' ' '\n' | sort -n | head -1)" -ge 6 ] && break; done
F741=0; for i in 1 2 3 4; do eval m=\$J$i; F741=$((F741 + $(members $i 741 | tr ' ' '\n' | grep -c ':master:') + $(since $i $m | grep -ac "cluster 741\] became master\|cluster 741\] join deadline expired"))); done
F742=$(for i in 1 2 3 4; do members $i 742; done | tr ' ' '\n' | grep -c ':master:')
kill $JK; wait $JK
T0=$(date +%s.%N)
A=""; for i in 1 2 3 4; do A="$A $(accepted $i INPUT)"; nx $i iptables -D INPUT -p udp -s 10.74.0.254 --dport $PORT -j ACCEPT; done
read -r JN JG <<<"$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["datagrams"], d["longest_gap_ms"])' $R/junk.json 2>/dev/null)"
echo "    junk: ${JN:-?} datagrams sent, longest pause ${JG:-?} ms; arrived at n1..n4:$A; rounds held:$H"
check "the junk reached every node, and each put its founding of 741 off for it, 6 rounds or more" $([ -n "$JG" ] && [ "$(echo $A | tr ' ' '\n' | awk '$1<1{b=1} END{print b?0:1}')" = 1 ] && [ "$(echo $H | tr ' ' '\n' | sort -n | head -1)" -ge 6 ] && echo 1 || echo 0) "arrived:$A, held:$H"
# three rounds without junk let a node found, by design: a sender paused that long proves nothing
if [ "${JG:-0}" -lt 2500 ] 2>/dev/null; then
  check "while the junk lasted no node founded 741 or named a master in it; 742 was founded meanwhile" $([ "$F741" = 0 ] && [ "${F742:-0}" -ge 1 ] && echo 1 || echo 0) "741: $F741, 742: $F742 node(s) naming a master"
else skip "T58 while the junk lasts" "its sender paused $JG ms"; fi
OK=0; for k in $(seq 1 90); do settled && { OK=1; break; }; sleep 1; done
DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))")
UU=$(for i in 1 2 3 4; do cfgval $i 741 cluster_uuid; done | sort -u)
check "the junk stopped: one cluster of four $DT s later - one master, distinct ids, one view, one uuid" $([ $OK = 1 ] && settled && [ -n "$UU" ] && [ "$(echo "$UU" | wc -l)" = 1 ] && echo 1 || echo 0) "$(view | tr '\n' '|') / $(echo $UU)"
fi

if grp 9; then
boot 4
echo "=== T32 a JOIN_REJECT sent again does not stop a node; no reply to a wrong password ==="
# bootstrap-key JOIN_REJECTs have no replay window, so each is bound to the JOIN_REQ it
# refuses: a recorded one replayed at a rejoining node (master held back) must not stop it
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 1 2 3 4; do [ $x != $MN ] && break; done
# T32 to T34 and T52 send records again on purpose: what replays_refused counted so far is kept
RFB=$(rf_growth)
stop_graceful $x; rm -f $R/n$x.pid; sleep 2
M0=$(wc -l < $R/n$MN.log); X0=$(wc -l < $R/n$x.log); JR0=$(cstat $MN joins_refused-741)
tap $MN 14 $R/t32.json >/dev/null & TP=$!
sleep 0.5; start $x $NEW 1 3       # query_time 3 against the cluster's 2
wait $TP
for k in $(seq 1 40); do alive $x || break; sleep 0.5; done
check "the master refused n$x, on other settings" $(since $MN $M0 | grep -aq "sent JOIN_REJECT to $(ip4 $x)" && echo 1 || echo 0) ""
# the event is one per address and reason a minute, however many requests were refused
for k in $(seq 1 20); do since $MN $M0 | grep -aq "EVT REFUSED 741 $(ip4 $x) config" && break; sleep 0.5; done
JR1=$(cstat $MN joins_refused-741); ER=$(since $MN $M0 | grep -ac "EVT REFUSED 741 $(ip4 $x) config")
check "the master counted the refusal (joins_refused-741) and raised E_CL_CTR_REFUSED for n$x once, reason config" $([ "${JR1:-0}" -gt "${JR0:-0}" ] 2>/dev/null && [ "$ER" = 1 ] && echo 1 || echo 0) "joins_refused $JR0 -> $JR1, $ER event(s)"
check "a refusal it earns still stops it: other settings" $(! alive $x && since $x $X0 | grep -aq "JOIN_REJECT from $MIP - the running cluster has different settings" && echo 1 || echo 0) "alive: $(alive $x && echo yes || echo no)"
alive $x && stop_hard $x; rm -f $R/n$x.pid
# the master's bootstrap-key datagrams only - the refusal and its beacons
python3 -c '
import json,sys
p=[d for d in json.load(open(sys.argv[1])) if d["data"][2:4] == "01"]   # key tier 1: bootstrap
json.dump(p,open(sys.argv[2],"w")); print(len(p))' $R/t32.json $R/t32b.json > $R/t32b.n
X0=$(wc -l < $R/n$x.log)
nx $x iptables -I INPUT -p udp -s $MIP --sport $PORT -j DROP
start $x $NEW
for k in 1 2 3 4 5 6; do replay $MN $R/t32b.json >/dev/null; sleep 0.5; done
DR=$(dropped $x INPUT)
nx $x iptables -D INPUT -p udp -s $MIP --sport $PORT -j DROP
sleep 8
check "the hold on the master's packets fired ($DR dropped), the record was sent 6 times ($(cat $R/t32b.n) datagrams)" $([ "$DR" -gt 0 ] && [ "$(cat $R/t32b.n)" -gt 0 ] && echo 1 || echo 0) ""
check "n$x, sent the recorded refusal while joining, joined" $(alive $x && members $MN 741 | tr ' ' '\n' | grep -q "^$(ip4 $x):[a-z]*:[1-9]" && echo 1 || echo 0) "alive: $(alive $x && echo yes || echo no), $(members $MN 741)"
check "n$x said it ignored a refusal of none of its JOIN_REQs" $(since $x $X0 | grep -aq "ignoring a JOIN_REJECT from $MIP that refuses none of this node's JOIN_REQs" && echo 1 || echo 0) ""
# a packet that does not authenticate gets no answer: its source and nonce are anyone's
stop_graceful $x; rm -f $R/n$x.pid; sleep 2
python3 "$HERE/cl_ctr_join_reject_test.py" --group 239.0.74.1 --port $PORT --cluster-id 741 --source 10.74.0.254 --count 4 --interval 0.5 > $R/t32u.txt 2>&1; RC=$?
# 3: the bridge address heard nothing of the group, so nothing was tested
if [ $RC = 3 ]; then skip "T32 on the wire" "the group's traffic does not reach the bridge address"
else check "junk under the bootstrap and the session magic: nothing sent to its source, nothing but beacons to the group" $([ $RC = 0 ] && echo 1 || echo 0) "exit $RC: $(grep -a 'FAIL\|sent [0-9]* bytes\|Error' $R/t32u.txt | tr '\n' ' ' | cut -c1-200)"; fi
# the same from a node with another password, 10 s next to three members (a lone master: T51)
M0=$(wc -l < $R/n$MN.log); X0=$(wc -l < $R/n$x.log); JR0=$(cstat $MN joins_refused-741)
RIG_PASSWORD=rig74-the-wrong-one start $x $NEW; sleep 10
check "wrong password: the master sent n$x no refusal" $(! since $MN $M0 | grep -aq "sent JOIN_REJECT to $(ip4 $x)" && echo 1 || echo 0) ""
JR1=$(cstat $MN joins_refused-741)
check "wrong password: no refusal counted, no E_CL_CTR_REFUSED raised" $([ -n "$JR0" ] && [ "$JR1" = "$JR0" ] && ! since $MN $M0 | grep -aq "EVT REFUSED 741 $(ip4 $x)" && echo 1 || echo 0) "joins_refused $JR0 -> $JR1"
check "wrong password: n$x keeps running, founds nothing" $(alive $x && ! members $x 741 | tr ' ' '\n' | grep -q ':master:' && ! since $x $X0 | grep -aq "my role changed: [a-z]* -> master\|became master" && echo 1 || echo 0) "alive: $(alive $x && echo yes || echo no), $(members $x 741)"
stop_hard $x; rm -f $R/n$x.pid; start $x $NEW; sleep 8
check "n$x back in" $(members $MN 741 | tr ' ' '\n' | grep -q "^$(ip4 $x):[a-z]*:[1-9]" && echo 1 || echo 0) "$(members $MN 741)"

echo "=== T33 a restarted node's old packets recorded and sent again, from another address and from its own ==="
# a packet seals its sender: from the bridge the record is refused for its source, from the
# node's own address for the life it was sent in - either way its old GOODBYE must not remove it
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
tap $x 4 $R/t33.json >/dev/null & TP=$!
sleep 0.5; stop_graceful $x; rm -f $R/n$x.pid; wait $TP
start $x $NEW; sleep 8
python3 -c '
import json,sys
p=[d for d in json.load(open(sys.argv[1])) if d["data"][2:4]=="00"]
json.dump(p,open(sys.argv[2],"w")); print(len(p))' $R/t33.json $R/t33s.json > $R/t33s.n
check "n$x back as a member, its stop recorded ($(cat $R/t33s.n) session datagrams)" $(members $MN 741 | tr ' ' '\n' | grep -q "^$(ip4 $x):[a-z]*:[1-9]" && [ "$(cat $R/t33s.n)" -gt 0 ] && echo 1 || echo 0) "$(members $MN 741)"
M0=$(wc -l < $R/n$MN.log)
python3 "$HERE/wire_tap.py" inject $R/t33s.json 10.74.0.254 >/dev/null; sleep 4
check "its old GOODBYE, sent from another address, removed nothing" $(! since $MN $M0 | grep -aq "GOODBYE from $(ip4 $x)" && members $MN 741 | tr ' ' '\n' | grep -q "^$(ip4 $x):[a-z]*:[1-9]" && echo 1 || echo 0) "$(since $MN $M0 | grep -a "GOODBYE from" | tail -1 | cut -c1-120) / $(members $MN 741)"
for k in $(seq 1 40); do [ "$(admission $MN $(ip4 $x))" = online ] && break; sleep 1; done
M0=$(wc -l < $R/n$MN.log); XID=$(nid $MN $x)
resent I $MN $x
replay $x $R/t33s.json >/dev/null; sleep 4
RS33=$(accepted $MN INPUT)
resent D $MN $x
check "the record reached the master from n$x's own address ($RS33 datagrams)" $([ "${RS33:-0}" -gt 0 ] && echo 1 || echo 0) "$RS33"
check "its old GOODBYE, sent from its own address, removed nothing: a previous life is refused" $(! since $MN $M0 | grep -aq "GOODBYE from $(ip4 $x)" && [ -n "$XID" ] && [ "$(nid $MN $x)" = "$XID" ] && [ "$(admission $MN $(ip4 $x))" = online ] && echo 1 || echo 0) "$(since $MN $M0 | grep -a "GOODBYE from" | tail -1 | cut -c1-120) / $(members $MN 741)"

echo "=== T34 a JOIN_REQ recorded and sent again, from another address and from its own ==="
# bootstrap packets have no replay window: a JOIN_REQ replayed from the bridge must not
# re-admit the node, and replies go to the joiner itself, not to the sending address
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
XID=$(nid $MN $x)
stop_graceful $x; rm -f $R/n$x.pid
tap $x 4 $R/t34.json >/dev/null & TP=$!
sleep 0.3; start $x $NEW; wait $TP; sleep 6
python3 -c '
import json,sys
p=[d for d in json.load(open(sys.argv[1])) if d["data"][2:4]=="01"]
json.dump(p,open(sys.argv[2],"w")); print(len(p))' $R/t34.json $R/t34b.json > $R/t34b.n
XID=$(nid $MN $x)
check "n$x rejoined, its JOIN_REQ recorded ($(cat $R/t34b.n) bootstrap datagrams)" $([ -n "$XID" ] && [ "$(cat $R/t34b.n)" -gt 0 ] && echo 1 || echo 0) "id '$XID'"
M0=$(wc -l < $R/n$MN.log)
GOT=$(python3 - $R/t34b.json <<'PY'
import json, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.74.0.254", 0)); s.settimeout(0.2)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("10.74.0.254"))
for d in json.load(open(sys.argv[1])):
    s.sendto(bytes.fromhex(d["data"]), (d["dst"], d["dport"])); time.sleep(0.05)
n, end = 0, time.time() + 3
while time.time() < end:
    try: s.recv(65535); n += 1
    except socket.timeout: pass
print(n)
PY
)
check "the master did not admit n$x again" $(! since $MN $M0 | grep -aq "JOIN_REQ from $(ip4 $x)" && echo 1 || echo 0) "$(since $MN $M0 | grep -ac "JOIN_REQ from $(ip4 $x)") JOIN_REQs processed"
check "nothing was sent to the address the record came from" $([ "${GOT:-1}" = 0 ] && echo 1 || echo 0) "$GOT datagrams"
check "n$x kept its node_id ($XID)" $([ "$(nid $MN $x)" = "$XID" ] && echo 1 || echo 0) "$(nid $MN $x)"
# from its own address the request passes the source check: it is one already taken, or a
# member's asking for the key again - never a second admission
for k in $(seq 1 40); do [ "$(admission $MN $(ip4 $x))" = online ] && break; sleep 1; done
M0=$(wc -l < $R/n$MN.log)
resent I $MN $x
replay $x $R/t34b.json >/dev/null
ADM=""; for k in 1 2 3 4 5 6; do ADM="$ADM $(admission $MN $(ip4 $x))"; sleep 0.5; done
RS34=$(accepted $MN INPUT)
resent D $MN $x
check "the record reached the master from n$x's own address ($RS34 datagrams)" $([ "${RS34:-0}" -gt 0 ] && echo 1 || echo 0) "$RS34"
check "sent from its own address, n$x's JOIN_REQ put it through no admission: online throughout, node_id $XID kept" $([ "$(echo $ADM | tr ' ' '\n' | sort -u)" = online ] && ! since $MN $M0 | grep -aq "EVT ADMISSION 741 $(ip4 $x) [0-9]* connecting\|admitting $(ip4 $x) - CONNECTING" && [ "$(nid $MN $x)" = "$XID" ] && echo 1 || echo 0) "$ADM / node_id $(nid $MN $x)"
echo "    answered as a member asking for the key again: $(since $MN $M0 | grep -ac "member $(ip4 $x) (node_id [0-9]*) asks for the key again") time(s); else dropped as already taken"

echo "=== T52 a member's packets of the life it runs, recorded and sent again from its own address: taken once ==="
# recorded while it says "evicted", sent again once it says "none": a node taking the record
# would list it evicted again, and only the replay window refuses it
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
XIP=$(ip4 $x)
mi $x clusterer:maintenance cluster_id=741 state=evicted >/dev/null
for k in $(seq 1 40); do V=""; for i in 1 2 3 4; do V="$V $(maint $i $XIP)"; done; [ "$(echo $V | tr ' ' '\n' | sort -u)" = evicted ] && break; sleep 0.5; done
tap $x 3 $R/t52.json >/dev/null
mi $x clusterer:maintenance cluster_id=741 state=none >/dev/null
for k in $(seq 1 40); do W=""; for i in 1 2 3 4; do W="$W $(maint $i $XIP)"; done; [ "$(echo $W | tr ' ' '\n' | sort -u)" = none ] && break; sleep 0.5; done
python3 -c '
import json,sys
p=[d for d in json.load(open(sys.argv[1])) if d["data"][2:4]=="00"]
json.dump(p,open(sys.argv[2],"w")); print(len(p))' $R/t52.json $R/t52s.json > $R/t52s.n
check "n$x recorded in maintenance ($(cat $R/t52s.n) session datagrams), then back in service on every node" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = evicted ] && [ "$(echo $W | tr ' ' '\n' | sort -u)" = none ] && [ "$(cat $R/t52s.n)" -gt 0 ] && echo 1 || echo 0) "in: $V, out: $W"
# these refusals are meant: what the closing check counted so far is kept, its marks move past them
RPB=0; for i in 1 2 3 4; do eval m=\${RP$i:-0}; RPB=$((RPB + $(since $i $m | grep -ac "already accepted, dropping\|older than the replay window, dropping"))); done
for i in 1 2 3 4; do eval Y$i=$(wc -l < $R/n$i.log); done
RQ0=$(rstat $MN)
resent I $MN $x
replay $x $R/t52s.json >/dev/null; sleep 3
RS52=$(accepted $MN INPUT)
resent D $MN $x
RQ1=$(rstat $MN)
EV=0; for i in 1 2 3 4; do eval m=\$Y$i; EV=$((EV + $(since $i $m | grep -ac "EVT MAINT 741 [0-9]* evicted"))); done
W=""; for i in 1 2 3 4; do W="$W $(maint $i $XIP)"; done
check "the record reached the master from n$x's own address ($RS52 datagrams)" $([ "${RS52:-0}" -gt 0 ] && echo 1 || echo 0) "$RS52"
check "no node took the recorded 'evicted' a second time: no maintenance event, n$x in service on all four" $([ $EV = 0 ] && [ "$(echo $W | tr ' ' '\n' | sort -u)" = none ] && echo 1 || echo 0) "$EV event(s), $W"
# the warning for a refused replay is one a minute; the statistic counts each
if [ -n "$RQ0" ] && [ -n "$RQ1" ]; then
  check "the master counted the record among the replays it refused (replays_refused-741 $RQ0 -> $RQ1)" $([ "$RQ1" -gt "$RQ0" ] 2>/dev/null && echo 1 || echo 0) "$RQ0 -> $RQ1"
else skip "T52 replays_refused" "the master reports no replays_refused statistic"; fi
for i in 1 2 3 4; do eval RP$i=$(wc -l < $R/n$i.log); done
rf_mark

echo "=== T35 BIN messages that would override the controller are ignored ==="
# binsend <from> <to> <type> <src_id> <dst_id> str:<s>|int:<n> - one clusterer-extra
# packet for cluster 741 over a fresh BIN connection from node <from>'s address
binsend() {
  nx $1 python3 - "$(ip4 $2)" "$3" "$4" "$5" "$6" <<'PY'
import socket, struct, sys, time
ip, ptype, src, dst, arg = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
kind, val = arg.split(":", 1)
body = struct.pack("=H", len(val)) + val.encode() if kind == "str" else struct.pack("=i", int(val))
body += struct.pack("=iii", 741, src, dst)
cap = b"clusterer-extra"
rest = struct.pack("=hH", 1, len(cap)) + cap + struct.pack("=i", ptype) + body
s = socket.create_connection((ip, 5588), timeout=3)
s.sendall(b"P4CK" + struct.pack("=I", 8 + len(rest)) + rest); time.sleep(0.5); s.close()
PY
}
cl_nodes() { mi $1 clusterer:list | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",{}).get("Clusters",[]):
    if c.get("cluster_id")==741: print(" ".join(sorted(str(n["node_id"]) for n in c.get("Nodes",[]))))'; }
H=; UP=
for i in 1 2 3 4; do alive $i || continue; UP="$UP $i"; [ "$(tagst $i)" = active ] && H=$i; done
set -- $(echo $UP | tr ' ' '\n' | grep -vx "${H:-0}"); X=${1:-}; Y=${2:-}
check "an active holder and two other members to work with" $([ -n "$H" ] && [ -n "$X" ] && [ -n "$Y" ] && echo 1 || echo 0) "holder '$H', up '$UP'"
HID=$(nid $H $H); XID=$(nid $H $X); YID=$(nid $H $Y)
# a master taking a managed tag announces nothing over BIN, so no ignored message yet -
# counted from T27's end: its older build still announces, as an older member would
NI=0; for i in 1 2 3 4; do [ -f $R/n$i.log ] || continue; eval m=\${ALLNEW$i:-0}; NI=$((NI + $(since $i $m | grep -ac "Ignoring BIN"))); done
check "no ignored BIN message while every node runs this build" $([ $NI = 0 ] && echo 1 || echo 0) "$NI lines"
MH=$(wc -l < $R/n$H.log); MY=$(wc -l < $R/n$Y.log)
binsend $X $H 13 $XID $HID str:tag741; sleep 2       # CLUSTERER_SHTAG_ACTIVE
check "a tag announcement over BIN from n$X's address left n$H the holder" $([ "$(tagst $H)" = active ] && echo 1 || echo 0) "n$H: $(tagst $H)"
NA=0; for i in $UP; do [ "$(tagst $i)" = active ] && NA=$((NA+1)); done
check "exactly one active holder" $([ $NA = 1 ] && echo 1 || echo 0) "$NA"
binsend $X $Y 6 $XID $YID int:$HID; sleep 2          # CLUSTERER_REMOVE_NODE
check "a remove-node over BIN from n$X's address left n$H in n$Y's table" $(cl_nodes $Y | tr ' ' '\n' | grep -qx "$HID" && echo 1 || echo 0) "n$Y lists: $(cl_nodes $Y)"
# the warning proves each packet reached the receiver, so a pass is not a lost packet
check "n$H and n$Y each logged the ignored message" $(since $H $MH | grep -aq "Ignoring BIN tag announcement" && since $Y $MY | grep -aq "Ignoring BIN remove-node" && echo 1 || echo 0) ""

echo "=== T36 clusterer's own overrides are refused: MI remove_node and set_status, clusterer.so loaded beside ==="
R1=$(mi $X clusterer:remove_node cluster_id=741 node_id=$YID)
R2=$(mi $X clusterer:set_status cluster_id=741 node_id=$YID status=0)
sleep 2
check "clusterer:remove_node on a managed cluster is refused, n$Y stays in n$X's table" $(echo "$R1" | grep -q "managed by the controller" && cl_nodes $X | tr ' ' '\n' | grep -qx "$YID" && echo 1 || echo 0) "$(echo "$R1" | cut -c1-120) / n$X lists: $(cl_nodes $X)"
check "clusterer:set_status on a managed cluster is refused" $(echo "$R2" | grep -q "managed by the controller" && echo 1 || echo 0) "$(echo "$R2" | cut -c1-120)"
sed -e 's|^loadmodule "clusterer_controller.so"$|loadmodule "clusterer.so"\nloadmodule "clusterer_controller.so"|' \
    -e "s|:5060$|:5099|; s|:5588$|:5599|; s|mi$X.sock|mi${X}b.sock|" $R/n$X.cfg > $R/both.cfg
nx $X timeout 20 $(lb $NEW) $NEW/sbin/opensips -F -f $R/both.cfg -m 32 -M 8 -w $R > $R/both.log 2>&1; RC=$?
# the controller's parameters are unknown to clusterer.so: the core refuses the config
check "clusterer.so beside it, with the controller's parameters: refused at startup, for a parameter clusterer.so has not" $(grep -q '^loadmodule "clusterer.so"$' $R/both.cfg && [ $RC != 0 ] && [ $RC != 124 ] && grep -aqi "parameter <cluster_options> not found in module <clusterer>" $R/both.log && echo 1 || echo 0) "exit $RC: $(grep -a -m2 ERROR $R/both.log | cut -c1-120)"
# with clusterer's own parameters only the config parses, and the module refuses
cat > $R/both2.cfg <<EOF
log_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=1
auto_aliases=no
socket=udp:$(ip4 $X):5097
socket=bin:$(ip4 $X):5597
mpath="$(modpath $NEW)"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "clusterer.so"
loadmodule "clusterer_controller.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", 1)
route { exit; }
EOF
nx $X timeout 20 $(lb $NEW) $NEW/sbin/opensips -F -f $R/both2.cfg -m 32 -M 8 -w $R > $R/both2.log 2>&1; RC=$?
check "clusterer.so beside it, with clusterer's parameters only: refused at startup by the module" $([ $RC != 0 ] && [ $RC != 124 ] && grep -aq "replaces clusterer.so - load only one" $R/both2.log && echo 1 || echo 0) "exit $RC: $(grep -a -m2 'ERROR\|CRIT' $R/both2.log | cut -c1-120)"

echo "=== T63 the control port held by another process: the node gives up after 3 s and says why ==="
# a port no other cluster of this OpenSIPS shares is bound without SO_REUSEADDR, so a second
# OpenSIPS on the host is refused, not left to take the first one's unicast packets
cat > $R/held.cfg <<EOF
log_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=1
auto_aliases=no
socket=udp:$(ip4 $X):5096
socket=bin:$(ip4 $X):5596
mpath="$(modpath $NEW)"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "clusterer_controller.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "cluster_options", "cluster_id=799, use_controller=1")
modparam("clusterer", "my_ip", "$(ip4 $X)")
modparam("clusterer", "password", "$RIG_PASSWORD")
modparam("clusterer", "cluster", "id=799,multicast=239.0.74.99:3799,bin_socket=bin:$(ip4 $X):5596")
route { exit; }
EOF
nx $X python3 -c 'import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 3799)); time.sleep(60)' & HP=$!
sleep 1
nx $X timeout 30 $(lb $NEW) $NEW/sbin/opensips -F -f $R/held.cfg -m 32 -M 8 -w $R > $R/held.log 2>&1; RC=$?
kill $HP 2>/dev/null; wait $HP 2>/dev/null
check "a node whose control port another process holds ends by itself, naming the port and the cause" $([ $RC != 124 ] && grep -aq "bind() port 3799: Address already in use - another process holds the port" $R/held.log && echo 1 || echo 0) "exit $RC: $(grep -a -m2 'bind()\|CRIT' $R/held.log | cut -c1-160)"

echo "=== T56 MI: a node id outside 1..127 names no node ==="
# mierr <node> <method> [k=v ...] -> "<code> <message>" of an MI error reply, empty for a result
mierr() { mi "$@" | python3 -c '
import json,sys
try: e=json.load(sys.stdin).get("error")
except Exception: e=None
print("%s %s" % (e.get("code"), e.get("message")) if isinstance(e, dict) else "")'; }
E1=$(mierr $X clusterer:shtag_force cluster_id=741 node_id=0); E2=$(mierr $X clusterer:shtag_force cluster_id=741 node_id=128)
check "clusterer:shtag_force with node_id 0 or 128 answers 400, out of range" $([ "$E1" = "400 node_id out of range (1..127)" ] && [ "$E2" = "$E1" ] && echo 1 || echo 0) "'$E1' / '$E2'"
E1=$(mierr $X clusterer:node_info node_id=0); E2=$(mierr $X clusterer:node_info node_id=128)
check "clusterer:node_info with node_id 0 or 128 answers 400, out of range" $([ "$E1" = "400 node_id out of range (1..127)" ] && [ "$E2" = "$E1" ] && echo 1 || echo 0) "'$E1' / '$E2'"
R1=$(mi $X clusterer:node_info node_id=${YID:-0})
check "clusterer:node_info with n$Y's node_id $YID answers with that node" $(echo "$R1" | grep -q '"result"' && echo "$R1" | grep -q "$(ip4 $Y)\"" && echo 1 || echo 0) "$(echo "$R1" | cut -c1-120)"

echo "=== T37 node ids are proposed: the founder founds under its own, a free one is granted, a taken one substituted ==="
# a cold start leaves no ids held; my_node_id is what n1..n3 propose, and n4
# asks for n3's - the founder may be any of the first three
IS=$(cfgval $X 741 identity_source)
check "without my_node_id a node's identity comes from the machine (smbios, mac or random)" $(echo "$IS" | grep -qx 'smbios\|mac\|random' && echo 1 || echo 0) "'$IS'"
for i in 1 2 3 4; do stop_hard $i; rm -f $R/n$i.pid; done; sleep 2
# on_config_mismatch=warn from here to T60, which needs a master on it: with every node on
# the same settings it changes nothing
export RIG_ON_MISMATCH=warn
RIG_NODE_ID=101 start 1 $NEW; RIG_NODE_ID=102 start 2 $NEW; RIG_NODE_ID=110 start 3 $NEW; sleep 12
for i in 1 2 3; do eval M$i=$(wc -l < $R/n$i.log); done
RIG_NODE_ID=110 start 4 $NEW; sleep 8
selfid() { mi $1 clusterer:list_topology | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",{}).get("Clusters",[]):
    if c.get("cluster_id")==int(sys.argv[1]): print(c["Nodes"][0]["node_id"])' $2; }
I741="$(nid 3 1) $(nid 3 2) $(nid 3 3)"
I742=$(for n in 1 2 3; do members 3 742 | tr ' ' '\n' | grep "^$(ip4 $n):" | cut -d: -f3; done | tr '\n' ' ')
check "n1, n2, n3 hold the ids they proposed, in 741 and in 742 (101, 102, 110)" $([ "$I741" = "101 102 110" ] && [ "$I742" = "101 102 110 " ] && echo 1 || echo 0) "741: $I741 / 742: $I742"
check "n4, proposing n3's 110, got another id" $(I=$(nid 3 4); [ -n "$I" ] && [ "$I" != 110 ] && [ "$I" != 0 ] && echo 1 || echo 0) "n4: '$(nid 3 4)'"
MSUB=0; for i in 1 2 3; do eval m=\$M$i; MSUB=$((MSUB + $(since $i $m | grep -ac "10.74.0.14 proposed node_id 110, which is in use - assigning"))); done
check "the master said whose proposal it could not grant" $([ $MSUB -ge 1 ] && echo 1 || echo 0) "$MSUB lines"
check "list_config reports what a node proposes and where its identity comes from" $([ "$(cfgval 4 741 proposed_node_id)" = 110 ] && echo "$(cfgval 4 741 identity_source)" | grep -qx 'my_node_id' && echo 1 || echo 0) "proposed '$(cfgval 4 741 proposed_node_id)', identity '$(cfgval 4 741 identity_source)'"
check "clusterer:list_topology names this node by its id in that cluster" $([ "$(selfid 1 741)" = 101 ] && [ "$(selfid 4 741)" = "$(nid 3 4)" ] && echo 1 || echo 0) "n1 741: '$(selfid 1 741)', n4 741: '$(selfid 4 741)'"

echo "=== T43 clusterer's own pings and node descriptions from outside a controller cluster: no answer, no change, one warning ==="
# binforge <to> <type> <src_id> [str:<s>|int:<n> ...] - one clusterer-internal packet for 741
# from the bridge's address (no member's); prints how many bytes came back
binforge() {
  python3 - "$(ip4 $1)" "$@" <<'PY'
import socket, struct, sys
ip, ptype, src = sys.argv[1], int(sys.argv[3]), int(sys.argv[4])
body = struct.pack("=ii", 741, src)
for a in sys.argv[5:]:
    kind, val = a.split(":", 1)
    body += struct.pack("=H", len(val)) + val.encode() if kind == "str" else struct.pack("=i", int(val))
cap = b"clusterer-internal"
rest = struct.pack("=hH", 1, len(cap)) + cap + struct.pack("=i", ptype) + body
s = socket.socket(); s.bind(("10.74.0.254", 0)); s.settimeout(1.5); s.connect((ip, 5588))
s.sendall(b"P4CK" + struct.pack("=I", 8 + len(rest)) + rest)
n = 0
try:
    while True:
        d = s.recv(65535)
        if not d: break
        n += len(d)
except socket.timeout: pass
s.close(); print(n)
PY
}
N0=$(cl_nodes 1); MF=$(wc -l < $R/n1.log)
GOT=0; for k in 1 2 3; do GOT=$((GOT + $(binforge 1 0 77 int:0))); done     # CLUSTERER_PING
GOT=$((GOT + $(binforge 1 5 77 str:bin:10.74.0.254:5588 str: int:0 int:3))); sleep 2   # CLUSTERER_NODE_DESCRIPTION
check "n1's 741 table unchanged by the forged node 77" $([ "$(cl_nodes 1)" = "$N0" ] && ! cl_nodes 1 | tr ' ' '\n' | grep -qx 77 && echo 1 || echo 0) "before: $N0, after: $(cl_nodes 1)"
check "nothing sent back to the forger" $([ "$GOT" = 0 ] && echo 1 || echo 0) "$GOT bytes"
W=$(since 1 $MF | grep -ac "membership is the controller's"); I=$(since 1 $MF | grep -ac "unknown source id")
# the one warning is also what shows the packets arrived
check "n1 logged one warning for the four packets, not a line each" $([ "$W" = 1 ] && [ "$I" = 0 ] && echo 1 || echo 0) "warnings $W, per-packet $I"

echo "=== T57 script functions: a node id outside 1..127 names no node ==="
# nodeq <node> <id>...: one request per id, which the node's route (RIG_SCRIPT) puts to
# cl_ctr_node_present(741, id)
nodeq() {
  python3 - "$(ip4 $1)" "${@:2}" <<'PY'
import socket, sys
ip = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0)); s.settimeout(1)
for k, q in enumerate(sys.argv[2:]):
    m = ("OPTIONS sip:x@%s SIP/2.0\r\nVia: SIP/2.0/UDP 10.74.0.254:%d;branch=z9hG4bKnq%d\r\n"
         "From: <sip:t@10.74.0.254>;tag=1\r\nTo: <sip:x@%s>\r\nCall-ID: nq-%d\r\nCSeq: 1 OPTIONS\r\n"
         "X-NodeQ: %s\r\nContent-Length: 0\r\n\r\n") % (ip, s.getsockname()[1], k, ip, k, q)
    s.sendto(m.encode(), (ip, 5060))
    try: s.recv(4096)
    except socket.timeout: pass
PY
}
stop_graceful 4; rm -f $R/n4.pid
N4=$(wc -l < $R/n4.log)
RIG_NODE_ID=110 RIG_SCRIPT=1 start 4 $NEW
I3=""; for k in $(seq 1 40); do sleep 1; I3=$(nid 4 3); [ -n "$I3" ] && [ "$I3" != 0 ] && break; done
nodeq 4 0 128 ${I3:-0}; sleep 1
Q=$(since 4 $N4 | grep -ao "\[NODEQ\] [0-9]* [a-z]*" | tr '\n' ' ')
check "cl_ctr_node_present(741, id) on n4: false for 0 and 128, true for n3's $I3" $([ -n "$I3" ] && [ "$I3" != 0 ] && echo "$Q" | grep -q "\[NODEQ\] 0 absent" && echo "$Q" | grep -q "\[NODEQ\] 128 absent" && echo "$Q" | grep -q "\[NODEQ\] $I3 present" && echo 1 || echo 0) "$Q"

echo "=== T60 on_config_mismatch=warn: a node on another query_time is admitted, and each side counts the mismatch ==="
# under reject, as in every other test, such a node never becomes a member and no ALIVE with
# other settings is heard; these nodes have run on warn since T37
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
stop_graceful $x; rm -f $R/n$x.pid
C0=$(cstat $MN config_mismatches-741); JR0=$(cstat $MN joins_refused-741); M0=$(wc -l < $R/n$MN.log)
start $x $NEW 1 3       # query_time 3 against the cluster's 2
for k in $(seq 1 40); do sleep 1; [ "$(cstat $MN config_mismatches-741)" -gt "${C0:-0}" ] 2>/dev/null && [ "$(cstat $x config_mismatches-741)" -ge 1 ] 2>/dev/null && break; done
C1=$(cstat $MN config_mismatches-741); CX=$(cstat $x config_mismatches-741); JR1=$(cstat $MN joins_refused-741)
check "n$x, on query_time 3, is a member: the master on warn sent it no refusal" $(alive $x && members $MN 741 | tr ' ' '\n' | grep -q "^$(ip4 $x):[a-z]*:[1-9]" && [ -n "$JR0" ] && [ "$JR1" = "$JR0" ] && echo 1 || echo 0) "alive: $(alive $x && echo yes || echo no), $(members $MN 741), joins_refused $JR0 -> $JR1"
check "the master counted the mismatch (config_mismatches-741) and named the setting" $([ "${C1:-0}" -gt "${C0:-0}" ] 2>/dev/null && since $MN $M0 | grep -aq "cluster 741\] CONFIG MISMATCH with peer $(ip4 $x) .*query_time local=2 peer=3" && echo 1 || echo 0) "config_mismatches $C0 -> $C1"
check "n$x counted the settings of the members it hears" $([ "${CX:-0}" -ge 1 ] 2>/dev/null && echo 1 || echo 0) "config_mismatches-741 on n$x: $CX"
unset RIG_ON_MISMATCH
fi

if grp 10; then
# native clusters on this module (the static cluster 900): nothing of group 10
# runs a controller cluster until T40
for i in 1 2 3 4; do stop_hard $i; rm -f $R/n$i.pid; done; sleep 2
for i in 1 2 3 4; do eval RP$i=$([ -f $R/n$i.log ] && wc -l < $R/n$i.log || echo 0); done
rf_mark
links900() { mi $1 clusterer:list | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",{}).get("Clusters",[]):
    if c.get("cluster_id")==900: print(" ".join(sorted("%s:%s" % (n["node_id"], n.get("link_state")) for n in c.get("Nodes",[]))))'; }
up900() { links900 $1 | tr ' ' '\n' | grep -qx "$2:Up"; }

echo "=== T38 a native cluster on this module behaves as on clusterer: static nodes, links, messages, no controller ==="
for i in 1 2 3; do start_native $i $NEW clusterer_controller.so 1 2 3 4; done; sleep 10
check "every node has the other two Up" $(up900 1 2 && up900 1 3 && up900 2 1 && up900 2 3 && up900 3 1 && up900 3 2 && echo 1 || echo 0) "n1: $(links900 1) / n2: $(links900 2) / n3: $(links900 3)"
bcast 1 20 nat >/dev/null; sleep 2
check "n2 and n3 got 20/20 of n1's cluster_broadcast_req on 900" $([ "$(rx900 2 nat)" = 20 ] && [ "$(rx900 3 nat)" = 20 ] && echo 1 || echo 0) "$(rx900 2 nat)/$(rx900 3 nat)"
check "no controller cluster and no controller worker" $([ "$(mi 1 clusterer:list_config | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("result",[])))')" = 0 ] && ! mi 1 ps | grep -q 'clusterer_controller worker' && echo 1 || echo 0) ""

echo "=== T39 a stock clusterer node in the same native cluster: links and messages both ways ==="
stop_graceful 3; rm -f $R/n3.pid
start_native 3 $NEW clusterer.so 1 2 3 4; sleep 10
check "n3 runs the stock clusterer.so" $(grep -q '^loadmodule "clusterer.so"$' $R/n3.cfg && alive 3 && echo 1 || echo 0) ""
check "n3 and the others see each other Up" $(up900 1 3 && up900 2 3 && up900 3 1 && up900 3 2 && echo 1 || echo 0) "n1: $(links900 1) / n3: $(links900 3)"
bcast 1 20 mix1 >/dev/null; bcast 3 20 mix3 >/dev/null; sleep 2
check "stock n3 got 20/20 from n1; n1 and n2 got 20/20 from stock n3" $([ "$(rx900 3 mix1)" = 20 ] && [ "$(rx900 1 mix3)" = 20 ] && [ "$(rx900 2 mix3)" = 20 ] && echo 1 || echo 0) "$(rx900 3 mix1) / $(rx900 1 mix3) / $(rx900 2 mix3)"

echo "=== T40 a static cluster beside controller clusters on one node ==="
RIG_NODE_ID=4 RIG_NATIVE="1 2 3 4" start 4 $NEW; sleep 12
check "n4 founded 741 and 742 alone, as node 4 (its my_node_id)" $([ "$(members 4 741)" = "10.74.0.14:master:4" ] && [ "$(members 4 742)" = "10.74.0.14:master:4" ] && echo 1 || echo 0) "741: $(members 4 741) / 742: $(members 4 742)"
check "n4 is Up in 900 on n1..n3, and they are on n4" $(up900 1 4 && up900 2 4 && up900 3 4 && up900 4 1 && up900 4 2 && up900 4 3 && echo 1 || echo 0) "n1: $(links900 1) / n4: $(links900 4)"
bcast 4 20 b900 X-Bcast900 >/dev/null; sleep 2
check "n1, n2 and stock n3 got 20/20 of n4's broadcast on 900" $([ "$(rx900 1 b900)" = 20 ] && [ "$(rx900 2 b900)" = 20 ] && [ "$(rx900 3 b900)" = 20 ] && echo 1 || echo 0) "$(rx900 1 b900)/$(rx900 2 b900)/$(rx900 3 b900)"
check "the controller left 900 alone: n4's 900 table is n1..n3 as configured" $([ "$(links900 4 | tr ' ' '\n' | cut -d: -f1 | tr '\n' ' ')" = "1 2 3 " ] && echo 1 || echo 0) "$(links900 4)"

echo "=== T41 a configuration still written for a separate clusterer_controller.so fails startup ==="
sed -e 's|^modparam("clusterer", "db_mode", 0)$|&\nmodparam("clusterer_controller", "password", "rig74-not-a-secret-9f3a1c")|' \
    -e 's|:5060$|:5098|; s|^socket=bin:\(.*\):5588$|socket=bin:\1:5598|; s|mi1.sock|mi1c.sock|' $R/n1.cfg > $R/old.cfg
nx 1 timeout 20 $(lb $NEW) $NEW/sbin/opensips -F -f $R/old.cfg -m 32 -M 8 -w $R > $R/old.log 2>&1; RC=$?
check "a modparam(\"clusterer_controller\", ...) left over: refused at startup, for a module that is not there" $(grep -q 'modparam("clusterer_controller"' $R/old.cfg && [ $RC != 0 ] && [ $RC != 124 ] && grep -aqi "parameter <password> not found in module <clusterer_controller>" $R/old.log && echo 1 || echo 0) "exit $RC: $(grep -a -m2 -i 'error' $R/old.log | cut -c1-120)"

echo "=== T42 one node of a native cluster switched to the controller: it keeps its id, answers the natives nothing, warns once ==="
# n2's configuration for cluster 900 rewritten as a controller-managed one,
# my_node_id 2 kept; n1, stock n3 and n4 still list it as their native node 2
stop_graceful 2; rm -f $R/n2.pid
RIG_NODE_ID=2 mkcfg 2 $NEW
sed -i -e 's/cluster_id=741, use_controller=1/cluster_id=900, use_controller=1/' -e '/cluster_id=742, use_controller=1/d' \
    -e 's|"tag741/741=backup"|"tag900/900=backup"|' -e 's|"id=741,multicast=239.0.74.1:|"id=900,multicast=239.0.74.9:|' \
    -e '/"id=742,multicast=/d' $R/n2.cfg
M2=$(wc -l < $R/n2.log)
nx 2 $(lb $NEW) $NEW/sbin/opensips -f $R/n2.cfg -m 64 -M 16 -w $R -P $R/n2.pid 2>>$R/n2.log; sleep 25
check "n2 founded 900 under the controller as node 2" $(grep -q 'cluster_id=900, use_controller=1' $R/n2.cfg && [ "$(members 2 900)" = "10.74.0.12:master:2" ] && echo 1 || echo 0) "$(members 2 900)"
check "the natives no longer see n2 Up, and still see each other" $(! up900 1 2 && ! up900 3 2 && ! up900 4 2 && up900 1 3 && up900 3 1 && up900 1 4 && echo 1 || echo 0) "n1: $(links900 1) / stock n3: $(links900 3) / n4: $(links900 4)"
W=$(since 2 $M2 | grep -ac "membership is the controller's"); I=$(since 2 $M2 | grep -ac "unknown source id"); E=$(since 2 $M2 | grep -ac "ERROR:")
check "n2 warned about the natives once, logging no line per packet and no error" $([ "$W" = 1 ] && [ "$I" = 0 ] && [ "$E" = 0 ] && echo 1 || echo 0) "warnings $W, per-packet $I, errors $E"

echo "=== T44 an MI reload of the DB clusters keeps the controller clusters ==="
# n1 restarted with cluster 901 in a db_text DB beside the controller's 741/742
# and tm on 741; n4 is 741's master since T40
stop_graceful 1; rm -f $R/n1.pid
D=$R/db1; mkdir -p $D
printf 'table_name(string) table_version(int) \nclusterer:4\nclusterer_bridge:1\n' > $D/version
printf 'id(int,auto) cluster_a(int) cluster_b(int) send_shtag(string) dst_node_csv(string,null) \n' > $D/clusterer_bridge
printf 'id(int,auto) cluster_id(int) node_id(int) url(string) state(int) no_ping_retries(int) priority(int) sip_addr(string,null) flags(string,null) description(string,null) \n%s\n%s\n' \
  '1:901:1:bin\:10.74.0.11\:5588:1:3:50::seed:' '2:901:9:bin\:10.74.0.19\:5588:1:3:50:::' > $D/clusterer
RIG_NODE_ID=1 RIG_TM=1 mkcfg 1 $NEW
# db_text before the module, which initialises its DB connection in mod_init
sed -i -e 's|^loadmodule "clusterer_controller.so"$|loadmodule "db_text.so"\n&|' \
    -e "s|^modparam(\"clusterer\", \"db_mode\", 0)\$|modparam(\"db_text\", \"db_mode\", 1)\nmodparam(\"clusterer\", \"db_url\", \"text://$D\")|" $R/n1.cfg
nx 1 $(lb $NEW) $NEW/sbin/opensips -f $R/n1.cfg -m 64 -M 16 -w $R -P $R/n1.pid 2>>$R/n1.log; sleep 15
# clusters <node>: "<cluster_id>:<node ids> ..." from clusterer:list, sorted
clusters() { mi $1 clusterer:list | python3 -c '
import json,sys
print(" ".join(sorted("%s:%s" % (c["cluster_id"], ",".join(sorted(str(n["node_id"]) for n in c.get("Nodes",[]))))
    for c in json.load(sys.stdin).get("result",{}).get("Clusters",[]))))'; }
tmcap() { mi $1 clusterer:list_cap | python3 -c '
import json,sys
print(sum(1 for c in json.load(sys.stdin).get("result",{}).get("Clusters",[]) if c["cluster_id"]==741
    for k in c.get("Capabilities",[]) if k["name"]=="tm-repl"))'; }
C0="741:4 742:4 901:9"; M0=$(members 1 741)
check "n1 has the DB's 901 and the controller's 741 (with n4) and 742, and tm's capability on 741" $([ "$(clusters 1)" = "$C0" ] && [ "$(echo $M0 | wc -w)" = 2 ] && [ "$(tmcap 1)" = 1 ] && echo 1 || echo 0) "clusters '$(clusters 1)', 741 members '$M0', tm-repl on 741: $(tmcap 1)"
RL=$(mi 1 clusterer:reload)
check "clusterer:reload succeeds and keeps 741 and 742, their nodes and tm's capability" $(echo "$RL" | grep -q '"result"' && [ "$(clusters 1)" = "$C0" ] && [ "$(tmcap 1)" = 1 ] && [ "$(members 1 741)" = "$M0" ] && echo 1 || echo 0) "reload: $(echo $RL | cut -c1-80) / clusters '$(clusters 1)', tm-repl $(tmcap 1)"
# the DB now has n1 in 741 instead of 901 (db_text ANDs a query's keys, so
# it loads one DB cluster per node: no second row)
sleep 1; sed -i 's/^\([12]\):901:/\1:741:/' $D/clusterer
RL=$(mi 1 clusterer:reload)
check "the DB defining the controller's 741 makes the reload fail, every cluster left as it was" $(echo "$RL" | grep -q '"error"' && [ "$(clusters 1)" = "$C0" ] && [ "$(members 1 741)" = "$M0" ] && echo 1 || echo 0) "reload: $(echo $RL | cut -c1-80) / clusters '$(clusters 1)'"

echo "=== T45 module broadcasts by multicast: once each, repaired, fragmented, given up past the window, by TCP while a member does not take them ==="
for i in 1 2 3 4; do stop_hard $i; rm -f $R/n$i.pid; done; sleep 2
unset RIG_NATIVE RIG_NODE_ID; RIG_TM=0
export RIG_BCAST=1 RIG_MCAST_WINDOW=512
for i in 1 2 3; do start $i $NEW; done; sleep 12
bmark() { for i in 1 2 3; do eval B$i=$(wc -l < $R/n$i.log); done; }
# rxb <node> <tag>: the numbers of <tag>'s broadcasts as <node> received them
rxb() { local m; eval m=\$B$1; since $1 $m | grep -aoE "\[RXB\] [0-9]+ $2-[0-9]+" | sed -E 's/.*-//' | tr '\n' ' '; }
# rxs: sorted - event routes run in any SIP worker, so their log order is not the
# dispatch order (test_data.c checks that)
rxs() { rxb $1 $2 | tr ' ' '\n' | sed '/^$/d' | sort -n | tr '\n' ' '; }
seq0() { seq 0 $(($1 - 1)) | tr '\n' ' '; }
st() { local v; v=$(cstat $1 $2-741); echo ${v:-0}; }
# bdrop <node> <percent>: lose that share of the broadcast datagrams into <node>
bdrop() {
  tc qdisc del dev v$1p root 2>/dev/null
  [ "$2" = 0 ] && return 0
  tc qdisc add dev v$1p root handle 1: prio
  tc qdisc add dev v$1p parent 1:3 handle 30: netem loss $2%
  tc filter add dev v$1p parent 1:0 protocol ip u32 match ip protocol 17 0xff \
     match ip dport $((PORT + 1)) 0xffff flowid 1:3
}
# bcastb <node> <count> <tag> <bytes>: broadcasts of "<tag>-<k>:" and <bytes> x's
bcastb() {
  python3 - "$(ip4 $1)" "$2" "$3" "$4" <<'PY'
import socket, sys, time
ip, n, tag, size = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0)); s.settimeout(1)
for k in range(n):
    body = "x" * size
    m = ("OPTIONS sip:x@%s SIP/2.0\r\nVia: SIP/2.0/UDP 10.74.0.254:%d;branch=z9hG4bK%s%d\r\n"
         "From: <sip:t@10.74.0.254>;tag=1\r\nTo: <sip:x@%s>\r\nCall-ID: %s-%d\r\nCSeq: 1 OPTIONS\r\n"
         "X-BcastB: %s-%d\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s") % (
         ip, s.getsockname()[1], tag, k, ip, tag, k, tag, k, size, body)
    s.sendto(m.encode(), (ip, 5060))
    try: s.recv(4096)
    except socket.timeout: pass
    time.sleep(0.01)
PY
}
W=$(nid 2 1)
check "three members, n1 known to n2 as node $W" $([ "$(members 2 741 | wc -w)" = 3 ] && [ -n "$W" ] && echo 1 || echo 0) "$(members 2 741)"

bmark; S0=$(st 1 mcast_sent); RP0=$(st 1 mcast_repairs)
bcast 1 200 mca X-BcastB >/dev/null; sleep 3
check "n2 and n3 got n1's 200 broadcasts once each" $([ "$(rxs 2 mca)" = "$(seq0 200)" ] && [ "$(rxs 3 mca)" = "$(seq0 200)" ] && echo 1 || echo 0) "n2 $(rxb 2 mca | wc -w), n3 $(rxb 3 mca | wc -w)"
check "nothing lost, nothing sent again: n1's repairs unchanged" $([ "$(st 1 mcast_repairs)" = "$RP0" ] && echo 1 || echo 0) "repairs $RP0 -> $(st 1 mcast_repairs)"
check "by multicast: n1 sent 200 datagrams, none by TCP; n2 received them" $([ $(($(st 1 mcast_sent) - S0)) -ge 200 ] && [ "$(st 1 mcast_tcp)" = 0 ] && [ "$(st 2 mcast_received)" -ge 200 ] && echo 1 || echo 0) "sent $(($(st 1 mcast_sent) - S0)), tcp $(st 1 mcast_tcp), n2 received $(st 2 mcast_received)"

bmark; N0=$(st 2 mcast_nacks); P0=$(st 1 mcast_repairs)
bdrop 2 20
bcast 1 300 los X-BcastB >/dev/null; sleep 4
bdrop 2 0
check "a fifth lost on the way to n2: n2 still got all 300, once each" $([ "$(rxs 2 los)" = "$(seq0 300)" ] && echo 1 || echo 0) "n2 $(rxb 2 los | wc -w)"
check "n2 asked again, n1 sent again, nothing given up" $([ $(($(st 2 mcast_nacks) - N0)) -gt 0 ] && [ $(($(st 1 mcast_repairs) - P0)) -gt 0 ] && [ "$(st 2 mcast_gaps)" = 0 ] && echo 1 || echo 0) "nacks $(($(st 2 mcast_nacks) - N0)), repairs $(($(st 1 mcast_repairs) - P0)), gaps $(st 2 mcast_gaps)"
check "n3, not lossy, got the 300 once each too" $([ "$(rxs 3 los)" = "$(seq0 300)" ] && echo 1 || echo 0) "n3 $(rxb 3 los | wc -w)"

bmark; bdrop 2 20
bcastb 1 20 big 3000; sleep 4
bdrop 2 0
BG=$(since 2 $B2 | grep -acE "\[RXB\] [0-9]+ big-[0-9]+:x{3000}$")
check "20 broadcasts of 3000 bytes (fragments, a fifth lost into n2): whole and once each on n2 and n3" $([ "$BG" = 20 ] && [ "$(rxs 2 big)" = "$(seq0 20)" ] && [ "$(rxs 3 big)" = "$(seq0 20)" ] && echo 1 || echo 0) "n2 whole $BG, got '$(rxs 2 big | cut -c1-40)'"

bmark; G0=$(st 2 mcast_gaps)
bdrop 2 100
bcast 1 700 gone X-BcastB >/dev/null
bdrop 2 0; sleep 4
bcast 1 10 tail X-BcastB >/dev/null; sleep 2
GOT=$(rxb 2 gone)
check "n2, cut off from 700 broadcasts with 512 kept by n1, gave the rest up" $([ $(($(st 2 mcast_gaps) - G0)) -gt 0 ] && since 2 $B2 | grep -aq "from node $W were lost and could not be repaired" && echo 1 || echo 0) "gaps $(($(st 2 mcast_gaps) - G0))"
ONCE=$(echo "$GOT" | python3 -c 'import sys; v=sys.stdin.read().split(); print(1 if len(v) == len(set(v)) else 0)')
check "what n2 got of them came once each, and the stream goes on after" $([ "$ONCE" = 1 ] && [ "$(rxs 2 tail)" = "$(seq0 10)" ] && echo 1 || echo 0) "got $(echo $GOT | wc -w), tail '$(rxs 2 tail)'"
# both, in either order: each event route runs in whichever SIP worker takes it
NEV=$(since 2 $B2 | grep -aoE "\[NODE\] 741 $W [01]" | awk '{print $4}' | sort | tr '\n' ' ')
check "n2 reported n1 down and up again to its modules" $(echo "$NEV" | grep -q "^0 .*1" && echo 1 || echo 0) "$(since 2 $B2 | grep -ac "\[NODE\] 741 $W ")"
check "n3 got all 700 once each" $([ "$(rxs 3 gone)" = "$(seq0 700)" ] && echo 1 || echo 0) "n3 $(rxb 3 gone | wc -w)"

bmark
python3 $HERE/malformed_test.py outsider 10.74.0.254 $(ip4 1),$(ip4 2),$(ip4 3),239.0.74.1 $((PORT + 1)) 741 742 5 > $R/mal-data.json
bcast 1 50 aft X-BcastB >/dev/null; sleep 2
check "garbage on the broadcast port: every node up, broadcasts still once each" $(alive 1 && alive 2 && alive 3 && [ "$(rxs 2 aft)" = "$(seq0 50)" ] && echo 1 || echo 0) "$(cat $R/mal-data.json | cut -c1-80)"
# replay, for broadcasts: n1's datagrams recorded and sent again are not dispatched
# again, while it runs or after it restarted
bmark
python3 "$HERE/wire_tap.py" capture v1p "$(ip4 1)" $((PORT + 1)) 3 $R/t45r.json >/dev/null & TP=$!
sleep 0.5; bcast 1 10 rpl X-BcastB >/dev/null; wait $TP
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' $R/t45r.json)
replay 1 $R/t45r.json >/dev/null; sleep 2
check "n1's broadcast datagrams recorded ($N) and sent again: still once each on n2" $([ "${N:-0}" -gt 0 ] && [ "$(rxs 2 rpl)" = "$(seq0 10)" ] && echo 1 || echo 0) "$(rxs 2 rpl)"
stop_hard 1; rm -f $R/n1.pid; start 1 $NEW; sleep 10
bmark; replay 1 $R/t45r.json >/dev/null; sleep 2
check "sent again after n1 restarted: none dispatched (a previous life)" $([ -z "$(rxb 2 rpl)" ] && echo 1 || echo 0) "$(rxb 2 rpl)"

stop_graceful 3; rm -f $R/n3.pid
bmark; RIG_MCAST=0 start 3 $NEW
# a master failover and n3's admission: wait until n1 has switched to TCP and
# both have the link up - a TCP broadcast goes to the nodes up, as with clusterer
for k in $(seq 1 30); do sleep 1; N3=$(nid 1 3); since 1 $B1 | grep -aq "cluster 741\] broadcasts now go by TCP" && [ "$(members 1 741 | wc -w)" = 3 ] && [ -n "$N3" ] && since 1 $B1 | grep -aq "\[NODE\] 741 $N3 1" && since 3 $B3 | grep -aq "\[cluster 741\] this node is ONLINE" && break; done
sleep 2
check "n1 switched to TCP for n3, which does not take broadcasts by multicast" $(since 1 $B1 | grep -aq "cluster 741\] broadcasts now go by TCP" && echo 1 || echo 0) "$(members 1 741)"
bmark; T0=$(st 1 mcast_tcp)
bcast 1 50 tcp X-BcastB >/dev/null; sleep 3
check "n3 restarted with mcast_broadcasts 0: n1's 50 broadcasts went by TCP, all once each on n2 and n3" $([ $(($(st 1 mcast_tcp) - T0)) -ge 50 ] && [ "$(rxs 2 tcp)" = "$(seq0 50)" ] && [ "$(rxs 3 tcp)" = "$(seq0 50)" ] && echo 1 || echo 0) "tcp $(($(st 1 mcast_tcp) - T0)), n2 $(rxb 2 tcp | wc -w), n3 $(rxb 3 tcp | wc -w)"
unset RIG_BCAST RIG_MCAST_WINDOW
fi

if grp 11; then
boot 4
# adm <node> <ip> -> that member's admission state as <node> sees it (empty: not a member)
adm() { mi $1 clusterer:list_members | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741:
        for m in c["members"]:
            if m["ip"]==sys.argv[1]: print(m.get("admission"))' $2; }
masters() { local MS="" i; for i in "$@"; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done; echo $MS; }
one_master() { [ "$(echo $1 | wc -w)" = $2 ] && [ "$(echo $1 | tr ' ' '\n' | sort -u | wc -l)" = 1 ]; }
# new_master <masters> <count> <dead node>: one master, and not the dead one
new_master() { one_master "$1" $2 && [ "${1%% *}" != "$(ip4 $3)" ]; }
holders() { local n=0 i; for i in "$@"; do [ "$(tagst $i)" = active ] && n=$((n + 1)); done; echo $n; }
# cut_from <I|D> <node> <peer>...: <node> drops everything from the peers
cut_from() { local op=$1 n=$2 p; shift 2; for p in "$@"; do nx $n iptables -$op INPUT -s $(ip4 $p) -j DROP; done; }
# bin_cut <I|D> <a> <b>: no BIN connection between a and b, either way
bin_cut() { nx $2 iptables -$1 INPUT -s $(ip4 $3) -p tcp --dport 5588 -j DROP; nx $3 iptables -$1 INPUT -s $(ip4 $2) -p tcp --dport 5588 -j DROP; }
mnode() { local m; m=$(masters $1); m=${m##*.}; echo ${m#1}; }
marks() { local i; for i in 1 2 3 4; do eval K$i=$([ -f $R/n$i.log ] && wc -l < $R/n$i.log || echo 0); done; }
log_since() { eval "since $1 \$K$1"; }

echo "=== T46 a 2-2 split: a master on each side, then one master and one tag holder ==="
for a in 1 2; do cut_from I $a 3 4; done; for b in 3 4; do cut_from I $b 1 2; done
sleep 16
MA=$(masters 1 2); MB=$(masters 3 4)
check "each side has its own master (n1, n2: $MA; n3, n4: $MB)" $(one_master "$MA" 2 && one_master "$MB" 2 && [ "${MA%% *}" != "${MB%% *}" ] && echo 1 || echo 0) "$MA | $MB"
check "each side holds the tag: two holders while split (no fencing, as documented)" $([ "$(holders 1 2 3 4)" = 2 ] && echo 1 || echo 0) "$(holders 1 2 3 4)"
marks; for i in 1 2 3 4; do eval G$i=$(cstat $i merges-741); done
for a in 1 2; do cut_from D $a 3 4; done; for b in 3 4; do cut_from D $b 1 2; done
for k in $(seq 1 40); do sleep 1; M=$(masters 1 2 3 4); one_master "$M" 4 && [ "$(holders 1 2 3 4)" = 1 ] && break; done
M=$(masters 1 2 3 4)
check "healed: all 4 name one master ($M) and list 4 members" $(one_master "$M" 4 && [ "$(members 1 741 | wc -w)" = 4 ] && [ "$(members 4 741 | wc -w)" = 4 ] && echo 1 || echo 0) "$M"
check "healed: exactly one node holds the active tag" $([ "$(holders 1 2 3 4)" = 1 ] && echo 1 || echo 0) "$(holders 1 2 3 4)"
# one of the two masters left its partition for the other's (on its keepalive, or on its key
# grant after its beacon): that one says so, as a master - which of them depends on the heal
GW=""; for k in $(seq 1 20); do
  for a in ${MA%% *} ${MB%% *}; do i=${a##*.}; i=${i#1}; log_since $i | grep -aq "EVT MERGE 741 [0-9.]* 1$" && GW=$i; done
  [ -n "$GW" ] && break; sleep 0.5
done
eval g0=\${G${GW:-1}:-0}; g1=$(cstat ${GW:-1} merges-741)
check "the master that gave way raised E_CL_CTR_MERGE, naming the master it moved to and itself as one (n${GW:-?})" $([ -n "$GW" ] && echo 1 || echo 0) "$(for i in 1 2 3 4; do log_since $i | grep -a 'EVT MERGE' | tail -1 | sed 's/.*EVT/EVT/'; done | tr '\n' ' ')"
check "and merges-741 counted it there" $([ -n "$GW" ] && [ "${g1:-0}" -gt "$g0" ] 2>/dev/null && echo 1 || echo 0) "n${GW:-?}: $g0 -> $g1"

echo "=== T47 two members cut from each other only: no election, the rest unchanged ==="
MN=$(mnode 1); P=""; for i in 1 2 3 4; do [ $i != $MN ] && P="$P $i"; done; set -- $P; A=$1; B=$2
T0=$(cfgval $MN 741 term); M0=$(masters 1 2 3 4)
cut_from I $A $B; cut_from I $B $A
sleep 15
CUT=$(( $(dropped $A INPUT) + $(dropped $B INPUT) ))
M=$(masters 1 2 3 4)
check "n$A and n$B cut from each other ($CUT dropped): the master stays ($M)" $([ $CUT -gt 0 ] && one_master "$M" 4 && [ "${M%% *}" = "${M0%% *}" ] && echo 1 || echo 0) "before $M0, now $M"
check "no new term while the pair is cut" $([ "$(cfgval $MN 741 term)" = "$T0" ] && echo 1 || echo 0) "$T0 -> $(cfgval $MN 741 term)"
check "the master still lists all 4 members" $([ "$(members $MN 741 | wc -w)" = 4 ] && echo 1 || echo 0) "$(members $MN 741)"
cut_from D $A $B; cut_from D $B $A
sleep 10

echo "=== T48 the master killed during an admission: the next master admits the joiner ==="
# before KEY_GRANT arrives: the joiner loses the master's datagrams, then it dies
# (dropped on the joiner: a drop on the master's OUTPUT fails the send instead)
MN=$(mnode 1); for J in 4 3 2 1; do [ $J != $MN ] && break; done
stop_graceful $J; rm -f $R/n$J.pid; sleep 3
nx $J iptables -I INPUT -s $(ip4 $MN) -p udp -j DROP
marks; start $J $NEW
for k in $(seq 1 30); do sleep 0.5; log_since $MN | grep -aq "cluster 741\] sent KEY_GRANT to $(ip4 $J) " && break; done
GRANT=$(log_since $MN | grep -ac "cluster 741\] sent KEY_GRANT to $(ip4 $J) ")
stop_hard $MN; rm -f $R/n$MN.pid
O=""; for i in 1 2 3 4; do [ $i != $MN ] && O="$O $i"; done; set -- $O; F=$1; [ $F = $J ] && F=$2
# the joiner's own word too: a member may still show what the dead master had said of it
for k in $(seq 1 60); do sleep 1; M=$(masters $O); new_master "$M" 3 $MN && [ "$(adm $F $(ip4 $J))" = online ] && [ "$(adm $J $(ip4 $J))" = online ] && break; done
M=$(masters $O)
check "n$MN granted n$J a key that never arrived ($GRANT) and died: the 3 left name one master ($M)" $([ "$GRANT" -ge 1 ] && new_master "$M" 3 $MN && echo 1 || echo 0) "$M"
check "n$J was admitted by the next master and is ONLINE" $([ "$(adm $F $(ip4 $J))" = online ] && [ "$(adm $J $(ip4 $J))" = online ] && echo 1 || echo 0) "n$F: $(adm $F $(ip4 $J)), n$J: $(adm $J $(ip4 $J))"
check "n$J never founded a cluster of its own" $([ "$(log_since $J | grep -ac "cluster 741\] became master")" = 0 ] && echo 1 || echo 0) "$(log_since $J | grep -a "became master" | head -1)"
nx $J iptables -D INPUT -s $(ip4 $MN) -p udp -j DROP
start $MN $NEW; sleep 12
# while CONNECTING: the joiner's BIN link to one member is cut, then the master dies
MN=$(mnode 1); P=""; for i in 4 3 2 1; do [ $i != $MN ] && P="$P $i"; done; set -- $P; J=$1; C=$2; O3=$3
stop_graceful $J; rm -f $R/n$J.pid; sleep 3
bin_cut I $J $C
marks; start $J $NEW; sleep 10
check "n$J, its BIN link to n$C cut, is CONNECTING: no role, no tag" $([ "$(adm $MN $(ip4 $J))" = connecting ] && [ "$(role_of $MN $(ip4 $J))" = member ] && [ "$(tagst $J)" != active ] && echo 1 || echo 0) "admission $(adm $MN $(ip4 $J)), role $(role_of $MN $(ip4 $J)), tag $(tagst $J)"
stop_hard $MN; rm -f $R/n$MN.pid
for k in $(seq 1 20); do sleep 1; M=$(masters $J $C $O3); new_master "$M" 3 $MN && break; done
NM=$(mnode $C)
check "the next master (n$NM) keeps n$J CONNECTING" $([ -n "$NM" ] && [ "$NM" != $J ] && [ "$(adm $NM $(ip4 $J))" = connecting ] && echo 1 || echo 0) "master n$NM, admission $(adm $NM $(ip4 $J))"
# a down link is probed again node_timeout (60 s) after its last probe
bin_cut D $J $C
for k in $(seq 1 75); do sleep 1; [ "$(adm $NM $(ip4 $J))" = online ] && break; done
check "its link back, n$J goes ONLINE under n$NM, and all name one master" $([ "$(adm $NM $(ip4 $J))" = online ] && one_master "$(masters $J $C $O3)" 3 && echo 1 || echo 0) "admission $(adm $NM $(ip4 $J)), masters $(masters $J $C $O3)"
start $MN $NEW; sleep 12

echo "=== T49 a joiner stuck CONNECTING is parked after 60 s, and the queue moves on past it ==="
MN=$(mnode 1); P=""; for i in 4 3 2 1; do [ $i != $MN ] && P="$P $i"; done; set -- $P; J=$1; Q=$2; C=$3
stop_graceful $J; stop_graceful $Q; rm -f $R/n$J.pid $R/n$Q.pid; sleep 3
bin_cut I $J $C
# adst: the master's admitted-741 and admissions_stuck-741, as counted from here on (nobody
# is CONNECTING then), and its connecting-741
for k in $(seq 1 30); do [ "$(cstat $MN connecting-741)" = 0 ] && break; sleep 1; done
AD0=$(cstat $MN admitted-741); AS0=$(cstat $MN admissions_stuck-741)
adst() { echo "$(( $(cstat $MN admitted-741) - ${AD0:-0} )) $(( $(cstat $MN admissions_stuck-741) - ${AS0:-0} )) $(cstat $MN connecting-741)"; }
marks; start $J $NEW; sleep 15
start $Q $NEW; sleep 12
check "n$J stuck: the master warns, and n$Q is queued behind it" $(log_since $MN | grep -aq "cluster 741\] $(ip4 $J) is still CONNECTING after" && log_since $Q | grep -aq "cluster 741\] master .* queued this node for admission" && [ "$(adm $MN $(ip4 $Q))" = "" ] && echo 1 || echo 0) "n$Q: $(adm $MN $(ip4 $Q))"
check "the master raised E_CL_CTR_ADMISSION for n$J, connecting and then stuck, and counted it stuck once; one node CONNECTING" $(log_since $MN | grep -aq "EVT ADMISSION 741 $(ip4 $J) [0-9]* connecting" && [ "$(log_since $MN | grep -ac "EVT ADMISSION 741 $(ip4 $J) [0-9]* stuck")" = 1 ] && [ "$(adst)" = "0 1 1" ] && echo 1 || echo 0) "admitted, stuck, connecting: $(adst)"
for k in $(seq 1 60); do sleep 1; [ "$(adm $MN $(ip4 $Q))" = online ] && break; done
check "after 60 s n$J is parked (warning, event) and n$Q is admitted past it, ONLINE" $(log_since $MN | grep -aq "cluster 741\] $(ip4 $J) is parked" && log_since $MN | grep -aq "EVT ADMISSION 741 $(ip4 $J) [0-9]* parked" && [ "$(adm $MN $(ip4 $Q))" = online ] && echo 1 || echo 0) "n$Q: $(adm $MN $(ip4 $Q))"
check "parked n$J stays CONNECTING, with no role and no tag" $([ "$(adm $MN $(ip4 $J))" = connecting ] && [ "$(role_of $MN $(ip4 $J))" = member ] && [ "$(tagst $J)" != active ] && echo 1 || echo 0) "admission $(adm $MN $(ip4 $J)), role $(role_of $MN $(ip4 $J)), tag $(tagst $J)"
for k in $(seq 1 10); do [ "$(cstat $C connecting-741)" = 1 ] && break; sleep 0.5; done
check "n$Q is counted admitted, n$J stuck once and still the one CONNECTING, as the master relays it to n$C too" $([ "$(adst)" = "1 1 1" ] && [ "$(cstat $C connecting-741)" = 1 ] && echo 1 || echo 0) "admitted, stuck, connecting: $(adst); connecting-741 on n$C: $(cstat $C connecting-741)"
bin_cut D $J $C
for k in $(seq 1 75); do sleep 1; [ "$(adm $MN $(ip4 $J))" = online ] && break; done
check "its link back, parked n$J goes ONLINE" $([ "$(adm $MN $(ip4 $J))" = online ] && echo 1 || echo 0) "$(adm $MN $(ip4 $J))"
for k in $(seq 1 20); do log_since $MN | grep -aq "EVT ADMISSION 741 $(ip4 $J) [0-9]* online" && break; sleep 0.5; done
check "n$J is counted admitted as well and its online event raised; nobody is CONNECTING" $(log_since $MN | grep -aq "EVT ADMISSION 741 $(ip4 $J) [0-9]* online" && [ "$(adst)" = "2 1 0" ] && echo 1 || echo 0) "admitted, stuck, connecting: $(adst)"

echo "=== T50 a node that hears the cluster but whose multicast is cut: a member, then the master ==="
# the other way round from T16: only the node's own multicast is dropped, its
# unicast and BIN go on, so the others stop hearing it while it hears them
mc_out() { nx $2 iptables -$1 OUTPUT -p udp -d 239.0.74.1 -j DROP; }
MN=$(mnode 1); for X in 4 3 2 1; do [ $X != $MN ] && break; done
marks; mc_out I $X
sleep 15
CUT=$(dropped $X OUTPUT); SIL=0
for i in 1 2 3 4; do [ $i != $X ] && log_since $i | grep -aq "($(ip4 $X)) went silent" && SIL=$((SIL + 1)); done
check "member n$X unheard ($CUT dropped): the other 3 report it down ($SIL)" $([ $CUT -gt 0 ] && [ $SIL = 3 ] && echo 1 || echo 0) "$SIL"
check "the master stays and one node holds the tag" $([ "$(masters $MN)" = "$(ip4 $MN)" ] && [ "$(holders 1 2 3 4)" = 1 ] && echo 1 || echo 0) "masters $(masters 1 2 3 4), holders $(holders 1 2 3 4)"
mc_out D $X
# past the purge window the master dropped it: heard again, it is admitted again
for k in $(seq 1 30); do sleep 1; M=$(masters 1 2 3 4); one_master "$M" 4 && [ "$(holders 1 2 3 4)" = 1 ] && [ "$(admission $MN $(ip4 $X))" = online ] && break; done
check "healed: n$X online on the master again, one master ($M), one tag holder" $(one_master "$M" 4 && [ "$(holders 1 2 3 4)" = 1 ] && [ "$(admission $MN $(ip4 $X))" = online ] && echo 1 || echo 0) "$M | $(holders 1 2 3 4) | n$X '$(admission $MN $(ip4 $X))'"

MN=$(mnode 1); P=""; for i in 1 2 3 4; do [ $i != $MN ] && P="$P $i"; done
marks; mc_out I $MN
for k in $(seq 1 40); do sleep 1; MO=$(masters $P); one_master "$MO" 3 && [ "${MO%% *}" != "$(ip4 $MN)" ] && break; done
EK=$k; sleep 5
CUT=$(dropped $MN OUTPUT); NM=${MO%% *}; NM=${NM##*.}; NM=${NM#1}
# its own answer no longer holds their election: they elect within a watchdog period or two
check "master n$MN unheard ($CUT dropped): the other 3 elect a master ($MO) in $EK s" $([ $CUT -gt 0 ] && one_master "$MO" 3 && [ "${MO%% *}" != "$(ip4 $MN)" ] && [ $EK -le 15 ] && echo 1 || echo 0) "$MO in $EK s"
# asked by them who still hears it, n$MN learnt it is the one unheard
check "n$MN stepped down: it follows the new master and holds no active tag" $([ "$(masters $MN)" = "${MO%% *}" ] && [ "$(tagst $MN)" != active ] && echo 1 || echo 0) "n$MN names '$(masters $MN)', tag $(tagst $MN)"
check "and one node holds the tag, the new master" $([ "$(holders 1 2 3 4)" = 1 ] && [ "$(tagst $NM)" = active ] && echo 1 || echo 0) "$(holders 1 2 3 4) holders, n$NM $(tagst $NM)"
mc_out D $MN
for k in $(seq 1 40); do sleep 1; M=$(masters 1 2 3 4); one_master "$M" 4 && [ "$(holders 1 2 3 4)" = 1 ] && [ "$(admission $NM $(ip4 $MN))" = online ] && break; done
check "healed: one master ($M), one tag holder, n$MN online on it again" $(one_master "$M" 4 && [ "$(holders 1 2 3 4)" = 1 ] && [ "$(admission $NM $(ip4 $MN))" = online ] && echo 1 || echo 0) "$M | $(holders 1 2 3 4) | n$MN '$(admission $NM $(ip4 $MN))'"

echo "=== T55 two members unheard together past the purge window: both are admitted again ==="
# their own multicast is cut, as in T50: the master purges both, and once heard again both
# ask at once - one is admitted, the other is told to wait and must ask again
MN=$(mnode 1); P=""; for i in 1 2 3 4; do [ $i != $MN ] && P="$P $i"; done; set -- $P; A=$1; B=$2
IA=$(nid $MN $A); IB=$(nid $MN $B)
mc_out I $A; mc_out I $B
for k in $(seq 1 90); do sleep 1; [ "$(members $MN 741 | wc -w)" = 2 ] && break; done
PG=$k; CUT=$(( $(dropped $A OUTPUT) + $(dropped $B OUTPUT) ))
check "n$A and n$B unheard ($CUT dropped): the master purged both, after $PG s" $([ $CUT -gt 0 ] && [ "$(members $MN 741 | wc -w)" = 2 ] && [ -z "$(admission $MN $(ip4 $A))$(admission $MN $(ip4 $B))" ] && echo 1 || echo 0) "$(members $MN 741)"
mc_out D $A; mc_out D $B
for k in $(seq 1 90); do sleep 1; M=$(masters 1 2 3 4); one_master "$M" 4 && [ "$(admission $MN $(ip4 $A))" = online ] && [ "$(admission $MN $(ip4 $B))" = online ] && [ "$(holders 1 2 3 4)" = 1 ] && break; done
check "heard again: n$A and n$B are both listed and online on the master, under their node ids ($k s)" $([ "$(admission $MN $(ip4 $A))" = online ] && [ "$(admission $MN $(ip4 $B))" = online ] && [ "$(members $MN 741 | wc -w)" = 4 ] && [ -n "$IA" ] && [ "$(nid $MN $A)" = "$IA" ] && [ "$(nid $MN $B)" = "$IB" ] && echo 1 || echo 0) "n$A '$(admission $MN $(ip4 $A))', n$B '$(admission $MN $(ip4 $B))', $(members $MN 741)"
check "one master ($M) named by all four, one tag holder" $(one_master "$M" 4 && [ "$(holders 1 2 3 4)" = 1 ] && echo 1 || echo 0) "$M | $(holders 1 2 3 4)"

echo "=== T51 another password next to a lone master: it founds nothing ==="
# a lone master sends two packets a second: a joiner that cannot read them waits all the same
K=$(mnode 1); for i in 1 2 3 4; do [ $i != $K ] && { stop_graceful $i; rm -f $R/n$i.pid; }; done
sleep 6
for X in 4 3 2 1; do [ $X != $K ] && break; done
X0=$(wc -l < $R/n$X.log)
RIG_PASSWORD=rig74-the-wrong-one start $X $NEW
# it says why after CL_CTR_AUTH_DEFER_MAX (32) one-second rounds past its query_time deadline;
# a round its worker slept through is not counted, so wait for the line, not for a time
for k in $(seq 1 100); do sleep 1; since $X $X0 | grep -aq "cannot authenticate on .* still trying to join" && break; done
check "n$X runs, never made itself master ($k s), and names no master of its own" $(alive $X && ! since $X $X0 | grep -aq "my role changed: [a-z]* -> master\|became master" && ! members $X 741 | tr ' ' '\n' | grep -q ':master:' && echo 1 || echo 0) "alive: $(alive $X && echo yes || echo no), $(members $X 741)"
check "the lone master n$K is still master and the only tag holder" $([ "$(masters $K)" = "$(ip4 $K)" ] && [ "$(tagst $K)" = active ] && [ "$(tagst $X)" != active ] && echo 1 || echo 0) "masters $(masters $K), tags n$K $(tagst $K) n$X $(tagst $X)"
check "n$X says why, as critical" $(since $X $X0 | grep -aq "cannot authenticate on .* still trying to join" && echo 1 || echo 0) ""
stop_hard $X; rm -f $R/n$X.pid

echo "=== T62 a lone master paused past the watchdog does not stand down ==="
# a master that is alone cannot have been replaced meanwhile: woken, it keeps the role
marks; S0=$(cfgval $K 741 self_stalls); RC0="$(cstat $K role_changes-741) $(cstat $K master_changes-741) $(cfgval $K 741 term)"
pause_node $K; sleep 6; resume_node $K
for k in $(seq 1 30); do sleep 1; [ "$(cfgval $K 741 self_stalls)" -gt "${S0:-0}" ] 2>/dev/null && break; done
sleep 3
S1=$(cfgval $K 741 self_stalls); RC1="$(cstat $K role_changes-741) $(cstat $K master_changes-741) $(cfgval $K 741 term)"
check "lone master n$K, paused 6 s, found that it had not run (self_stalls $S0 -> $S1)" $([ -n "$S0" ] && [ "$S1" -gt "$S0" ] 2>/dev/null && log_since $K | grep -aq "cluster 741\] this node did not run for" && echo 1 || echo 0) "$S0 -> $S1"
check "it did not stand down: still master with the tag, no role or master change counted, the same term" $(! log_since $K | grep -a "cluster 741\]" | grep -aq "stands down" && [ "$(masters $K)" = "$(ip4 $K)" ] && [ "$(tagst $K)" = active ] && [ "$RC1" = "$RC0" ] && echo 1 || echo 0) "role changes, master changes, term: $RC0 -> $RC1; master '$(masters $K)', tag $(tagst $K)"

echo "=== T59 two nodes, the master's multicast cut: its only member elects itself, and the master stands down ==="
# with no third node to ask, the member still tells the group that it hears no master, which
# is how the master learns that it is unheard; before, each stayed master and held the tag
for Y in 4 3 2 1; do [ $Y != $K ] && break; done
start $Y $NEW
for k in $(seq 1 40); do sleep 1; [ "$(admission $K $(ip4 $Y))" = online ] && [ "$(masters $Y)" = "$(ip4 $K)" ] && break; done
check "n$Y joined lone master n$K: two members, n$Y online, the tag on n$K alone" $([ "$(members $K 741 | wc -w)" = 2 ] && [ "$(admission $K $(ip4 $Y))" = online ] && [ "$(masters $Y)" = "$(ip4 $K)" ] && [ "$(tagst $K)" = active ] && [ "$(holders $K $Y)" = 1 ] && echo 1 || echo 0) "$(members $K 741), n$Y '$(admission $K $(ip4 $Y))', $(holders $K $Y) holder(s)"
marks; mc_out I $K
for k in $(seq 1 40); do sleep 1; [ "$(masters $Y)" = "$(ip4 $Y)" ] && [ "$(masters $K)" = "$(ip4 $Y)" ] && [ "$(tagst $Y)" = active ] && [ "$(tagst $K)" != active ] && break; done
EK=$k; CUT=$(dropped $K OUTPUT)
check "master n$K unheard ($CUT dropped): n$Y, with nobody to ask, elected itself ($EK s)" $([ $CUT -gt 0 ] && [ "$(masters $Y)" = "$(ip4 $Y)" ] && echo 1 || echo 0) "n$Y names '$(masters $Y)'"
check "n$K, asked by its only member whether anyone hears it, stood down: it follows n$Y" $(log_since $K | grep -aq "cluster 741\] 1 of the 1 other members asked whether anyone still hears this master" && [ "$(masters $K)" = "$(ip4 $Y)" ] && echo 1 || echo 0) "n$K names '$(masters $K)'"
check "one tag holder while cut: n$Y, not n$K" $([ "$(holders $K $Y)" = 1 ] && [ "$(tagst $Y)" = active ] && [ "$(tagst $K)" != active ] && echo 1 || echo 0) "n$Y $(tagst $Y), n$K $(tagst $K)"
mc_out D $K
for k in $(seq 1 60); do
  sleep 1; M=$(masters $K $Y); NM=${M%% *}; NM=${NM##*.}; NM=${NM#1}; [ "$NM" = "$K" ] && O=$Y || O=$K
  one_master "$M" 2 && [ "$(holders $K $Y)" = 1 ] && [ "$(admission ${NM:-0} $(ip4 $O))" = online ] && [ "$(cstat ${NM:-0} members-741)" = 2 ] && break
done
check "healed: one master ($M) named by both, one tag holder, the other node online on it and heard ($k s)" $(one_master "$M" 2 && [ "$(holders $K $Y)" = 1 ] && [ "$(admission ${NM:-0} $(ip4 $O))" = online ] && [ "$(cstat ${NM:-0} members-741)" = 2 ] && echo 1 || echo 0) "$M | $(holders $K $Y) | n$O '$(admission ${NM:-0} $(ip4 $O))', members-741 $(cstat ${NM:-0} members-741)"
fi

# groups 1 and 2 run before T11 and are not checked
if [ -z "$GROUP" ] || [ "$GROUP" -ge 3 ]; then
echo "=== replays after T12: none ==="
RPN=${RPB:-0}; for i in 1 2 3 4; do eval m=\$RP$i; RPN=$((RPN + $(since $i $m | grep -ac "already accepted, dropping\|older than the replay window, dropping"))); done
check "no control packet refused as a replay since T12 (re-keys keep the sequence)" $([ $RPN = 0 ] && echo 1 || echo 0) "$RPN"
# the same by the statistic, which also counts what the once-a-minute warning leaves unsaid
RFN=$(rf_growth)
if [ -n "$RFN" ]; then
  check "replays_refused-741 grew on no node since T12, but for the records sent again on purpose" $([ $((${RFB:-0} + RFN)) = 0 ] && echo 1 || echo 0) "$((${RFB:-0} + RFN))"
else skip "replays_refused in the closing check" "no node reports a replays_refused statistic"; fi
fi
echo "=== logs: crashes / criticals ==="
# "BUG trying to overwrite entry": core TCP_main on BIN reconnect (#4289); T32's refused nodes'
# CRITICAL is matched by function name, as another process's output can cut into the line
C=$(cat $R/n?.log | grep -av "CRITICAL:clusterer_controller:cl_ctr_handle_join_reject: \|cannot authenticate on .* still trying to join\|join failed after .* Still trying" | grep -aic "segfault\|SIGSEGV\|CRITICAL\|BUG trying to overwrite entry")
check "no crashes, CRITICAL or TCP_main BUG lines" $([ "$C" = 0 ] && echo 1 || echo 0) "$C"
echo
# a test left out for a build not given is no failure, and is not counted as passed either
[ $SKIPN = 0 ] || echo "SKIPPED: $SKIPN test(s): $SKIPL"
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL = 0 ] || exit 1
