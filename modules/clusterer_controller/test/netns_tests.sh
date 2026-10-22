#!/bin/bash
# netns_tests.sh - end-to-end tests of clusterer_controller on four network
# namespaces of this host (see netns_rig.sh and README.md).  Run as root:
#
#   NEW=/usr/local/opensips [OLD=/opt/opensips-wire1] [PREV=/opt/opensips-prev] ./netns_tests.sh
#
# OLD is a build of another wire version, e.g. 1 (T6); PREV a build of this
# wire version that advertises no capabilities - this tree built with
# CC_EXTRA_OPTS=-DCL_CTR_CAPS_MINE=0 (T27).  Tests needing one are skipped
# without it.
#
# Assertions are on EFFECTS (delivery counts, member tables, ids, processes),
# log lines only where the log line IS the behaviour (a warning that must be
# emitted).
. "$(dirname "$0")/netns_rig.sh"
trap 'tc qdisc del dev v1p root 2>/dev/null; teardown' EXIT
PASS=0; FAIL=0
check() { if [ "$2" = 1 ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1  ($3)"; FAIL=$((FAIL+1)); fi; }
members() {  # members <node> <cluster> -> "ip:status:id ..." sorted
  mi $1 clusterer_controller:list_members | python3 -c '
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
cfgval() { mi $1 clusterer_controller:list_config | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c["cluster_id"]==int(sys.argv[1]): print(c.get(sys.argv[2]))' $2 $3; }
nid() { members $1 741 | tr ' ' '\n' | grep "^$(ip4 $2):" | cut -d: -f3; }

setup
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
X=$(cat $R/n?.log | grep -ac "is not ours\|already accepted\|speaks wire version")
check "no cross-cluster multicast leakage (IP_MULTICAST_ALL)" $([ "$X" = 0 ] && echo 1 || echo 0) "$X lines"

echo "=== T2 consumer broadcast, steady state ==="
bcast 1 20 a >/dev/null; sleep 2
check "n2 got 20/20 from n1" $([ "$(rx_count 2 a)" = 20 ] && echo 1 || echo 0) "$(rx_count 2 a)"
check "n3 got 20/20 from n1" $([ "$(rx_count 3 a)" = 20 ] && echo 1 || echo 0) "$(rx_count 3 a)"

echo "=== T3 SIGKILL restart of member n1 after > replay-window traffic ==="
ID1=$(nid 3 1)
bcast 1 1200 pump >/dev/null; sleep 2
echo "    n2 received $(rx_count 2 pump) of 1200 pump messages before the kill"
stop_hard 1; rm -f $R/n1.pid
start 1 $NEW; sleep 8
bcast 1 30 b >/dev/null; sleep 2
check "after restart: non-master n2 gets n1's traffic (30/30)" $([ "$(rx_count 2 b)" = 30 ] && echo 1 || echo 0) "$(rx_count 2 b)"
check "after restart: master n3 gets n1's traffic (30/30)" $([ "$(rx_count 3 b)" = 30 ] && echo 1 || echo 0) "$(rx_count 3 b)"
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
check "new nodes name the v1 peer" $(grep -aq "10.74.0.14 speaks wire version 1, this node speaks 3" $R/n3.log && echo 1 || echo 0) ""
MM=$(members 3 741)
check "main partition unaffected: 3 members" $([ "$(echo $MM | wc -w)" = 3 ] && echo 1 || echo 0) "$MM"
else
echo "  SKIP  (OLD not set)"
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
# The majority's master leads the healed cluster: masters are ranked on the
# members they hear now, and the isolated n2 still LISTS peers it has not
# purged yet - ranked on its table it could tie the majority and win on term.
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

echo "=== T10 recorded consumer broadcasts sent again are not delivered again ==="
tap 1 4 $R/t10.json >/dev/null & TP=$!
sleep 0.5; bcast 1 5 rp >/dev/null; wait $TP
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' $R/t10.json)
check "n2 and n3 got 5/5 first" $([ "$(rx_count 2 rp)" = 5 ] && [ "$(rx_count 3 rp)" = 5 ] && echo 1 || echo 0) "$(rx_count 2 rp)/$(rx_count 3 rp)"
check "recorded n1's datagrams to send again ($N)" $([ "${N:-0}" -gt 0 ] && echo 1 || echo 0) "$N"
replay 1 $R/t10.json >/dev/null; sleep 2
check "replayed while n1 runs: still 5 on n2 and n3" $([ "$(rx_count 2 rp)" = 5 ] && [ "$(rx_count 3 rp)" = 5 ] && echo 1 || echo 0) "$(rx_count 2 rp)/$(rx_count 3 rp)"
stop_hard 1; rm -f $R/n1.pid
start 1 $NEW 1 2 fleet-a; sleep 8
replay 1 $R/t10.json >/dev/null; sleep 2
check "replayed after n1 restarted: still 5 on n2 and n3" $([ "$(rx_count 2 rp)" = 5 ] && [ "$(rx_count 3 rp)" = 5 ] && echo 1 || echo 0) "$(rx_count 2 rp)/$(rx_count 3 rp)"
echo "    n2 'replay from before it restarted' lines: $(grep -ac 'a replay from before it restarted' $R/n2.log)"

echo "=== T11 an older MEMBER_LIST arriving late does not undo a newer one ==="
# n2 misses the list that pins the tag on n1 (L1), receives the one that pins
# it on n2 (L2), and then L1 arrives - sealed, from the master's address, and
# never seen by n2's replay window, so only the list's own stamp can order it.
# n2 is cut off for under 2 s, inside the 3 s master keepalive timeout.
I1=$(nid 3 1); I2=$(nid 3 2)
nx 2 iptables -I INPUT -p udp -s $(ip4 3) --dport $PORT -j DROP
tap 3 1.5 $R/t11.json >/dev/null & TP=$!
sleep 0.3; mi 3 clusterer_controller:shtag_force cluster_id=741 node_id=$I1 >/dev/null; wait $TP
CUT11=$(dropped 2 INPUT)
nx 2 iptables -D INPUT -p udp -s $(ip4 3) --dport $PORT -j DROP
check "the T11 cut fired ($CUT11 dropped)" $([ "$CUT11" -gt 0 ] && echo 1 || echo 0) ""
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' $R/t11.json)
check "recorded the master's datagrams, L1 among them ($N)" $([ "${N:-0}" -gt 0 ] && echo 1 || echo 0) "$N"
check "n2 missed L1 (still auto)" $([ "$(cfgval 2 741 shtag_mode)" = auto ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
mi 3 clusterer_controller:shtag_force cluster_id=741 node_id=$I2 >/dev/null; sleep 2
check "n2 applied L2 (override:$I2)" $([ "$(cfgval 2 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
replay 3 $R/t11.json >/dev/null; sleep 2
check "after the late L1: n2 still override:$I2" $([ "$(cfgval 2 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
check "after the late L1: n1 still override:$I2" $([ "$(cfgval 1 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 1 741 shtag_mode)"
mi 3 clusterer_controller:shtag_auto cluster_id=741 >/dev/null; sleep 1

echo "=== T12 tm anycast Via cid: absent until the node has an id, then the live id ==="
# A sink on the bridge records the top Via of every request n4 relays
# statefully.  Requests start before n4 does, and n4's controller traffic is
# held back for its first 1.2 s (under query_time, so it does not found a
# cluster of its own), so the first relayed requests leave before n4 has an id.
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

# T10/T11 replay packets on purpose; from here on no control packet may be
# refused as a replay - a node's sequence never restarts within its life
for i in 1 2 3 4; do eval RP$i=$(wc -l < $R/n$i.log); done
echo "=== T13 a member paused past every timeout wakes without electing itself ==="
# 15 s is past the master watchdog (3 s), the election window and the purge
# window (query_time x 3 and x 6 = 6 s and 12 s here).  Woken, the node finds
# every timer expired and every peer stale - although only it was gone.
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
# n2 is paused while junk floods its cluster port; the kernel drops what does
# not fit its receive buffer, and SO_RXQ_OVFL reports the count when it reads
# again.  The junk itself is refused as undecryptable; n2 must stay a member.
# clusters 741 and 742 share the port: either socket may take the flood
drops2() { echo $(( $(cfgval 2 741 rx_kernel_drops) + $(cfgval 2 742 rx_kernel_drops) )); }
D0=$(drops2); B2=$(cfgval 2 741 rcvbuf_bytes)
pause_node 2
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.74.0.254", 0))
junk = b"\xCD\x00" + b"\x55" * 1198
for _ in range(4000):
    s.sendto(junk, ("10.74.0.12", 3741))
PY
sleep 1; resume_node 2; sleep 6
D1=$(drops2)
echo "    n2 rcvbuf_bytes $B2, rx_kernel_drops $D0 -> $D1"
check "rx_kernel_drops grew" $([ "${D1:-0}" -gt "${D0:-0}" ] 2>/dev/null && echo 1 || echo 0) "$D0 -> $D1"
check "n2 still a member after the flood" $(members 3 741 | grep -q "10.74.0.12:" && echo 1 || echo 0) "$(members 3 741)"

echo "=== T16 a member that alone stops hearing the master asks before electing ==="
# A one-sided fault: the member's own input from the master is cut, every
# other node still hears it.  The member must not re-elect - its peers say
# the master is alive - and the cluster must keep one master.
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
# maint <node> <ip> -> that member's maintenance state as <node> sees it
maint() { mi $1 clusterer_controller:list_members | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741:
        for m in c["members"]:
            if m["ip"]==sys.argv[1]: print(m.get("maintenance"))' $2; }
role_of() { members $1 741 | tr ' ' '\n' | grep "^$2:" | cut -d: -f2; }
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)
BIP=$(members 2 741 | tr ' ' '\n' | grep ':backup:' | cut -d: -f1)
BN=${BIP##*.}; BN=${BN#1}; MN=${MIP##*.}; MN=${MN#1}
echo "    master $MIP, backup $BIP"
mi $BN clusterer_controller:maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $BIP)"; done
check "every node lists backup $BIP as evicted" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = evicted ] && echo 1 || echo 0) "$V"
RO=""; for i in 1 2 3 4; do RO="$RO $(role_of $i $BIP)"; done
check "no node names $BIP backup any more" $(echo "$RO" | grep -q backup && echo 0 || echo 1) "$RO"
BID=$(nid $MN $BN)
echo "    $BIP is node_id '$BID' in the master's view: $(members $MN 741)"
check "pinning the tag on a node in maintenance is refused" $(mi $MN clusterer_controller:shtag_force cluster_id=741 node_id=${BID:-0} | grep -q "maintenance" && echo 1 || echo 0) "$(mi $MN clusterer_controller:shtag_force cluster_id=741 node_id=${BID:-0} | cut -c1-120)"
check "$BIP lists itself as evicted" $([ "$(maint $BN $BIP)" = evicted ] && echo 1 || echo 0) ""
for i in 1 2 3 4; do eval L$i=$(wc -l < $R/n$i.log); done
mi $MN clusterer_controller:maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
NM=$(echo $MS | cut -d' ' -f1)
check "the master in maintenance handed over: one new master, named by all" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && [ "$NM" != "$MIP" ] && [ "$NM" != "$BIP" ] && echo 1 || echo 0) "$MS"
WS=0; for i in 1 2 3 4; do eval m=\$L$i; WS=$((WS + $(since $i $m | grep -ac "went silent"))); done
check "the handover did not wait for the master watchdog (no 'went silent')" $([ $WS = 0 ] && echo 1 || echo 0) "$WS"
NN=${NM##*.}; NN=${NN#1}
check "the active tag moved with it: $NM active, $MIP backup" $([ "$(tagst $NN)" = active ] && [ "$(tagst $MN)" = backup ] && echo 1 || echo 0) "new $(tagst $NN) old $(tagst $MN)"
mi $BN clusterer_controller:maintenance cluster_id=741 state=none >/dev/null
mi $MN clusterer_controller:maintenance cluster_id=741 state=none >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $BIP) $(maint $i $MIP)"; done
check "both back in service on every node" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && echo 1 || echo 0) "$V"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "still one master, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T18 one member cut off for 11, 12 and 13 s: the majority's master leads after each heal ==="
# The isolated node elects itself (a higher term).  Around the purge window the
# majority has already purged it while it still lists the members it has not
# purged yet: on table counts that is a tie it wins on term, taking the whole
# cluster; on the members each master hears it is 3 to 1.  The exact second
# depends on where the ALIVE and purge ticks fall, so three lengths are tried.
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
# On a steady link the learned watchdog stays at its 3 s floor: a master that
# dies (SIGKILL - no GOODBYE) must be replaced within that plus one probe
# round and an election tick.
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
# As systemd Restart=always does it: the restarted node asks to join while the
# survivors still list it and have no master to answer; the master they elect
# announces the active tag to every node it lists - this one included, before
# it has an identity (10.22.23.196, 21 Oct: a TCP receiver segfaulted).
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

echo "=== T20 a lossy, jittery link into one member: patience, not an election ==="
# 25% loss and 300 ms +/- 300 ms delay on everything n1 receives, for 90 s.
# Keepalive gaps of 2-4 s are now routine there: the member must learn a
# longer wait and keep the master; once the link is clean the wait shrinks
# back towards the 3 s floor (over minutes - patience is meant to outlast one
# burst of loss).
x=1; MX=$(wc -l < $R/n$x.log); PEAK=0
tc qdisc add dev v${x}p root netem delay 300ms 300ms loss 25%
for k in 1 2 3 4 5 6 7 8 9; do sleep 10; T=$(cfgval $x 741 master_timeout_ms); [ "${T:-0}" -gt "$PEAK" ] 2>/dev/null && PEAK=$T; done
tc qdisc del dev v${x}p root
E=$(since $x $MX | grep -a "cluster 741\]" | grep -ac "went silent"); P=$(since $x $MX | grep -a "cluster 741\]" | grep -ac "asking .* peer")
echo "    n$x over 90 s: $P watchdog round(s), $E election(s), learned wait peaked at $PEAK ms, $(cfgval $x 741 master_false_suspicions) false suspicion(s)"
check "no election on the lossy member" $([ "$E" = 0 ] && echo 1 || echo 0) "$E"
check "it learned to wait longer than 3 s" $([ "$PEAK" -gt 3000 ] && echo 1 || echo 0) "$PEAK"
sleep 30
T=$(cfgval $x 741 master_timeout_ms)
check "the learned wait shrinks once the link is clean ($PEAK -> $T ms)" $([ "${T:-0}" -lt "$PEAK" ] && [ "${T:-0}" -ge 3000 ] && echo 1 || echo 0) "$T"
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
check "one master throughout, named by all four" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && echo 1 || echo 0) "$MS"

echo "=== T21 a member cut off in both directions suspects itself first ==="
# Nobody answers its question: it is the likeliest fault, so it waits one
# more watchdog period before electing itself.
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
# Nobody confirms the master is gone, so its self-election keeps the term
# (PreVote): the cluster's term is the same after the heal as before, and
# the cluster's master leads.
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 1 2 3 4; do [ "$(ip4 $x)" != "$MIP" ] && break; done
# a rested node: after T21's cut its local health and learned margin stay
# raised for a while, and a watchdog stretched past the 25 s cut never gets
# as far as electing itself
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
# Short pauses (1.3 s on, 1 s off, ten times) stay under the stall threshold
# but make the member's timers run late again and again: its local health
# multiplier rises, it neither elects itself nor purges anyone, and once it
# runs smoothly again the multiplier drains back to 0.
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

echo "=== T24 release_tag_when_isolated: a cut-off master, or a member cut off alone, gives up the active tag ==="
# Off until here: no node may have released anything so far.
check "with the option off, no tag was released anywhere" $(cat $R/n?.log | grep -aq "releasing the active sharing tag" && echo 0 || echo 1) ""
for i in 1 2 3 4; do stop_graceful $i; rm -f $R/n$i.pid; done; sleep 2
for i in 1 2 3 4; do RIG_TAG_RELEASE=1 start $i $NEW 1 2 fleet-a; done; sleep 16
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
check "the option is on everywhere" $([ "$(cfgval $MN 741 release_tag_when_isolated)" = 1 ] && echo 1 || echo 0) ""
# a member cut off alone: the master still hears 3 of 4 and keeps the tag;
# the member elects itself and, counting from the 4 it knew as a member,
# releases the tag (~10 s to elect unconfirmed, then one election window)
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
mi $y clusterer_controller:maintenance cluster_id=741 state=full node_id=${XID:-0} >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $XIP)"; done
check "every node lists n$x as full, asked from n$y" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = full ] && echo 1 || echo 0) "$V"
check "n$x applied it to itself on n$y's request" $(eval m=\$F$x; since $x $m | grep -aq "asks this node into maintenance state full" && echo 1 || echo 0) ""
D=""; for i in 1 2 3 4; do [ $i = $x ] && continue; D="$D $(cl_state $i $XID)"; done
check "the other nodes disabled n$x in their clusterer" $([ "$(echo $D | tr ' ' '\n' | sort -u)" = disabled ] && echo 1 || echo 0) "$D"
RO=""; for i in 1 2 3 4; do RO="$RO $(role_of $i $XIP)"; done
check "nobody names n$x master or backup" $(echo "$RO" | grep -q 'master\|backup' && echo 0 || echo 1) "$RO"
mi $y clusterer_controller:maintenance cluster_id=741 state=none node_id=${XID:-0} >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $XIP)"; done
check "back in service on every node" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && echo 1 || echo 0) "$V"
D=""; for i in 1 2 3 4; do [ $i = $x ] && continue; D="$D $(cl_state $i $XID)"; done
check "the other nodes enabled n$x again" $([ "$(echo $D | tr ' ' '\n' | sort -u)" = enabled ] && echo 1 || echo 0) "$D"
check "a node_id outside the cluster is refused" $(mi $y clusterer_controller:maintenance cluster_id=741 state=full node_id=999 | grep -q "not a member" && echo 1 || echo 0) "$(mi $y clusterer_controller:maintenance cluster_id=741 state=full node_id=999 | cut -c1-100)"

echo "=== T27 a previous build in the cluster: capabilities gate the newer mechanisms ==="
# PREV = a build of this wire version that advertises no capabilities - this
# tree built with -DCL_CTR_CAPS_MINE=0, standing in for an older build.  A
# mixed cluster used to cost an extra watchdog period at every failover, the
# survivors waiting for answers the older member would not give.  One member
# runs it while the others run this build.
if [ -z "${PREV:-}" ] || [ ! -x "$PREV/sbin/opensips" ]; then
  echo "  SKIP  PREV (a build of this wire version advertising no capabilities) not given"
else
capsof() { mi $1 clusterer_controller:list_members | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741:
        for m in c["members"]:
            if m["ip"]==sys.argv[1]: print(" ".join(m.get("capabilities",["(no field)"])))' $2; }
clcaps() { mi $1 clusterer_controller:list_config | python3 -c '
import json,sys
for c in json.load(sys.stdin).get("result",[]):
    if c.get("cluster_id")==741: print(" ".join(c.get("cluster_capabilities",["(no field)"])))'; }
ALL="probe maint_set maint_full"
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
for y in 1 2 3 4; do [ $y != $MN ] && [ $y != $x ] && break; done
XIP=$(ip4 $x); YIP=$(ip4 $y)
echo "    n$x on the previous build; asking from n$y; master $MIP"
stop_graceful $x; RIG_EVENTS=0 start $x $PREV 1 2 fleet-a; sleep 10
check "n$x rejoined on the previous build" $(alive $x && members $y 741 | tr ' ' '\n' | grep -q "^$XIP:" && echo 1 || echo 0) "$(members $y 741)"
check "the master lists no capabilities for n$x, all three for n$y" $([ -z "$(capsof $MN $XIP)" ] && [ "$(capsof $MN $YIP)" = "$ALL" ] && echo 1 || echo 0) "n$x '$(capsof $MN $XIP)' n$y '$(capsof $MN $YIP)'"
check "the cluster's shared capabilities are none while n$x runs it (master and n$y)" $([ -z "$(clcaps $MN)" ] && [ -z "$(clcaps $y)" ] && echo 1 || echo 0) "master '$(clcaps $MN)' n$y '$(clcaps $y)'"
XID=$(nid $y $x)
R1=$(mi $y clusterer_controller:maintenance cluster_id=741 state=evicted node_id=${XID:-0})
sleep 3
check "remote maintenance of n$x is refused, and nothing changes" $(echo "$R1" | grep -q "maint_set" && [ "$(maint $y $XIP)" = none ] && echo 1 || echo 0) "$(echo "$R1" | cut -c1-140) / $(maint $y $XIP)"
R2=$(mi $y clusterer_controller:maintenance cluster_id=741 state=full)
sleep 3
check "the full level on n$y is refused while n$x would not act on it" $(echo "$R2" | grep -q "maint_full" && [ "$(maint $y $YIP)" = none ] && echo 1 || echo 0) "$(echo "$R2" | cut -c1-140) / $(maint $y $YIP)"
mi $y clusterer_controller:maintenance cluster_id=741 state=none >/dev/null   # a build without the gate took it
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
  check "a master killed with n$x aboard: replaced within 8 s, nobody on this build waiting for n$x's answer (took ${DT} s: $NEWM)" $([ -n "$NEWM" ] && [ $CO = 0 ] && python3 -c "import sys; sys.exit(0 if $DT <= 8 else 1)" && echo 1 || echo 0) "cut-off waits $CO, $MS"
  start $MN $NEW 1 2 fleet-a
fi
stop_graceful $x; start $x $NEW 1 2 fleet-a; sleep 10
check "all on this build again: the cluster shares every capability" $([ "$(clcaps $y)" = "$ALL" ] && echo 1 || echo 0) "'$(clcaps $y)'"
fi

echo "=== T28 statistics, one set per cluster ==="
# stats <node> -> "name=value ..." of the clusterer_controller group
stats() { mi $1 statistics:get 'statistics=["clusterer_controller:"]' | python3 -c '
import json,sys
try: d=json.load(sys.stdin).get("result",{})
except Exception: d={}
print(" ".join("%s=%s" % (k.split(":",1)[1], v) for k,v in sorted(d.items()) if k.startswith("clusterer_controller:")))'; }
cstat() { stats $1 | tr ' ' '\n' | grep "^$2=" | cut -d= -f2; }
MIP=$(members 2 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 4 3 2 1; do [ $x != $MN ] && break; done
N741=$(stats $MN | tr ' ' '\n' | grep -c -- '-741='); N742=$(stats $MN | tr ' ' '\n' | grep -c -- '-742=')
check "every statistic, once per cluster (23 each for 741 and 742)" $([ "$N741" = 23 ] && [ "$N742" = 23 ] && echo 1 || echo 0) "741: $N741, 742: $N742"
M=""; for i in 1 2 3 4; do M="$M $(cstat $i members-741)/$(cfgval $i 741 member_count)"; done
check "members-741 is the live count on every node" $(echo $M | tr ' ' '\n' | awk -F/ '$1!=4{b=1} END{print b?0:1}') "$M (stat/table)"
check "the master: role 2, is_master 1; n$x: is_master 0" $([ "$(cstat $MN role-741)" = 2 ] && [ "$(cstat $MN is_master-741)" = 1 ] && [ "$(cstat $x is_master-741)" = 0 ] && echo 1 || echo 0) "role $(cstat $MN role-741) is_master $(cstat $MN is_master-741) / $(cstat $x is_master-741)"
check "term-741 matches clusterer_controller:list_config" $([ "$(cstat $MN term-741)" = "$(cfgval $MN 741 term)" ] && echo 1 || echo 0) "$(cstat $MN term-741) vs $(cfgval $MN 741 term)"
check "every node counted at least one master change" $(for i in 1 2 3 4; do [ "$(cstat $i master_changes-741)" -ge 1 ] 2>/dev/null || { echo 0; exit; }; done; echo 1) "$(for i in 1 2 3 4; do echo -n "$(cstat $i master_changes-741) "; done)"
J0=$(cstat $MN members_joined-741); L0=$(cstat $MN members_left-741)
stop_graceful $x; sleep 2; start $x $NEW 1 2 fleet-a; sleep 8
J1=$(cstat $MN members_joined-741); L1=$(cstat $MN members_left-741)
check "n$x restarted: the master counted it leaving and joining" $([ "${L1:-0}" -gt "${L0:-0}" ] && [ "${J1:-0}" -gt "${J0:-0}" ] && echo 1 || echo 0) "left $L0 -> $L1, joined $J0 -> $J1"

echo "=== T29 events: role, master, members, maintenance ==="
# the rig's event routes log every cluster-state event as an "EVT ..." line
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
mi $x clusterer_controller:maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
EV=""; for i in 1 2 3 4; do eval m=\$V$i; EV="$EV $(since $i $m | grep -a "EVT MAINT 741 [0-9]* evicted" | grep -c .)"; done
check "E_CL_CTR_MAINTENANCE on every node, n$x's own included" $(echo $EV | tr ' ' '\n' | awk '$1<1{b=1} END{print b?0:1}') "$EV"
mi $x clusterer_controller:maintenance cluster_id=741 state=none >/dev/null; sleep 4

echo "=== T30 malformed datagrams: no crash, no change, a bounded log ==="
# Datagrams that are not packets of the cluster: first from an address that
# has no password (too short, a magic no build uses, another wire version,
# bodies that do not decrypt, random cluster uuids, other cluster ids, the
# largest datagram), then sealed by a holder of the password - every type
# byte with payloads at every field boundary, which pass decryption and reach
# the parsers - from an address that is no member, from a member's and from
# the master's.  No node may stop or change its view; a flood from one
# address may cost a node's log a line per kind of refusal, not one per
# datagram, while the statistics still count it.
MAL=$HERE/malformed_test.py; PW=rig74-not-a-secret-9f3a1c
view() { for i in 1 2 3 4; do echo "$(members $i 741) / $(members $i 742)"; done | sort -u; }
fuuids() { for i in 1 2 3 4; do for c in 741 742; do mi $i clusterer_controller:list_config | python3 -c '
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
# sealed by a holder of the password from twenty addresses that are no member
SRC=""; for k in $(seq 100 119); do ip addr add 10.74.0.$k/24 dev $BR; SRC="$SRC,10.74.0.$k"; done; SRC=${SRC#,}
mark; AF2=$(cstat $MN auth_failures-741)
python3 $MAL sealed $SRC 239.0.74.1 $PORT 741 239.0.74.1 $PW 15 > $R/mal2.json
sleep 3
for k in $(seq 100 119); do ip addr del 10.74.0.$k/24 dev $BR; done
echo "    sealed, no member: $(cat $R/mal2.json)"
check "sealed: the packets passed decryption (none failed it; the master named a sender's empty JOIN_REQ)" $([ "$(cstat $MN auth_failures-741)" = "$AF2" ] && eval m=\$L$MN && since $MN $m | grep -aq "JOIN_REQ from 10.74.0.1[01][0-9] names no valid address" && echo 1 || echo 0) "auth_failures $AF2 -> $(cstat $MN auth_failures-741)"
check "sealed, no member: every node still running" $([ "$(alive4)" = 4 ] && echo 1 || echo 0) "$(alive4) of 4"
V2=$(view)
check "sealed, no member: every node's view unchanged" $([ "$V2" = "$V0" ] && [ "$(echo "$V2" | wc -l)" = 1 ] && echo 1 || echo 0) "$V2"
# ... and from a member's own address and the master's, at once
for x in 1 2 3 4; do [ $x != $MN ] && break; done
nx $x python3 $MAL sealed $(ip4 $x) 239.0.74.1 $PORT 741 239.0.74.1 $PW 8 lite > $R/mal3.json &
nx $MN python3 $MAL sealed $(ip4 $MN) 239.0.74.1 $PORT 741 239.0.74.1 $PW 8 lite > $R/mal4.json
wait; sleep 10
echo "    sealed from n$x: $(cat $R/mal3.json)"; echo "    sealed from master n$MN: $(cat $R/mal4.json)"
check "sealed from a member and the master: every node still running" $([ "$(alive4)" = 4 ] && echo 1 || echo 0) "$(alive4) of 4"
V3=$(view)
check "sealed from a member and the master: every node's view unchanged" $([ "$V3" = "$V0" ] && [ "$(echo "$V3" | wc -l)" = 1 ] && echo 1 || echo 0) "$V3"

echo "=== T31 several nodes joining at once ==="
# Three members stopped and started in the same instant, five times (cleanly,
# then killed): each time all four are back with distinct node ids under the
# same master.  Then all four started cold at once, three times, with no
# pinned uuid: one cluster per id, one master, one uuid, distinct node ids.
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

echo "=== T32 a JOIN_REJECT sent again does not stop a node ==="
# A JOIN_REJECT travels under the bootstrap key, which has no replay window,
# so it is bound to the JOIN_REQ it refuses.  Record the master refusing a
# member started with a wrong password; start it again with the right one
# and, while it joins, send it the record from the master's address - the
# master's own packets to it held back meanwhile, so it is still joining.
# It must join, not exit.  A refusal it earns - other settings - still stops it.
MIP=$(members 1 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1); MN=${MIP##*.}; MN=${MN#1}
for x in 1 2 3 4; do [ $x != $MN ] && break; done
stop_graceful $x; rm -f $R/n$x.pid; sleep 2
M0=$(wc -l < $R/n$MN.log)
tap $MN 14 $R/t32.json >/dev/null & TP=$!
sleep 0.5; RIG_PASSWORD=rig74-the-wrong-one start $x $NEW; wait $TP
check "the master refused n$x, on the wrong password" $(since $MN $M0 | grep -aq "sent JOIN_REJECT to $(ip4 $x)" && echo 1 || echo 0) ""
alive $x && stop_hard $x; rm -f $R/n$x.pid
# the master's bootstrap-key datagrams only - the refusal and its beacons
python3 -c '
import json,sys
p=[d for d in json.load(open(sys.argv[1])) if d["data"].startswith("ce01")]
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
stop_graceful $x; rm -f $R/n$x.pid; sleep 2
X0=$(wc -l < $R/n$x.log)
start $x $NEW 1 3       # query_time 3 against the cluster's 2
for k in $(seq 1 40); do alive $x || break; sleep 0.5; done
check "a refusal it earns still stops it: other settings" $(! alive $x && since $x $X0 | grep -aq "JOIN_REJECT from $MIP - the running cluster has different settings" && echo 1 || echo 0) "alive: $(alive $x && echo yes || echo no)"
rm -f $R/n$x.pid; start $x $NEW; sleep 8
check "n$x back in" $(members $MN 741 | tr ' ' '\n' | grep -q "^$(ip4 $x):[a-z]*:[1-9]" && echo 1 || echo 0) "$(members $MN 741)"

echo "=== T33 a node's packets recorded and sent again from another address ==="
# The datagram's source is not authenticated; the sender is what a packet
# seals (wire version 3).  Record a member's traffic while it stops - its
# GOODBYE among it - start it again, and send the session-key part of the
# record from the bridge's address, which no node has in its table: the
# packets must meet that member's window, as packets from its previous life,
# and its old GOODBYE must not remove it.
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

echo "=== replays after T12: none ==="
RPN=0; for i in 1 2 3 4; do eval m=\$RP$i; RPN=$((RPN + $(since $i $m | grep -ac "already accepted, dropping\|older than the replay window, dropping"))); done
check "no control packet refused as a replay since T12 (re-keys keep the sequence)" $([ $RPN = 0 ] && echo 1 || echo 0) "$RPN"
echo "=== logs: crashes / criticals ==="
# "BUG trying to overwrite entry" was core TCP_main on BIN reconnect after T8,
# fixed in core by #4289; it is checked here so it cannot come back unseen.
# T32's refused nodes stop with a CRITICAL line by design; nothing else may
C=$(cat $R/n?.log | grep -av "JOIN_REJECT from .* shutting down\|cannot authenticate on .* Shutting down\|join failed after .* Shutting down" | grep -aic "segfault\|SIGSEGV\|CRITICAL\|BUG trying to overwrite entry")
check "no crashes, CRITICAL or TCP_main BUG lines" $([ "$C" = 0 ] && echo 1 || echo 0) "$C"
echo
echo "RESULT: $PASS passed, $FAIL failed"
