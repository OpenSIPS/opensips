#!/bin/bash
# netns_tests.sh - end-to-end tests of clusterer_controller on four network
# namespaces of this host (see netns_rig.sh and README.md).  Run as root:
#
#   NEW=/usr/local/opensips [OLD=/opt/opensips-wire1] ./netns_tests.sh
#
# Assertions are on EFFECTS (delivery counts, member tables, ids, processes),
# log lines only where the log line IS the behaviour (a warning that must be
# emitted).
. "$(dirname "$0")/netns_rig.sh"
trap 'tc qdisc del dev v1p root 2>/dev/null; teardown' EXIT
PASS=0; FAIL=0
check() { if [ "$2" = 1 ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1  ($3)"; FAIL=$((FAIL+1)); fi; }
members() {  # members <node> <cluster> -> "ip:status:id ..." sorted
  mi $1 cl_ctr_list_members | python3 -c '
import json,sys
r=json.load(sys.stdin).get("result",[])
for c in r:
    if c.get("cluster_id")==int(sys.argv[1]):
        print(" ".join(sorted("%s:%s:%s"%(m["ip"],m["status"],m["node_id"]) for m in c["members"])))' $2
}
cfgval() { mi $1 cl_ctr_list_config | python3 -c '
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
start 4 $OLD; sleep 10
check "new nodes name the v1 peer" $(grep -aq "10.74.0.14 speaks wire version 1, this node speaks 2" $R/n3.log && echo 1 || echo 0) ""
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
sleep 0.3; mi 3 cl_ctr_shtag_force cluster_id=741 node_id=$I1 >/dev/null; wait $TP
CUT11=$(dropped 2 INPUT)
nx 2 iptables -D INPUT -p udp -s $(ip4 3) --dport $PORT -j DROP
check "the T11 cut fired ($CUT11 dropped)" $([ "$CUT11" -gt 0 ] && echo 1 || echo 0) ""
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' $R/t11.json)
check "recorded the master's datagrams, L1 among them ($N)" $([ "${N:-0}" -gt 0 ] && echo 1 || echo 0) "$N"
check "n2 missed L1 (still auto)" $([ "$(cfgval 2 741 shtag_mode)" = auto ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
mi 3 cl_ctr_shtag_force cluster_id=741 node_id=$I2 >/dev/null; sleep 2
check "n2 applied L2 (override:$I2)" $([ "$(cfgval 2 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
replay 3 $R/t11.json >/dev/null; sleep 2
check "after the late L1: n2 still override:$I2" $([ "$(cfgval 2 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 2 741 shtag_mode)"
check "after the late L1: n1 still override:$I2" $([ "$(cfgval 1 741 shtag_mode)" = "override:$I2" ] && echo 1 || echo 0) "$(cfgval 1 741 shtag_mode)"
mi 3 cl_ctr_shtag_auto cluster_id=741 >/dev/null; sleep 1

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
maint() { mi $1 cl_ctr_list_members | python3 -c '
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
mi $BN cl_ctr_maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
V=""; for i in 1 2 3 4; do V="$V $(maint $i $BIP)"; done
check "every node lists backup $BIP as evicted" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = evicted ] && echo 1 || echo 0) "$V"
RO=""; for i in 1 2 3 4; do RO="$RO $(role_of $i $BIP)"; done
check "no node names $BIP backup any more" $(echo "$RO" | grep -q backup && echo 0 || echo 1) "$RO"
BID=$(nid $MN $BN)
echo "    $BIP is node_id '$BID' in the master's view: $(members $MN 741)"
check "pinning the tag on a node in maintenance is refused" $(mi $MN cl_ctr_shtag_force cluster_id=741 node_id=${BID:-0} | grep -q "maintenance" && echo 1 || echo 0) "$(mi $MN cl_ctr_shtag_force cluster_id=741 node_id=${BID:-0} | cut -c1-120)"
check "$BIP lists itself as evicted" $([ "$(maint $BN $BIP)" = evicted ] && echo 1 || echo 0) ""
for i in 1 2 3 4; do eval L$i=$(wc -l < $R/n$i.log); done
mi $MN cl_ctr_maintenance cluster_id=741 state=evicted >/dev/null; sleep 4
MS=""; for i in 1 2 3 4; do MS="$MS $(members $i 741 | tr ' ' '\n' | grep ':master:' | cut -d: -f1)"; done
NM=$(echo $MS | cut -d' ' -f1)
check "the master in maintenance handed over: one new master, named by all" $([ "$(echo $MS | tr ' ' '\n' | sort -u | wc -l)" = 1 ] && [ "$(echo $MS | wc -w)" = 4 ] && [ "$NM" != "$MIP" ] && [ "$NM" != "$BIP" ] && echo 1 || echo 0) "$MS"
WS=0; for i in 1 2 3 4; do eval m=\$L$i; WS=$((WS + $(since $i $m | grep -ac "went silent"))); done
check "the handover did not wait for the master watchdog (no 'went silent')" $([ $WS = 0 ] && echo 1 || echo 0) "$WS"
mi $BN cl_ctr_maintenance cluster_id=741 state=none >/dev/null
mi $MN cl_ctr_maintenance cluster_id=741 state=none >/dev/null; sleep 4
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
start $MN $NEW 1 2 fleet-a; sleep 8

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

echo "=== replays after T12: none ==="
RPN=0; for i in 1 2 3 4; do eval m=\$RP$i; RPN=$((RPN + $(since $i $m | grep -ac "already accepted, dropping\|older than the replay window, dropping"))); done
check "no control packet refused as a replay since T12 (re-keys keep the sequence)" $([ $RPN = 0 ] && echo 1 || echo 0) "$RPN"
echo "=== logs: crashes / criticals ==="
# "BUG trying to overwrite entry" was core TCP_main on BIN reconnect after T8,
# fixed in core by #4289; it is checked here so it cannot come back unseen.
C=$(cat $R/n?.log | grep -aic "segfault\|SIGSEGV\|CRITICAL\|BUG trying to overwrite entry")
check "no crashes, CRITICAL or TCP_main BUG lines" $([ "$C" = 0 ] && echo 1 || echo 0) "$C"
echo
echo "RESULT: $PASS passed, $FAIL failed"
