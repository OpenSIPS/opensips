#!/bin/bash
# rtests.sh <cluster_id> <node IP> <node IP> [...]  - clusterer_controller on a real cluster.
#
# Runs from a separate host.  Every node: root SSH (BatchMode), mi_http enabled,
# iptables, the service run by systemd.  The faults are real - SIGSTOP/SIGCONT,
# SIGKILL, systemctl stop/restart, iptables cuts on the controller's UDP port,
# maintenance - and every one is undone by the EXIT trap: iptables rules tagged
# "cctest" removed, paused services resumed, stopped services started.
#
# Settings (environment): MI_PORT (8888), MI_ROOT (mi - the mi_http root path),
# PORT (3333 - the cluster's multicast port), LOG (/var/log/opensips.log),
# UNIT (opensips), SSH_USER (root).
#
# Run it only on a test cluster: it takes masters down on purpose.
set -u
[ $# -ge 4 ] || { echo "usage: $0 <cluster_id> <node IP> <node IP> <node IP> [...]"; exit 2; }
CL=$1; shift; NODES="$*"
PORT=${PORT:-3333}; MI_PORT=${MI_PORT:-8888}; MI_ROOT=${MI_ROOT:-mi}
LOG=${LOG:-/var/log/opensips.log}; UNIT=${UNIT:-opensips}; SSH_USER=${SSH_USER:-root}
PASS=0; FAIL=0
TS(){ date '+%H:%M:%S'; }
say(){ echo "[$(TS)] $*"; }
check(){ if [ "$2" = 1 ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1  ($3)"; FAIL=$((FAIL+1)); fi; }
sx(){ timeout ${T:-60} ssh -o BatchMode=yes -o ConnectTimeout=8 $SSH_USER@$1 "$2"; }
nip(){ echo $1; }   # nodes are named by their IP
mi(){ local p='{}'; [ -n "${3:-}" ] && p=$3
      curl -s -m 5 -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":$p,\"id\":1}" http://$1:$MI_PORT/$MI_ROOT; }
members(){ mi $1 clusterer_controller:list_members | python3 -c '
import json,sys
try: d=json.load(sys.stdin)["result"]
except Exception: sys.exit()
for c in d:
    if c["cluster_id"]==int(sys.argv[1]):
        print(" ".join(sorted("%s:%s:%s:%s"%(m["ip"],m["status"],m["node_id"],m.get("maintenance","")) for m in c["members"])))' $CL; }
cfg(){ mi $1 clusterer_controller:list_config | python3 -c '
import json,sys
try: d=json.load(sys.stdin)["result"]
except Exception: sys.exit()
for c in d:
    if c["cluster_id"]==int(sys.argv[1]): print(c.get(sys.argv[2]))' $CL $2; }
master_of(){ members $1 | tr ' ' '\n' | grep ':master:' | cut -d: -f1; }
masters(){ local m=""; for n in ${1:-$NODES}; do m="$m $(master_of $n)"; done; echo $m; }
one_master(){ local ms; ms=$(masters "$1"); [ "$(echo $ms | wc -w)" = "$(echo $1 | wc -w)" ] && [ "$(echo $ms | tr ' ' '\n' | sort -u | wc -l)" = 1 ]; }
num(){ echo ${1:-}; }
mark(){ sx $1 "wc -l < $LOG"; }
since(){ sx $1 "tail -n +\$(( $2 + 1 )) $LOG"; }
ids_ok(){ ! members $1 | tr ' ' '\n' | grep -q ':0:'; }
shtag_on(){ mi $1 clusterer:list_shtags | python3 -c '
import json,sys
try: d=json.load(sys.stdin)["result"]
except Exception: sys.exit()
print(" ".join(sorted(set(t["State"] for t in d if t["Cluster"]==int(sys.argv[1])))))' $CL; }
cut_rule(){ # cut_rule <node> <-I|-D> <iptables match...>
  local n=$1 op=$2; shift 2; sx $n "iptables $op INPUT -p udp --dport $PORT $* -m comment --comment cctest -j DROP"; }
cleanup(){
  for n in $NODES; do
    sx $n "U=$UNIT; "'while iptables -S INPUT | grep -q cctest; do r=$(iptables -S INPUT | grep cctest | head -1 | sed "s/^-A/-D/"); iptables $r; done
           while iptables -S OUTPUT | grep -q cctest; do r=$(iptables -S OUTPUT | grep cctest | head -1 | sed "s/^-A/-D/"); iptables $r; done
           systemctl kill -s SIGCONT $U 2>/dev/null; systemctl is-active -q $U || systemctl start $U' >/dev/null 2>&1
  done
}
trap cleanup EXIT
QT=$(cfg $(echo $NODES | cut -d' ' -f1) query_time); QT=${QT:-5}
HEAL=$(( QT * 3 + 10 ))
say "=== cluster $CL on $NODES (query_time $QT, election window $((QT*3)) s, purge $((QT*6)) s) ==="
declare -A M0; for n in $NODES; do M0[$n]=$(mark $n); done

wait_one_master(){ # wait_one_master <nodes> <max s> -> 0 when agreed
  local k; for k in $(seq 1 $(( $2 * 4 ))); do one_master "$1" && return 0; sleep 0.25; done; return 1; }

# ---------------------------------------------------------------- R0
say "R0 baseline"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1))
check "one master, named by all ($MIP)" $(one_master "$NODES" && echo 1 || echo 0) "$(masters)"
check "every member known by node_id" $(for n in $NODES; do ids_ok $n || { echo 0; exit; }; done; echo 1) "$(members $(num $MIP))"
check "cluster identity established" $([ "$(cfg $(num $MIP) cluster_uuid_state)" = established ] && echo 1 || echo 0) ""
ST=$(shtag_on $(num $MIP)); [ -n "$ST" ] && check "the master holds the active sharing tag(s) ($ST)" $([ "$ST" = active ] && echo 1 || echo 0) "$ST"

pick_member(){ for n in $NODES; do [ "$(nip $n)" != "$(master_of $n)" ] && { echo $n; return; }; done; }

# ---------------------------------------------------------------- R1
say "R1 graceful restart of a member: rejoins with its node_id"
X=$(pick_member); IDX=$(members $X | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f3); MIP=$(master_of $X)
sx $X "systemctl restart $UNIT"; sleep $HEAL
check "member $X back with node_id $IDX" $([ "$(members $(num $MIP) | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f3)" = "$IDX" ] && echo 1 || echo 0) "$(members $(num $MIP))"
check "master unchanged ($MIP)" $(one_master "$NODES" && [ "$(master_of $X)" = "$MIP" ] && echo 1 || echo 0) "$(masters)"

# ---------------------------------------------------------------- R2
PZ=$(( QT * 6 + 5 ))
say "R2 a member paused ${PZ} s (past the purge window): wakes without electing itself, re-admitted with its id"
X=$(pick_member); IDX=$(members $X | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f3); MX=$(mark $X); MIP=$(master_of $X)
sx $X "systemctl kill -s SIGSTOP $UNIT"; sleep $PZ; sx $X "systemctl kill -s SIGCONT $UNIT"; sleep $HEAL
L=$(since $X $MX)
check "woken $X did not elect itself" $(echo "$L" | grep -aq "my role changed: [a-z]* -> master" && echo 0 || echo 1) ""
check "woken $X did not purge its peers" $(echo "$L" | grep -aq "purging timed-out peer" && echo 0 || echo 1) ""
check "woken $X reported the stall" $(echo "$L" | grep -aq "did not run for" && echo 1 || echo 0) ""
check "one master, still $MIP" $(one_master "$NODES" && [ "$(master_of $X)" = "$MIP" ] && echo 1 || echo 0) "$(masters)"
check "$X known again by node_id $IDX" $([ "$(members $(num $MIP) | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f3)" = "$IDX" ] && echo 1 || echo 0) "$(members $(num $MIP))"

# ---------------------------------------------------------------- R3
say "R3 the master paused 20 s: replaced; woken it stands down"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); MN=$(num $MIP); MM=$(mark $MN)
OTH=$(for n in $NODES; do [ $n != $MN ] && echo -n "$n "; done)
sx $MN "systemctl kill -s SIGSTOP $UNIT"; sleep 20
NEWM=$(master_of $(echo $OTH | cut -d' ' -f1))
check "the others elected a new master while $MIP was paused ($NEWM)" $([ -n "$NEWM" ] && [ "$NEWM" != "$MIP" ] && one_master "$OTH" && echo 1 || echo 0) "$(masters "$OTH")"
sx $MN "systemctl kill -s SIGCONT $UNIT"; sleep $HEAL
check "woken $MIP stood down" $(since $MN $MM | grep -aq "stands down" && echo 1 || echo 0) ""
check "the master chosen meanwhile kept it, named by all" $(one_master "$NODES" && [ "$(master_of $MN)" = "$NEWM" ] && echo 1 || echo 0) "$(masters)"
check "every member known by node_id" $(for n in $NODES; do ids_ok $n || { echo 0; exit; }; done; echo 1) "$(members $(num $NEWM))"
ST=$(shtag_on $(num $NEWM)); [ -n "$ST" ] && check "the new master holds the active tag, the old one does not" $([ "$ST" = active ] && [ "$(shtag_on $MN)" = backup ] && echo 1 || echo 0) "new $ST old $(shtag_on $MN)"

# ---------------------------------------------------------------- R4
say "R4 one member stops hearing the master only (10 s): holds the election"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); X=$(pick_member); MX=$(mark $X); H0=$(cfg $X election_holds); MMK=$(mark $(num $MIP))
cut_rule $X -I -s $MIP; sleep 10; cut_rule $X -D -s $MIP; sleep 6
L=$(since $X $MX)
check "$X held the election (holds $H0 -> $(cfg $X election_holds))" $([ "$(cfg $X election_holds)" -gt "${H0:-0}" ] 2>/dev/null && echo 1 || echo 0) ""
check "$X did not re-elect" $(echo "$L" | grep -aq "went silent .* re-electing" && echo 0 || echo 1) ""
check "one master, still $MIP" $(one_master "$NODES" && [ "$(master_of $X)" = "$MIP" ] && echo 1 || echo 0) "$(masters)"
MV=$(since $(num $MIP) $MMK | grep -ac "member $(nip $X) cannot hear")
check "the master logged that a member cannot hear it" $([ "$MV" -gt 0 ] && echo 1 || echo 0) "$MV"

# ---------------------------------------------------------------- R5
say "R5 a member cut off both ways for 25 s: suspects itself, keeps the term, heals to the cluster's master"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); X=$(pick_member); MX=$(mark $X); TB=$(cfg $(num $MIP) term)
cut_rule $X -I; sx $X "iptables -I OUTPUT -p udp --dport $PORT -m comment --comment cctest -j DROP"
sleep 25
TI=$(cfg $X term)
cut_rule $X -D; sx $X "iptables -D OUTPUT -p udp --dport $PORT -m comment --comment cctest -j DROP"
sleep $HEAL
L=$(since $X $MX)
check "isolated $X suspected itself first" $(echo "$L" | grep -aq "may be the one cut off" && echo 1 || echo 0) ""
check "its self-election did not raise the term ($TI vs $TB)" $([ "$TI" = "$TB" ] && echo 1 || echo 0) ""
check "healed: $MIP leads, named by all; term still $TB" $(one_master "$NODES" && [ "$(master_of $X)" = "$MIP" ] && [ "$(cfg $(num $MIP) term)" = "$TB" ] && echo 1 || echo 0) "$(masters) term $(cfg $(num $MIP) term)"

# ---------------------------------------------------------------- R6
say "R6 the master killed (SIGKILL): replaced on the peers' confirmation; back with its node_id"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); MN=$(num $MIP); IDM=$(members $MN | tr ' ' '\n' | grep "^$MIP:" | cut -d: -f3)
OTH=$(for n in $NODES; do [ $n != $MN ] && echo -n "$n "; done)
RST=$(sx $MN "systemctl show $UNIT -p Restart --value")
declare -A K; for n in $OTH; do K[$n]=$(mark $n); done
T0=$(date +%s.%N); sx $MN "systemctl kill -s SIGKILL $UNIT"
NEWM=""; for k in $(seq 1 80); do if one_master "$OTH" && [ "$(master_of $(echo $OTH | cut -d' ' -f1))" != "$MIP" ]; then NEWM=$(master_of $(echo $OTH | cut -d' ' -f1)); break; fi; sleep 0.25; done
DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))")
if [ "$RST" = no ]; then
  check "the survivors agree on a new master within 10 s (took ${DT} s: $NEWM)" $([ -n "$NEWM" ] && python3 -c "import sys; sys.exit(0 if $DT <= 10 else 1)" && echo 1 || echo 0) "$(masters "$OTH")"
else
  echo "    (unit Restart=$RST: systemd restarts the killed node at once)"
  check "the survivors agree on a master other than the killed one within 20 s (took ${DT} s: $NEWM)" $([ -n "$NEWM" ] && echo 1 || echo 0) "$(masters "$OTH")"
fi
if [ -n "$NEWM" ]; then
  TS=""; for k in 1 2 3 4; do TS=$(shtag_on $(num $NEWM)); [ "$TS" = active ] && break; sleep 0.25; done
  LISTED=$(members $(num $NEWM) | tr ' ' '\n' | grep -c "^$MIP:")
  check "the new master holds the active tag at once ($TS; killed master still listed: $LISTED)" $([ "$TS" = active ] && echo 1 || echo 0) "$TS"
fi
CF=0; for n in $OTH; do CF=$((CF + $(since $n ${K[$n]} | grep -ac "confirm that master .* is silent"))); done
check "elected on the peers' confirmation" $([ $CF -gt 0 ] && echo 1 || echo 0) "$CF"
sleep 5; sx $MN "systemctl is-active -q $UNIT || systemctl start $UNIT"; sleep $HEAL
NEWM=${NEWM:-$(master_of $(echo $OTH | cut -d' ' -f1))}
check "$MIP back with node_id $IDM, one master named by all" $([ "$(members $(num $NEWM) | tr ' ' '\n' | grep "^$MIP:" | cut -d: -f3)" = "$IDM" ] && one_master "$NODES" && echo 1 || echo 0) "$(members $(num $NEWM)) / $(masters)"

# ---------------------------------------------------------------- R6b
say "R6b the master stopped gracefully: hands over at once, without the watchdog"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); MN=$(num $MIP); IDM=$(members $MN | tr ' ' '\n' | grep "^$MIP:" | cut -d: -f3)
OTH=$(for n in $NODES; do [ $n != $MN ] && echo -n "$n "; done)
declare -A G; for n in $OTH; do G[$n]=$(mark $n); done
T0=$(date +%s.%N); sx $MN "systemctl stop $UNIT"
NEWM=""; for k in $(seq 1 40); do if one_master "$OTH" && [ "$(master_of $(echo $OTH | cut -d' ' -f1))" != "$MIP" ]; then NEWM=$(master_of $(echo $OTH | cut -d' ' -f1)); break; fi; sleep 0.25; done
DT=$(python3 -c "import time; print('%.1f' % (time.time() - $T0))")
check "a new master within 5 s of the stop (took ${DT} s: $NEWM)" $([ -n "$NEWM" ] && python3 -c "import sys; sys.exit(0 if $DT <= 5 else 1)" && echo 1 || echo 0) "$(masters "$OTH")"
[ -n "$NEWM" ] && check "the new master holds the active tag ($(shtag_on $(num $NEWM)))" $([ "$(shtag_on $(num $NEWM))" = active ] && echo 1 || echo 0) ""
WS=0; for n in $OTH; do WS=$((WS + $(since $n ${G[$n]} | grep -ac "went silent"))); done
check "nobody waited for the watchdog" $([ $WS = 0 ] && echo 1 || echo 0) "$WS"
sx $MN "systemctl start $UNIT"; sleep $HEAL
check "$MIP back with node_id $IDM, one master named by all" $([ "$(members $(num $NEWM) | tr ' ' '\n' | grep "^$MIP:" | cut -d: -f3)" = "$IDM" ] && one_master "$NODES" && echo 1 || echo 0) "$(members $(num $NEWM)) / $(masters)"
# ---------------------------------------------------------------- R6c
say "R6c the master killed and restarted at once: survives the new master's tag announcement"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); MN=$(num $MIP)
RST=$(sx $MN "systemctl show $UNIT -p Restart --value"); NR0=$(sx $MN "systemctl show $UNIT -p NRestarts --value"); MK=$(mark $MN)
sx $MN "systemctl kill -s SIGKILL $UNIT"
[ "$RST" = no ] && { sleep 0.5; sx $MN "systemctl start $UNIT"; }
for k in $(seq 1 80); do one_master "$NODES" && [ "$(master_of $MN)" != "$MIP" ] && break; sleep 0.25; done
sleep 8
NR1=$(sx $MN "systemctl show $UNIT -p NRestarts --value")
SG=$(since $MN $MK | grep -ac "segfault")
check "restarted $MIP did not crash (segfaults $SG, systemd restarts $NR0 -> $NR1, Restart=$RST)" $([ "$SG" = 0 ] && { [ "$RST" = no ] || [ "$NR1" = $((NR0 + 1)) ]; } && echo 1 || echo 0) ""
NM=$(master_of $(echo $NODES | cut -d' ' -f1))
check "one master named by all ($NM), holding the active tag" $(one_master "$NODES" && [ "$(shtag_on $(num $NM))" = active ] && echo 1 || echo 0) "$(masters) tag $(shtag_on $(num $NM))"
echo "    packets that reached it before its identity, dropped: $(since $MN $MK | grep -ac "before local identity is established") (0 = the race window was not hit this time)"

# ---------------------------------------------------------------- R7
say "R7 maintenance: backup out of election, then the master hands over"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); MN=$(num $MIP)
BIP=$(members $MN | tr ' ' '\n' | grep ':backup:' | cut -d: -f1); BN=$(num $BIP); BID=$(members $MN | tr ' ' '\n' | grep "^$BIP:" | cut -d: -f3)
mi $BN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"evicted\"}" >/dev/null; sleep 6
V=""; for n in $NODES; do V="$V $(members $n | tr ' ' '\n' | grep "^$BIP:" | cut -d: -f4)"; done
check "every node lists $BIP as evicted" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = evicted ] && echo 1 || echo 0) "$V"
check "no node names $BIP backup" $(for n in $NODES; do members $n | tr ' ' '\n' | grep -q "^$BIP:backup:" && { echo 0; exit; }; done; echo 1) ""
check "pinning the tag on it is refused" $(mi $MN clusterer_controller:shtag_force "{\"cluster_id\":$CL,\"node_id\":$BID}" | grep -q maintenance && echo 1 || echo 0) "$(mi $MN clusterer_controller:shtag_force "{\"cluster_id\":$CL,\"node_id\":$BID}" | cut -c1-120)"
declare -A W; for n in $NODES; do W[$n]=$(mark $n); done
mi $MN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"evicted\"}" >/dev/null; sleep 6
NM=$(master_of $(echo $NODES | cut -d' ' -f1))
check "the master in maintenance handed over (to $NM), named by all" $(one_master "$NODES" && [ "$NM" != "$MIP" ] && [ "$NM" != "$BIP" ] && echo 1 || echo 0) "$(masters)"
WS=0; for n in $NODES; do WS=$((WS + $(since $n ${W[$n]} | grep -ac "went silent"))); done
check "without waiting for the watchdog" $([ $WS = 0 ] && echo 1 || echo 0) "$WS"
ST=$(shtag_on $(num $NM)); [ -n "$ST" ] && check "the active tag moved to $NM" $([ "$ST" = active ] && [ "$(shtag_on $MN)" = backup ] && echo 1 || echo 0) "new $ST old $(shtag_on $MN)"
mi $BN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"none\"}" >/dev/null
mi $MN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"none\"}" >/dev/null; sleep 6
V=""; for n in $NODES; do V="$V $(members $n | tr ' ' '\n' | cut -d: -f4)"; done
check "both back in service everywhere; one master" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && one_master "$NODES" && echo 1 || echo 0) "$V / $(masters)"

# ---------------------------------------------------------------- R8
say "R8 30% of the master's packets into one member lost for 90 s: it learns to wait longer, no election"
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); X=$(pick_member); MX=$(mark $X); PEAK=0; H0=$(cfg $X election_holds); F0=$(cfg $X master_false_suspicions)
sx $X "iptables -I INPUT -p udp --dport $PORT -s $MIP -m statistic --mode random --probability 0.30 -m comment --comment cctest -j DROP"
for k in $(seq 1 18); do sleep 5; v=$(cfg $X master_timeout_ms); [ "${v:-0}" -gt "$PEAK" ] 2>/dev/null && PEAK=$v; done
echo "    $X: mean $(cfg $X master_ka_mean_ms) dev $(cfg $X master_ka_dev_ms) margin $(cfg $X master_ka_margin_ms) timeout $(cfg $X master_timeout_ms) ms; holds $H0 -> $(cfg $X election_holds); false suspicions $F0 -> $(cfg $X master_false_suspicions)"
sx $X "iptables -D INPUT -p udp --dport $PORT -s $MIP -m statistic --mode random --probability 0.30 -m comment --comment cctest -j DROP"; sleep 10
L=$(since $X $MX)
check "no election on lossy $X" $(echo "$L" | grep -aqE "went silent|my role changed: [a-z]* -> master" && echo 0 || echo 1) ""
check "it learned to wait longer than 3 s (peak $PEAK ms)" $([ "$PEAK" -gt 3000 ] && echo 1 || echo 0) "$PEAK"
check "one master throughout ($MIP)" $(one_master "$NODES" && [ "$(master_of $X)" = "$MIP" ] && echo 1 || echo 0) "$(masters)"
# ---------------------------------------------------------------- R9
say "R9 maintenance of another node at the full level (CC-10b)"
cl_state(){ mi $1 clusterer:list | python3 -c '
import json,sys
try: d=json.load(sys.stdin)["result"]
except Exception: sys.exit()
for c in d.get("Clusters",[]):
    if c.get("cluster_id")==int(sys.argv[1]):
        for n in c.get("Nodes",[]):
            if n.get("node_id")==int(sys.argv[2]): print(n.get("state"))' $CL $2; }
MIP=$(master_of $(echo $NODES | cut -d' ' -f1)); MN=$(num $MIP); X=$(pick_member)
XID=$(members $MN | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f3); MX=$(mark $X)
echo "    from master $MN: $X (node_id $XID) into full"
mi $MN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"full\",\"node_id\":${XID:-0}}" >/dev/null; sleep 6
V=""; for n in $NODES; do V="$V $(members $n | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f4)"; done
check "every node lists $X as full" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = full ] && echo 1 || echo 0) "$V"
check "$X applied the request itself" $(since $X $MX | grep -aq "asks this node into maintenance state full" && echo 1 || echo 0) ""
D=""; for n in $NODES; do [ $n = $X ] && continue; D="$D $(cl_state $n $XID)"; done
check "the other nodes disabled $X in clusterer" $([ "$(echo $D | tr ' ' '\n' | sort -u)" = disabled ] && echo 1 || echo 0) "$D"
check "one master, still $MIP" $(one_master "$NODES" && [ "$(master_of $X)" = "$MIP" ] && echo 1 || echo 0) "$(masters)"
mi $MN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"none\",\"node_id\":${XID:-0}}" >/dev/null; sleep 6
V=""; for n in $NODES; do V="$V $(members $n | tr ' ' '\n' | grep "^$(nip $X):" | cut -d: -f4)"; done
D=""; for n in $NODES; do [ $n = $X ] && continue; D="$D $(cl_state $n $XID)"; done
check "back in service and enabled everywhere" $([ "$(echo $V | tr ' ' '\n' | sort -u)" = none ] && [ "$(echo $D | tr ' ' '\n' | sort -u)" = enabled ] && echo 1 || echo 0) "$V / $D"
check "a node_id outside the cluster is refused" $(mi $MN clusterer_controller:maintenance "{\"cluster_id\":$CL,\"state\":\"full\",\"node_id\":999}" | grep -q "not a member" && echo 1 || echo 0) ""

# ---------------------------------------------------------------- logs
say "logs since the start"
RP=0; CR=0; for n in $NODES; do L=$(since $n ${M0[$n]}); RP=$((RP + $(echo "$L" | grep -acE "clusterer_controller: packet from .* dropping|a replay from before it restarted"))); CR=$((CR + $(echo "$L" | grep -acE "CRITICAL|segfault|SIGSEGV"))); done
check "no control packet refused as a replay" $([ $RP = 0 ] && echo 1 || echo 0) "$RP"
check "no CRITICAL or crash" $([ $CR = 0 ] && echo 1 || echo 0) "$CR"
for n in $NODES; do echo "    $n: NRestarts $(sx $n "systemctl show $UNIT -p NRestarts --value") procs $(sx $n 'pgrep -c -x opensips') local_health $(cfg $n local_health) self_stalls $(cfg $n self_stalls) false_suspicions $(cfg $n master_false_suspicions) holds $(cfg $n election_holds)"; done
say "RESULT cluster $CL: $PASS passed, $FAIL failed"
