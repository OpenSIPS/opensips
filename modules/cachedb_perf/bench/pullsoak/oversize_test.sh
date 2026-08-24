#!/bin/sh
# Drive an out-of-spec key at the serve path, which no well-behaved node can
# do - so the sender's own gate is relaxed for this build only (test_relax.py).
#
# n1 = clctr transport (the node under test: it frames replies into a fixed
#      1300-byte datagram buffer)
# n2 = bin transport   (the sender: BIN puts no bound on the key it can push)
#
# The mixed transport is the point: both receivers are live on n1, so a BIN
# request reaches its serve path and, before the fix, was answered by the
# clctr writer - copying an unbounded key into that fixed buffer.
set -e
D=/dn/clctrpull
KEYLEN=${KEYLEN:-5000}

sed -i 's/pull_transport", "clctr"/pull_transport", "bin"/' $D/n2.cfg
pkill -f "clctrpull/n2.cfg" 2>/dev/null || true
sleep 1
ip netns exec n2 /dn/wt-cp15/opensips -f $D/n2.cfg -F >> $D/n2.log 2>&1 &
sleep 8

python3 - "$KEYLEN" <<'PY'
import json, os, socket, sys, time
D = "/dn/clctrpull"
klen = int(sys.argv[1])

def mi(n, method, params=None, timeout=20):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("/tmp/ov.%d.%f" % (os.getpid(), time.time())); c.settimeout(timeout)
    c.sendto(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
        "params": params if params is not None else []}).encode(),
        "%s/mi%d.sock" % (D, n))
    try:
        r = json.loads(c.recv(262144))
    except socket.timeout:
        return None
    finally:
        c.close()
    return r.get("result", r.get("error"))

n1_before = mi(1, "perf_stats") is not None
print("  n1 alive before: %s" % n1_before)

key = "th:" + "K" * (klen - 3)
print("  n2 pulling a %d byte key over BIN, to be served by n1 (clctr)" % len(key))
r = mi(2, "perf_pull", {"key": key, "collection": "sync"}, timeout=25)
print("  n2 perf_pull ->", str(r)[:120])

time.sleep(2)
alive = mi(1, "perf_stats")
print("  n1 alive after : %s" % (alive is not None))

log = open("%s/n1.log" % D, errors="replace").read()
crashed = ("sig_usr: segfault" in log or "core dumped" in log
           or "*** stack smashing" in log)
rejected = "out of range" in log
print("  n1 logged an out-of-range rejection: %s" % rejected)
print("  n1 shows a crash/smash            : %s" % crashed)
print("RESULT alive=%s rejected=%s crashed=%s" % (alive is not None, rejected, crashed))
PY
