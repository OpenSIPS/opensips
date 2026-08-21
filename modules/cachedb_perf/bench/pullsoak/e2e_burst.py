#!/usr/bin/env python3
"""CP-15.14: a burst of cross-node misses, blocking versus suspending.

Every request asks node 2 for a state only node 1 has, so every one of
them costs a cluster round trip.  With the lookup blocking, a worker is
occupied for the whole of it and the node can have only as many in flight
as it has workers.  Suspending should let far more overlap.
"""
import os, socket, subprocess, sys, threading, time

D = "/dn/e2e"
N = int(os.environ.get("N", "120"))
CONC = int(os.environ.get("CONC", "20"))

def sip_batch(node, keys):
    """fire len(keys) requests from inside the namespace, concurrently,
    and report how long the whole batch took plus each reply code"""
    ip = "10.95.0.%d" % node
    prog = """
import socket, sys, threading, time
keys = sys.argv[1].split(",")
res = []
lock = threading.Lock()
def one(k):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("%s", 0)); p = s.getsockname()[1]
    m = ("OPTIONS sip:uas@%s:5060;tk=_" + k + " SIP/2.0\\r\\n"
         "Via: SIP/2.0/UDP %s:" + str(p) + ";branch=z9hG4bK-" + k + "\\r\\n"
         "From: <sip:c@x>;tag=f" + k + "\\r\\nTo: <sip:u@x>;tag=t" + k + "\\r\\n"
         "Call-ID: c-" + k + "\\r\\nCSeq: 4 OPTIONS\\r\\nX-Match: 1\\r\\n"
         "Max-Forwards: 70\\r\\nContent-Length: 0\\r\\n\\r\\n")
    s.settimeout(15)
    try:
        s.sendto(m.encode(), ("%s", 5060))
        d, _ = s.recvfrom(65535)
        code = d.decode(errors="replace").split()[1]
    except Exception:
        code = "timeout"
    finally:
        s.close()
    with lock:
        res.append(code)
t0 = time.time()
ths = [threading.Thread(target=one, args=(k,)) for k in keys]
for t in ths: t.start()
for t in ths: t.join()
print("%%.3f" %% (time.time() - t0))
print(",".join(res))
""" % (ip, ip, ip, ip)
    out = subprocess.run(["ip", "netns", "exec", "e%d" % node, "python3", "-c",
                          prog, ",".join(keys)],
                         capture_output=True, text=True, timeout=300)
    lines = (out.stdout or "").strip().split("\n")
    if len(lines) < 2:
        return None, (out.stderr or "")[:200]
    return float(lines[0]), lines[1].split(",")

import json
def mi(n, method, params=None):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("/tmp/e2.%d.%f" % (os.getpid(), time.time())); c.settimeout(30)
    c.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":method,
        "params": params if params is not None else []}).encode(),
        "%s/mi%d.sock" % (D, n))
    r = json.loads(c.recv(262144)); c.close()
    return r.get("result", r.get("error"))

BLOB = "0:22:sip:uas@10.95.0.9:50993:10018:udp:10.95.0.1:5060"

def seed_mi(keys):
    """the key must be exactly TH_KEY_LEN or th_store rejects it by length
    - a mistake that silently looks like a failed lookup"""
    for k in keys:
        assert len(k) == 16, k
        mi(1, "perf_set", {"key": "th:" + k, "value": BLOB, "ttl": 600,
                           "collection": "th"})

def pulls(n):
    return {k: v for k, v in mi(n, "perf_stats").get("cluster", {}).items()
            if k.startswith("pull")}

def old_seed():
    ip = "10.95.0.1"
    prog = ("import socket,time\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('%s',0))\n"
            "p=s.getsockname()[1]\n"
            "m=('OPTIONS sip:b@%s SIP/2.0\\r\\nVia: SIP/2.0/UDP %s:'+str(p)+';branch=z9hG4bK-s\\r\\n'\n"
            " 'From: <sip:b@x>;tag=b\\r\\nTo: <sip:b@x>\\r\\nCall-ID: seed\\r\\nCSeq: 1 OPTIONS\\r\\n'\n"
            " 'X-Seed: 1\\r\\nMax-Forwards: 70\\r\\nContent-Length: 0\\r\\n\\r\\n')\n"
            "s.settimeout(60); s.sendto(m.encode(),('%s',5060))\n"
            "print(s.recvfrom(65535)[0].decode().split()[1])\n") % (ip, ip, ip, ip)
    out = subprocess.run(["ip", "netns", "exec", "e1", "python3", "-c", prog],
                         capture_output=True, text=True, timeout=120)
    return (out.stdout or out.stderr).strip()

mode = sys.argv[1] if len(sys.argv) > 1 else "?"
keys = ["e2ekey%010d" % i for i in range(N)]      # exactly 16 characters
# clear both nodes first: a pull converges, so a previous run would leave
# n2 holding everything and the burst would measure local hits
mi(1, "perf_del", {"glob": "th:*", "collection": "th"})
mi(2, "perf_del", {"glob": "th:*", "collection": "th"})
seed_mi(keys)
print("seeded %d keys on n1; n2 holds %s"
      % (len(keys), mi(2, "perf_stats")["collections"][0]["entries"]))
before = pulls(2)
dt, codes = sip_batch(2, keys)
after = pulls(2)
if dt is None:
    print("FAILED:", codes)
    sys.exit(1)
good = sum(1 for c in codes if c == "200")
print("%-6s %d requests, %d concurrent-ish: %.2fs  matched=%d  other=%s"
      % (mode, N, CONC, dt, good,
         sorted(set(c for c in codes if c != "200")) or "none"))
print("  pulls:", {k: after.get(k,0) - before.get(k,0) for k in after
                     if k in ("pulls_requested","pulls_received","pulls_timed_out")})
print("RESULT %s %.3f %d" % (mode, dt, good))
