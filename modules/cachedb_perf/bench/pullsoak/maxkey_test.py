#!/usr/bin/env python3
"""The serve path now rejects out-of-range keys before it echoes them into a
fixed reply buffer.  That gate sits right next to the largest key a
legitimate requester can send, so this checks the boundary from both sides:
a key of exactly PCACHE_PULL_MAX_KEY must still pull cleanly, and the value
that rides back with it must still fit the controller plane's datagram.

Run against the live clctr netns rig (/tmp/clctrig.sh)."""
import json, os, socket, time

D = "/dn/clctrpull"
MAXKEY = 256                      # PCACHE_PULL_MAX_KEY
RPL_HDR = 14                      # PCACHE_CLCTR_RPL_HDR
CLCTR_MAX = 1300                  # CLCTR_MAX_PAYLOAD

def mi(n, method, params=None):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("/tmp/mk.%d.%f" % (os.getpid(), time.time())); c.settimeout(15)
    c.sendto(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
        "params": params if params is not None else []}).encode(),
        "%s/mi%d.sock" % (D, n))
    r = json.loads(c.recv(262144)); c.close()
    return r.get("result", r.get("error"))

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    print("  %-56s %s %s" % (name, "PASS" if cond else "FAIL", detail))
    ok, fail = ok + (1 if cond else 0), fail + (0 if cond else 1)

# a key of exactly the maximum a requester may send
key = "th:" + "k" * (MAXKEY - 3)
assert len(key) == MAXKEY
# the largest value that still fits beside it on the controller plane
val = "v" * (CLCTR_MAX - RPL_HDR - MAXKEY)
print("key %d bytes, value %d bytes, reply %d of %d\n"
      % (len(key), len(val), RPL_HDR + len(key) + len(val), CLCTR_MAX))

mi(1, "perf_set", {"key": key, "value": val, "ttl": 600, "collection": "sync"})
check("n1 stored the max-length key",
      (mi(1, "perf_get", {"key": key, "collection": "sync"}) or {}).get("value") == val)

# pull counters live in the cluster object; collections are keyed by "name"
b = mi(2, "perf_stats")["cluster"]

got = mi(2, "perf_pull", {"key": key, "collection": "sync"})
check("n2 pulled a max-length key across the cluster",
      isinstance(got, dict) and got.get("value") == val,
      "" if isinstance(got, dict) and got.get("value") == val else got)

a = mi(2, "perf_stats")["cluster"]
d = {k: a[k] - b[k] for k in ("pulls_requested", "pulls_received",
                              "pulls_stored", "pulls_timed_out")}
print("  deltas:", d)
check("the pull was answered, not timed out",
      d["pulls_received"] == 1 and d["pulls_timed_out"] == 0, d)
check("and stored locally", d["pulls_stored"] == 1, d)
check("n2 now serves it without asking again",
      (mi(2, "perf_get", {"key": key, "collection": "sync"}) or {}).get("value") == val)

for n in (1, 2):
    log = open("%s/n%d.log" % (D, n)).read()
    check("n%d: no key-range rejection for a legitimate key" % n,
          "out of range" not in log)
    check("n%d: no crash" % n,
          "SIGSEGV" not in log and "CRITICAL:" not in log)

print("\n%d passed, %d failed" % (ok, fail))
raise SystemExit(1 if fail else 0)
