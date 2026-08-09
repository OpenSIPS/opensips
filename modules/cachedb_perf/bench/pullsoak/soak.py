#!/usr/bin/env python3
"""Concurrent pull soak - the test shape that WOULD have caught the three
defects found by reading the code back:

  lock scope     -> concurrent pulls + writes deadlock or stall
  sender dedupe  -> a false cluster-wide "absent" while a key demonstrably
                    exists (ghost band vs real band)
  atomic counters-> requested/received/stored stop adding up

plus the leak the gauge now exposes: slots taken and never released.
"""
import json, os, socket, sys, threading, time

D = os.environ.get("SOAK_DIR", "/tmp/cachedb_perf_soak")
KEYS = int(os.environ.get("KEYS", "500"))
THREADS = int(os.environ.get("THREADS", "8"))
ROUNDS = int(os.environ.get("ROUNDS", "6"))

def mi(n, method, params=None):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("/tmp/sk.%d.%f" % (os.getpid(), time.time())); c.settimeout(20)
    c.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":method,
        "params": params if params is not None else []}).encode(),
        "%s/mi%d.sock" % (D, n))
    r = json.loads(c.recv(262144)); c.close()
    return r.get("result", r.get("error"))

def sip(port, hdrs, timeout=60):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    m = ("OPTIONS sip:b@127.0.0.1 SIP/2.0\r\n"
         "Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-%f\r\n"
         "From: <sip:b@127.0.0.1>;tag=b\r\nTo: <sip:b@127.0.0.1>\r\n"
         "Call-ID: soak-%f-%d\r\nCSeq: 1 OPTIONS\r\n%s"
         "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n") % (
         p, time.time(), time.time(), p, hdrs)
    s.settimeout(timeout)
    s.sendto(m.encode(), ("127.0.0.1", port))
    try:
        d, _ = s.recvfrom(65535)
        return d.decode(errors="replace").split("\r\n")[0]
    finally:
        s.close()

results = []
lock = threading.Lock()

def hammer(tid):
    try:
        lo = tid * (KEYS // THREADS)
        hi = lo + (KEYS // THREADS)
        for _ in range(ROUNDS):
            r = sip(5082, "X-Hammer: 1\r\nX-From: %d\r\nX-To: %d\r\n" % (lo, hi))
            with lock: results.append(("hammer", r))
    except Exception as e:
        with lock: results.append(("hammer-EXC", str(e)))

def ghost(tid):
    try:
        for _ in range(ROUNDS):
            r = sip(5082, "X-Ghost: 1\r\n")
            with lock: results.append(("ghost", r))
    except Exception as e:
        with lock: results.append(("ghost-EXC", str(e)))

def churn(tid):
    try:
        for _ in range(ROUNDS):
            r = sip(5081, "X-Churn: 1\r\n")
            with lock: results.append(("churn", r))
    except Exception as e:
        with lock: results.append(("churn-EXC", str(e)))

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    print("  %-50s %s %s" % (name, "PASS" if cond else "FAIL", detail))
    ok, fail = ok + (1 if cond else 0), fail + (0 if cond else 1)

print("seeding %d keys on n1..." % KEYS)
print("  ", sip(5081, "X-Seed: 1\r\n", timeout=120))

before = {k: v for k, v in mi(2, "perf_stats").get("cluster", {}).items()
          if k.startswith("pull")}
print("\nrunning %d hammer + 2 ghost + 2 churn threads, %d rounds each..."
      % (THREADS, ROUNDS))
t0 = time.time()
threads = ([threading.Thread(target=hammer, args=(i,)) for i in range(THREADS)] +
           [threading.Thread(target=ghost,  args=(i,)) for i in range(2)] +
           [threading.Thread(target=churn,  args=(i,)) for i in range(2)])
for t in threads: t.start()
for t in threads: t.join()
dt = time.time() - t0
print("  finished in %.1fs" % dt)

after = {k: v for k, v in mi(2, "perf_stats").get("cluster", {}).items()
         if k.startswith("pull")}

excs = [r for r in results if "EXC" in r[0]]
check("no thread hung or errored", not excs, excs[:2])

bad = [r for r in results if r[0] == "hammer" and "bad=0" not in r[1]]
check("no reply matched to the wrong request", not bad, bad[:2])

hammered = [r for r in results if r[0] == "hammer"]
check("every hammer round answered",
      len(hammered) == THREADS * ROUNDS, len(hammered))

gh = [r for r in results if r[0] == "ghost" and "ghostfound=0" not in r[1]]
check("keys that exist nowhere are never invented", not gh, gh[:2])

# a real key must never be declared absent: hit counts must be full
zero = [r for r in hammered if "hit=0 " in r[1]]
check("no hammer round came back empty (no false absence)", not zero, zero[:2])

d = {k: after.get(k, 0) - before.get(k, 0) for k in after}
print("  deltas:", d)
check("counters add up: stored <= received <= requested",
      d["pulls_stored"] <= d["pulls_received"] <= d["pulls_requested"], d)
check("nothing timed out", d["pulls_timed_out"] == 0, d["pulls_timed_out"])

st = mi(2, "perf_stats").get("cluster", {})
check("all pull slots released (no leak)",
      st.get("pulls_in_flight", -1) == 0,
      "%s/%s" % (st.get("pulls_in_flight"), st.get("pull_slots")))

for n in (1, 2):
    log = open("%s/n%d.log" % (D, n), errors="replace").read()
    bad = [l for l in log.splitlines()
           if "CRITICAL" in l or "SIGSEGV" in l or "slots busy" in l]
    check("n%d: no crash or slot exhaustion" % n, not bad, bad[:1])

print("\n%d passed, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
