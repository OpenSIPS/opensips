#!/usr/bin/env python3
"""The ASYNC path must not hold a slot when no conclusive answer arrives.

This is the path the leak lives on.  A first attempt drove `perf_pull` (MI)
instead, and it passed on the UNFIXED build - because MI uses the blocking
entry point, which polls for pull_timeout_ms and then calls finish()
regardless, so it can never leak.  Only async(topology_hiding_match())
suspends on the eventfd and depends on the reply handler to arm it.

Reproduction: seed the state on n1 only, freeze n1 with SIGSTOP so the
request still goes out but no answer can come back, then drive the async
match on n2.  `negative` never reaches `expect`, the fd is never armed, and
before the reaper the slot was held for ever.

Run on /dn/thasync (netns rig).
"""
import json, os, signal, socket, subprocess, sys, time

D = "/dn/thasync"
KEY = "a1b2c3d4e5f60718"

def mi(n, method, params=None, timeout=20):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("/tmp/al.%d.%f" % (os.getpid(), time.time())); c.settimeout(timeout)
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

def sip(node, hdr, ruri_param="", timeout=60):
    ip = "10.97.0.%d" % node
    prog = ("import socket,time\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "s.bind(('%s',0)); p=s.getsockname()[1]\n"
            "m=('BYE sip:uas@%s:5060%s SIP/2.0\\r\\n'\n"
            "   'Via: SIP/2.0/UDP %s:%%d;branch=z9hG4bK-%%f\\r\\n'\n"
            "   'From: <sip:a@x>;tag=aa\\r\\nTo: <sip:b@x>;tag=bb\\r\\n'\n"
            "   'Call-ID: leak-%%f\\r\\nCSeq: 2 BYE\\r\\n%s'\n"
            "   'Max-Forwards: 70\\r\\nContent-Length: 0\\r\\n\\r\\n')"
            "%%(p,time.time(),time.time())\n"
            "s.settimeout(%d); s.sendto(m.encode(),('%s',5060))\n"
            "try: print(s.recvfrom(65535)[0].decode().split('\\r\\n')[0])\n"
            "except Exception as e: print('NO-REPLY', e)\n"
            ) % (ip, ip, ruri_param, ip, hdr.replace("\r\n", "\\r\\n"),
                 timeout, ip)
    out = subprocess.run(["ip", "netns", "exec", "t%d" % node,
                          "python3", "-c", prog],
                         capture_output=True, text=True, timeout=timeout + 30)
    return (out.stdout or out.stderr).strip()

def cl(n):
    return (mi(n, "perf_stats") or {}).get("cluster", {})

def pids(cfg):
    out = subprocess.run(["pgrep", "-f", "thasync/%s" % cfg],
                         capture_output=True, text=True).stdout.split()
    return [int(p) for p in out]

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    print("  %-54s %s %s" % (name, "PASS" if cond else "FAIL", detail))
    ok, fail = ok + (1 if cond else 0), fail + (0 if cond else 1)

contact = "sip:uas@10.97.0.9:5099"
sock = "udp:10.97.0.1:5060"
blob = "0:" + "%d:%s" % (len(contact), contact) + "3:100" + \
       "%d:%s" % (len(sock), sock)

# convergence from an earlier run would leave n2 holding it - clear both
mi(1, "perf_del", {"glob": "th:*", "collection": "th"})
mi(2, "perf_del", {"glob": "th:*", "collection": "th"})
mi(1, "perf_set", {"key": "th:" + KEY, "value": blob, "ttl": 300,
                   "collection": "th"})
check("state seeded on n1 only",
      (mi(2, "perf_probe", {"key": "th:" + KEY, "collection": "th"}) or {})
          .get("code") == 404)

b = cl(2)
print("  before: in_flight=%s timed_out=%s abandoned=%s"
      % (b.get("pulls_in_flight"), b.get("pulls_timed_out"),
         b.get("pulls_abandoned")))

frozen = pids("n1.cfg")
check("n1 processes located to freeze", len(frozen) > 0, len(frozen))
for p in frozen:
    os.kill(p, signal.SIGSTOP)
try:
    time.sleep(0.5)
    r = sip(2, "X-Async: 1\r\n", ";tk=_" + KEY, timeout=20)
    print("  n2 async match with n1 frozen ->", r)
    time.sleep(10)          # deadline + abandon grace + reaper ticks
    a = cl(2)
    print("  after : in_flight=%s timed_out=%s abandoned=%s"
          % (a.get("pulls_in_flight"), a.get("pulls_timed_out"),
             a.get("pulls_abandoned")))
    check("THE FIX: slot reclaimed (in_flight back to 0)",
          a.get("pulls_in_flight") == 0, a.get("pulls_in_flight"))
    check("and the pull was accounted for",
          a.get("pulls_timed_out", 0) > b.get("pulls_timed_out", 0)
          or a.get("pulls_abandoned", 0) > b.get("pulls_abandoned", 0))
finally:
    for p in frozen:
        try:
            os.kill(p, signal.SIGCONT)
        except ProcessLookupError:
            pass
    time.sleep(5)

check("cluster topology is reported", isinstance(cl(2).get("topology"), list)
      and cl(2).get("topology"), json.dumps(cl(2).get("topology"))[:100])

log = open("%s/n2.log" % D, errors="replace").read()
check("n2 did not crash",
      "sig_usr: segfault" not in log and "*** stack smashing" not in log)

print("\n%d passed, %d failed" % (ok, fail))
raise SystemExit(1 if fail else 0)
