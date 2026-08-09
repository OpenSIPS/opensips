#!/usr/bin/env python3
"""CP-15.13: a script sends to its peers and receives as an event route,
the same surface clusterer offers, over the controller's plane."""
import json, os, socket, subprocess, sys, time

D = "/dn/scripttier"

def sip(node, hdrs):
    ip = "10.96.0.%d" % node
    prog = ("import socket,time\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "s.bind(('%s',0)); p=s.getsockname()[1]\n"
            "m=('OPTIONS sip:b@%s SIP/2.0\\r\\nVia: SIP/2.0/UDP %s:%%d;branch=z9hG4bK-%%f\\r\\n'\n"
            " 'From: <sip:b@x>;tag=b\\r\\nTo: <sip:b@x>\\r\\nCall-ID: sc-%%f\\r\\nCSeq: 1 OPTIONS\\r\\n%s'\n"
            " 'Max-Forwards: 70\\r\\nContent-Length: 0\\r\\n\\r\\n')%%(p,time.time(),time.time())\n"
            "s.settimeout(20); s.sendto(m.encode(),('%s',5060))\n"
            "print(s.recvfrom(65535)[0].decode().split('\\r\\n')[0])\n"
            ) % (ip, ip, ip, hdrs.replace("\r\n", "\\r\\n"), ip)
    out = subprocess.run(["ip", "netns", "exec", "s%d" % node, "python3", "-c", prog],
                         capture_output=True, text=True, timeout=60)
    return (out.stdout or out.stderr).strip()

def log(n):
    return open("%s/n%d.log" % (D, n), errors="replace").read()

def mi(n, method, params=None):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    c.bind("/tmp/st.%d.%f" % (os.getpid(), time.time())); c.settimeout(10)
    c.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":method,
        "params": params if params is not None else []}).encode(),
        "%s/mi%d.sock" % (D, n))
    r = json.loads(c.recv(262144)); c.close()
    return r.get("result", r.get("error"))

def peer_id_seen_by(n):
    """the id THIS node knows its peer by - which is the peer's real id,
    because the controller assigns ids and clusterer adopts them.  Never
    assume the my_node_id in the config: the controller overrides it."""
    for cl in mi(n, "clusterer:list").get("Clusters", []):
        for nd in cl.get("Nodes", []):
            return nd["node_id"]
    return 0

ok = fail = 0
def check(name, cond, detail=""):
    global ok, fail
    print("  %-52s %s %s" % (name, "PASS" if cond else "FAIL", detail))
    ok, fail = ok + (1 if cond else 0), fail + (0 if cond else 1)

# --- broadcast from n1: n2 must receive it as an event, and reply ---
print("broadcast from n1:", sip(1, "X-Bcast: 1\r\n"))
time.sleep(2)
l1, l2 = log(1), log(2)

check("the peer received it as a script event",
      "SCRIPT-REQ" in l2 and "hello-from-node1" in l2,
      [x for x in l2.splitlines() if "SCRIPT-REQ" in x][:1])
N1 = peer_id_seen_by(2)      # what n2 calls n1
N2 = peer_id_seen_by(1)      # what n1 calls n2
print("  runtime ids: n1=%d n2=%d (config said 1 and 2)" % (N1, N2))
check("with the sender's real node id",
      any("src=%d" % N1 in x for x in l2.splitlines() if "SCRIPT-REQ" in x),
      "expected src=%d" % N1)
check("the sender did NOT receive its own broadcast",
      "SCRIPT-REQ" not in l1)
check("the reply came back as the other event",
      "SCRIPT-RPL" in l1 and "ack-from-node2" in l1,
      [x for x in l1.splitlines() if "SCRIPT-RPL" in x][:1])

# --- directed send from n2 to node 1 ---
print("unicast n2 -> n1 (id %d):" % N1,
      sip(2, "X-Ucast: 1\r\nX-To-Node: %d\r\n" % N1))
time.sleep(2)
l1b, l2b = log(1), log(2)
check("a directed message reached only its target",
      "direct-to-you" in l1b and "direct-to-you" not in l2b)

for n, l in ((1, l1b), (2, l2b)):
    bad = [x for x in l.splitlines()
           if "CRITICAL:" in x or "core dumped" in x or "Segmentation" in x]
    check("n%d: no crash" % n, not bad, bad[:1])

print("\n%d passed, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
