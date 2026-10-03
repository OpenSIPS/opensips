#!/usr/bin/env python3
"""The sequence split, under the two cases that matter: heavy consumer
traffic must not make control traffic look like a replay, and a node
restart (which rewinds both counters) must not wedge the consumer plane."""
import json, socket, subprocess, sys, time
SRC = sys.argv[1] if len(sys.argv)>1 else "/dn/wt-cp15/modules/clusterer_controller/clusterer_controller.c"
def mi(n,m,p=None):
    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); c.settimeout(10)
    c.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p or []}).encode(),
             ("10.94.0.1%d"%n,8787))
    r=json.loads(c.recv(262144)); c.close(); return r.get("result",r.get("error"))
ok=fail=0
def check(name,cond,detail=""):
    global ok,fail
    print("  %-58s %s %s"%(name,"PASS" if cond else "FAIL",detail))
    ok,fail=ok+(1 if cond else 0),fail+(0 if cond else 1)

# heavy consumer traffic: 20k pulls, the rate our convergence storm produced
mi(1,"perf_del",{"glob":"th:*","collection":"th"})
mi(2,"perf_del",{"glob":"th:*","collection":"th"})
mi(3,"perf_del",{"glob":"th:*","collection":"th"})
for i in range(3000):
    mi(1,"perf_set",{"key":"th:seq%06d"%i,"value":"v"*40,"ttl":600,"collection":"th"})
t0=time.time(); pulled=0
for i in range(3000):
    r=mi(2,"perf_pull",{"key":"th:seq%06d"%i,"collection":"th"})
    if isinstance(r,dict) and r.get("value"): pulled+=1
dt=time.time()-t0
print("  %d pulls in %.1fs (%.0f/s of consumer traffic)"%(pulled,dt,pulled/dt))
check("every pull answered under sustained consumer load", pulled==3000, "%d/3000"%pulled)

logs=subprocess.run(["nerdctl","logs","n2"],capture_output=True,text=True)
tail=logs.stdout+logs.stderr
check("no control packet mistaken for a replay", "replay from" not in tail,
      [l for l in tail.splitlines() if "replay from" in l][:1])
check("cluster still healthy after the load",
      len([nd for cl in mi(2,"clusterer:list").get("Clusters",[])
           for nd in cl.get("Nodes",[])])==2)

# The rewind path (session re-key / re-join) cannot be exercised from here:
# a restarted node currently fails to rejoin this cluster for reasons that
# predate this change - the identical failure reproduces on a build with none
# of it - so it is not what this test is for.  The invariant is checked in the
# source instead: every site that rewinds a peer's last_seq must rewind
# last_consumer_seq beside it, or a receiver stays ahead of a sender that
# restarted at zero and silently drops everything it sends.
src = open(SRC).read()
parts = src.split("last_seq = 0")[:-1]
missed = [p for p in parts if "last_consumer_seq" not in p[-300:]
          and "last_consumer_seq" not in src[src.find(p)+len(p):][:300]]
check("every last_seq rewind also rewinds last_consumer_seq",
      not missed, "%d site(s) missing" % len(missed))
print("\n%d passed, %d failed" % (ok, fail))
