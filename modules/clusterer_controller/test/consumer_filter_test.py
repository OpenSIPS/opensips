#!/usr/bin/env python3
"""Both fixes, on the live 3-node cluster."""
import json, socket, subprocess, time
def mi(n,m,p=None):
    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); c.settimeout(8)
    c.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p or []}).encode(),
             ("10.94.0.1%d"%n,8787))
    r=json.loads(c.recv(262144)); c.close(); return r.get("result",r.get("error"))

ok=fail=0
def check(name,cond,detail=""):
    global ok,fail
    print("  %-56s %s %s"%(name,"PASS" if cond else "FAIL",detail))
    ok,fail=ok+(1 if cond else 0),fail+(0 if cond else 1)

# 1. legitimate cross-node pull still works through the membership filter
mi(1,"perf_set",{"key":"th:filtertest","value":"still-works","ttl":600,"collection":"th"})
r2=mi(2,"perf_pull",{"key":"th:filtertest","collection":"th"})
check("a real pull between members still succeeds",
      isinstance(r2,dict) and r2.get("value")=="still-works", r2)

# 2. a flood of consumer-magic packets from a NON-member is dropped early
before=mi(1,"clusterer_controller:node_info") if False else None
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("10.94.0.1",0))                      # host bridge IP - not a cluster member
pkt=bytes([0xCC,0x02])+ (9).to_bytes(2,"big") + b"\x00"*80
t0=time.time(); n=0
while time.time()-t0 < 3:
    for _ in range(200):
        s.sendto(pkt,("10.94.0.11",4499)); n+=1
s.close()
print("  sent %d consumer-magic packets from a non-member in 3s"%n)
time.sleep(1)

logs=subprocess.run(["nerdctl","logs","n1"],capture_output=True,text=True)
tail=logs.stdout[-4000:]+logs.stderr[-4000:]
check("the node did not die under the flood",
      "SIGSEGV" not in tail and mi(1,"perf_stats") is not None)
check("no rate-limit warning (dropped before the limiter)",
      "rate limit of" not in tail)
# the cluster must still be healthy afterwards
peers=[nd["node_id"] for cl in mi(1,"clusterer:list").get("Clusters",[])
       for nd in cl.get("Nodes",[])]
check("cluster membership intact after the flood", len(peers)==2, peers)
mi(1,"perf_set",{"key":"th:aftertest","value":"post-flood","ttl":600,"collection":"th"})
r3=mi(3,"perf_pull",{"key":"th:aftertest","collection":"th"})
check("pulls still work after the flood",
      isinstance(r3,dict) and r3.get("value")=="post-flood", r3)
print("\n%d passed, %d failed"%(ok,fail))
