#!/usr/bin/env python3
"""A list send must reach exactly its targets - no more, no fewer."""
import socket, subprocess, sys, time
def sip(node, hdrs):
    ip="10.94.0.1%d"%node
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.94.0.1",0))
    p=s.getsockname()[1]; s.settimeout(15)
    m=("OPTIONS sip:x@%s:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.94.0.1:%d;branch=z9hG4bK-l%d\r\n"
       "From: <sip:l@x>;tag=l%d\r\nTo: <sip:b@x>\r\nCall-ID: lt-%d\r\nCSeq: 1 OPTIONS\r\n"
       "%sMax-Forwards: 5\r\nContent-Length: 0\r\n\r\n")%(ip,p,int(time.time()),int(time.time()),int(time.time()),hdrs)
    s.sendto(m.encode(),(ip,5060))
    try: return s.recvfrom(2048)[0].split(b" ",2)[1].decode()
    except socket.timeout: return "timeout"
    finally: s.close()
def logs(n):
    r=subprocess.run(["nerdctl","logs","n%d"%n],capture_output=True,text=True)
    return r.stdout+r.stderr
ok=fail=0
def check(name,cond,detail=""):
    global ok,fail
    print("  %-56s %s %s"%(name,"PASS" if cond else "FAIL",detail)); 
    ok,fail=ok+(1 if cond else 0),fail+(0 if cond else 1)

base={n:logs(n).count("L-GOT") for n in (1,2,3)}
# node ids are assigned by the controller - ask a node what its peers are called
import json
def mi(n,m,p=None):
    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); c.settimeout(8)
    c.sendto(json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p or []}).encode(),("10.94.0.1%d"%n,8787))
    r=json.loads(c.recv(262144)); c.close(); return r.get("result",r.get("error"))
peers={}
for n in (1,2,3):
    peers[n]=sorted(nd["node_id"] for cl in mi(n,"clusterer:list").get("Clusters",[]) for nd in cl.get("Nodes",[]))
print("  peer views:",peers)
# n1 sends to exactly one of its two peers
target=peers[1][0]
print("  n1 -> list containing only node %d"%target)
print("  reply:", sip(1,"X-List: 1\r\nX-N1: %d\r\n"%target))
time.sleep(2)
after={n:logs(n).count("L-GOT") for n in (1,2,3)}
delta={n:after[n]-base[n] for n in (1,2,3)}
print("  who received:",delta)
got=[n for n in (1,2,3) if delta[n]>0]
check("exactly one node received the message", len(got)==1, got)
check("the sender did not receive its own list send", delta[1]==0)
sent=[l for l in logs(1).splitlines() if "L-SENT" in l][-1:]
check("the function reported one delivery", "n=1" in (sent[0] if sent else ""), sent)
print("\n%d passed, %d failed"%(ok,fail))
