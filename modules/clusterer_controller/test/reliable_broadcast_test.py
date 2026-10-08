#!/usr/bin/env python3
"""Reliable broadcast: one multicast out, an ACK from every member, and
repair by unicast only to whoever did not answer."""
import re, socket, subprocess, time
def sip(node,hdrs):
    ip="10.94.0.1%d"%node
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.94.0.1",0))
    p=s.getsockname()[1]; s.settimeout(15); t=int(time.time()*1000)%100000
    m=("OPTIONS sip:x@%s:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.94.0.1:%d;branch=z9hG4bK-r%d\r\n"
       "From: <sip:l@x>;tag=r%d\r\nTo: <sip:b@x>\r\nCall-ID: rl-%d\r\nCSeq: 1 OPTIONS\r\n"
       "%sMax-Forwards: 5\r\nContent-Length: 0\r\n\r\n")%(ip,p,t,t,t,hdrs)
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
    print("  %-58s %s %s"%(name,"PASS" if cond else "FAIL",detail))
    ok,fail=ok+(1 if cond else 0),fail+(0 if cond else 1)

base_got={n:logs(n).count("L-GOT") for n in (1,2,3)}
BR=subprocess.run("ip -o link show type bridge | grep -oE 'br-[a-z0-9]+' | head -1",
                  shell=True,capture_output=True,text=True).stdout.strip()
cap=subprocess.Popen(["timeout","12","tcpdump","-i",BR,"-nn","-q","udp port 4499"],
                     stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
time.sleep(1.5)
print("  reply:", sip(1,"X-Rel: 1\r\n"))
time.sleep(4)
cap.terminate(); out=cap.stdout.read()

after={n:logs(n).count("L-GOT") for n in (1,2,3)}
delta={n:after[n]-base_got[n] for n in (1,2,3)}
print("  received by:",delta)
check("both peers received the broadcast", delta[2]>=1 and delta[3]>=1, delta)
check("the sender did not receive its own broadcast", delta[1]==0)

mc=len([l for l in out.splitlines() if "239.0.94.1.4499" in l and "10.94.0.11" in l])
check("it went out as ONE multicast, not one packet per peer", mc==1, "%d multicast(s)"%mc)

l1=logs(1)
acks=re.findall(r"broadcast seq (\d+) acknowledged by (\d+) of (\d+)", l1)
allack=re.findall(r"broadcast seq (\d+) acknowledged by all (\d+)", l1)
check("the sender counted acknowledgements from every member",
      len(allack)>=1, allack[-1:] or acks[-2:])
check("no repair was needed when nothing was lost",
      "repairing" not in l1 or "repairing 0 node" in l1,
      [l for l in l1.splitlines() if "repairing" in l][-1:])
print("\n%d passed, %d failed"%(ok,fail))
