#!/usr/bin/env python3
"""
cl_ctr_join_reject_test.py - what a host without the password gets back from a
clusterer_controller cluster: nothing.

A packet that does not authenticate is never answered - its source and its
nonce are anyone's to copy - and never makes a member ask to be admitted
again.  This sends such packets to the group and listens:

  1. datagrams with the bootstrap magic, as a JOIN_REQ has, and a body that
     does not decrypt;
  2. the same with the session magic, as a keepalive has.

It fails when a node sends anything to this host's address, or sends the
group a bootstrap-key datagram that is not the master's beacon (a JOIN_REJECT,
or the JOIN_REQ of a member that the junk made re-join).  A beacon goes out
every few seconds whoever listens, and is no answer.

Run it on the cluster's segment, on a host that runs no node on that port,
while no node is joining (netns_tests.sh T32 does).  Only python3 is needed.

  ./cl_ctr_join_reject_test.py --group 239.0.90.1 --port 3333 --cluster-id 1

Exit status: 0 nothing came back, 1 something did, 3 no cluster was heard.
"""
import argparse, os, select, socket, struct, sys, time

# must match cl_ctr.h: first magic byte = CL_CTR_MAGIC_BASE + CL_CTR_WIRE_VERSION
WIRE_MAGIC0 = 0xCB + 5
BOOTSTRAP_MAGIC = bytes([WIRE_MAGIC0, 0x01])
SESSION_MAGIC = bytes([WIRE_MAGIC0, 0x00])
CID_SZ, NONCE_SZ, TAG_SZ = 16, 24, 16
# a MASTER_BEACON on the wire: header 44, sealed header 17, [count 2][term 4]
# [config 4][MTU 2][live 2][unraised 1], tag 16
BEACON_LEN = 44 + 17 + 15 + 16


def bogus_packet(magic, cluster_id):
    # an all-zero uuid is a sender in no cluster yet, which every node lets
    # through to decryption
    return (magic + struct.pack("!H", cluster_id & 0xFFFF)
            + bytes(CID_SZ) + os.urandom(NONCE_SZ) + os.urandom(60) + os.urandom(TAG_SZ))


def listen(uni, grp, me, seconds, heard):
    """for <seconds>, note what other hosts send: (to this host?, magic, length, source)"""
    end = time.time() + seconds
    while True:
        left = end - time.time()
        if left <= 0:
            return
        ready, _, _ = select.select([uni, grp], [], [], left)
        for s in ready:
            data, addr = s.recvfrom(65535)
            if addr[0] != me:
                heard.append((s is uni, data[:2], len(data), addr[0]))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--group", default="239.0.90.1")
    ap.add_argument("--port", type=int, default=3333)
    ap.add_argument("--cluster-id", type=int, default=1, help="the cluster's id")
    ap.add_argument("--source", default=None,
                    help="this host's address on the cluster's segment "
                         "(default: the one the kernel sends to the group from)")
    ap.add_argument("--count", type=int, default=6, help="packets per phase")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between packets")
    ap.add_argument("--baseline", type=float, default=6.0,
                    help="seconds to listen for the cluster before sending")
    args = ap.parse_args()

    me = args.source
    if not me:
        p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        p.connect((args.group, args.port))
        me = p.getsockname()[0]
        p.close()

    # this host's address at the cluster's port: where an answer to a joiner
    # goes, whether a node sends it to the joiner or to the datagram's source
    uni = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uni.bind((me, args.port))
    uni.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
    uni.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    uni.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    # the group's own traffic
    grp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    grp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    grp.bind((args.group, args.port))
    grp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                   socket.inet_aton(args.group) + socket.inet_aton(me))

    print("from %s to %s:%d, cluster_id %d" % (me, args.group, args.port, args.cluster_id))
    base = []
    listen(uni, grp, me, args.baseline, base)
    nodes = sorted(set(h[3] for h in base if not h[0]))
    print("heard before sending, in %.0f s: %d datagram(s) to the group from %s"
          % (args.baseline, sum(1 for h in base if not h[0]), ", ".join(nodes) or "nobody"))
    if not nodes:
        print("NOTHING TESTED  no node of a cluster was heard on the group")
        return 3

    failed = 0
    for name, magic in (("bootstrap", BOOTSTRAP_MAGIC), ("session", SESSION_MAGIC)):
        got = []
        for _ in range(args.count):
            uni.sendto(bogus_packet(magic, args.cluster_id), (args.group, args.port))
            listen(uni, grp, me, args.interval, got)
        listen(uni, grp, me, 2.0, got)
        to_me = [h for h in got if h[0]]
        boot = [h for h in got if not h[0] and h[1] == BOOTSTRAP_MAGIC]
        other = [h for h in boot if h[2] != BEACON_LEN]
        print("%d datagram(s) with the %s magic that do not decrypt: %d sent to this "
              "host, %d beacon(s) and %d other bootstrap-key datagram(s) sent to the group"
              % (args.count, name, len(to_me), len(boot) - len(other), len(other)))
        for h in to_me + other:
            print("    %s sent %d bytes, magic %s, to %s"
                  % (h[3], h[2], h[1].hex(), "this host" if h[0] else "the group"))
        if to_me or other:
            print("FAIL  the %s-magic datagrams were answered" % name)
            failed = 1
        else:
            print("PASS  the %s-magic datagrams were not answered" % name)
    return failed


if __name__ == "__main__":
    sys.exit(main())
