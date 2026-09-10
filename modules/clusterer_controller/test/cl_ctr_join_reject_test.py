#!/usr/bin/env python3
"""
cl_ctr_join_reject_test.py - rogue-joiner security test for clusterer_controller.

Simulates an unauthorized node on the cluster's multicast group WITHOUT touching
any node config.  It exercises two defences:

  1. JOIN_REJECT path: send JOIN_REQ packets with the correct bootstrap magic but
     a bogus (wrong-key) body.  The master cannot decrypt them; after a few it is
     expected to emit an encrypted JOIN_REJECT (a bootstrap-magic packet back on
     the group).  We can't decrypt that reject (wrong key), but observing a
     bootstrap-magic packet from a cluster node in response confirms the master's
     reject logic fired.

  2. Rogue-traffic isolation (anti-churn): send bogus SESSION-magic packets
     (a fake MASTER_ALIVE).  A correct cluster must IGNORE these.  We measure the
     rate of real session traffic before vs during the flood: a large spike would
     mean the flood pushed non-master nodes into a re-JOIN churn (the old bug).

Run this on a host on the multicast segment that is NOT a live cluster member
(e.g. one node with `systemctl stop opensips`).  Requires only python3.

  ./cl_ctr_join_reject_test.py --group 239.0.90.1 --port 3333
"""
import argparse, collections, os, socket, struct, threading, time

# --- wire constants (must match clusterer_controller.c) ---
BOOTSTRAP_MAGIC = bytes([0xCC, 0x01])
SESSION_MAGIC   = bytes([0xCC, 0x00])
MAGIC_SZ, CLUSTER_ID_SZ, NONCE_SZ, TAG_SZ = 2, 2, 12, 16


def bogus_packet(magic, cluster_id):
    # [magic 2B][cluster_id 2B BE][nonce 12B][~60B random 'ciphertext'][tag 16B]
    return (magic + struct.pack("!H", cluster_id & 0xFFFF)
            + os.urandom(NONCE_SZ) + os.urandom(60) + os.urandom(TAG_SZ))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--group", default="239.0.90.1")
    ap.add_argument("--port", type=int, default=3333)
    ap.add_argument("--count", type=int, default=6, help="packets per phase")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between packets")
    ap.add_argument("--cluster-id", type=int, default=1,
                    help="cluster_id to stamp on packets; use a value the target "
                         "cluster does NOT use to verify foreign packets are filtered")
    args = ap.parse_args()

    # discover our own source IP (to filter our own loopback out)
    p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    p.connect((args.group, args.port)); my_ip = p.getsockname()[0]; p.close()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(("", args.port))
    rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                  struct.pack("4s4s", socket.inet_aton(args.group),
                              socket.inet_aton(my_ip)))
    rx.settimeout(0.3)

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

    boot_from = collections.Counter()   # bootstrap-magic pkts from peers (JOIN_REJECT candidates)
    sess_from = collections.Counter()   # session-magic pkts from peers
    stop = threading.Event()

    def receiver():
        while not stop.is_set():
            try:
                data, addr = rx.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[0] == my_ip or len(data) < MAGIC_SZ:
                continue
            if data[:MAGIC_SZ] == BOOTSTRAP_MAGIC:
                boot_from[addr[0]] += 1
            elif data[:MAGIC_SZ] == SESSION_MAGIC:
                sess_from[addr[0]] += 1

    threading.Thread(target=receiver, daemon=True).start()
    print(f"[*] rogue joiner {my_ip} -> {args.group}:{args.port}")
    print(f"    cluster_id={args.cluster_id}  bootstrap={BOOTSTRAP_MAGIC.hex()} session={SESSION_MAGIC.hex()}")

    # baseline: 3s of quiet listening to learn the normal session-traffic rate
    print("[*] measuring baseline cluster traffic for 3s ...")
    t0 = time.time(); base0 = sum(sess_from.values()); time.sleep(3.0)
    base_rate = (sum(sess_from.values()) - base0) / (time.time() - t0)
    print(f"    baseline session rate: {base_rate:.1f} pkt/s")

    # phase 1 - JOIN_REJECT probe
    boot_before = sum(boot_from.values())
    print(f"\n[*] PHASE 1: sending {args.count} bogus JOIN_REQ (bootstrap magic) ...")
    for i in range(args.count):
        tx.sendto(bogus_packet(BOOTSTRAP_MAGIC, args.cluster_id), (args.group, args.port))
        print(f"    -> JOIN_REQ #{i+1}")
        time.sleep(args.interval)
    time.sleep(2.0)
    rejects = sum(boot_from.values()) - boot_before

    # phase 2 - anti-churn probe (fake MASTER_ALIVE flood)
    print(f"\n[*] PHASE 2: flooding {args.count*3} bogus SESSION packets (fake MASTER_ALIVE) ...")
    t1 = time.time(); sess1 = sum(sess_from.values())
    for i in range(args.count * 3):
        tx.sendto(bogus_packet(SESSION_MAGIC, args.cluster_id), (args.group, args.port))
        time.sleep(args.interval / 3.0)
    flood_rate = (sum(sess_from.values()) - sess1) / (time.time() - t1)

    time.sleep(1.0); stop.set()

    # --- report ---
    print("\n===================== RESULT =====================")
    print(f"JOIN_REQ sent (phase 1):                 {args.count}")
    print(f"JOIN_REJECT-candidate replies from master: {rejects} "
          f"from {sorted(k for k,v in boot_from.items() if v)}")
    print(f"real session rate  baseline={base_rate:.1f}/s  during-flood={flood_rate:.1f}/s")
    print("--------------------------------------------------")
    ok = True
    if rejects > 0:
        print("PASS  master answered unauthenticated JOIN_REQ with a JOIN_REJECT")
    else:
        print("WARN  no JOIN_REJECT seen (rejection may rely on joiner-side shutdown)")
    # a >3x spike over baseline indicates the flood induced re-JOIN churn
    if flood_rate <= max(base_rate * 3.0, base_rate + 5):
        print("PASS  cluster ignored the rogue session flood (no churn spike)")
    else:
        print("FAIL  session traffic spiked under the flood -> cluster was disrupted"); ok = False
    print("==================================================")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
