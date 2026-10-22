#!/usr/bin/env python3
"""
malformed_test.py - malformed datagrams for the malformed-input test in
netns_tests.sh (T30).  Sends; checks nothing - the suite checks the nodes.

  malformed_test.py outsider <src_ip> <dsts> <port> <cluster_id> <sibling_id> <seconds>
      No password: datagrams too short to be a packet, with a magic no build
      uses, with another wire version's magic, with this cluster's magic and
      id but a body that does not decrypt (zero uuid, random uuids, another
      local cluster's id, a cluster id nobody runs) and oversized ones, spread
      evenly over <seconds>.

  malformed_test.py sealed <src_ips> <dsts> <port> <cluster_id> <group> <password> <rate> [lite]
      With the password: packets sealed with the cluster's bootstrap key, as
      any holder of the password can seal them - every packet type byte, the
      known ones and some no build uses, each with payloads of the lengths a
      parser has to bound (empty, one short of each field, exact, one over,
      the largest datagram) and of random, all-zero and all-0xff bytes.
      These pass decryption and reach the parser of their type.  <src_ips> is
      a comma-separated list of addresses to send from round-robin (the node
      limits each source to 20 control packets a second, so more sources means
      more of the set gets through); <rate> is packets per second per source.
      "lite" sends the known types only, random bytes only, at the field
      boundaries only - for a source that is also a live node, which must
      stay under that limit with its own traffic.

<dsts> is a comma-separated list of unicast addresses and multicast groups.
The bootstrap key is derived as cl_ctr_derive_key() derives it: Argon2id over
the password, salted with "opensips-cl-ctr-bootstrap-v1:<group>" folded to 16
bytes with BLAKE2b.  Only python3 and libsodium (already loaded by the module)
are needed.
"""
import ctypes, ctypes.util, json, os, random, socket, struct, sys, time

# --- wire constants (must match cl_ctr.h) ---
WIRE_MAGIC0 = 0xCB + 2                       # CL_CTR_MAGIC_BASE + wire version
PACKET_MAGIC, BOOTSTRAP_MAGIC, CONSUMER_MAGIC = (bytes([WIRE_MAGIC0, t]) for t in (0, 1, 2))
CID_SZ, NONCE_SZ, TAG_SZ = 16, 24, 16
HDR_SZ = 2 + 2 + CID_SZ + NONCE_SZ           # CL_CTR_WIRE_HDR_SZ = 44
MIN_PKT = HDR_SZ + 1 + 4 + 8 + TAG_SZ        # the receiver's minimum, 73
MAX_UDP = 65507
KNOWN_TYPES = list(range(0x01, 0x12))        # CL_CTR_PKT_ALIVE .. CL_CTR_PKT_MAINT_SET
OTHER_TYPES = [0x00, 0x12, 0x7f, 0x80, 0xff]
# payload lengths around every field a parser reads: IP (15 + NUL), pubkey 32,
# config 4, MTU 2, maintenance 1, capabilities 4, node ids, counts, bitmaps
LENGTHS = [0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 20, 31, 32, 33, 48, 49,
           52, 53, 54, 55, 56, 57, 58, 59, 60, 64, 65, 80, 96, 128, 255, 256,
           257, 512, 1024, 1400, 1472, 4096, 8192, 65000]
LITE_LENGTHS = [0, 1, 4, 15, 16, 17, 32, 33, 48, 52, 53, 56, 57, 60, 64, 256, 1472]


def sock(src_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    s.bind((src_ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    return s


def send(s, pkt, dsts, port, sent):
    for d in dsts:
        try:
            s.sendto(pkt, (d, port))
            sent[0] += 1
        except OSError:
            sent[1] += 1


def header(magic, cluster_id, uuid=bytes(CID_SZ)):
    return magic + struct.pack("!H", cluster_id & 0xFFFF) + uuid + os.urandom(NONCE_SZ)


def outsider(src_ip, dsts, port, cluster_id, sibling_id, seconds):
    rnd = random.Random(0x7430)
    other_wire = [bytes([0xCB + v, t]) for v in (1, 3, 4, 15) for t in (0, 1, 2)]
    ours = (PACKET_MAGIC, BOOTSTRAP_MAGIC, CONSUMER_MAGIC)
    pkts = []
    # too short to be a packet: every length below the minimum, random and
    # with a valid magic and cluster id in front
    for n in range(0, MIN_PKT):
        pkts.append(("short", os.urandom(n)))
        pkts.append(("short", (BOOTSTRAP_MAGIC + struct.pack("!H", cluster_id) + os.urandom(MIN_PKT))[:n]))
    # a magic no build uses
    for _ in range(200):
        m = bytes([rnd.choice([b for b in range(256) if not 0xCC <= b <= 0xDA]), rnd.randrange(256)])
        pkts.append(("badmagic", m + os.urandom(rnd.randrange(MIN_PKT, 1400))))
    # another wire version: refused at the gate, named once a minute
    for m in other_wire:
        for _ in range(10):
            pkts.append(("wire", m + os.urandom(rnd.randrange(MIN_PKT, 400))))
    # our magic and cluster id, a body that does not decrypt
    for m in ours:
        for _ in range(150):
            n = rnd.randrange(MIN_PKT - HDR_SZ, 1400)
            pkts.append(("undecryptable", header(m, cluster_id) + os.urandom(n)))
    # ... stamped with random cluster uuids
    for m in ours:
        for _ in range(100):
            pkts.append(("foreign-uuid", header(m, cluster_id, os.urandom(CID_SZ)) + os.urandom(rnd.randrange(40, 400))))
    # ... with the other local cluster's id, and with an id nobody runs
    for cid in (sibling_id, 999):
        for m in ours:
            for _ in range(50):
                pkts.append(("other-cluster", header(m, cid) + os.urandom(rnd.randrange(40, 400))))
    # the largest datagram, valid magic
    for m in ours:
        for _ in range(5):
            pkts.append(("oversized", header(m, cluster_id) + os.urandom(MAX_UDP - HDR_SZ)))
    rnd.shuffle(pkts)
    s = sock(src_ip)
    sent = [0, 0]
    per = {}
    gap = seconds / max(1, len(pkts))
    t0 = time.time()
    for k, (cat, p) in enumerate(pkts):
        send(s, p, dsts, port, sent)
        per[cat] = per.get(cat, 0) + 1
        delay = t0 + (k + 1) * gap - time.time()
        if delay > 0:
            time.sleep(delay)
    print(json.dumps({"mode": "outsider", "datagrams": sent[0], "send_errors": sent[1],
                      "packets": len(pkts), "per_category": per}))


def sodium():
    lib = ctypes.CDLL(ctypes.util.find_library("sodium") or "libsodium.so.23")
    if lib.sodium_init() < 0:
        sys.exit("sodium_init failed")
    return lib


def bootstrap_key(lib, password, group):
    salt = ("opensips-cl-ctr-bootstrap-v1:%s" % group).encode()
    salt16 = ctypes.create_string_buffer(16)
    lib.crypto_generichash(salt16, ctypes.c_size_t(16), salt, ctypes.c_ulonglong(len(salt)), None, ctypes.c_size_t(0))
    key = ctypes.create_string_buffer(32)
    pw = password.encode()
    if lib.crypto_pwhash(key, ctypes.c_ulonglong(32), pw, ctypes.c_ulonglong(len(pw)), salt16,
                         ctypes.c_ulonglong(3), ctypes.c_size_t(64 << 20),
                         ctypes.c_int(lib.crypto_pwhash_alg_argon2id13())) != 0:
        sys.exit("crypto_pwhash failed")
    return key.raw


def seal(lib, key, cluster_id, ptype, payload):
    hdr = header(BOOTSTRAP_MAGIC, cluster_id)
    plain = bytes([ptype]) + os.urandom(4) + os.urandom(8) + payload
    out = ctypes.create_string_buffer(len(plain) + TAG_SZ)
    olen = ctypes.c_ulonglong(0)
    if lib.crypto_aead_xchacha20poly1305_ietf_encrypt(
            out, ctypes.byref(olen), plain, ctypes.c_ulonglong(len(plain)),
            hdr[:HDR_SZ - NONCE_SZ], ctypes.c_ulonglong(HDR_SZ - NONCE_SZ),
            None, hdr[HDR_SZ - NONCE_SZ:], key) != 0:
        sys.exit("encrypt failed")
    return hdr + out.raw[:olen.value]


def sealed(src_ips, dsts, port, cluster_id, group, password, rate, lite):
    lib = sodium()
    key = bootstrap_key(lib, password, group)
    cases = []
    for t in KNOWN_TYPES + ([] if lite else OTHER_TYPES):
        for n in (LITE_LENGTHS if lite else LENGTHS):
            if HDR_SZ + 13 + n + TAG_SZ > MAX_UDP:
                n = MAX_UDP - HDR_SZ - 13 - TAG_SZ
            for fill in (("rnd",) if lite else ("rnd", "zero", "ff")):
                if fill != "rnd" and n > 1472:
                    continue
                body = os.urandom(n) if fill == "rnd" else bytes([0 if fill == "zero" else 0xFF]) * n
                cases.append((t, n, fill, body))
    socks = [sock(ip) for ip in src_ips]
    sent = [0, 0]
    gap = 1.0 / (rate * len(socks))
    t0 = time.time()
    for k, (t, n, fill, body) in enumerate(cases):
        send(socks[k % len(socks)], seal(lib, key, cluster_id, t, body), dsts, port, sent)
        delay = t0 + (k + 1) * gap - time.time()
        if delay > 0:
            time.sleep(delay)
    print(json.dumps({"mode": "sealed", "datagrams": sent[0], "send_errors": sent[1],
                      "packets": len(cases), "sources": len(socks),
                      "seconds": round(time.time() - t0, 1)}))


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 7 and a[0] == "outsider":
        outsider(a[1], a[2].split(","), int(a[3]), int(a[4]), int(a[5]), float(a[6]))
    elif len(a) in (8, 9) and a[0] == "sealed" and a[8:] in ([], ["lite"]):
        sealed(a[1].split(","), a[2].split(","), int(a[3]), int(a[4]), a[5], a[6], float(a[7]), a[8:] == ["lite"])
    else:
        sys.exit(__doc__)
