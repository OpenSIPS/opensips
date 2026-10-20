#!/usr/bin/env python3
"""
wire_tap.py - capture controller datagrams off a veth port and send them
again later, unchanged, for the replay and reordering tests in netns_tests.sh.

  wire_tap.py capture <iface> <src_ip> <port> <seconds> <out.json>
      Record every IPv4/UDP datagram from <src_ip> to <port> seen on <iface>
      (the host side of a node's veth pair sees all of that node's traffic,
      unicast included, which the bridge device itself does not).

  wire_tap.py inject <in.json> [<src_ip>]
      Send each recorded payload to its recorded destination, from <src_ip>
      (default: the recorded source).  Run it inside the sender's netns so the
      datagrams leave with the sender's address, as a delayed or replayed
      packet would.

The payloads are sealed; nothing here can read or alter them, which is the
point: a node must refuse or order them on what the wire carries alone.
"""
import json, socket, struct, sys, time

ETH_P_IP = 0x0800


def capture(iface, src_ip, port, seconds, out):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.bind((iface, 0))
    s.settimeout(0.2)
    want = socket.inet_aton(src_ip)
    pkts, end = [], time.time() + seconds
    while time.time() < end:
        try:
            frame, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[2] == socket.PACKET_OUTGOING:
            continue        # the same frame is seen once per direction
        ip = frame[14:]
        if len(ip) < 28 or ip[9] != 17 or ip[12:16] != want:
            continue
        ihl = (ip[0] & 0x0F) * 4
        sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
        if dport != port:
            continue
        pkts.append({"t": time.time(), "dst": socket.inet_ntoa(ip[16:20]),
                     "dport": dport, "len": ulen - 8,
                     "data": ip[ihl + 8:ihl + ulen].hex()})
    with open(out, "w") as f:
        json.dump(pkts, f)
    print(len(pkts))


def inject(path, src_ip=None):
    with open(path) as f:
        pkts = json.load(f)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src_ip:
        s.bind((src_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                     socket.inet_aton(src_ip))
    for p in pkts:
        s.sendto(bytes.fromhex(p["data"]), (p["dst"], p["dport"]))
        time.sleep(0.005)
    print(len(pkts))


if __name__ == "__main__":
    if len(sys.argv) >= 7 and sys.argv[1] == "capture":
        capture(sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5]),
                sys.argv[6])
    elif len(sys.argv) >= 3 and sys.argv[1] == "inject":
        inject(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else:
        sys.exit(__doc__)
