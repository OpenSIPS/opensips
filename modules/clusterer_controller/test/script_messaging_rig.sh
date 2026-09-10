#!/bin/sh
# CP-15.13: script-to-script messaging over the controller's plane.
set -e
T=/dn/wt-cp15
D=/dn/scripttier
mkdir -p $D
pkill -f "scripttier/n[12].cfg" 2>/dev/null || true
sleep 1
for i in 1 2; do ip netns del s$i 2>/dev/null || true; ip link del x${i}p 2>/dev/null || true; done
ip link del br96 2>/dev/null || true
sleep 1
rm -f $D/mi1.sock $D/mi2.sock

ip link add br96 type bridge
ip link set br96 up
echo 0 > /sys/class/net/br96/bridge/multicast_snooping 2>/dev/null || true
for i in 1 2; do
  ip netns add s$i
  ip link add x$i type veth peer name x${i}p
  ip link set x$i netns s$i
  ip link set x${i}p master br96 up
  ip netns exec s$i ip link set lo up
  ip netns exec s$i ip addr add 10.96.0.$i/24 dev x$i
  ip netns exec s$i ip link set x$i up
  ip netns exec s$i ip route add 239.0.0.0/8 dev x$i

  cat > $D/n$i.cfg <<EOF
log_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=2
socket=udp:10.96.0.$i:5060
socket=bin:10.96.0.$i:5588
mpath="$T/modules/"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
loadmodule "clusterer.so"
loadmodule "clusterer_controller.so"
loadmodule "mi_datagram.so"
loadmodule "sl.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", $i)
modparam("clusterer", "cluster_options", "cluster_id=5, use_controller=1")
modparam("clusterer_controller", "my_ip", "10.96.0.$i")
modparam("clusterer_controller", "password", "scripttest")
modparam("clusterer_controller", "cluster", "id=5,multicast=239.0.96.1:4477,bin_socket=bin:10.96.0.$i:5588")
modparam("mi_datagram", "socket_name", "$D/mi$i.sock")

route {
    if (\$hdr(X-Bcast) == "1") {
        cl_ctr_broadcast_req(5, "hello-from-node$i");
        sl_send_reply(200, "sent");
        exit;
    }
    if (\$hdr(X-Ucast) == "1") {
        cl_ctr_send_req(5, \$(hdr(X-To-Node){s.int}), "direct-to-you");
        sl_send_reply(200, "sent");
        exit;
    }
    sl_send_reply(200, "ok");
    exit;
}
event_route[E_CL_CTR_REQ_RECEIVED] {
    xlog("L_NOTICE", "SCRIPT-REQ cluster=\$param(cluster_id) src=\$param(src_id) msg=[\$param(msg)]\n");
    # answer the sender, so the reply half is exercised too
    cl_ctr_send_rpl(5, \$param(src_id), "ack-from-node$i");
}
event_route[E_CL_CTR_RPL_RECEIVED] {
    xlog("L_NOTICE", "SCRIPT-RPL cluster=\$param(cluster_id) src=\$param(src_id) msg=[\$param(msg)]\n");
}
EOF
  ip netns exec s$i $T/opensips -f $D/n$i.cfg -F > $D/n$i.log 2>&1 &
done
echo "waiting for the cluster..."
sleep 14
grep -ahc "roles:" $D/n1.log $D/n2.log
