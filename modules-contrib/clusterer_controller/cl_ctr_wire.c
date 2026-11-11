/*
 * clusterer_controller - socket, wire format, replay windows and packet senders
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "cl_ctr.h"
#include "cl_ctr_data.h"
#include "cl_ctr_identity.h"
#include "cl_ctr_caps.h"
const unsigned char CL_CTR_PACKET_MAGIC[CL_CTR_MAGIC_SZ]    = { CL_CTR_WIRE_MAGIC0, 0x00 };
const unsigned char CL_CTR_BOOTSTRAP_MAGIC[CL_CTR_MAGIC_SZ] = { CL_CTR_WIRE_MAGIC0, 0x01 };

/* the MTU we joined at (the cluster's) - admission and drift are judged against
 * it; 0 only before mod_init */
int cc_mtu = 0;
/* current MTU from the drift poll, and what we advertise: advertising cc_mtu
 * would hide our own drift from the peers */
int cc_mtu_now = 0;
/* consecutive polls that disagreed with cc_mtu (see CL_CTR_MTU_DRIFT_STRIKES) */
int cc_mtu_drift_strikes = 0;
/* consecutive polls that could not read the MTU; kept apart from the strikes
 * since a failed read is no evidence (see cl_ctr_mtu_step) */
int cc_mtu_read_fails = 0;

/* kernel MTU of the plane's interface, -1 if unreadable; the only MTU source,
 * by design - there is no configured fallback */
int cl_ctr_read_iface_mtu(void)
{
    struct ifreq ifr;
    int          s, mtu = -1;

    if (my_interface_buf[0] == '\0')
        return -1;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, my_interface_buf,
           strnlen(my_interface_buf, IF_NAMESIZE - 1));
    if (ioctl(s, SIOCGIFMTU, &ifr) == 0)
        mtu = ifr.ifr_mtu;
    close(s);
    return mtu;
}

/* a failed read is neither drift nor recovery: strikes stay as they are, so a
 * flaky ioctl cannot hold a drifted node alive or log a recovery never read */
int cl_ctr_mtu_step(int now_mtu, int joined_mtu, int *strikes, int *fails)
{
    if (now_mtu <= 0) {
        (*fails)++;
        return CL_CTR_MTU_STEP_UNREADABLE;
    }
    *fails = 0;
    if (now_mtu == joined_mtu) {
        if (*strikes) {
            *strikes = 0;
            return CL_CTR_MTU_STEP_RECOVERED;
        }
        return CL_CTR_MTU_STEP_STEADY;
    }
    if (++(*strikes) >= CL_CTR_MTU_DRIFT_STRIKES)
        return CL_CTR_MTU_STEP_CONFIRMED;
    return CL_CTR_MTU_STEP_DRIFTING;
}

/* unknown senders are accepted so their first packet (ALIVE/JOIN_REQ) can enter
 * the peer table; worker-only, no lock; bootstrap packets use join_nonce */
int cl_ctr_check_and_update_seq(const char *sender_ip, uint32_t pkt_seq,
                                   uint64_t pkt_inc, cl_ctr_cluster_t *cl)
{
    const char *why;
    int i, rc;
    for (i = 0; i < cl->peers->count; i++) {
        if (strcmp(cl->peers->entries[i].ip, sender_ip) == 0) {
            cl_ctr_peer_t   *e = &cl->peers->entries[i];

            /* a higher incarnation is a restart: reset its window on its first
             * packet; a lower one is a replay from a previous life */
            if (pkt_inc != e->incarnation) {
                if (e->incarnation != 0 && pkt_inc < e->incarnation) {
                    static time_t last_stale_warn;
                    time_t now = cl_ctr_now();
                    if (now - last_stale_warn >= CL_CTR_WIRE_WARN_IVL) {
                        last_stale_warn = now;
                        LM_WARN("clusterer_controller: [cluster %d] packet "
                                "from %s carries incarnation %llu, older than "
                                "the %llu it is running now - a replay from "
                                "before it restarted, refused\n",
                                cl->cluster_id, sender_ip,
                                (unsigned long long)pkt_inc,
                                (unsigned long long)e->incarnation);
                    }
                    return CL_CTR_SEQ_STALE;
                }
                if (e->incarnation != 0)
                    LM_INFO("clusterer_controller: [cluster %d] %s restarted "
                            "(incarnation %llu -> %llu) - its sequence "
                            "numbers start again\n", cl->cluster_id, sender_ip,
                            (unsigned long long)e->incarnation,
                            (unsigned long long)pkt_inc);
                e->incarnation = pkt_inc;
                cl_ctr_replay_reset(&e->replay);
            }

            rc = cl_ctr_replay_check(&e->replay, pkt_seq);
            if (rc == CL_CTR_SEQ_OK)
                return rc;

            why = rc == CL_CTR_SEQ_DUP  ? "already accepted"
                : rc == CL_CTR_SEQ_JUMP ? "implausibly far ahead - a wrapped "
                                          "replay, or this peer's traffic has "
                                          "been lost wholesale"
                                        : "older than the replay window";
            LM_WARN("clusterer_controller: packet from %s seq=%u last=%u "
                    "%s, dropping\n", sender_ip, pkt_seq, e->replay.last, why);
            return rc;
        }
    }
    return CL_CTR_SEQ_OK;
}

int cl_ctr_setup_socket(cl_ctr_cluster_t *cl)
{
    int                sock;
    int                yes = 1;
    unsigned char      loop = 1, ttl = 32;
    struct sockaddr_in local;
    struct ip_mreq     mreq;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	LM_ERR("clusterer_controller: socket(): %s\n", strerror(errno));
	return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
	LM_ERR("clusterer_controller: SO_REUSEADDR: %s\n", strerror(errno));
	close(sock);
	return -1;
    }

    /* room for a reassembled MEMBER_LIST (~4 KB at 256 peers) even when it was
     * fragmented on a low-MTU link */
    {
	int rcvbuf = 1 << 20;   /* request 1 MB; kernel may cap lower */
	int got = 0;
	socklen_t gl = sizeof(got);
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
	               &rcvbuf, sizeof(rcvbuf)) < 0)
	    LM_WARN("clusterer_controller: SO_RCVBUF: %s\n", strerror(errno));
	/* warn when capped: bursts (join storm, MEMBER_LIST re-broadcast)
	 * overflow it and look like network loss; Linux reports twice the size */
	if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &got, &gl) == 0) {
	    cl->peers->rcvbuf_bytes = got / 2;
	    if (got / 2 < rcvbuf)
		LM_WARN("clusterer_controller: [cluster %d] receive buffer is "
		        "%d bytes, %d were asked for - capped by "
		        "net.core.rmem_max; raise it if rx_kernel_drops grows\n",
		        cl->cluster_id, got / 2, rcvbuf);
	}
	/* count what the kernel drops because that buffer was full */
	if (setsockopt(sock, SOL_SOCKET, SO_RXQ_OVFL, &yes, sizeof(yes)) < 0)
	    LM_WARN("clusterer_controller: SO_RXQ_OVFL: %s\n", strerror(errno));
    }

    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_port        = htons((uint16_t)cl->multicast_port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    /* SO_REUSEADDR lets a second process share the port, and the kernel then
     * gives each unicast datagram (KEY_GRANT, ACKs) to only one of the two */
    {
	int probe = socket(AF_INET, SOCK_DGRAM, 0);

	if (probe >= 0) {
	    /* without SO_REUSEADDR the bind fails with EADDRINUSE iff the port
	     * is held; advisory only - a restart can race the outgoing process */
	    if (bind(probe, (struct sockaddr *)&local, sizeof(local)) < 0 &&
	        errno == EADDRINUSE)
		LM_WARN("clusterer_controller: [cluster %d] another process is "
			"already bound to port %d - multicast will reach both, "
			"but every unicast leg (KEY_GRANT, ACKs) goes to only "
			"ONE of them, chosen by the kernel and not by address.  "
			"A node that cannot join is explained by this and not "
			"by a bad password.  One controller instance per host "
			"per port is what is supported.\n",
			cl->cluster_id, cl->multicast_port);
	    close(probe);
	}
    }

#ifdef IP_MULTICAST_ALL
    /* Linux delivers every group joined on this port host-wide by default, so
     * sibling clusters would read each other's multicast; must precede bind() */
    {
	int mc_all = 0;
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_ALL,
	               &mc_all, sizeof(mc_all)) < 0)
	    LM_WARN("clusterer_controller: [cluster %d] IP_MULTICAST_ALL: %s - "
	            "this socket may also receive other groups joined on port %d\n",
	            cl->cluster_id, strerror(errno), cl->multicast_port);
    }
#endif

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
	LM_ERR("clusterer_controller: bind() port %d: %s\n",
	       cl->multicast_port, strerror(errno));
	close(sock);
	return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(cl->multicast_address);
    /* join on our own interface (my_ip), not INADDR_ANY: the default route may
     * silently pick another one, and the nodes never see each other */
    mreq.imr_interface.s_addr = inet_addr(my_ip);

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
	LM_ERR("clusterer_controller: IP_ADD_MEMBERSHIP (%s): %s\n",
	       cl->multicast_address, strerror(errno));
	close(sock);
	return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &loop, sizeof(loop)) < 0)
	LM_WARN("clusterer_controller: IP_MULTICAST_LOOP: %s\n",
	        strerror(errno));

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   &ttl, sizeof(ttl)) < 0)
	LM_WARN("clusterer_controller: IP_MULTICAST_TTL: %s\n",
	        strerror(errno));

    /* loopback packets then carry my_ip as source, which self-loopback
     * detection in cl_ctr_handle_member_list() relies on (multi-homed hosts) */
    {
	struct in_addr local_if;
	local_if.s_addr = inet_addr(my_ip);
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
	               &local_if, sizeof(local_if)) < 0)
	    LM_WARN("clusterer_controller: [cluster %d] IP_MULTICAST_IF: %s\n",
	        cl->cluster_id,
	            strerror(errno));
    }

    /* stricter than IP_MULTICAST_IF on multi-homed hosts: routing-independent */
    if (my_interface_buf[0] != '\0') {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, my_interface_buf,
	       strnlen(my_interface_buf, IF_NAMESIZE - 1));
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
	               &ifr, sizeof(ifr)) < 0)
	    /* needs CAP_NET_RAW, lost on privilege drop - IP_MULTICAST_IF suffices */
	    LM_DBG("clusterer_controller: SO_BINDTODEVICE (%s): %s "
	           "(non-fatal, IP_MULTICAST_IF covers this)\n",
	           my_interface_buf, strerror(errno));
    }

    LM_INFO("clusterer_controller: [cluster %d] socket ready, joined %s:%d\n",
            cl->cluster_id, cl->multicast_address, cl->multicast_port);

    /* cl->mcast_dest comes from mod_init, inherited across fork */

    /* so sendto() never blocks the worker on a full send buffer; reads already go
     * through select() */
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0) {
	LM_WARN("clusterer_controller: fcntl O_NONBLOCK: %s\n",
	        strerror(errno));
	/* non-fatal - we continue; send paths handle EAGAIN explicitly */
    }

    return sock;
}

/* packet senders */

/* encrypts @pkt in place (magic stamped, @plain_len bytes at CL_CTR_WIRE_HDR_SZ)
 * and sends it to @dest; @type is for logging only */
int cl_ctr_seal_and_send_to(int sock, cl_ctr_cluster_t *cl, char *pkt,
                               int plain_len, const unsigned char *key,
                               unsigned char type,
                               const struct sockaddr *dest, socklen_t destlen)
{
    int total_len;

    /* JOIN_REQ carries no cid: a node merging into another master must not be
     * refused for the id of the partition it is leaving */
    total_len = cl_ctr_encrypt_pkt(pkt, CL_CTR_WIRE_HDR_SZ, plain_len, key,
                                   cl->cluster_id,
                                   (type == CL_CTR_PKT_JOIN_REQ
                                    || cl->peers->cid_state == CL_CTR_CID_NONE)
                                   ? NULL : cl->peers->cid);
    if (total_len < 0)
        return -1;

    if (sendto(sock, pkt, total_len, 0, dest, destlen) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            LM_DBG("clusterer_controller: [cluster %d] sendto (type=0x%02x) "
                   "would block\n", cl->cluster_id, type);
        else
            LM_ERR("clusterer_controller: [cluster %d] sendto (type=0x%02x): %s\n",
                   cl->cluster_id, type, strerror(errno));
        return -1;
    }
    LM_DBG("clusterer_controller: [cluster %d] sent 0x%02x\n", cl->cluster_id, type);
    return 0;
}

int cl_ctr_seal_and_send(int sock, cl_ctr_cluster_t *cl, char *pkt, int plain_len,
                            const unsigned char *key, unsigned char type)
{
    return cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, key, type,
                               (const struct sockaddr *)&cl->mcast_dest,
                               sizeof(cl->mcast_dest));
}

/* sealed in the acked packet's key class (@use_bootstrap for KEY_GRANT): the
 * acker may not hold the session key yet */
void cl_ctr_send_ack(int sock, cl_ctr_cluster_t *cl, uint32_t acked_seq,
                        unsigned char acked_type, int use_bootstrap,
                        const struct sockaddr *dest, socklen_t destlen)
{
    char          pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_ACK_SZ
                      + CL_CTR_TAG_SZ];
    uint32_t      seq      = htonl(++cl->peers->my_seq);
    uint32_t      acked_be = htonl(acked_seq);
    const unsigned char *key = use_bootstrap ? cl->key : cl->session_key;

    memcpy(pkt, use_bootstrap ? CL_CTR_BOOTSTRAP_MAGIC : CL_CTR_PACKET_MAGIC,
           CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_ACK;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, &acked_be, sizeof(acked_be));
    pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + sizeof(acked_be)] = (char)acked_type;

    cl_ctr_seal_and_send_to(sock, cl, pkt, CL_CTR_PLAIN_HDR_SZ + CL_CTR_ACK_SZ,
                        key, CL_CTR_PKT_ACK, dest, destlen);
}

/* ALIVE: [type][seq][ip NUL][pubkey 32B][config][mtu][maint 1B][caps][links]
 * [last broadcast number 8B][capability states]; GOODBYE ends after the ip */
void cl_ctr_send_pkt_with_ip(int sock, unsigned char type, cl_ctr_cluster_t *cl,
                                const struct sockaddr *dest, socklen_t destlen)
{
    char               pkt[CL_CTR_SMALL_PKT_SZ + CL_CTR_PUBKEY_SZ
                           + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ + 1
                           + CL_CTR_CAPS_SZ + CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_ALIVE_DSEQ_SZ + CL_CTR_CAPST_MAX_SZ];
    uint32_t           seq     = htonl(++cl->peers->my_seq);
    int                ip_len  = (int)strlen(my_ip);
    int                plain_len;

    if (ip_len > CL_CTR_MAX_IP_LEN)
	ip_len = CL_CTR_MAX_IP_LEN;

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);

    pkt[CL_CTR_WIRE_HDR_SZ] = (char)type;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, my_ip, ip_len);
    pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + ip_len] = '\0';
    plain_len = CL_CTR_PLAIN_HDR_SZ + ip_len + 1;

    if (type == CL_CTR_PKT_ALIVE) {
	memcpy(pkt + CL_CTR_WIRE_HDR_SZ + plain_len, cl->my_pubkey, CL_CTR_PUBKEY_SZ);
	plain_len += CL_CTR_PUBKEY_SZ;
	/* so peers can detect per-node config drift */
	{
	    char    *c  = pkt + CL_CTR_WIRE_HDR_SZ + plain_len;
	    uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
	    c[0] = (char)(cl->manage_shtags ? 1 : 0);
	    c[1] = (char)(cl->master_stickiness ? 1 : 0);
	    memcpy(c + 2, &qt, 2);
	    plain_len += CL_CTR_CONFIG_SZ;
	}
	/* the live MTU - detected, not configured (see CL_CTR_MTU_SZ) */
	{
	    uint16_t m = htons(cl_ctr_mtu_wire(cc_mtu_now));
	    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + plain_len, &m, CL_CTR_MTU_SZ);
	    plain_len += CL_CTR_MTU_SZ;
	}
	/* older builds ignore this byte; newer ones read 0 when it is absent */
	pkt[CL_CTR_WIRE_HDR_SZ + plain_len] = (char)cl->maint_adv;
	plain_len += 1;
	/* caps; older builds stop before them and imply none */
	{
	    uint32_t c = htonl(cl_ctr_caps_mine(cl));
	    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + plain_len, &c, CL_CTR_CAPS_SZ);
	    plain_len += CL_CTR_CAPS_SZ;
	}
	/* the nodes it has a BIN link up with: admission and the link matrix */
	cl_ctr_build_link_bitmap(cl, (unsigned char *)pkt + CL_CTR_WIRE_HDR_SZ + plain_len);
	plain_len += CL_CTR_ALIVE_BITMAP_SZ;
	{
	    uint64_t s = cl_ctr_data_tx_seq(cl);
	    int      k;
	    for (k = 0; k < CL_CTR_ALIVE_DSEQ_SZ; k++)
		pkt[CL_CTR_WIRE_HDR_SZ + plain_len + k] = (char)(s >> (56 - 8 * k));
	    plain_len += CL_CTR_ALIVE_DSEQ_SZ;
	}
	/* its capability states, for sync donors (no CAP_UPDATE over BIN) */
	plain_len += cl_ctr_build_capst(cl, pkt + CL_CTR_WIRE_HDR_SZ + plain_len,
	                                CL_CTR_CAPST_MAX_SZ);
    }

    if (dest)
        cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, cl->session_key, type,
                            dest, destlen);
    else
        cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->session_key, type);
}

void cl_ctr_send_list_pkt(int sock, unsigned char type, cl_ctr_cluster_t *cl,
                             const struct sockaddr *dest, socklen_t destlen)
{
    char               pkt[CL_CTR_LIST_PKT_MAX_SZ];
    uint32_t           seq      = htonl(++cl->peers->my_seq);
    uint16_t           count    = 0;
    uint16_t           count_be;
    char              *p;
    time_t             cutoff;
    int                i, plain_len;

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);

    /* Plaintext: [type][seq][incarnation][count BE][forced_shtag_node_id BE]
     *            [entries...][master term BE][list seq BE] */
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)type;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    /* count filled after iteration; forced_shtag_node_id filled below */
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ;

    cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_ELECT_FACTOR);

    lock_start_read(cl->peers->lock);
    {
	uint16_t forced_be = htons(cl->peers->shtag_forced_node_id);
	memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_LIST_COUNT_SZ,
	       &forced_be, CL_CTR_NODE_ID_SZ);
    }

    for (i = 0; i < cl->peers->count && count < CL_CTR_MAX_PEERS; i++) {
	cl_ctr_peer_t *e = &cl->peers->entries[i];
	if (e->last_seen < cutoff)
	    continue;
	memset(p, 0, CL_CTR_IP_ENTRY_SZ);
	memcpy(p, e->ip, strnlen(e->ip, CL_CTR_MAX_IP_LEN));
	p[CL_CTR_IP_ENTRY_SZ - 1] = (char)(e->is_master ? 1 : 0);
	p += CL_CTR_IP_ENTRY_SZ;
	count++;
    }

    lock_stop_read(cl->peers->lock);

    count_be = htons(count);
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, &count_be, CL_CTR_LIST_COUNT_SZ);

    {
	uint32_t t_be = htonl(cl->peers->my_term);
	uint32_t s_be = htonl(++cl->peers->list_seq);
	memcpy(p, &t_be, 4);  p += 4;
	memcpy(p, &s_be, 4);
    }

    plain_len = CL_CTR_PLAIN_HDR_SZ + CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ
                + count * CL_CTR_IP_ENTRY_SZ + CL_CTR_LIST_STAMP_SZ;
    if ((dest ? cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, cl->session_key,
                                    type, dest, destlen)
              : cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->session_key, type)) == 0)
	LM_INFO("clusterer_controller: [cluster %d] sent MEMBER_LIST (%d members)%s\n",
	        cl->cluster_id, count, dest ? " (unicast)" : "");
}

void cl_ctr_send_join_req_pkt(int sock, cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_JOIN_PKT_MAX_SZ];
    uint32_t           seq;

    /* several paths (defer timer, re-key, rejoin timer) may ask within a second;
     * JOIN_REQ is idempotent and the next tick resends, so drop the extras */
    {
        utime_t now_us = get_uticks();
        if (cl->last_join_req_utime != 0 &&
            (utime_t)(now_us - cl->last_join_req_utime) < CL_CTR_JOIN_REQ_MIN_US)
            return;
        cl->last_join_req_utime = now_us;
    }

    seq = htonl(++cl->peers->my_seq);
    int                ip_len  = (int)strlen(my_ip);
    char              *p;
    int                plain_len;

    if (ip_len > CL_CTR_MAX_IP_LEN)
	ip_len = CL_CTR_MAX_IP_LEN;

    memcpy(pkt, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ);

    /* plaintext: [type][seq][ip NUL][bin_count][sock NUL]...[noise msg1 48B]
     * [config][mtu][proposal][caps] */
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_JOIN_REQ;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;

    memcpy(p, my_ip, ip_len);
    p[ip_len] = '\0';
    p += ip_len + 1;

    /* Advertise only the BIN socket resolved for this specific cluster */
    {
	int slen = (int)strnlen(cl->bin_socket, CL_CTR_MAX_BIN_SOCK_LEN - 1);
	*p++ = 1;   /* bin_count */
	memcpy(p, cl->bin_socket, slen);
	p[slen] = '\0';
	p += slen + 1;
    }

    /* Noise msg 1 (-> psk, e), PSK = bootstrap key; the state kept reads msg 2
     * (KEY_GRANT) - a newer JOIN_REQ replaces it, so a stale grant fails */
    {
	int m1 = cl_ctr_noise_write1(&cl->noise_hs, cl->noise_e_priv, cl->key,
	                         NULL, 0, (unsigned char *)p);
	cl->noise_hs_valid = 1;
	p += m1;   /* 48 bytes: 32 ephemeral + 16 tag */
    }

    /* Advertise our consistency-critical config so the master can reject (or
     * warn about) a join with settings that differ from the running cluster. */
    {
	uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
	*p++ = (char)(cl->manage_shtags ? 1 : 0);
	*p++ = (char)(cl->master_stickiness ? 1 : 0);
	memcpy(p, &qt, 2);
	p += 2;
    }

    /* the master admits only its own MTU, so every member matches and a handover
     * cannot change it */
    {
	uint16_t m = htons(cl_ctr_mtu_wire(cc_mtu_now));
	memcpy(p, &m, CL_CTR_MTU_SZ);
	p += CL_CTR_MTU_SZ;
    }

    /* the node id it asks for: granted if free (absent on older builds) */
    {
	uint16_t pr = htons(cl_ctr_proposal);
	memcpy(p, &pr, CL_CTR_PROPOSAL_SZ);
	p += CL_CTR_PROPOSAL_SZ;
    }

    /* what it can do: a master queues only a joiner that waits on JOIN_WAIT */
    {
	uint32_t c = htonl(cl_ctr_caps_mine(cl));
	memcpy(p, &c, CL_CTR_JOIN_CAPS_SZ);
	p += CL_CTR_JOIN_CAPS_SZ;
    }

    plain_len = (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ));
    if (cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->key, CL_CTR_PKT_JOIN_REQ) == 0) {
	/* sealing left this request's nonce in the header: a refusal of it
	 * must echo it (cl_ctr_handle_join_reject) */
	memcpy(cl->join_nonces[cl->join_nonce_next], pkt + CL_CTR_NONCE_OFF,
	       CL_CTR_NONCE_SZ);
	cl->join_nonce_next = (cl->join_nonce_next + 1) % CL_CTR_JOIN_NONCES;
	if (cl->join_nonces_n < CL_CTR_JOIN_NONCES)
	    cl->join_nonces_n++;
	LM_DBG("clusterer_controller: [cluster %d] sent JOIN_REQ bin=%s\n",
	       cl->cluster_id, cl->bin_socket);
    }
}

/* master -> all after allocating a node_id: [node_id 2B BE][ip NUL][bin_count]
 * [sock NUL]...[incarnation BE] */
void cl_ctr_send_node_assign(int sock, const char *ip, uint16_t node_id,
                                uint8_t bin_count,
                                const char (*bin_sockets)[CL_CTR_MAX_BIN_SOCK_LEN],
                                uint64_t inc, cl_ctr_cluster_t *cl,
                                const struct sockaddr *dest, socklen_t destlen)
{
    char               pkt[CL_CTR_NODE_ASSIGN_MAX_SZ];
    uint32_t           seq      = htonl(++cl->peers->my_seq);
    uint16_t           nid_be   = htons(node_id);
    int                ip_len   = (int)strnlen(ip, CL_CTR_MAX_IP_LEN);
    char              *p;
    int                i, plain_len;

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);

    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_NODE_ASSIGN;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;

    memcpy(p, &nid_be, CL_CTR_NODE_ID_SZ);
    p += CL_CTR_NODE_ID_SZ;

    memcpy(p, ip, ip_len);
    p[ip_len] = '\0';
    p += ip_len + 1;

    *p++ = (char)bin_count;
    for (i = 0; i < bin_count; i++) {
	int slen = (int)strnlen(bin_sockets[i], CL_CTR_MAX_BIN_SOCK_LEN - 1);
	memcpy(p, bin_sockets[i], slen);
	p[slen] = '\0';
	p += slen + 1;
    }

    /* the incarnation the master admitted this node at (0 = unknown) */
    for (i = 0; i < CL_CTR_INC_SZ; i++)
	*p++ = (char)(inc >> (56 - 8 * i));

    plain_len = (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ));
    /* session-keyed to match CL_CTR_PACKET_MAGIC (else every receipt fails AEAD,
     * storming JOIN_REQs); KEY_GRANT went first, so the joiner has the key */
    if ((dest ? cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, cl->session_key,
                                    CL_CTR_PKT_NODE_ASSIGN, dest, destlen)
              : cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->session_key,
                                 CL_CTR_PKT_NODE_ASSIGN)) == 0)
	LM_INFO("clusterer_controller: [cluster %d] NODE_ASSIGN node_id=%u ip=%s%s\n",
	        cl->cluster_id, node_id, ip, dest ? " (unicast)" : "");
}

/* Build a sockaddr_in for an IPv4 dotted string + port (for unicast sends). */
void cl_ctr_sockaddr_in(const char *ip, int port, struct sockaddr_in *out)
{
    memset(out, 0, sizeof(*out));
    out->sin_family      = AF_INET;
    out->sin_port        = htons((uint16_t)port);
    out->sin_addr.s_addr = inet_addr(ip);
}

/* master-only keepalive; its membership digest lets members spot a missed
 * NODE_ASSIGN and pull a RESYNC */
void cl_ctr_send_master_alive(int sock, cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
                           + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_TERM_SZ + CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_LIVE_SZ + CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_CAPS_SZ + CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_UNRAISED_SZ + CL_CTR_TAG_SZ];
    uint16_t           live_be = htons(cl_ctr_live_count(cl));
    uint32_t           seq = htonl(++cl->peers->my_seq);
    uint32_t           term_be = htonl(cl->peers->my_term);
    uint16_t           cnt;
    uint64_t           hash;
    char              *p;
    int                k;

    cl_ctr_membership_digest(cl, &cnt, &hash);

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ]     = (char)CL_CTR_PKT_MASTER_ALIVE;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;
    *p++ = (char)(cnt >> 8); *p++ = (char)cnt;
    for (k = 0; k < 8; k++) *p++ = (char)(hash >> (56 - 8 * k));
    /* relay the per-node liveness bitmap so settled non-masters can refresh
     * their election window without hearing peers' ALIVEs directly */
    cl_ctr_build_alive_bitmap(cl, (unsigned char *)p);
    p += CL_CTR_ALIVE_BITMAP_SZ;
    /* the term of this mastership, for cl_ctr_master_outranks() */
    memcpy(p, &term_be, CL_CTR_TERM_SZ);
    p += CL_CTR_TERM_SZ;
    /* relay which nodes are in maintenance, by node_id - members hear only
     * the master, never each other's ALIVEs */
    cl_ctr_build_maint_bitmap(cl, (unsigned char *)p);
    p += CL_CTR_ALIVE_BITMAP_SZ;
    /* the members this master hears now, for cl_ctr_master_outranks() */
    memcpy(p, &live_be, CL_CTR_LIVE_SZ);
    p += CL_CTR_LIVE_SZ;
    /* and which of the nodes in maintenance are at the 'full' level */
    cl_ctr_build_maint_full_bitmap(cl, (unsigned char *)p);
    p += CL_CTR_ALIVE_BITMAP_SZ;
    /* and what every live member shares: only the master hears
     * every member's ALIVE */
    {
        uint32_t ccaps = cl_ctr_table_caps(cl), c_be = htonl(ccaps);
        lock_start_write(cl->peers->lock);
        cl->peers->cluster_caps = ccaps;
        lock_stop_write(cl->peers->lock);
        memcpy(p, &c_be, CL_CTR_CAPS_SZ);
        p += CL_CTR_CAPS_SZ;
    }
    /* and which nodes are CONNECTING (cl_ctr_admission.c) */
    cl_ctr_build_conn_bitmap(cl, (unsigned char *)p);
    p += CL_CTR_ALIVE_BITMAP_SZ;
    *p = (char)(cl->master_unconfirmed ? 1 : 0);

    cl_ctr_seal_and_send(sock, cl, pkt,
                     CL_CTR_PLAIN_HDR_SZ + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ
                     + CL_CTR_TERM_SZ + CL_CTR_ALIVE_BITMAP_SZ + CL_CTR_LIVE_SZ
                     + CL_CTR_ALIVE_BITMAP_SZ + CL_CTR_CAPS_SZ + CL_CTR_ALIVE_BITMAP_SZ
                     + CL_CTR_UNRAISED_SZ,
                     cl->session_key, CL_CTR_PKT_MASTER_ALIVE);
}

/* member -> master: our view differs from your digest, resend (ours rides
 * along for its logs); rate-limited by the caller */
void cl_ctr_send_resync(int sock, cl_ctr_cluster_t *cl,
                           const struct sockaddr *dest, socklen_t destlen)
{
    char     pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_DIGEST_SZ
                 + CL_CTR_TAG_SZ];
    uint32_t seq = htonl(++cl->peers->my_seq);
    uint16_t cnt;
    uint64_t hash;
    char    *p;
    int      k;

    cl_ctr_membership_digest(cl, &cnt, &hash);
    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_RESYNC;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;
    *p++ = (char)(cnt >> 8); *p++ = (char)cnt;
    for (k = 0; k < 8; k++) *p++ = (char)(hash >> (56 - 8 * k));

    cl_ctr_seal_and_send_to(sock, cl, pkt, CL_CTR_PLAIN_HDR_SZ + CL_CTR_DIGEST_SZ,
                        cl->session_key, CL_CTR_PKT_RESYNC, dest, destlen);
}

/* MAINT_SET [node_id 2B BE][state 1B]: sent 3x - idempotent, and a lost copy
 * would silently undo an operator's request; worker only */
int cl_ctr_send_maint_set(cl_ctr_cluster_t *cl, uint16_t node_id, int st)
{
    char     pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + 3 + CL_CTR_TAG_SZ];
    uint16_t nid_be = htons(node_id);
    int      k, rc = 0;

    for (k = 0; k < 3; k++) {
        uint32_t seq = htonl(++cl->peers->my_seq);
        memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
        pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_MAINT_SET;
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, &nid_be, 2);
        pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + 2] = (char)st;
        if (cl_ctr_seal_and_send(cl->sock, cl, pkt, CL_CTR_PLAIN_HDR_SZ + 3,
                                 cl->session_key, CL_CTR_PKT_MAINT_SET) < 0)
            rc = -1;
    }
    return rc;
}

/* MASTER_PROBE: [master ip, NUL-terminated], multicast to the group - one
 * datagram asks every member at once. */
void cl_ctr_send_master_probe(cl_ctr_cluster_t *cl, const char *master_ip)
{
    char     pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1
                 + CL_CTR_TAG_SZ];
    uint32_t seq = htonl(++cl->peers->my_seq);
    int      l   = (int)strnlen(master_ip, CL_CTR_MAX_IP_LEN);

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_MASTER_PROBE;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, master_ip, l);
    pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + l] = '\0';
    cl_ctr_seal_and_send(cl->sock, cl, pkt, CL_CTR_PLAIN_HDR_SZ + l + 1,
                         cl->session_key, CL_CTR_PKT_MASTER_PROBE);
}

/* MASTER_PROBE_ACK: [master ip, NUL-terminated][ms since heard, 4B BE] */
void cl_ctr_send_master_probe_ack(cl_ctr_cluster_t *cl, const char *master_ip,
                                  uint32_t heard_ms_ago,
                                  const struct sockaddr *dest, socklen_t destlen)
{
    char     pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_MAX_IP_LEN + 1
                 + 4 + CL_CTR_TAG_SZ];
    uint32_t seq = htonl(++cl->peers->my_seq), ago = htonl(heard_ms_ago);
    int      l   = (int)strnlen(master_ip, CL_CTR_MAX_IP_LEN);
    char    *p   = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_MASTER_PROBE_ACK;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    memcpy(p, master_ip, l);
    p[l] = '\0';
    memcpy(p + l + 1, &ago, 4);
    cl_ctr_seal_and_send_to(cl->sock, cl, pkt, CL_CTR_PLAIN_HDR_SZ + l + 1 + 4,
                            cl->session_key, CL_CTR_PKT_MASTER_PROBE_ACK,
                            dest, destlen);
}

/* bootstrap-keyed, unlike MASTER_ALIVE: masters with different session keys
 * (e.g. after a simultaneous cold start) can still read it and merge */
void cl_ctr_send_master_beacon(int sock, cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
                           + CL_CTR_BEACON_SZ + CL_CTR_LIVE_SZ + CL_CTR_UNRAISED_SZ
                           + CL_CTR_TAG_SZ];
    uint32_t           seq   = htonl(++cl->peers->my_seq);
    uint32_t           term_be = htonl(cl->peers->my_term);
    uint16_t           cnt, cnt_be;
    uint64_t           hash;
    char              *p;

    /* The same count MASTER_ALIVE's digest carries, so both paths into
     * cl_ctr_master_outranks() compare like with like. */
    cl_ctr_membership_digest(cl, &cnt, &hash);
    cnt_be = htons(cnt);

    memcpy(pkt, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_MASTER_BEACON;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;
    memcpy(p, &cnt_be, 2);                    p += 2;
    memcpy(p, &term_be, CL_CTR_TERM_SZ);      p += CL_CTR_TERM_SZ;
    /* settings and MTU as JOIN_REQ carries them, so a master sees we would refuse
     * it BEFORE demoting itself (cl_ctr_handle_master_beacon) */
    {
        uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
        uint16_t m  = htons(cl_ctr_mtu_wire(cc_mtu));
        p[0] = (char)(cl->manage_shtags ? 1 : 0);
        p[1] = (char)(cl->master_stickiness ? 1 : 0);
        memcpy(p + 2, &qt, 2);                p += CL_CTR_CONFIG_SZ;
        memcpy(p, &m, CL_CTR_MTU_SZ);         p += CL_CTR_MTU_SZ;
    }
    /* the members this master hears now - ranked on before the table count */
    {
        uint16_t live_be = htons(cl_ctr_live_count(cl));
        memcpy(p, &live_be, CL_CTR_LIVE_SZ);  p += CL_CTR_LIVE_SZ;
    }
    *p++ = (char)(cl->master_unconfirmed ? 1 : 0);

    cl_ctr_seal_and_send(sock, cl, pkt,
                     (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ)), cl->key,
                     CL_CTR_PKT_MASTER_BEACON);
}

/* [target_ip NUL][Noise msg 2 carrying master_salt]; bootstrap-keyed since the
 * joiner has no session key yet; target_ip still carried for older peers */
void cl_ctr_send_key_grant(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                              const unsigned char *msg1, int msg1_len,
                              const struct sockaddr *dest, socklen_t destlen)
{
    char               pkt[CL_CTR_KEY_GRANT_SZ];
    uint32_t           seq_h   = ++cl->peers->my_seq;
    uint32_t           seq     = htonl(seq_h);
    unsigned char      msg2[32 + CL_CTR_MASTER_SALT_SZ + CL_CTR_TAG_SZ];
    char              *p;
    int                ip_len, plain_len, m2;

    m2 = cl_ctr_noise_respond(cl->key, msg1, (size_t)msg1_len,
                          cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ, msg2);
    if (m2 < 0) {
        LM_DBG("clusterer_controller: [cluster %d] Noise msg1 from %s did not "
               "verify - no KEY_GRANT sent\n", cl->cluster_id, target_ip);
        return;
    }

    ip_len = (int)strnlen(target_ip, CL_CTR_MAX_IP_LEN);

    memcpy(pkt, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_KEY_GRANT;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;

    memcpy(p, target_ip, ip_len); p[ip_len] = '\0'; p += ip_len + 1;
    memcpy(p, msg2, m2);                              p += m2;

    plain_len = (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ));
    if (cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, cl->key,
                            CL_CTR_PKT_KEY_GRANT, dest, destlen) == 0) {
        LM_INFO("clusterer_controller: [cluster %d] sent KEY_GRANT to %s (unicast)\n",
                cl->cluster_id, target_ip);
        /* Critical 1:1 packet - retransmit until the joiner ACKs it. */
        cl_ctr_retx_enqueue(cl, seq_h, CL_CTR_PKT_KEY_GRANT, (const unsigned char *)pkt,
                        CL_CTR_WIRE_HDR_SZ + plain_len + CL_CTR_TAG_SZ, dest, destlen);
    }
}

/* salt sealed to the next master's X25519 key (learned via ALIVE), so only it
 * can open it; the session-key envelope proves the sender is a member */
void cl_ctr_send_key_handoff(int sock, const char *next_master_ip,
                                const unsigned char *next_master_pubkey,
                                cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_KEY_HANDOFF_SZ];
    uint32_t           seq     = htonl(++cl->peers->my_seq);
    unsigned char      sealed[crypto_box_SEALBYTES + CL_CTR_MASTER_SALT_SZ];
    char              *p;
    int                ip_len, plain_len;

    if (crypto_box_seal(sealed, cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ,
                        next_master_pubkey) != 0) {
        LM_ERR("clusterer_controller: [cluster %d] crypto_box_seal failed\n",
               cl->cluster_id);
        return;
    }

    ip_len = (int)strnlen(next_master_ip, CL_CTR_MAX_IP_LEN);

    memcpy(pkt, CL_CTR_PACKET_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_KEY_HANDOFF;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    p = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;

    memcpy(p, next_master_ip, ip_len); p[ip_len] = '\0'; p += ip_len + 1;
    memcpy(p, sealed, sizeof(sealed));                   p += sizeof(sealed);

    plain_len = (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ));
    if (cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->session_key,
                         CL_CTR_PKT_KEY_HANDOFF) == 0)
        LM_INFO("clusterer_controller: [cluster %d] sent KEY_HANDOFF to %s\n",
                cl->cluster_id, next_master_ip);
}
