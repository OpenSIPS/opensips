/*
 * clusterer_controller - socket, wire format, replay windows and packet senders
 *
 * Copyright (C) 2026 Yury Kirsanov
 *                          VoIPLine Telecom
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
const unsigned char CL_CTR_PACKET_MAGIC[CL_CTR_MAGIC_SZ]    = { CL_CTR_WIRE_MAGIC0, 0x00 };
const unsigned char CL_CTR_BOOTSTRAP_MAGIC[CL_CTR_MAGIC_SZ] = { CL_CTR_WIRE_MAGIC0, 0x01 };
/* Consumer traffic carries its own magic.  It is encrypted with the same
 * session key as everything else - the distinction exists purely so the
 * rate limiter, which runs BEFORE decryption and therefore cannot see a
 * packet's type, can charge consumer data against its own budget instead
 * of the control plane's.  Without this, a consumer sending faster than
 * the control-plane limit is silently throttled, and control packets and
 * data compete for one allowance. */
const unsigned char CL_CTR_CONSUMER_MAGIC[CL_CTR_MAGIC_SZ]  = { CL_CTR_WIRE_MAGIC0, 0x02 };

/* Maximum consumer payload in bytes, derived from the interface MTU at
 * mod_init time.  Replaces the compile-time CLCTR_MAX_PAYLOAD constant so
 * jumbo-frame interfaces (MTU 9000) are not artificially limited to 1300 B.
 * Read-only after mod_init; safe to access from any process. */
int cc_max_payload = CLCTR_MAX_PAYLOAD;
/* This node's cluster-plane MTU as read from my_interface_buf at mod_init.
 * 0 only before mod_init has resolved it; after that it is always a real
 * kernel-reported value, because mod_init refuses to start otherwise. */
int cc_mtu = 0;
/* The interface's CURRENT MTU, refreshed by the drift poll.  Distinct from
 * cc_mtu on purpose, and the distinction is load-bearing:
 *
 *   cc_mtu     - what we joined at.  The cluster's MTU, and therefore the only
 *                thing admission and drift are judged against.  Never changes.
 *   cc_mtu_now - what the kernel says right now.  This is what we ADVERTISE.
 *
 * Advertising the joined-at value instead would make the peer-drift warning
 * unreachable: a node whose link changed would keep announcing the old number,
 * so no peer could ever observe the change.  Announcing the live reading means
 * a healthy peer sees the drift on the next ALIVE - which matters, because the
 * drifting node is about to remove itself and its own log is the one least
 * likely to be watched. */
int cc_mtu_now = 0;
/* Consecutive polls that disagreed with cc_mtu (see CL_CTR_MTU_DRIFT_STRIKES). */
int cc_mtu_drift_strikes = 0;
/* Consecutive polls that could not read the MTU at all.  Tracked separately
 * from the drift strikes because a failed read is not evidence of anything -
 * see cl_ctr_mtu_step(). */
int cc_mtu_read_fails = 0;

/**
 * cl_ctr_read_iface_mtu() - current MTU of the interface we run the plane on.
 *
 * Returns the kernel's value, or -1 if it cannot be read.  This is the ONLY
 * source of MTU truth in the module; there is no configured alternative to
 * fall back to, by design.
 */
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

/**
 * cl_ctr_mtu_step() - decide what one MTU reading means.
 *
 * Split out of the timer callback so the decision can be exercised directly:
 * the interesting sequences (a failed read landing in the middle of a drift, a
 * transient that recovers, a drift that persists) are awkward to produce
 * against a real interface and trivial to enumerate here.
 *
 * THE FAILED READ IS THE WHOLE POINT.  It used to fall into the same branch as
 * "the link is fine again", which did two wrong things at once: it cleared the
 * strike count, so an ioctl failing at roughly the confirmation cadence could
 * hold a genuinely drifted node alive indefinitely; and it logged that the MTU
 * was "back to" a value it had never read - a measurement that did not happen,
 * which is the one kind of log line worse than no log line at all.
 *
 * A failed read is neither drift nor recovery.  It is an absence of evidence,
 * so it leaves the strike count exactly where it was.
 */
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

/**
 * cl_ctr_check_and_update_seq() - accept each sequence number exactly once.
 * Looks up sender_ip in the peer table and runs @pkt_seq through that peer's
 * replay window for the requested plane.  Unknown senders (new nodes not yet
 * in the peer table) are accepted so their first packet (ALIVE/JOIN_REQ) can
 * populate the table.
 * Only called for CL_CTR_PACKET_MAGIC packets; bootstrap packets use join_nonce.
 * Single-threaded caller (cl_ctr_worker reactor); no lock needed for the check.
 * @return CL_CTR_SEQ_OK to accept, CL_CTR_SEQ_DUP / CL_CTR_SEQ_OLD to drop.
 */
int cl_ctr_check_and_update_seq(const char *sender_ip, uint32_t pkt_seq,
                                   uint64_t pkt_inc, cl_ctr_cluster_t *cl,
                                   int is_consumer)
{
    const char *why;
    int i, rc;
    for (i = 0; i < cl->peers->count; i++) {
        if (strcmp(cl->peers->entries[i].ip, sender_ip) == 0) {
            cl_ctr_peer_t   *e = &cl->peers->entries[i];
            cl_ctr_replay_t *r = is_consumer ? &e->replay_consumer : &e->replay;

            /* A window is only meaningful within one incarnation of its
             * sender.  A higher one means the peer restarted and numbers
             * from 1 again: start its windows afresh, here, on the first
             * packet of the new life - no broadcast has to reach us first.
             * A lower one is a packet from a previous life: a replay. */
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
                cl_ctr_replay_reset(&e->replay_consumer);
            }

            rc = cl_ctr_replay_check(r, pkt_seq);
            if (rc == CL_CTR_SEQ_OK)
                return rc;

            /* Debug for consumer traffic, warning for the control plane.  A
             * consumer sending at rate will duplicate on any path that retries,
             * and a warning per copy says "attack" about something entirely
             * ordinary.  Reordering no longer reaches here at all - the window
             * accepts it - so what is left really is a repeat or something
             * older than the window can vouch for. */
            why = rc == CL_CTR_SEQ_DUP  ? "already accepted"
                : rc == CL_CTR_SEQ_JUMP ? "implausibly far ahead - a wrapped "
                                          "replay, or this peer's traffic has "
                                          "been lost wholesale"
                                        : "older than the replay window";
            if (is_consumer)
                LM_DBG("clusterer_controller: consumer packet from %s seq=%u "
                       "last=%u %s, dropping\n", sender_ip, pkt_seq, r->last,
                       why);
            else
                LM_WARN("clusterer_controller: packet from %s seq=%u last=%u "
                        "%s, dropping\n", sender_ip, pkt_seq, r->last, why);
            return rc;
        }
    }
    return CL_CTR_SEQ_OK;   /* unknown sender: accept, handler will upsert into peer table */
}

/* =========================================================================
 * Socket setup
 * ========================================================================= */

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

    /* Expand the kernel receive buffer so it can hold a fully reassembled
     * MEMBER_LIST datagram (up to ~4 KB with 256 peers) even when IP
     * fragmentation is in play on a low-MTU link such as PPP at 128 bytes. */
    {
	int rcvbuf = 1 << 20;   /* request 1 MB; kernel may cap lower */
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
	               &rcvbuf, sizeof(rcvbuf)) < 0)
	    LM_WARN("clusterer_controller: SO_RCVBUF: %s\n", strerror(errno));
    }

    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_port        = htons((uint16_t)cl->multicast_port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    /* Is somebody else already on this ip:port?
     *
     * We bind INADDR_ANY:multicast_port with SO_REUSEADDR because that is what
     * multicast reception needs, and it is also what lets a SECOND process take
     * the same port without any error.  That second process is not harmless:
     * the kernel fans multicast out to every co-bound socket, but delivers a
     * UNICAST datagram to exactly ONE of them, chosen without reference to the
     * destination address.  Every 1:1 leg of the protocol - KEY_GRANT during
     * the join, consumer replies, ACKs - can therefore land in the wrong
     * process.  The symptom is deeply misleading: the joiner never sees its
     * KEY_GRANT and dies with "cannot authenticate ... wrong password", sending
     * the operator after a credential problem that does not exist.
     *
     * Detect it by probing the port WITHOUT SO_REUSEADDR: that bind fails with
     * EADDRINUSE precisely when someone already holds it, and succeeds when the
     * port is free.  (A probe WITH SO_REUSEADDR would succeed either way, which
     * is why the real bind below cannot tell the difference.)
     *
     * Advisory only - never fatal.  A restart can briefly race the outgoing
     * process, and one spurious warning is a far smaller cost than refusing to
     * start.  cl_ctr_maybe_forward() still recovers the in-process case, where
     * several clusters in THIS process share a port. */
    {
	int probe = socket(AF_INET, SOCK_DGRAM, 0);

	if (probe >= 0) {
	    if (bind(probe, (struct sockaddr *)&local, sizeof(local)) < 0 &&
	        errno == EADDRINUSE)
		LM_WARN("clusterer_controller: [cluster %d] another process is "
			"already bound to port %d - multicast will reach both, "
			"but every unicast leg (KEY_GRANT, consumer replies) "
			"goes to only ONE of them, chosen by the kernel and not "
			"by address.  A node that cannot join, or a consumer "
			"that never gets replies, is explained by this and not "
			"by a bad password.  One controller instance per host "
			"per port is what is supported.\n",
			cl->cluster_id, cl->multicast_port);
	    close(probe);
	}
    }

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
	LM_ERR("clusterer_controller: bind() port %d: %s\n",
	       cl->multicast_port, strerror(errno));
	close(sock);
	return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(cl->multicast_address);
    /* Bind the join to our OWN resolved interface (my_ip, set by
     * cl_ctr_resolve_local_identity() before this runs), not
     * INADDR_ANY. INADDR_ANY leaves the actual interface choice to
     * the kernel's default-route selection, which is NOT necessarily
     * the interface this cluster was configured for - on a host whose
     * default route goes out a different (e.g. external-facing)
     * interface than the one named by the "interface" modparam, the
     * join silently lands on the wrong interface: setsockopt still
     * succeeds (no error logged), but peers on the intended interface
     * never see it, so every node times out waiting for a master that
     * was never reachable and self-elects instead. Found live: two
     * production nodes each joined on their external interface
     * (matching their default route) instead of the internal one the
     * cluster was actually meant to run on, and neither ever saw the
     * other. The send side already pins to my_ip a few lines below
     * (local_if.s_addr = inet_addr(my_ip)) - this makes the join side
     * consistent with it. */
    mreq.imr_interface.s_addr = inet_addr(my_ip);

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
	LM_ERR("clusterer_controller: IP_ADD_MEMBERSHIP (%s): %s\n",
	       cl->multicast_address, strerror(errno));
	close(sock);
	return -1;
    }

#ifdef IP_MULTICAST_ALL
    /* Receive only the group THIS socket joined.  Linux defaults
     * IP_MULTICAST_ALL to 1, which delivers to a socket bound to
     * INADDR_ANY:port every group joined on that port by ANY socket on the
     * host.  Two clusters sharing a port on different groups then each read
     * the other's multicast: every packet is rejected on its cluster_id,
     * forwarded to the sibling by cl_ctr_maybe_forward(), and arrives there a
     * second time - the copy fails the replay check and logs a warning per
     * keepalive - while the foreign traffic is charged to this cluster's rate
     * table.  Unicast is still demultiplexed by port alone; that case is what
     * the forwarder is for. */
    {
	int mc_all = 0;
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_ALL,
	               &mc_all, sizeof(mc_all)) < 0)
	    LM_WARN("clusterer_controller: [cluster %d] IP_MULTICAST_ALL: %s - "
	            "this socket may also receive other groups joined on port %d\n",
	            cl->cluster_id, strerror(errno), cl->multicast_port);
    }
#endif

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &loop, sizeof(loop)) < 0)
	LM_WARN("clusterer_controller: IP_MULTICAST_LOOP: %s\n",
	        strerror(errno));

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   &ttl, sizeof(ttl)) < 0)
	LM_WARN("clusterer_controller: IP_MULTICAST_TTL: %s\n",
	        strerror(errno));

    /* Pin the sending interface to my_ip so that loopback packets carry
     * my_ip as source address - this makes self-loopback detection in
     * cl_ctr_handle_member_list() reliable on multi-homed hosts.           */
    {
	struct in_addr local_if;
	local_if.s_addr = inet_addr(my_ip);
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
	               &local_if, sizeof(local_if)) < 0)
	    LM_WARN("clusterer_controller: [cluster %d] IP_MULTICAST_IF: %s\n",
	        cl->cluster_id,
	            strerror(errno));
    }

    /* Bind socket to the resolved interface by name for stricter routing.
     * This is more reliable than IP_MULTICAST_IF alone on multi-homed hosts
     * because it works at the socket level regardless of routing tables.   */
    if (my_interface_buf[0] != '\0') {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, my_interface_buf,
	       strnlen(my_interface_buf, IF_NAMESIZE - 1));
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
	               &ifr, sizeof(ifr)) < 0)
	    /* Requires CAP_NET_RAW - not available after privilege drop.
	     * IP_MULTICAST_IF (set above) already pins the interface by
	     * IP, so this is belt-and-suspenders only; failure is safe.  */
	    LM_DBG("clusterer_controller: SO_BINDTODEVICE (%s): %s "
	           "(non-fatal, IP_MULTICAST_IF covers this)\n",
	           my_interface_buf, strerror(errno));
    }

    LM_INFO("clusterer_controller: [cluster %d] socket ready, joined %s:%d\n",
            cl->cluster_id, cl->multicast_address, cl->multicast_port);

    /* cl->mcast_dest was resolved in mod_init (main process) and inherited
     * across fork; no need to rebuild it here. */

    /* Set non-blocking so sendto() never hangs the worker if the kernel
     * UDP send buffer fills up.  recvfrom() already relies on select()
     * for readiness, so O_NONBLOCK is safe and consistent for both.    */
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0) {
	LM_WARN("clusterer_controller: fcntl O_NONBLOCK: %s\n",
	        strerror(errno));
	/* non-fatal - we continue; send paths handle EAGAIN explicitly */
    }

    return sock;
}

/* =========================================================================
 * Packet senders
 * ========================================================================= */

/**
 * cl_ctr_seal_and_send_to() - encrypt a prepared packet in place and send it to
 * an explicit destination.
 *
 * On entry @pkt holds the cleartext framing (magic already stamped) plus the
 * @plain_len-byte plaintext starting at CL_CTR_WIRE_HDR_SZ; cl_ctr_encrypt_pkt() fills
 * the cluster_id + nonce and appends the AEAD tag.  @dest/@destlen is the target
 * sockaddr: the cluster's multicast group for group packets (see the
 * cl_ctr_seal_and_send() wrapper), or a single peer for the strictly 1:1 packets
 * of the join handshake (e.g. KEY_GRANT), which every other member would
 * otherwise decrypt only to discard.  @dest is passed straight to sendto(), so
 * its address family is whatever the caller supplies - v4 today, v6-ready.
 * @type is only used for logging.
 *
 * @return 0 on success, -1 on encrypt or send failure.
 */
int cl_ctr_seal_and_send_to(int sock, cl_ctr_cluster_t *cl, char *pkt,
                               int plain_len, const unsigned char *key,
                               unsigned char type,
                               const struct sockaddr *dest, socklen_t destlen)
{
    int total_len;

    /* Always unicast to @dest as the caller asked.  When several local clusters
     * share a multicast port a unicast reply may be delivered by the kernel to
     * the wrong sibling's socket (unicast is demuxed by port alone); the
     * receiver recovers it by cluster_id in cl_ctr_maybe_forward(), so we no
     * longer fall back to the multicast group here. */
    /* A JOIN_REQ carries no cluster id: it asks to be admitted on its key,
     * and a node merging into another cluster's master must not be refused
     * at the door for the id of the partition it is leaving. */
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

/**
 * cl_ctr_seal_and_send() - multicast wrapper over cl_ctr_seal_and_send_to().
 *
 * Sends to the cluster's multicast group (cached in cl->mcast_dest); used by
 * every group packet (ALIVE, MASTER_ALIVE, MEMBER_LIST, NODE_ASSIGN, ...).
 */
int cl_ctr_seal_and_send(int sock, cl_ctr_cluster_t *cl, char *pkt, int plain_len,
                            const unsigned char *key, unsigned char type)
{
    return cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, key, type,
                               (const struct sockaddr *)&cl->mcast_dest,
                               sizeof(cl->mcast_dest));
}

/*
 * Send an ACK for @acked_seq back to @dest.  Sealed in the same key class as the
 * packet being acknowledged (@use_bootstrap: KEY_GRANT is bootstrap-keyed), so
 * the sender can read it without assuming the receiver already holds a key.
 */
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

/**
 * cl_ctr_send_pkt_with_ip() - build and multicast a small (ALIVE/GOODBYE) packet.
 * JOIN_REQ is handled by cl_ctr_send_join_req_pkt() which carries BIN socket info.
 *
 * ALIVE: [type 1B][seq 4B][ip NUL][pubkey 32B]   - peers learn our pubkey here
 * GOODBYE: [type 1B][seq 4B][ip NUL]              - no pubkey needed
 */
void cl_ctr_send_pkt_with_ip(int sock, unsigned char type, cl_ctr_cluster_t *cl,
                                const struct sockaddr *dest, socklen_t destlen)
{
    /* Sized for ALIVE which carries an extra pubkey + config descriptor + MTU */
    char               pkt[CL_CTR_SMALL_PKT_SZ + CL_CTR_PUBKEY_SZ
                           + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ];
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

    /* ALIVE appends our X25519 public key so peers accumulate pubkeys
     * without bloating MEMBER_LIST (avoids excessive IP fragmentation). */
    if (type == CL_CTR_PKT_ALIVE) {
	memcpy(pkt + CL_CTR_WIRE_HDR_SZ + plain_len, cl->my_pubkey, CL_CTR_PUBKEY_SZ);
	plain_len += CL_CTR_PUBKEY_SZ;
	/* Advertise our effective consistency-critical config so peers can
	 * detect accidental per-node config drift for the same cluster. */
	{
	    char    *c  = pkt + CL_CTR_WIRE_HDR_SZ + plain_len;
	    uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
	    c[0] = (char)(cl->manage_shtags ? 1 : 0);
	    c[1] = (char)(cl->master_stickiness ? 1 : 0);
	    memcpy(c + 2, &qt, 2);
	    plain_len += CL_CTR_CONFIG_SZ;
	}
	/* And the MTU of the link this plane runs on, so peers can notice that
	 * one of them has drifted.  Separate from the config block above
	 * because it is detected, not configured - see CL_CTR_MTU_SZ. */
	{
	    uint16_t m = htons(cl_ctr_mtu_wire(cc_mtu_now));
	    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + plain_len, &m, CL_CTR_MTU_SZ);
	    plain_len += CL_CTR_MTU_SZ;
	}
    }

    if (dest)
        cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, cl->session_key, type,
                            dest, destlen);
    else
        cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->session_key, type);
}

/**
 * cl_ctr_send_list_pkt() - encrypt and multicast the active peer table.
 *
 * Wire: [magic 2B][cluster_id 2B][nonce 24B][XChaCha20-Poly1305([type 1B][seq 4B][count 2B][entries...])][tag 16B]
 */
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
    /* nonce at [8..19] written by cl_ctr_encrypt_pkt */

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
	/* Entry layout: [ip 16B null-padded][is_master 1B] = 17B */
	memset(p, 0, CL_CTR_IP_ENTRY_SZ);
	memcpy(p, e->ip, strnlen(e->ip, CL_CTR_MAX_IP_LEN));
	p[CL_CTR_IP_ENTRY_SZ - 1] = (char)(e->is_master ? 1 : 0);
	p += CL_CTR_IP_ENTRY_SZ;
	count++;
    }

    lock_stop_read(cl->peers->lock);

    count_be = htons(count);
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, &count_be, CL_CTR_LIST_COUNT_SZ);

    /* stamp: this mastership's term and the list's own sequence, so a
     * receiver can tell an old list arriving late from a new one */
    {
	uint32_t t_be = htonl(cl->peers->my_term);
	uint32_t s_be = htonl(++cl->peers->list_seq);
	memcpy(p, &t_be, 4);  p += 4;
	memcpy(p, &s_be, 4);  p += 4;
    }

    plain_len = CL_CTR_PLAIN_HDR_SZ + CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ
                + count * CL_CTR_IP_ENTRY_SZ + CL_CTR_LIST_STAMP_SZ;
    if ((dest ? cl_ctr_seal_and_send_to(sock, cl, pkt, plain_len, cl->session_key,
                                    type, dest, destlen)
              : cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->session_key, type)) == 0)
	LM_INFO("clusterer_controller: [cluster %d] sent MEMBER_LIST (%d members)%s\n",
	        cl->cluster_id, count, dest ? " (unicast)" : "");
}

/**
 * cl_ctr_send_join_req_pkt() - send CL_CTR_PKT_JOIN_REQ with BIN socket info.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 */
void cl_ctr_send_join_req_pkt(int sock, cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_JOIN_PKT_MAX_SZ];
    uint32_t           seq;

    /* Rate-limit JOIN_REQ transmissions.  During a key-mismatch / split-brain
     * heal several code paths (defer timer, session-mismatch re-key, rejoin
     * timer) can each ask to (re)send a JOIN_REQ within the same second.  A
     * JOIN_REQ is idempotent - the master answers whichever one arrives - so
     * drop any that lands within CL_CTR_JOIN_REQ_MIN_US of the previous send; the
     * next timer tick resends if the join is still pending.  The very first
     * send (last_join_req_utime == 0) is never throttled.                     */
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

    memcpy(pkt, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ);  /* JOIN_REQ uses bootstrap key */

    /* Plaintext: [type][seq][ip NUL][bin_count][sock1 NUL]...[sockN NUL][pubkey 32B] */
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

    /* Noise msg 1 (-> psk, e): a fresh ephemeral public key plus an empty
     * authenticated payload, PSK = the Argon2id bootstrap key (cl->key).  Keep
     * the initiator handshake state so we can read the master's KEY_GRANT
     * (msg 2).  A later JOIN_REQ overwrites it, so a stale KEY_GRANT just fails
     * to decrypt and is dropped. */
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

    /* Advertise the MTU of our cluster link.  The master admits only nodes
     * whose MTU equals its own, which is what keeps the whole cluster uniform:
     * every member matched at this point, so the backup that eventually
     * becomes master necessarily carries the same value and a handover cannot
     * change it. */
    {
	uint16_t m = htons(cl_ctr_mtu_wire(cc_mtu_now));
	memcpy(p, &m, CL_CTR_MTU_SZ);
	p += CL_CTR_MTU_SZ;
    }

    plain_len = (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ));
    if (cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->key, CL_CTR_PKT_JOIN_REQ) == 0)
	LM_DBG("clusterer_controller: [cluster %d] sent JOIN_REQ bin=%s\n",
	       cl->cluster_id, cl->bin_socket);
}

/**
 * cl_ctr_send_node_assign() - send CL_CTR_PKT_NODE_ASSIGN to multicast.
 *
 * Payload: [node_id 2B BE][ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * Sent by master after allocating a node_id.  All cluster members receive
 * it and update their peer tables accordingly.
 */
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

    /* node_id (2B BE) */
    memcpy(p, &nid_be, CL_CTR_NODE_ID_SZ);
    p += CL_CTR_NODE_ID_SZ;

    /* IP NUL */
    memcpy(p, ip, ip_len);
    p[ip_len] = '\0';
    p += ip_len + 1;

    /* BIN sockets */
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
    /* NODE_ASSIGN carries the CL_CTR_PACKET_MAGIC session magic, so the receiver
     * decrypts it with session_key.  It MUST therefore be encrypted with
     * session_key, not the bootstrap key - otherwise every NODE_ASSIGN fails
     * AEAD auth on receipt ("session key mismatch"), driving a JOIN_REQ storm.
     * KEY_GRANT is sent before NODE_ASSIGN so the joiner already holds the
     * session key by the time this arrives. */
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

/**
 * cl_ctr_send_master_alive() - master-only keepalive.  Encrypted with session_key
 * (CL_CTR_PACKET_MAGIC).  Carries the membership digest ([count 2B][hash 8B]) so
 * members can detect a missed NODE_ASSIGN and pull a RESYNC.
 */
void cl_ctr_send_master_alive(int sock, cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
                           + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_TERM_SZ + CL_CTR_TAG_SZ];
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

    cl_ctr_seal_and_send(sock, cl, pkt,
                     CL_CTR_PLAIN_HDR_SZ + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ
                     + CL_CTR_TERM_SZ,
                     cl->session_key, CL_CTR_PKT_MASTER_ALIVE);
}

/*
 * cl_ctr_send_resync() - member -> master (unicast, session-keyed): "my membership
 * view differs from your digest, please resend".  Carries our own digest for
 * the master's logs.  Best-effort and rate-limited by the caller.
 */
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

/**
 * cl_ctr_send_master_beacon() - master-only split-brain merge announcement.
 *
 * Encrypted with the BOOTSTRAP key (CL_CTR_BOOTSTRAP_MAGIC) - unlike MASTER_ALIVE,
 * which uses the per-cluster session key.  Every correctly-configured node
 * shares the bootstrap key, so two masters that hold *different* session keys
 * (e.g. after an all-node simultaneous cold start) can still read each other's
 * beacon and reconcile.  Payload is this partition's member count (2B BE); the
 * sender IP comes from the datagram source.  See cl_ctr_handle_master_beacon().
 */
void cl_ctr_send_master_beacon(int sock, cl_ctr_cluster_t *cl)
{
    char               pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
                           + CL_CTR_BEACON_SZ + CL_CTR_TAG_SZ];
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
    /* Our settings and MTU, encoded as JOIN_REQ carries them, so a master
     * that would otherwise merge into us can see BEFORE demoting itself that
     * we would refuse it - see cl_ctr_handle_master_beacon(). */
    {
        uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
        uint16_t m  = htons(cl_ctr_mtu_wire(cc_mtu));
        p[0] = (char)(cl->manage_shtags ? 1 : 0);
        p[1] = (char)(cl->master_stickiness ? 1 : 0);
        memcpy(p + 2, &qt, 2);                p += CL_CTR_CONFIG_SZ;
        memcpy(p, &m, CL_CTR_MTU_SZ);         p += CL_CTR_MTU_SZ;
    }

    cl_ctr_seal_and_send(sock, cl, pkt,
                     (int)(p - (pkt + CL_CTR_WIRE_HDR_SZ)), cl->key,
                     CL_CTR_PKT_MASTER_BEACON);
}

/**
 * cl_ctr_send_key_grant() - send ECDH-wrapped master_salt to a joining node.
 * Encrypted with bootstrap key (CL_CTR_BOOTSTRAP_MAGIC) so the joining node can
 * read it before having the session key.  Unicast to the joiner (@dest, its
 * JOIN_REQ datagram source): it is strictly 1:1, so multicasting it only made
 * every other member spend an AEAD decrypt to discard a KEY_GRANT not addressed
 * to it.  The wire format is unchanged (target_ip still carried), so this
 * interoperates with peers that still multicast it.
 *
 * Runs the Noise responder over the joiner's msg 1 and answers with msg 2,
 * whose AEAD payload is the master_salt.  The Noise handshake authenticates the
 * exchange (PSK = bootstrap key) and binds it to the joiner's ephemeral, so a
 * stale KEY_GRANT for a superseded JOIN_REQ fails on the joiner's side.
 *
 * Payload: [target_ip NUL][noise_msg2 64B]
 */
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

/**
 * cl_ctr_send_key_handoff() - send master_salt to the next master before departing.
 * Outer envelope is the session key (CL_CTR_PACKET_MAGIC); the salt itself is sealed
 * to the next master's long-lived X25519 key (learned via ALIVE) with an
 * anonymous crypto_box - only that node can open it.  Sender authenticity comes
 * from the session-key envelope (only cluster members can send it).
 *
 * Payload: [next_master_ip NUL][sealed_box 64B]
 */
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
