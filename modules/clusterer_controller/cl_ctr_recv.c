/*
 * clusterer_controller - receive dispatcher, rate limiting and forwarding
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

static void cl_ctr_maybe_forward(const char *buf, int n,
                             const struct sockaddr_in *src, uint16_t pkt_cid,
                             cl_ctr_cluster_t *from);
static void cl_ctr_rpc_forward(int sender, void *param);

/* =========================================================================
 * Receive dispatcher
 * ========================================================================= */

/**
 * cl_ctr_rate_check() - per-source-IP rate limiter, called before decryption.
 * Finds or creates a 1-second sliding-window counter for src_ip.
 * @return 0 if within CL_CTR_RATE_LIMIT packets/s, -1 to drop.
 */
/**
 * cl_ctr_consumer_src_known() - is this address one of our cluster members?
 *
 * Consumer traffic only ever passes between nodes that have already joined:
 * a module registers a channel and talks to its peers, and nothing legitimate
 * sends consumer packets before it is a member.  Control traffic is different
 * - a JOIN_REQ necessarily comes from a stranger - so this filter is applied
 * to consumer packets only.
 *
 * It runs before the rate limiter and therefore before any crypto, which is
 * the point: a flood from an address we have never heard of costs one scan of
 * a table bounded by the cluster size, and does not reach the AEAD, does not
 * consume a rate-table slot, and cannot evict a real peer's counter from it.
 * Our own address passes, because multicast comes back to its sender.
 *
 * A spoofed source that copies a member's address still gets through - this
 * filter cannot fix address spoofing, and does not claim to.  What it removes
 * is the much easier attack of pointing a flood at the port from anywhere.
 */
static int cl_ctr_consumer_src_known(cl_ctr_cluster_t *cl, uint32_t src_ip)
{
    static uint32_t mine;        /* my_ip in host order, resolved once */
    uint32_t        src_num = ntohl(src_ip);   /* peers keep host order */
    int             i, known = 0;

    if (!mine && my_ip)
	mine = ip_to_num(my_ip);
    if (src_num == mine)
	return 1;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++)
	if (cl->peers->entries[i].ip_num == src_num) {
	    known = 1;
	    break;
	}
    lock_stop_read(cl->peers->lock);

    return known;
}

static int cl_ctr_rate_check(cl_ctr_cluster_t *cl, uint32_t src_ip,
                             int is_consumer)
{
    time_t            now     = cl_ctr_now();
    cl_ctr_rate_entry_t  *oldest  = NULL;
    int               limit   = is_consumer ? cl->consumer_rate
                                            : CL_CTR_RATE_LIMIT;
    int               i;

    /* Just woken from a stall: the kernel queued everything sent to this
     * node meanwhile, and it all arrives now - a master's keepalives, its
     * assignments, a peer's ALIVEs.  That burst is not a flood; limited, it
     * would drop the very keepalives the node needs to follow the master. */
    if (!is_consumer && cl->rate_grace_until_ms &&
            cl_ctr_now_ms() < cl->rate_grace_until_ms)
        return 0;

    for (i = 0; i < CL_CTR_RATE_TBL_SZ; i++) {
        cl_ctr_rate_entry_t *e = &cl->rate_tbl[i];
        int *cnt;

        if (e->ip == 0) {
            if (!oldest) oldest = e;             /* prefer empty slot  */
            continue;
        }
        if (e->ip == src_ip) {
            cnt = is_consumer ? &e->consumer_count : &e->count;
            if (now > e->window_start) {         /* new second         */
                e->window_start   = now;
                e->count          = 0;
                e->consumer_count = 0;
                *cnt              = 1;
                return 0;
            }
            if (++(*cnt) > limit) {
                /* Say so, once per window per source: a silent drop here
                 * looks exactly like packet loss to whatever was sending,
                 * which is a miserable thing to debug. */
                if (*cnt == limit + 1)
                    LM_WARN("clusterer_controller: [cluster %d] %s rate "
                        "limit of %d/s exceeded by a peer - dropping\n",
                        cl->cluster_id,
                        is_consumer ? "consumer" : "control", limit);
                return -1;
            }
            return 0;
        }
        /* track oldest entry for eviction when table is full */
        if (!oldest || e->window_start < oldest->window_start)
            oldest = e;
    }

    /* new source IP - claim oldest/empty slot */
    oldest->ip             = src_ip;
    oldest->window_start   = now;
    oldest->count          = 0;
    oldest->consumer_count = 0;
    if (is_consumer)
        oldest->consumer_count = 1;
    else
        oldest->count = 1;
    return 0;
}

/**
 * cl_ctr_recv_one() - read one datagram, validate header, dispatch by type.
 */
/* A datagram received on a shared ip:port for a sibling local cluster, handed
 * to that cluster's worker (still encrypted) by its cleartext cluster_id. */
struct cl_ctr_fwd_pkt {
    cl_ctr_cluster_t   *cl;      /* target cluster (owns the reply socket)  */
    struct sockaddr_in  src;     /* original datagram source                */
    int                 n;       /* length of buf                           */
    unsigned char       buf[1];  /* the encrypted packet (flexible array)   */
};

void cl_ctr_recv_one(int sock, cl_ctr_cluster_t *cl,
                        const char *fwd_buf, int fwd_n,
                        const struct sockaddr_in *fwd_src)
{
    /* Static buffer: avoids a 64 KB stack frame; safe because cl_ctr_recv_one
     * is called only from the single-threaded cl_ctr_worker process.         */
    static char        buf[CL_CTR_RECV_BUF_SZ];
    struct sockaddr_in src_addr;
    socklen_t          src_len = sizeof(src_addr);
    ssize_t            n;
    unsigned char      pkt_type;
    const char        *payload;
    int                payload_len;

    if (fwd_buf) {
	/* Forwarded from a sibling cluster's worker that received this on our
	 * shared ip:port (see cl_ctr_maybe_forward).  Process it exactly as if
	 * it had arrived on our own socket. */
	n = (fwd_n > (int)sizeof(buf) - 1) ? (int)sizeof(buf) - 1 : fwd_n;
	memcpy(buf, fwd_buf, (size_t)n);
	src_addr = *fwd_src;
	(void)src_len;
    } else {
	struct iovec   iov = { buf, sizeof(buf) - 1 };
	char           cbuf[CMSG_SPACE(sizeof(uint32_t))];
	struct msghdr  mh;
	struct cmsghdr *cm;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name       = &src_addr;
	mh.msg_namelen    = src_len;
	mh.msg_iov        = &iov;
	mh.msg_iovlen     = 1;
	mh.msg_control    = cbuf;
	mh.msg_controllen = sizeof(cbuf);
	n = recvmsg(sock, &mh, 0);
	if (n < 0) {
	    if (errno != EAGAIN && errno != EWOULDBLOCK)
		LM_ERR("clusterer_controller: recvmsg(): %s\n", strerror(errno));
	    return;
	}
	src_len = mh.msg_namelen;
	/* SO_RXQ_OVFL: the kernel's running count of datagrams it dropped for
	 * this socket because the receive buffer was full */
	for (cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
	    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_RXQ_OVFL) {
		uint32_t drops;
		memcpy(&drops, CMSG_DATA(cm), sizeof(drops));
		if (drops > cl->peers->rx_kernel_drops) {
		    time_t now = cl_ctr_now();
		    if (now - cl->peers->rx_drops_warned_at >= CL_CTR_WIRE_WARN_IVL) {
			cl->peers->rx_drops_warned_at = now;
			LM_WARN("clusterer_controller: [cluster %d] the kernel "
			        "dropped %lu cluster datagram(s) so far because "
			        "this socket's %d-byte receive buffer was full\n",
			        cl->cluster_id, (unsigned long)drops,
			        cl->peers->rcvbuf_bytes);
		    }
		    cl->peers->rx_kernel_drops = drops;
		}
	    }
	}
    }

    /* Minimum: wire header magic(2)+cluster_id(2)+uuid(16)+nonce(24), plaintext
     * header type(1)+seq(4)+incarnation(8), tag(16) = 73 bytes */
    if (n < CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_TAG_SZ) {
	LM_WARN("clusterer_controller: short packet (%zd bytes), dropping\n",
	        n);
	return;
    }

    if (memcmp(buf, CL_CTR_PACKET_MAGIC,   CL_CTR_MAGIC_SZ) != 0 &&
        memcmp(buf, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ) != 0 &&
        memcmp(buf, CL_CTR_CONSUMER_MAGIC,  CL_CTR_MAGIC_SZ) != 0) {
	unsigned char m0 = (unsigned char)buf[0], m1 = (unsigned char)buf[1];

	/* Another build of this module on another wire version: refuse it
	 * here, before it reaches any key or handler, and say so - a node on
	 * the wrong version otherwise just never joins, with nothing in the
	 * log on either side to explain why. */
	if (m0 > CL_CTR_MAGIC_BASE && m0 <= CL_CTR_MAGIC_BASE + 0x0F &&
	    m1 <= CL_CTR_MAGIC_TIER_MAX) {
	    char ip[INET_ADDRSTRLEN];
	    time_t now = cl_ctr_now();

	    cl->wire_refused_pkts++;
	    if (cl->wire_warned_at == 0 ||
	        now - cl->wire_warned_at >= CL_CTR_WIRE_WARN_IVL) {
		inet_ntop(AF_INET, &src_addr.sin_addr, ip, sizeof ip);
		LM_WARN("clusterer_controller: [cluster %d] %s speaks wire "
		        "version %d, this node speaks %d - refused (%lu packet(s) "
		        "from other versions so far). Every member of a cluster "
		        "must run the same clusterer_controller wire version; "
		        "upgrade the cluster as a whole.\n", cl->cluster_id, ip,
		        (int)(m0 - CL_CTR_MAGIC_BASE), CL_CTR_WIRE_VERSION,
		        cl->wire_refused_pkts);
		cl->wire_warned_at = now;
	    }
	    return;
	}
	LM_DBG("clusterer_controller: bad magic, dropping\n");
	return;
    }

    /* Cleartext cluster_id filter: silently ignore packets for a different
     * cluster sharing this multicast group.  Done BEFORE decryption so foreign
     * traffic never counts as an auth failure (auth_fail_pkts) - a wrong-cluster
     * packet is not a wrong-password attempt.                                */
    {
	uint16_t pkt_cid_be;
	memcpy(&pkt_cid_be, buf + CL_CTR_MAGIC_SZ, CL_CTR_CLUSTER_ID_SZ);
	if (ntohs(pkt_cid_be) != (uint16_t)cl->cluster_id) {
	    /* Not ours.  On a shared ip:port the kernel routes unicast by port
	     * alone, so it may have delivered a sibling local cluster's packet
	     * to us - hand it to that cluster's worker by its cleartext
	     * cluster_id (still encrypted; the sibling decrypts with its own
	     * key).  A packet we were already forwarded is never re-forwarded. */
	    if (!fwd_buf)
		cl_ctr_maybe_forward(buf, (int)n, &src_addr, ntohs(pkt_cid_be), cl);
	    else
		LM_DBG("clusterer_controller: [cluster %d] forwarded packet for "
		       "cluster %u is not ours, dropping\n", cl->cluster_id,
		       ntohs(pkt_cid_be));
	    return;
	}
    }

    /* Founded-identity filter: once our cluster's id is established, traffic
     * stamped with another cluster's id is refused here - before the rate
     * table and before any key is tried, so a foreign deployment sharing our
     * group, password and cluster_id is never merged with, and never counts
     * as an authentication failure.  Zeros come from a node that belongs to
     * no cluster yet (a joiner, a JOIN_REQ) and always pass. */
    {
	const unsigned char *pc = (const unsigned char *)buf + CL_CTR_CID_OFF;
	int st = cl->peers->cid_state;

	if ((st == CL_CTR_CID_ESTABLISHED || st == CL_CTR_CID_PINNED)
	        && !cl_ctr_cid_is_zero(pc)
	        && memcmp(pc, cl->peers->cid, CL_CTR_CID_SZ) != 0) {
	    time_t now = cl_ctr_now();
	    cl->peers->foreign_pkts++;
	    {
		/* which foreign cluster: remember it for cl_ctr_list_config */
		char ip[INET_ADDRSTRLEN];
		int  k, slot = -1, oldest = 0, is_new = 0;

		inet_ntop(AF_INET, &src_addr.sin_addr, ip, sizeof ip);
		lock_start_write(cl->peers->lock);
		for (k = 0; k < cl->peers->foreign_n; k++) {
		    if (memcmp(cl->peers->foreign[k].uuid, pc, CL_CTR_CID_SZ) == 0) {
			slot = k;
			break;
		    }
		    if (cl->peers->foreign[k].last_seen
		            < cl->peers->foreign[oldest].last_seen)
			oldest = k;
		}
		if (slot < 0) {
		    slot = cl->peers->foreign_n < CL_CTR_FOREIGN_MAX
		           ? cl->peers->foreign_n++ : oldest;
		    memset(&cl->peers->foreign[slot], 0,
		           sizeof(cl->peers->foreign[slot]));
		    memcpy(cl->peers->foreign[slot].uuid, pc, CL_CTR_CID_SZ);
		    cl->peers->foreign[slot].first_seen = now;
		    is_new = 1;
		}
		memcpy(cl->peers->foreign[slot].last_ip, ip, strlen(ip) + 1);
		cl->peers->foreign[slot].last_seen = now;
		cl->peers->foreign[slot].pkts++;
		if (is_new && (cl->peers->foreign_new_logged_at == 0
		        || now - cl->peers->foreign_new_logged_at
		           >= CL_CTR_WIRE_WARN_IVL)) {
		    char theirs[37];
		    cl->peers->foreign_new_logged_at = now;
		    cl_ctr_cid_str(pc, theirs);
		    LM_ERR("clusterer_controller: [cluster %d] another cluster "
		           "(uuid %s) is on this group, first heard from %s - "
		           "see foreign_clusters in cl_ctr_list_config\n",
		           cl->cluster_id, theirs, ip);
		}
		lock_stop_write(cl->peers->lock);
	    }
	    if (cl->foreign_warned_at == 0
	            || now - cl->foreign_warned_at >= CL_CTR_WIRE_WARN_IVL) {
		char ip[INET_ADDRSTRLEN], theirs[37], ours[37];
		inet_ntop(AF_INET, &src_addr.sin_addr, ip, sizeof ip);
		cl_ctr_cid_str(pc, theirs);
		cl_ctr_cid_str(cl->peers->cid, ours);
		LM_WARN("clusterer_controller: [cluster %d] %s belongs to another "
		        "cluster (uuid %s, ours %s) on the same group, password and "
		        "cluster_id - refused, never merged (%lu packet(s) so far). "
		        "Give the two deployments different cluster ids or groups.\n",
		        cl->cluster_id, ip, theirs, ours, cl->peers->foreign_pkts);
		cl->foreign_warned_at = now;
	    }
	    return;
	}
    }

    /* Rate-limit before any crypto work to shed floods cheaply.  Consumer
     * traffic from an address that is not a member is dropped one step
     * earlier still - it cannot be legitimate, and dropping it here keeps it
     * out of the rate table as well as out of the cipher. */
    {
	int is_consumer = (memcmp(buf, CL_CTR_CONSUMER_MAGIC,
	                          CL_CTR_MAGIC_SZ) == 0);

	if (is_consumer && !cl_ctr_consumer_src_known(cl,
	                       src_addr.sin_addr.s_addr)) {
	    if (cl->peers->count > 0)      /* quiet while still forming */
		LM_DBG("clusterer_controller: [cluster %d] consumer packet "
		       "from a non-member, dropping\n", cl->cluster_id);
	    return;
	}
	if (cl_ctr_rate_check(cl, src_addr.sin_addr.s_addr, is_consumer) < 0)
	    return;
    }

    /* Resolve sender IP once - used for HMAC warning and MEMBER_LIST dispatch */
    {
	char sender_ip_buf[INET_ADDRSTRLEN];
	const unsigned char *dec_key;
	inet_ntop(AF_INET, &src_addr.sin_addr,
	          sender_ip_buf, sizeof(sender_ip_buf));

	/* Select decryption key by magic:
	 *   CL_CTR_BOOTSTRAP_MAGIC -> bootstrap key (JOIN_REQ, KEY_GRANT)
	 *   CL_CTR_PACKET_MAGIC    -> session key   (all normal traffic)
	 * If session key decryption fails, schedule a re-JOIN to refresh it. */
	int is_bootstrap = (memcmp(buf, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ) == 0);
	uint32_t pkt_seq = 0;   /* needed again below, to acknowledge by seq */
	uint64_t pkt_inc = 0;   /* the sender's incarnation (CL_CTR_INC_SZ) */
	dec_key = is_bootstrap ? cl->key : cl->session_key;

	if (cl_ctr_decrypt_pkt(buf, n, sender_ip_buf, dec_key, is_bootstrap) < 0) {
	    int  _im, _new;
	    char _lm[CL_CTR_MAX_IP_LEN + 1];
	    lock_start_read(cl->peers->lock);
	    _im  = cl_ctr_i_am_master_locked(cl);
	    _new = (cl->peers->node_state == CL_CTR_NODE_NEW);
	    memcpy(_lm, cl->peers->last_master, sizeof(_lm));
	    lock_stop_read(cl->peers->lock);

	    /* A packet from another peer we cannot decrypt, seen while still
	     * joining, means a cluster (or rogue) whose key we do not share is
	     * present on this group.  We count it (any magic) as evidence that we
	     * may not belong here: session-key failures matter too, because a
	     * running cluster's steady traffic (MASTER_ALIVE/MEMBER_LIST) is
	     * session-encrypted, so a wrong-password joiner would otherwise see too
	     * little bootstrap traffic to notice the cluster and would self-promote
	     * into a split-brain lone master.  This is only *evidence*, never an
	     * immediate death sentence: cl_ctr_on_join_tfd defers and keeps re-joining,
	     * and a KEY_GRANT arriving in the grace window resets this counter, so a
	     * healthy node whose key is merely slow is not affected.  Our own
	     * loopback decrypts fine, so guard on my_ip. */
	    if (_new && strcmp(sender_ip_buf, my_ip) != 0)
		cl->auth_fail_pkts++;

	    if (is_bootstrap) {

		/* Master: track per-IP bootstrap failures; send JOIN_REJECT on limit.
		 * JOIN_REJECT is encrypted (BOOTSTRAP_MAGIC/AEAD) so only nodes with
		 * the correct password can read it.  Forgeries are impossible without
		 * the bootstrap key.                                                  */
		if (_im && cl_ctr_join_fail_check(sender_ip_buf, cl))
		    cl_ctr_send_join_reject(sock, sender_ip_buf, cl, CL_CTR_REJECT_GENERIC);

		/* Joiner fallback: count bootstrap decrypt failures during CL_CTR_NODE_NEW
		 * only when the packet came from the known master.  This filters out
		 * rogue nodes on the multicast group whose JOIN_REQs (encrypted with
		 * their own wrong key) would otherwise increment this counter and
		 * trigger a spurious exit on a legitimate joining node.
		 * If last_master is empty we have no master reference yet, so we
		 * conservatively skip counting - no master means no rejection.      */
		if (_new && _lm[0] != '\0' && strcmp(sender_ip_buf, _lm) == 0)
		    cl->bootstrap_auth_fails++;
	    }
	    if (!is_bootstrap && !cl->join_pending) {
		/* Session key mismatch: request a re-key ONLY when the packet we
		 * could not decrypt came from OUR current master (a legitimate key
		 * rotation).  Undecryptable session packets from any other source
		 * are rogue or stale traffic (e.g. a wrong-password node broadcasting
		 * on the group); reacting to them would drive an endless re-JOIN
		 * churn across the whole cluster.  Masters never re-JOIN.           */
		if (!_im && _lm[0] != '\0' && strcmp(sender_ip_buf, _lm) == 0) {
		    LM_INFO("clusterer_controller: [cluster %d] session key mismatch "
		            "from master %s - sending JOIN_REQ to re-key\n",
		            cl->cluster_id, sender_ip_buf);
		    cl->join_pending = 1;
		    cl_ctr_send_join_req(cl->sock, cl);
		}
	    }
	    return;
	}

	/* While we belong to no cluster, remember an id we hear on traffic that
	 * authenticated: if we must found a cluster ourselves, we found into this
	 * one rather than mint an id its members would refuse. */
	if (cl->peers->cid_state == CL_CTR_CID_NONE && !cl->heard_cid_set
	        && strcmp(sender_ip_buf, my_ip) != 0
	        && !cl_ctr_cid_is_zero((const unsigned char *)buf + CL_CTR_CID_OFF)) {
	    memcpy(cl->heard_cid, buf + CL_CTR_CID_OFF, CL_CTR_CID_SZ);
	    cl->heard_cid_set = 1;
	}

	/* The sender's incarnation, stamped into every packet by
	 * cl_ctr_encrypt_pkt(); authenticated, since it is inside the AEAD. */
	{
	    const unsigned char *ib = (const unsigned char *)buf
	                              + CL_CTR_WIRE_HDR_SZ + 1 + CL_CTR_SEQ_SZ;
	    int k;
	    for (k = 0; k < CL_CTR_INC_SZ; k++)
		pkt_inc = (pkt_inc << 8) | ib[k];
	}

	/* Sequence check: reject replays for all session-key packets including
	 * GOODBYE.  my_seq lives in shm so mod_destroy increments the same
	 * counter the worker uses - GOODBYE gets a valid monotonic seq number
	 * without any special-casing.
	 * Bootstrap packets (CL_CTR_BOOTSTRAP_MAGIC) use join_nonce instead. */
	if (!is_bootstrap) {
	    /* The type byte, not the cleartext magic: this runs after the AEAD,
	     * so the byte is authenticated and the magic is only the hint the
	     * rate limiter needed before there was anything to trust. */
	    /* Both flavours belong to the consumer plane - the reliable one is
	     * still consumer traffic, and counting it against the control plane
	     * would put back exactly the mixing the split removed. */
	    unsigned char _t = (unsigned char)buf[CL_CTR_WIRE_HDR_SZ];
	    int is_consumer_pkt = (_t == CL_CTR_PKT_CONSUMER ||
	                           _t == CL_CTR_PKT_CONSUMER_REL);
	    int _seq_rc;

	    memcpy(&pkt_seq, buf + CL_CTR_WIRE_HDR_SZ + 1, CL_CTR_SEQ_SZ);
	    pkt_seq = ntohl(pkt_seq);
	    _seq_rc = cl_ctr_check_and_update_seq(sender_ip_buf, pkt_seq, pkt_inc,
	                                          cl, is_consumer_pkt);
	    if (_seq_rc != CL_CTR_SEQ_OK) {
		if (_t == CL_CTR_PKT_CONSUMER_REL && _seq_rc != CL_CTR_SEQ_STALE) {
		    if (_seq_rc == CL_CTR_SEQ_DUP) {
			/* A duplicate of a message that asked to be
			 * acknowledged means our acknowledgement did not
			 * arrive: say it again.  Without this the sender spends
			 * its whole retransmit budget against a receiver that
			 * has had the message all along and is dropping every
			 * copy in silence. */
			cl_ctr_send_ack(cl->sock, cl, pkt_seq,
			                CL_CTR_PKT_CONSUMER_REL, 0,
			                (const struct sockaddr *)&src_addr,
			                src_len);
		    } else {
			/* Below the window.  We genuinely do not know whether
			 * this payload was ever delivered, so we must not claim
			 * it was - an ACK here is exactly the silent lie that
			 * made reliable delivery unreliable before the window
			 * existed.  Withholding it costs the sender the rest of
			 * its budget and one honest "unacked" line.
			 *
			 * Reaching this at all means the window is too small
			 * for the offered rate, which is a sizing problem the
			 * operator can act on - hence a warning, not a debug
			 * line, rate limited per process because a burst that
			 * outruns the window outruns it for many packets. */
			static unsigned int last_old_warn;
			unsigned int now_t = get_ticks();

			if (last_old_warn == 0 ||
			    now_t - last_old_warn >= CL_CTR_RELIABLE_WARN_IVL) {
			    last_old_warn = now_t;
			    if (_seq_rc == CL_CTR_SEQ_JUMP)
				LM_WARN("clusterer_controller: reliable message "
				        "from %s seq=%u is implausibly far ahead "
				        "of that peer's last accepted sequence - "
				        "refused and NOT acknowledged. Either a "
				        "replay of a very old packet, or this "
				        "peer's traffic has been lost wholesale; "
				        "the window starts afresh when that peer "
				        "restarts.\n", sender_ip_buf, pkt_seq);
			    else
				LM_WARN("clusterer_controller: reliable message "
				        "from %s seq=%u fell more than %d messages "
				        "behind the replay window and cannot be "
				        "confirmed - NOT acknowledging. The sender "
				        "is offering more than the window spans "
				        "within its retransmit horizon "
				        "(consumer_retries x consumer_retry_ms = "
				        "%d ms); lower that horizon or expect "
				        "losses.\n", sender_ip_buf, pkt_seq,
				        CL_CTR_REPLAY_WIN_BITS,
				        cl->consumer_retries * cl->consumer_retry_ms);
			}
		    }
		}
		return;
	    }
	}

	pkt_type    = (unsigned char)buf[CL_CTR_WIRE_HDR_SZ];
	payload     = buf + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;
	/* Non-negative: the minimum-length gate above guarantees
	 * n >= CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_TAG_SZ. */
	payload_len = (int)(n - CL_CTR_WIRE_HDR_SZ - CL_CTR_PLAIN_HDR_SZ - CL_CTR_TAG_SZ);

	switch (pkt_type) {

	case CL_CTR_PKT_ALIVE: {
	    char           ip_buf[CL_CTR_MAX_IP_LEN + 1];
	    int            ip_len = (int)strnlen(payload, CL_CTR_MAX_IP_LEN);
	    const unsigned char *pubkey = NULL;
	    int            cfg_present = 0, p_manage = 0, p_stick = 0, p_qt = 0;
	    int            p_mtu = 0, p_maint = 0;
	    memcpy(ip_buf, payload, ip_len);
	    ip_buf[ip_len] = '\0';
	    /* Pubkey appended after NUL-terminated IP */
	    if (payload_len >= ip_len + 1 + (int)CL_CTR_PUBKEY_SZ)
		pubkey = (const unsigned char *)payload + ip_len + 1;
	    /* Config descriptor appended after the pubkey (optional) */
	    if (payload_len >= ip_len + 1 + (int)CL_CTR_PUBKEY_SZ + CL_CTR_CONFIG_SZ) {
		const char *c = payload + ip_len + 1 + CL_CTR_PUBKEY_SZ;
		uint16_t    qt_be;
		p_manage    = (unsigned char)c[0];
		p_stick     = (unsigned char)c[1];
		memcpy(&qt_be, c + 2, 2);
		p_qt        = ntohs(qt_be);
		cfg_present = 1;
	    }
	    /* MTU appended after the config block (optional - older builds) */
	    if (payload_len >= ip_len + 1 + (int)CL_CTR_PUBKEY_SZ
	                       + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ) {
		uint16_t m_be;
		memcpy(&m_be, payload + ip_len + 1 + CL_CTR_PUBKEY_SZ
		              + CL_CTR_CONFIG_SZ, CL_CTR_MTU_SZ);
		p_mtu = ntohs(m_be);
	    }
	    /* maintenance state after the MTU (optional - older builds) */
	    if (payload_len >= ip_len + 1 + (int)CL_CTR_PUBKEY_SZ
	                       + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ + 1)
		p_maint = (unsigned char)payload[ip_len + 1 + CL_CTR_PUBKEY_SZ
		                                 + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ];
	    cl_ctr_handle_alive(ip_buf, pubkey, cfg_present, p_manage, p_stick, p_qt,
	                        p_mtu, p_maint, cl);
	    break;
	}

	case CL_CTR_PKT_CONSUMER_REL:
	    /* Acknowledge first, deliver second: the sender is holding a
	     * retransmit slot on this, and delivery cannot fail in a way the
	     * acknowledgement should report - the consumer's own callback owns
	     * what happens next. */
	    cl_ctr_send_ack(cl->sock, cl, pkt_seq, CL_CTR_PKT_CONSUMER_REL,
	                    0/*session key*/,
	                    (const struct sockaddr *)&src_addr, src_len);
	    cl_ctr_handle_consumer(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_CONSUMER:
	    /* session-key only: a consumer message under the bootstrap key
	     * would come from a node that has not even joined - drop it */
	    if (is_bootstrap)
		break;
	    cl_ctr_handle_consumer(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_JOIN_REQ:
	    cl_ctr_handle_join_req(sock, payload, payload_len, pkt_inc, cl,
	                       (const struct sockaddr *)&src_addr, src_len);
	    break;

	case CL_CTR_PKT_MEMBER_LIST:
	    cl_ctr_handle_member_list(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_GOODBYE: {
	    char ip_buf[CL_CTR_MAX_IP_LEN + 1];
	    int  ip_len = payload_len > CL_CTR_MAX_IP_LEN ? CL_CTR_MAX_IP_LEN : payload_len;
	    memcpy(ip_buf, payload, ip_len);
	    ip_buf[ip_len] = '\0';
	    cl_ctr_handle_goodbye(sock, ip_buf, cl);
	    break;
	}

	case CL_CTR_PKT_NODE_ASSIGN:
	    cl_ctr_handle_node_assign(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_MASTER_ALIVE:
	    cl_ctr_handle_master_alive(sender_ip_buf, cl, payload, payload_len,
	                           (const struct sockaddr *)&src_addr, src_len);
	    break;

	case CL_CTR_PKT_RESYNC:
	    cl_ctr_handle_resync(sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_KEY_GRANT: {
	    uint32_t in_seq;
	    memcpy(&in_seq, buf + CL_CTR_WIRE_HDR_SZ + 1, CL_CTR_SEQ_SZ);
	    in_seq = ntohl(in_seq);
	    cl_ctr_handle_key_grant(payload, payload_len, sender_ip_buf, cl,
	                        in_seq, (const unsigned char *)buf + CL_CTR_CID_OFF,
	                        (const struct sockaddr *)&src_addr, src_len);
	    break;
	}

	case CL_CTR_PKT_ACK:
	    cl_ctr_handle_ack(payload, payload_len, cl, sender_ip_buf);
	    break;

	case CL_CTR_PKT_KEY_HANDOFF:
	    cl_ctr_handle_key_handoff(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_JOIN_REJECT:
	    cl_ctr_handle_join_reject(payload, payload_len, sender_ip_buf, cl);
	    break;

	case CL_CTR_PKT_MASTER_BEACON:
	    cl_ctr_handle_master_beacon(sender_ip_buf, payload, payload_len, cl);
	    break;

	case CL_CTR_PKT_MASTER_PROBE:
	    cl_ctr_handle_master_probe(sender_ip_buf, payload, payload_len, cl,
	                               (const struct sockaddr *)&src_addr, src_len);
	    break;

	case CL_CTR_PKT_MASTER_PROBE_ACK:
	    cl_ctr_handle_master_probe_ack(sender_ip_buf, payload, payload_len, cl);
	    break;

	default: {
	    /* A newer build of the same wire version (a rolling upgrade): the
	     * type is one this build does not know, and dropping it is the
	     * contract - say so once a minute, not once a packet. */
	    static time_t unknown_warned_at;
	    time_t now = cl_ctr_now();
	    if (now - unknown_warned_at >= CL_CTR_WIRE_WARN_IVL) {
		unknown_warned_at = now;
		LM_WARN("clusterer_controller: [cluster %d] packet type 0x%02x "
		        "from %s is unknown to this build (a newer one?) - "
		        "dropped\n", cl->cluster_id, pkt_type, sender_ip_buf);
	    }
	    break;
	}
	}
    }
}

/*
 * cl_ctr_maybe_forward() - hand a datagram received on a shared ip:port to the
 * sibling local cluster it actually belongs to.
 *
 * On a shared multicast_port every controller cluster on this node binds the
 * same ip:port.  Multicast reaches only the socket that joined the group (with
 * IP_MULTICAST_ALL cleared in cl_ctr_setup_socket() - the Linux default is to
 * deliver every group joined on the port), but unicast is demultiplexed by
 * port alone, so a 1:1 reply meant for a co-located cluster can be delivered
 * to the wrong worker.  We recover it here: find the local cluster
 * whose cluster_id matches the packet's cleartext header and forward the still-
 * encrypted bytes to its worker via IPC.  The target decrypts with its own key.
 *
 * Called only from the original receiver (never re-entered for a forwarded
 * packet), so no forwarding loop is possible.
 */
static void cl_ctr_maybe_forward(const char *buf, int n,
                             const struct sockaddr_in *src, uint16_t pkt_cid,
                             cl_ctr_cluster_t *from)
{
    cl_ctr_cluster_t      *target = NULL;
    struct cl_ctr_fwd_pkt *fp;
    int                    i, proc_no;

    /* Bound the work: only a legitimately-sized unicast is worth forwarding. */
    if (n <= 0 || n > CL_CTR_LIST_PKT_MAX_SZ)
	return;

    for (i = 0; i < cl_ctr_cluster_count; i++) {
	if ((uint16_t)cl_ctr_clusters[i].cluster_id == pkt_cid &&
	    &cl_ctr_clusters[i] != from) {
	    target = &cl_ctr_clusters[i];
	    break;
	}
    }
    if (!target) {
	/* Nothing in THIS process owns that cluster_id, so the datagram is
	 * unrecoverable here - it was almost certainly meant for a different
	 * process co-bound to the same port (see the probe in
	 * cl_ctr_setup_socket).  This used to be LM_DBG, which meant it was
	 * invisible at every log_level anyone actually runs, and a whole class
	 * of "the cluster just does not converge" reports had no trace at all.
	 *
	 * Rate-limited because a misdelivering peer can produce one of these
	 * per packet, and a warning that can fire at line rate is its own
	 * outage.  First occurrence prints immediately; after that at most one
	 * per CL_CTR_FWD_WARN_IVL seconds, carrying the count it stands for. */
	static time_t last_warn;
	static unsigned long suppressed;
	time_t now = cl_ctr_now();

	if (last_warn == 0 || now - last_warn >= CL_CTR_FWD_WARN_IVL) {
	    if (suppressed)
		LM_WARN("clusterer_controller: [cluster %d] no local cluster %u "
			"for packet on shared port, dropping (%lu more in the "
			"last %lds - another process is probably bound to this "
			"port)\n", from->cluster_id, pkt_cid, suppressed,
			(long)(now - last_warn));
	    else
		LM_WARN("clusterer_controller: [cluster %d] no local cluster %u "
			"for packet on shared port, dropping - another process "
			"is probably bound to this port\n",
			from->cluster_id, pkt_cid);
	    last_warn  = now;
	    suppressed = 0;
	} else {
	    suppressed++;
	}
	return;
    }

    /* Shed floods before allocating: charge the source against our own limiter
     * (the target re-checks after it receives the forward). */
    {
	int is_consumer = (memcmp(buf, CL_CTR_CONSUMER_MAGIC,
	                          CL_CTR_MAGIC_SZ) == 0);

	/* Judged against the target cluster's membership, not ours - the
	 * packet is about to be handed to that cluster's worker. */
	if (is_consumer && !cl_ctr_consumer_src_known(target,
	                       src->sin_addr.s_addr))
	    return;
	if (cl_ctr_rate_check(from, src->sin_addr.s_addr, is_consumer) < 0)
	    return;
    }

    /* worker_proc_no is written once at worker fork and stable thereafter. */
    proc_no = target->peers ? target->peers->worker_proc_no : -1;
    if (proc_no < 0)
	return;   /* target worker not up yet */

    fp = shm_malloc(sizeof(*fp) + (size_t)n - 1);
    if (!fp) {
	LM_ERR("clusterer_controller: out of shm forwarding to cluster %u\n",
	       pkt_cid);
	return;
    }
    fp->cl  = target;
    fp->src = *src;
    fp->n   = n;
    memcpy(fp->buf, buf, (size_t)n);

    if (ipc_send_rpc(proc_no, cl_ctr_rpc_forward, fp) < 0) {
	LM_ERR("clusterer_controller: ipc forward to cluster %u failed\n",
	       pkt_cid);
	shm_free(fp);
    }
}

/*
 * cl_ctr_rpc_forward() - runs in the target cluster's worker; process a datagram
 * a sibling worker forwarded to us (see cl_ctr_maybe_forward).
 */
static void cl_ctr_rpc_forward(int sender, void *param)
{
    struct cl_ctr_fwd_pkt *fp = (struct cl_ctr_fwd_pkt *)param;
    (void)sender;

    cl_ctr_recv_one(fp->cl->sock, fp->cl, (char *)fp->buf, fp->n, &fp->src);
    shm_free(fp);
}
