/*
 * clusterer_controller - receive dispatcher, rate limiting and forwarding
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
#include "cl_ctr_caps.h"
#include "cl_ctr_stats.h"

static void cl_ctr_maybe_forward(const char *buf, int n,
                             const struct sockaddr_in *src, uint16_t pkt_cid,
                             cl_ctr_cluster_t *from);
static void cl_ctr_rpc_forward(int sender, void *param);

/* control packets past the base rate: checked before AEAD, so a stranger's
 * flood costs one scan (a spoofed source still passes) */
static int cl_ctr_src_known(cl_ctr_cluster_t *cl, uint32_t src_ip)
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

/* count a refusal on @w; when a report is due (first at once, then once per
 * CL_CTR_WIRE_WARN_IVL) return how many it stands for, else 0 */
static unsigned long cl_ctr_warn_due(cl_ctr_warn_t *w)
{
    time_t        now = cl_ctr_now();
    unsigned long n;

    w->pkts++;
    if (w->reported_at && now - w->reported_at < CL_CTR_WIRE_WARN_IVL)
        return 0;
    n = w->pkts - w->pkts_reported;
    w->pkts_reported = w->pkts;
    w->reported_at   = now;
    return n;
}

/* A bootstrap packet from @ip that did not decrypt: counted by the caller
 * (auth_failures), reported here once a minute. */
static void cl_ctr_warn_bootstrap(cl_ctr_cluster_t *cl, const char *ip)
{
    unsigned long k = cl_ctr_warn_due(&cl->warn_bootstrap);

    if (k)
        LM_WARN("clusterer_controller: [cluster %d] %lu bootstrap packet(s) "
                "did not decrypt since the last report, the latest from %s - "
                "wrong password, foreign cluster, or tampered packet\n",
                cl->cluster_id, k, ip);
}

/* bootstrap packets have no replay window: refuse a recent nonce, or a lower
 * incarnation from a node whose current life was heard within 2 query periods */
static int cl_ctr_boot_replayed(cl_ctr_cluster_t *cl, const char *nonce,
                                const char *sender, uint64_t inc)
{
    int i, old_life = 0;

    for (i = 0; i < cl->boot_seen_n; i++)
        if (memcmp(cl->boot_seen[i], nonce, CL_CTR_NONCE_SZ) == 0) {
            LM_DBG("clusterer_controller: [cluster %d] bootstrap packet from "
                   "%s seen before, dropping\n", cl->cluster_id, sender);
            return 1;
        }
    lock_start_read(cl->peers->lock);
    {
        cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, sender);
        if (e && e->incarnation && inc < e->incarnation &&
                cl_ctr_now() - e->last_seen < 2 * (time_t)query_time)
            old_life = 1;
    }
    lock_stop_read(cl->peers->lock);
    if (old_life) {
        LM_DBG("clusterer_controller: [cluster %d] bootstrap packet from a "
               "previous life of %s, which is still heard - dropping\n",
               cl->cluster_id, sender);
        return 1;
    }
    memcpy(cl->boot_seen[cl->boot_seen_next], nonce, CL_CTR_NONCE_SZ);
    cl->boot_seen_next = (cl->boot_seen_next + 1) % CL_CTR_BOOT_SEEN;
    if (cl->boot_seen_n < CL_CTR_BOOT_SEEN)
        cl->boot_seen_n++;
    return 0;
}

/* The types a sender seals with the bootstrap key: the admission handshake
 * (JOIN_REQ, KEY_GRANT and its ACK, JOIN_REJECT, JOIN_WAIT) and the master's beacon. */
static int cl_ctr_bootstrap_type(unsigned char t)
{
    return t == CL_CTR_PKT_JOIN_REQ || t == CL_CTR_PKT_KEY_GRANT ||
           t == CL_CTR_PKT_ACK || t == CL_CTR_PKT_JOIN_REJECT ||
           t == CL_CTR_PKT_JOIN_WAIT ||
           t == CL_CTR_PKT_MASTER_BEACON;
}

/* per source IP, before decryption: 0 within the per-second limit, -1 to drop */
static int cl_ctr_rate_check(cl_ctr_cluster_t *cl, uint32_t src_ip)
{
    time_t            now     = cl_ctr_now();
    cl_ctr_rate_entry_t  *oldest  = NULL;
    int               limit   = CL_CTR_RATE_LIMIT;
    int               i;

    /* just woken from a stall: the queued backlog is not a flood, and limiting
     * it would drop the keepalives we need to follow the master */
    if (cl->rate_grace_until_ms && cl_ctr_now_ms() < cl->rate_grace_until_ms)
        return 0;

    for (i = 0; i < CL_CTR_RATE_TBL_SZ; i++) {
        cl_ctr_rate_entry_t *e = &cl->rate_tbl[i];

        if (e->ip == 0) {
            if (!oldest) oldest = e;             /* prefer empty slot  */
            continue;
        }
        if (e->ip == src_ip) {
            if (now > e->window_start) {         /* new second         */
                e->window_start = now;
                e->count        = 1;
                return 0;
            }
            if (++e->count > limit && cl_ctr_src_known(cl, src_ip))
                limit += CL_CTR_RATE_PER_MEMBER * cl->peers->count;
            if (e->count > limit) {
                /* a silent drop looks like packet loss, so say so - once a minute with a
                 * count, so a flood does not flood the log */
                unsigned long k = cl_ctr_warn_due(&cl->warn_rate);
                if (k) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &src_ip, ip, sizeof ip);
                    LM_WARN("clusterer_controller: [cluster %d] control rate "
                        "limit of %d/s exceeded - %lu packet(s) dropped since "
                        "the last report, the latest from %s\n",
                        cl->cluster_id, limit, k, ip);
                }
                return -1;
            }
            return 0;
        }
        /* track oldest entry for eviction when table is full */
        if (!oldest || e->window_start < oldest->window_start)
            oldest = e;
    }

    /* new source IP - claim oldest/empty slot */
    oldest->ip           = src_ip;
    oldest->window_start = now;
    oldest->count        = 1;
    return 0;
}

/* the uuid is cleartext: only a bootstrap packet that decrypts proves another
 * cluster for foreign_clusters; rate-charged first, since decrypting costs */
static int cl_ctr_foreign_authentic(const char *buf, ssize_t n,
                                    const struct sockaddr_in *src,
                                    cl_ctr_cluster_t *cl)
{
    static char   tmp[CL_CTR_LIST_PKT_MAX_SZ];   /* worker-local, like buf */
    char          ip[INET_ADDRSTRLEN];

    if (memcmp(buf, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ) != 0)
        return 0;
    if (n > (ssize_t)sizeof(tmp) ||
            cl_ctr_rate_check(cl, src->sin_addr.s_addr) < 0)
        return 0;
    memcpy(tmp, buf, (size_t)n);
    inet_ntop(AF_INET, &src->sin_addr, ip, sizeof ip);
    if (cl_ctr_decrypt_pkt(tmp, n, ip, cl->key, 1) == 0)
        return 1;
    cl_ctr_note_auth_failure(cl, ip);
    cl_ctr_warn_bootstrap(cl, ip);
    return 0;
}

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
	/* forwarded by a sibling cluster's worker (cl_ctr_maybe_forward): handled
	 * as if it had arrived on our own socket */
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

    if (n < CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_TAG_SZ) {
	/* before any filter, so anyone can send these: once a minute */
	unsigned long k = cl_ctr_warn_due(&cl->warn_short);
	if (k) {
	    char ip[INET_ADDRSTRLEN];
	    inet_ntop(AF_INET, &src_addr.sin_addr, ip, sizeof ip);
	    LM_WARN("clusterer_controller: [cluster %d] %lu datagram(s) too short "
	            "to be a packet dropped since the last report, the latest "
	            "%zd bytes from %s\n", cl->cluster_id, k, n, ip);
	}
	return;
    }

    if (memcmp(buf, CL_CTR_PACKET_MAGIC,   CL_CTR_MAGIC_SZ) != 0 &&
        memcmp(buf, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ) != 0) {
	unsigned char m0 = (unsigned char)buf[0], m1 = (unsigned char)buf[1];

	/* another wire version: refuse it before any key and say so, or the node
	 * just never joins with nothing logged on either side */
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

    /* cleartext cluster_id, before decryption: another cluster's packet is not
     * a wrong-password attempt */
    {
	uint16_t pkt_cid_be;
	memcpy(&pkt_cid_be, buf + CL_CTR_MAGIC_SZ, CL_CTR_CLUSTER_ID_SZ);
	if (ntohs(pkt_cid_be) != (uint16_t)cl->cluster_id) {
	    /* maybe a sibling local cluster's (cl_ctr_maybe_forward); a forwarded
	     * packet is never forwarded again */
	    if (!fwd_buf)
		cl_ctr_maybe_forward(buf, (int)n, &src_addr, ntohs(pkt_cid_be), cl);
	    else
		LM_DBG("clusterer_controller: [cluster %d] forwarded packet for "
		       "cluster %u is not ours, dropping\n", cl->cluster_id,
		       ntohs(pkt_cid_be));
	    return;
	}
    }

    /* once our uuid is founded, another one is refused before any key, so a twin
     * deployment is never merged; zeros (no cluster yet) pass */
    {
	const unsigned char *pc = (const unsigned char *)buf + CL_CTR_CID_OFF;
	int st = cl->peers->cid_state;

	if ((st == CL_CTR_CID_ESTABLISHED || st == CL_CTR_CID_PINNED)
	        && !cl_ctr_cid_is_zero(pc)
	        && memcmp(pc, cl->peers->cid, CL_CTR_CID_SZ) != 0) {
	    time_t now = cl_ctr_now();

	    if (!cl_ctr_foreign_authentic(buf, n, &src_addr, cl)) {
		LM_DBG("clusterer_controller: [cluster %d] unauthenticated "
		       "packet stamped with another cluster uuid, dropping\n",
		       cl->cluster_id);
		return;
	    }
	    cl->peers->foreign_pkts++;
	    {
		/* which foreign cluster: remember it for clusterer:list_config */
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
		           "see foreign_clusters in clusterer:list_config\n",
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

    /* shed floods before any crypto */
    if (cl_ctr_rate_check(cl, src_addr.sin_addr.s_addr) < 0)
	return;

    {
	char sender_ip_buf[INET_ADDRSTRLEN];
	const unsigned char *dec_key;
	inet_ntop(AF_INET, &src_addr.sin_addr,
	          sender_ip_buf, sizeof(sender_ip_buf));

	int is_bootstrap = (memcmp(buf, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ) == 0);
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
	    if (strcmp(sender_ip_buf, my_ip) != 0)
		cl_ctr_note_auth_failure(cl, sender_ip_buf);
	    if (is_bootstrap && strcmp(sender_ip_buf, my_ip) != 0)
		cl_ctr_warn_bootstrap(cl, sender_ip_buf);

	    /* while joining, any undecryptable packet is evidence of a cluster we hold no
	     * key for - session ones too, or a wrong-password joiner would self-promote */
	    if (_new && strcmp(sender_ip_buf, my_ip) != 0)
		cl->auth_fail_pkts++;

	    if (is_bootstrap) {
		if (_im && cl_ctr_join_fail_check(sender_ip_buf, cl))
		    cl_ctr_send_join_reject(sock, sender_ip_buf, cl, CL_CTR_REJECT_GENERIC,
		        (const unsigned char *)buf + CL_CTR_NONCE_OFF);

		/* joiner: count only the known master's failures, so a rogue node's
		 * JOIN_REQs cannot make us exit; no master yet, nothing counted */
		if (_new && _lm[0] != '\0' && strcmp(sender_ip_buf, _lm) == 0)
		    cl->bootstrap_auth_fails++;
	    }
	    if (!is_bootstrap && !cl->join_pending) {
		/* re-key only on our master's packets (a rotation): reacting to rogue or
		 * stale ones would churn re-JOINs cluster-wide; masters never re-JOIN */
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

	/* from here sender_ip_buf is the sealed sender, not the spoofable source:
	 * replay windows follow it, replies still go to the datagram source */
	{
	    struct in_addr a;

	    memcpy(&a.s_addr, buf + CL_CTR_SENDER_OFF, CL_CTR_SENDER_SZ);
	    if (a.s_addr == 0 || a.s_addr == htonl(INADDR_BROADCAST)) {
		LM_DBG("clusterer_controller: [cluster %d] packet from %s seals no "
		       "sender, dropping\n", cl->cluster_id, sender_ip_buf);
		return;
	    }
	    inet_ntop(AF_INET, &a, sender_ip_buf, sizeof(sender_ip_buf));
	}

	/* the bootstrap key is the password's, admitted or not: any type but the
	 * handshake and the beacon under it is from a node no master admitted */
	if (is_bootstrap && !cl_ctr_bootstrap_type((unsigned char)buf[CL_CTR_WIRE_HDR_SZ])) {
	    LM_DBG("clusterer_controller: [cluster %d] packet type 0x%02x from %s "
	           "sealed with the bootstrap key, dropping\n", cl->cluster_id,
	           (unsigned char)buf[CL_CTR_WIRE_HDR_SZ], sender_ip_buf);
	    return;
	}

	/* in no cluster yet: remember an authenticated uuid, so if we must found one
	 * we found this one rather than mint an id its members would refuse */
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

	/* replay check for every session packet, GOODBYE too: my_seq is in shm, so
	 * mod_destroy numbers it from the worker's counter */
	if (!is_bootstrap) {
	    uint32_t pkt_seq;

	    memcpy(&pkt_seq, buf + CL_CTR_WIRE_HDR_SZ + 1, CL_CTR_SEQ_SZ);
	    pkt_seq = ntohl(pkt_seq);
	    if (cl_ctr_check_and_update_seq(sender_ip_buf, pkt_seq, pkt_inc, cl)
	            != CL_CTR_SEQ_OK)
		return;
	} else {
	    /* no window for these: a JOIN_REQ or beacon sent again is caught
	     * by its nonce or its incarnation instead */
	    unsigned char _t = (unsigned char)buf[CL_CTR_WIRE_HDR_SZ];
	    if ((_t == CL_CTR_PKT_JOIN_REQ || _t == CL_CTR_PKT_MASTER_BEACON) &&
	            cl_ctr_boot_replayed(cl, buf + CL_CTR_NONCE_OFF,
	                                 sender_ip_buf, pkt_inc))
		return;
	}

	pkt_type    = (unsigned char)buf[CL_CTR_WIRE_HDR_SZ];
	payload     = buf + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ;
	/* Non-negative: the minimum-length gate above guarantees
	 * n >= CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + CL_CTR_TAG_SZ. */
	payload_len = (int)(n - CL_CTR_WIRE_HDR_SZ - CL_CTR_PLAIN_HDR_SZ - CL_CTR_TAG_SZ);

	switch (pkt_type) {

	case CL_CTR_PKT_ALIVE: {
	    char           ip_buf[CL_CTR_MAX_IP_LEN + 1];
	    /* bounded by the payload too: past it lie the tag and stale bytes */
	    int            ip_len = (int)strnlen(payload,
	                               payload_len < CL_CTR_MAX_IP_LEN
	                               ? (size_t)payload_len : CL_CTR_MAX_IP_LEN);
	    const unsigned char *pubkey = NULL;
	    int            cfg_present = 0, p_manage = 0, p_stick = 0, p_qt = 0;
	    int            p_mtu = 0, p_maint = 0;
	    uint32_t       p_caps = 0;
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
	    /* a level a newer build knows and this one does not: still out of
	     * election and tags - the meaning every level shares */
	    if (p_maint > CL_CTR_MAINT_FULL)
		p_maint = CL_CTR_MAINT_EVICTED;
	    /* capability bits after the maintenance byte (absent: none) */
	    if (payload_len >= ip_len + 1 + (int)CL_CTR_PUBKEY_SZ + CL_CTR_CONFIG_SZ
	                       + CL_CTR_MTU_SZ + 1 + CL_CTR_CAPS_SZ) {
		uint32_t c_be;
		memcpy(&c_be, payload + ip_len + 1 + CL_CTR_PUBKEY_SZ
		              + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ + 1, CL_CTR_CAPS_SZ);
		p_caps = ntohl(c_be);
	    }
	    /* a node announces itself, and no other */
	    if (strcmp(ip_buf, sender_ip_buf) != 0) {
		LM_DBG("clusterer_controller: [cluster %d] ALIVE for %s sealed "
		       "by %s, dropping\n", cl->cluster_id, ip_buf, sender_ip_buf);
		break;
	    }
	    cl_ctr_handle_alive(ip_buf, pubkey, cfg_present, p_manage, p_stick, p_qt,
	                        p_mtu, p_maint, p_caps, cl);
	    /* its BIN links, after the caps (absent on older builds) */
	    {
		int lo = ip_len + 1 + CL_CTR_PUBKEY_SZ + CL_CTR_CONFIG_SZ
		         + CL_CTR_MTU_SZ + 1 + CL_CTR_CAPS_SZ;

		if (payload_len >= lo + CL_CTR_ALIVE_BITMAP_SZ)
		    cl_ctr_note_links(cl, ip_buf, (const unsigned char *)payload + lo);
		lo += CL_CTR_ALIVE_BITMAP_SZ;
		if (payload_len >= lo + CL_CTR_ALIVE_DSEQ_SZ) {
		    const unsigned char *q = (const unsigned char *)payload + lo;
		    uint64_t s = 0;
		    int      k, nid = 0;
		    for (k = 0; k < CL_CTR_ALIVE_DSEQ_SZ; k++)
			s = (s << 8) | q[k];
		    /* not our own, looped back: we never receive our own broadcasts */
		    if (strcmp(ip_buf, my_ip) != 0) {
			lock_start_read(cl->peers->lock);
			{
			    cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, ip_buf);
			    nid = e ? e->node_id : 0;
			}
			lock_stop_read(cl->peers->lock);
			cl_ctr_data_note_seq(cl, nid, pkt_inc, s);
		    }
		    lo += CL_CTR_ALIVE_DSEQ_SZ;
		}
		if (payload_len > lo)
		    cl_ctr_note_capst(cl, ip_buf, (const unsigned char *)payload + lo,
		                      payload_len - lo);
	    }
	    break;
	}

	case CL_CTR_PKT_JOIN_REQ:
	    cl_ctr_handle_join_req(sock, payload, payload_len, pkt_inc,
	                       (const unsigned char *)buf + CL_CTR_NONCE_OFF,
	                       sender_ip_buf, cl,
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
	    /* a node takes leave for itself, and no other */
	    if (strcmp(ip_buf, sender_ip_buf) != 0) {
		LM_DBG("clusterer_controller: [cluster %d] GOODBYE for %s sealed "
		       "by %s, dropping\n", cl->cluster_id, ip_buf, sender_ip_buf);
		break;
	    }
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
	    cl_ctr_handle_resync(sender_ip_buf, cl,
	                         (const struct sockaddr *)&src_addr, src_len);
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

	case CL_CTR_PKT_JOIN_WAIT:
	    cl_ctr_handle_join_wait(payload, payload_len, sender_ip_buf, cl);
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

	case CL_CTR_PKT_MAINT_SET:
	    cl_ctr_handle_maint_set(sender_ip_buf, payload, payload_len, cl);
	    break;

	default: {
	    /* a newer build of this wire version (rolling upgrade): dropping is the
	     * contract, said once a minute */
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

/* on a shared ip:port unicast is demultiplexed by port alone (multicast is
 * not, IP_MULTICAST_ALL is cleared), so hand a sibling's packet to its worker */
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
	/* no such cluster here: likely another process bound to the port (see the
	 * probe in cl_ctr_setup_socket); first warning at once, then rate-limited */
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
    if (cl_ctr_rate_check(from, src->sin_addr.s_addr) < 0)
	return;

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

/* in the target cluster's worker: a datagram a sibling forwarded */
static void cl_ctr_rpc_forward(int sender, void *param)
{
    struct cl_ctr_fwd_pkt *fp = (struct cl_ctr_fwd_pkt *)param;
    (void)sender;

    cl_ctr_recv_one(fp->cl->sock, fp->cl, (char *)fp->buf, fp->n, &fp->src);
    shm_free(fp);
}
