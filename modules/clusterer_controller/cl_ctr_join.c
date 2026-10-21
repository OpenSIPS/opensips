/*
 * clusterer_controller - join protocol, both sides
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
#include "cl_ctr_stats.h"

/**
 * cl_ctr_transition_to_active() - switch from CL_CTR_NODE_NEW to CL_CTR_NODE_ACTIVE.
 *
 * Disarms the join-phase timers, sends the first ALIVE immediately, then
 * arms the periodic ALIVE timer.  Called from both:
 *   - the join_tfd handler (deadline expired, fresh cluster), and
 *   - cl_ctr_handle_member_list (master responded before deadline).
 * Must be called with cl->peers->lock NOT held.
 */
void cl_ctr_transition_to_active(cl_ctr_cluster_t *cl)
{
    cl_ctr_arm_tfd(cl->join_tfd,   0, 0);              /* disarm one-shot deadline */
    cl_ctr_arm_tfd(cl->rejoin_tfd, 0, 0);              /* disarm JOIN_REQ retry    */
    cl->granted_by[0]    = '\0';                        /* joined: forget the grant */
    cl->grant_wait_count = 0;
    cl_ctr_send_alive(cl->sock, cl);                    /* first heartbeat now      */
    cl_ctr_arm_tfd(cl->alive_tfd, query_time, query_time); /* periodic from here   */
}

/* =========================================================================
 * Packet handlers
 * ========================================================================= */

/**
 * cl_ctr_fmt_cfg_diff() - render only the consistency-critical settings that
 * actually DIFFER into 'out' (e.g. "manage_shtags cluster=1 node=0"), so a
 * mismatch log names just the offending setting(s) rather than all three.
 * 'la'/'lb' are the labels for the local/peer sides ("cluster"/"node" or
 * "local"/"peer").
 */
void cl_ctr_fmt_cfg_diff(char *out, int outsz, const char *la, const char *lb,
                            int a_manage, int b_manage, int a_stick, int b_stick,
                            int a_qt, int b_qt)
{
    int n = 0;
    out[0] = '\0';
#define CL_CTR_DIFF_APPEND(cond, name, av, bv)                                     \
    do {                                                                       \
        if (cond) {                                                            \
            int _w = snprintf(out + n, (n < outsz) ? (outsz - n) : 0,          \
                              "%s" name " %s=%d %s=%d",                         \
                              n ? ", " : "", la, (av), lb, (bv));              \
            if (_w > 0) { n += _w; if (n > outsz) n = outsz; }                 \
        }                                                                      \
    } while (0)
    CL_CTR_DIFF_APPEND(a_manage != b_manage, "manage_shtags",     a_manage, b_manage);
    CL_CTR_DIFF_APPEND(a_stick  != b_stick,  "master_stickiness", a_stick,  b_stick);
    CL_CTR_DIFF_APPEND(a_qt     != b_qt,     "query_time",        a_qt,     b_qt);
#undef CL_CTR_DIFF_APPEND
}

/**
 * cl_ctr_adopt_config() - adopt the running cluster's consistency-critical settings
 * (on_config_mismatch=adopt).  Called on a non-master node when the master's
 * advertised config differs from ours.  Call WITHOUT cl->peers->lock held.
 */
void cl_ctr_adopt_config(cl_ctr_cluster_t *cl, int new_manage, int new_stick,
                            int new_qt, int is_active)
{
    int old_manage = cl->manage_shtags ? 1 : 0;

    LM_INFO("clusterer_controller: [cluster %d] adopting cluster settings from "
            "master (manage_shtags %d->%d, master_stickiness %d->%d, "
            "query_time %d->%d)\n",
            cl->cluster_id, old_manage, new_manage ? 1 : 0,
            cl->master_stickiness ? 1 : 0, new_stick ? 1 : 0, query_time, new_qt);

    cl->master_stickiness = new_stick ? 1 : 0;

    /* query_time is declared global but is a per-process copy after fork, and
     * there is one worker process per cluster, so updating it here affects only
     * THIS cluster's worker - never another cluster on a multi-cluster node.
     * Re-arm the periodic ALIVE timer if we are already active; the election
     * window and purge derive from query_time dynamically and need no re-arm. */
    if (new_qt >= 1 && new_qt != query_time) {
        query_time = new_qt;
        if (is_active)
            cl_ctr_arm_tfd(cl->alive_tfd, query_time, query_time);
    }

    /* Mirror the effective values into shm so clusterer_controller:list_config (MI process)
     * reports what is actually in force after adoption. */
    cl->peers->eff_manage_shtags     = new_manage ? 1 : 0;
    cl->peers->eff_master_stickiness = cl->master_stickiness;
    cl->peers->eff_query_time        = query_time;

    if ((new_manage ? 1 : 0) != old_manage) {
        cl->manage_shtags = new_manage ? 1 : 0;
        if (clctl_loaded) {
            if (cl->manage_shtags) {
                if (clctl.set_shtag_managed)
                    clctl.set_shtag_managed(cl->cluster_id);
            } else if (clctl.unset_shtag_managed) {
                clctl.unset_shtag_managed(cl->cluster_id);
            }
        }
        /* Reconcile tag state under the new policy (no-op when now unmanaged). */
        cl_ctr_apply_shtags(cl);
    }
}

/**
 * cl_ctr_mtu_note_reject() - remember that we refused a peer on MTU, and if we
 * have now refused several DIFFERENT peers while holding no members of our own,
 * say plainly that WE are the likely misconfiguration.
 *
 * Why this exists.  Master election is highest-IP (cl_ctr_elect_master) and
 * entirely MTU-blind, so on a simultaneous cold start the winner is decided by
 * something with no relationship to which MTU is correct.  If six nodes run at
 * 9000 and the one 1500 host happens to hold the highest IP, it becomes master
 * and refuses all six - one misconfigured host takes down the whole fleet,
 * where that same host booting into an already-formed cluster would only have
 * killed itself.  Nothing else in the design catches that, so this warning is
 * the safety net rather than a nicety.
 *
 * It WARNS and nothing more.  A master that stepped down or terminated because
 * OTHERS disagreed would break the rule that a node acts only on its own
 * condition, and would hand anyone holding the bootstrap key a way to force
 * re-elections at will.
 */
static void cl_ctr_mtu_note_reject(const char *src_ip, cl_ctr_cluster_t *cl)
{
    uint32_t ip_num = ip_to_num(src_ip);
    int      i, members;

    if (ip_num == 0 || cl->mtu_suspect_said)
        return;
    for (i = 0; i < cl->mtu_reject_n; i++)
        if (cl->mtu_reject_ips[i] == ip_num)
            return;                     /* same peer retrying, not a new one */
    if (cl->mtu_reject_n < (int)(sizeof(cl->mtu_reject_ips)
                                 / sizeof(cl->mtu_reject_ips[0])))
        cl->mtu_reject_ips[cl->mtu_reject_n++] = ip_num;

    /* "Holding no members" means nobody but ourselves is in the table. */
    lock_start_read(cl->peers->lock);
    members = cl->peers->count;
    lock_stop_read(cl->peers->lock);

    if (cl->mtu_reject_n >= CL_CTR_MTU_SUSPECT_PEERS && members <= 1) {
        cl->mtu_suspect_said = 1;
        LM_CRIT("clusterer_controller: [cluster %d] THIS NODE IS PROBABLY THE "
                "MISCONFIGURED ONE: it is master at MTU %d on %s, has refused %d "
                "different peers for not matching, and holds no members of its "
                "own. Master election is by highest IP and ignores the MTU, so a "
                "single wrongly-configured host that wins it will refuse an "
                "otherwise healthy fleet. Check this node's MTU before changing "
                "any of the others\n",
                cl->cluster_id, cc_mtu,
                my_interface_buf[0] ? my_interface_buf : "(unknown)",
                cl->mtu_reject_n);
    }
}

/**
 * cl_ctr_cfg_note_reject() - the config analogue of cl_ctr_mtu_note_reject().
 *
 * Election is highest-IP and just as blind to manage_shtags / master_stickiness
 * / query_time as it is to the MTU, so the same failure exists: one host booted
 * with the wrong settings that happens to win the election becomes master and
 * refuses an otherwise-agreeing fleet, where that same host joining an already
 * formed cluster would only have shut itself down.  Warn, and nothing more, for
 * the same reasons spelled out above the MTU version.
 */
static void cl_ctr_cfg_note_reject(const char *src_ip, cl_ctr_cluster_t *cl)
{
    uint32_t ip_num = ip_to_num(src_ip);
    int      i, members;

    if (ip_num == 0 || cl->cfg_suspect_said)
        return;
    for (i = 0; i < cl->cfg_reject_n; i++)
        if (cl->cfg_reject_ips[i] == ip_num)
            return;                     /* same peer retrying, not a new one */
    if (cl->cfg_reject_n < (int)(sizeof(cl->cfg_reject_ips)
                                 / sizeof(cl->cfg_reject_ips[0])))
        cl->cfg_reject_ips[cl->cfg_reject_n++] = ip_num;

    lock_start_read(cl->peers->lock);
    members = cl->peers->count;
    lock_stop_read(cl->peers->lock);

    if (cl->cfg_reject_n >= CL_CTR_CFG_SUSPECT_PEERS && members <= 1) {
        cl->cfg_suspect_said = 1;
        LM_CRIT("clusterer_controller: [cluster %d] THIS NODE IS PROBABLY THE "
                "MISCONFIGURED ONE: it is master with manage_shtags=%d "
                "master_stickiness=%d query_time=%d, has refused %d different "
                "peers for not matching, and holds no members of its own. Master "
                "election is by highest IP and ignores these settings, so a "
                "single wrongly-configured host that wins it will refuse an "
                "otherwise healthy fleet. Check this node's config before "
                "changing any of the others\n",
                cl->cluster_id, cl->manage_shtags ? 1 : 0,
                cl->master_stickiness ? 1 : 0, query_time, cl->cfg_reject_n);
    }
}

/**
 * cl_ctr_handle_join_req() - process a CL_CTR_PKT_JOIN_REQ packet.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * Non-masters ignore JOIN_REQ - the master handles discovery exclusively.
 *
 * Master behaviour:
 *   1. Parse joining node's IP and BIN sockets from payload.
 *   2. Upsert peer; store BIN info and allocate a node_id.
 *   3. Send NODE_ASSIGN (joining node + all existing peers) so every
 *      node in the cluster learns the full updated picture.
 *   4. If joining IP > own IP: run election, send MEMBER_LIST.
 *   5. If joining IP <= own IP: send MEMBER_LIST (self still master).
 */
void cl_ctr_handle_join_req(int sock, const char *payload, int payload_len,
                               uint64_t pkt_inc, cl_ctr_cluster_t *cl,
                               const struct sockaddr *src, socklen_t src_len)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           src_ip[CL_CTR_MAX_IP_LEN + 1];
    char           bin_socks[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
    const unsigned char *noise_msg1 = NULL;   /* points into payload */
    int            noise_msg1_len = 0;
    uint8_t        bin_cnt   = 0;
    int            ip_len, was_master, i;
    int            j_cfg_present = 0, j_manage = 0, j_stick = 0, j_qt = 0;
    int            j_mtu = 0;   /* 0 = joiner advertised none (older build) */
    uint16_t       new_id;

    /* --- Parse IP --- */
    ip_len = (int)strnlen(p, CL_CTR_MAX_IP_LEN);
    if (p + ip_len >= end) {
	LM_WARN("clusterer_controller: JOIN_REQ payload truncated\n");
	return;
    }
    memcpy(src_ip, p, ip_len);
    src_ip[ip_len] = '\0';
    p += ip_len + 1;

    /* Ignore our own JOIN_REQ via loopback */
    if (strcmp(src_ip, my_ip) == 0)
	return;

    /* --- Parse BIN sockets --- */
    memset(bin_socks, 0, sizeof(bin_socks));
    if (p < end) {
	bin_cnt = (uint8_t)*p++;
	if (bin_cnt > CL_CTR_MAX_BIN_SOCKETS)
	    bin_cnt = CL_CTR_MAX_BIN_SOCKETS;
	for (i = 0; i < (int)bin_cnt && p < end; i++) {
	    int slen = (int)strnlen(p, CL_CTR_MAX_BIN_SOCK_LEN - 1);
	    memcpy(bin_socks[i], p, slen);
	    bin_socks[i][slen] = '\0';
	    p += slen + 1;
	}
    }

    /* --- Parse the Noise msg 1 (appended after BIN info) --- */
    if (p + CL_CTR_NOISE_MSG1_SZ <= end) {
	noise_msg1     = (const unsigned char *)p;
	noise_msg1_len = CL_CTR_NOISE_MSG1_SZ;
	p += CL_CTR_NOISE_MSG1_SZ;
    }

    /* --- Parse the joiner's consistency-critical config (after join_nonce) --- */
    if (p + CL_CTR_CONFIG_SZ <= end) {
	uint16_t qt_be;
	j_manage = (unsigned char)p[0];
	j_stick  = (unsigned char)p[1];
	memcpy(&qt_be, p + 2, 2);
	j_qt          = ntohs(qt_be);
	j_cfg_present = 1;
	p += CL_CTR_CONFIG_SZ;
    }

    /* --- Parse the joiner's cluster-plane MTU (absent on older builds) --- */
    if (p + CL_CTR_MTU_SZ <= end) {
	uint16_t m_be;
	memcpy(&m_be, p, CL_CTR_MTU_SZ);
	j_mtu = ntohs(m_be);
	p += CL_CTR_MTU_SZ;
    }

    LM_INFO("clusterer_controller: [cluster %d] JOIN_REQ from %s "
            "(%d BIN socket(s))\n", cl->cluster_id, src_ip, bin_cnt);

    lock_start_write(cl->peers->lock);

    was_master = (cl->peers->node_state == CL_CTR_NODE_ACTIVE) &&
                 cl_ctr_i_am_master_locked(cl);

    if (!was_master) {
	/* Split-brain prevention: while we are ourselves still joining, record
	 * the other joiner so the join-deadline election can defer to the
	 * highest-IP starter instead of every node self-promoting into a
	 * divergent-key lone master.  (An active non-master simply ignores it;
	 * the master drives discovery.)                                        */
	if (cl->peers->node_state == CL_CTR_NODE_NEW) {
	    cl_ctr_upsert_peer_locked(src_ip, cl);
	    /* A fresh JOIN_REQ from a *higher-IP* peer proves it is still alive
	     * and joining, so reset our split-brain defer budget: keep waiting
	     * for it to become master instead of prematurely self-promoting into
	     * a divergent-key split brain.  join_defer_total still grows (hard
	     * cap) so a peer that is stuck forever cannot stall us indefinitely. */
	    if (ip_to_num(src_ip) > ip_to_num(my_ip))
		cl->join_defer_count = 0;
	}
	lock_stop_write(cl->peers->lock);
	LM_DBG("clusterer_controller: non-master ignoring JOIN_REQ from %s\n",
	       src_ip);
	return;
    }

    /* Config-consistency gate (master side): if the joiner advertises
     * consistency-critical settings that differ from the running cluster and
     * the policy is 'reject', refuse the join so the node shuts down rather
     * than joining and behaving inconsistently.  (warn/adopt admit the node;
     * the joiner then warns or adopts on the master's ALIVE.) */
    if (j_cfg_present && on_config_mismatch == CL_CTR_CFGMISMATCH_REJECT) {
	int loc_manage = cl->manage_shtags ? 1 : 0;
	int loc_stick  = cl->master_stickiness ? 1 : 0;
	if (j_manage != loc_manage || j_stick != loc_stick || j_qt != query_time) {
	    char diff[160];
	    /* Drop before releasing the lock: while we were ourselves NEW we may
	     * have upserted this joiner, and refusing alone would leave it in the
	     * table, so cl_ctr_cfg_note_reject() would count it as a member we
	     * hold and never fire.  Mirrors the MTU refusal below. */
	    cl_ctr_drop_peer_locked(src_ip, cl);
	    lock_stop_write(cl->peers->lock);
	    cl_ctr_fmt_cfg_diff(diff, sizeof(diff), "cluster", "node",
	                    loc_manage, j_manage, loc_stick, j_stick,
	                    query_time, j_qt);
	    LM_WARN("clusterer_controller: [cluster %d] rejecting JOIN_REQ from %s: "
	            "different settings than the running cluster (%s)\n",
	            cl->cluster_id, src_ip, diff);
	    cl_ctr_send_join_reject(sock, src_ip, cl, CL_CTR_REJECT_CONFIG);
	    cl_ctr_cfg_note_reject(src_ip, cl);
	    return;
	}
    }

    /* MTU gate (master side).  A cluster must have ONE MTU: an oversized
     * datagram is dropped by the small-MTU node's NIC with no ICMP to report
     * it (same L2 segment, so there is no router to generate one), and a
     * multicast sender has no path to discover.  So the receiver can never
     * observe the packet it failed to receive - the mismatch has to be caught
     * here, while both sides are still exchanging small handshake packets that
     * do arrive.
     *
     * Refuse BEFORE KEY_GRANT, which is key custody rather than speed: the
     * joiner holds no session key until KEY_GRANT hands it the ECDH-wrapped
     * master_salt, so refusing now means a mismatched node never obtains the
     * group key at all.  Admitting it and ejecting it later would have handed
     * it multicast decryption and required a key rotation to take that back.
     *
     * Unconditional - there is no policy modparam here, unlike the config gate
     * above.  A node that cannot participate must not serve SIP: without shared
     * usrloc, dialog replication and shtag coordination it would answer
     * REGISTERs into a local store and route on a partial view while the load
     * balancer kept feeding it calls.  Down is the honest state. */
    if (j_mtu > 0 && cc_mtu > 0 && j_mtu != cc_mtu) {
	/* Drop it before releasing the lock: while we were ourselves NEW we
	 * upserted every joiner we heard, so this peer may already be in the
	 * table and refusing the join alone would leave it there. */
	cl_ctr_drop_peer_locked(src_ip, cl);
	lock_stop_write(cl->peers->lock);
	LM_WARN("clusterer_controller: [cluster %d] rejecting JOIN_REQ from %s: "
	        "its cluster-plane MTU is %d, this cluster runs at %d. Every "
	        "member must agree, because an oversized datagram is dropped "
	        "silently by the smaller link.\n",
	        cl->cluster_id, src_ip, j_mtu, cc_mtu);
	cl_ctr_send_join_reject(sock, src_ip, cl, CL_CTR_REJECT_MTU);
	cl_ctr_mtu_note_reject(src_ip, cl);
	return;
    }
    if (j_mtu == 0) {
	/* Older build: it cannot tell us, so uniformity is unenforceable for
	 * this peer.  Admitting it is deliberate - refusing would make a
	 * rolling upgrade impossible, since every not-yet-upgraded node would
	 * be turned away by the first upgraded master. */
	LM_WARN("clusterer_controller: [cluster %d] %s did not advertise an "
	        "MTU (older build) - admitting it, but MTU uniformity is NOT "
	        "enforced for this peer until it is upgraded\n",
	        cl->cluster_id, src_ip);
    }

    /* Reject JOIN_REQ from an unknown IP when the peer table is full.
     * Known peers (reconnecting after restart) are still allowed through
     * since they already occupy a slot.                                   */
    if (cl->peers->count >= CL_CTR_MAX_PEERS) {
	int _found = 0, _fi;
	for (_fi = 0; _fi < cl->peers->count; _fi++) {
	    if (strcmp(cl->peers->entries[_fi].ip, src_ip) == 0) {
		_found = 1;
		break;
	    }
	}
	if (!_found) {
	    lock_stop_write(cl->peers->lock);
	    LM_WARN("clusterer_controller: [cluster %d] peer table full "
	            "(%d/%d), rejecting JOIN_REQ from %s\n",
	            cl->cluster_id, cl->peers->count, CL_CTR_MAX_PEERS, src_ip);
	    cl_ctr_send_join_reject(sock, src_ip, cl, CL_CTR_REJECT_GENERIC);
	    return;
	}
    }

    /* Upsert peer and store BIN info + node_id.
     * If this IP already has a node_id (rejoining after crash/restart),
     * reuse it so the id stays stable and clusterer stays in sync.     */
    cl_ctr_upsert_peer_locked(src_ip, cl);
    {
	int _i;
	new_id = 0;
	for (_i = 0; _i < cl->peers->count; _i++) {
	    if (strcmp(cl->peers->entries[_i].ip, src_ip) == 0) {
		new_id = cl->peers->entries[_i].node_id;
		break;
	    }
	}
	if (new_id == 0)
	    new_id = cl_ctr_alloc_node_id_locked(cl, src_ip);
    }
    cl_ctr_update_peer_bin_locked(src_ip, new_id,
                               bin_cnt,
                               (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])bin_socks,
                               cl);

    /* Admission records the joiner's incarnation and starts its replay
     * windows afresh.  Its session packets would reset them anyway on a higher
     * incarnation; doing it here also covers a joiner whose clock was stepped
     * back across its restart, whose new incarnation is LOWER than the one we
     * hold.  The NODE_ASSIGN below carries the same value to every member.  The
     * joiner's long-lived pubkey (for a future KEY_HANDOFF) is learned from its
     * ALIVE, not here - the JOIN_REQ carries only an ephemeral Noise key. */
    {
	cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, src_ip);
	if (e && pkt_inc != 0 && e->incarnation != pkt_inc) {
	    e->incarnation = pkt_inc;
	    cl_ctr_replay_reset(&e->replay);
	    cl_ctr_replay_reset(&e->replay_consumer);
	}
    }

    lock_stop_write(cl->peers->lock);

    /* JOIN_REQ decrypted successfully - clear any failure record for this IP
     * so a node that fixes its password isn't immediately rejected again. */
    {
        uint32_t _ip_num = ip_to_num(src_ip);
        int _fi;
        for (_fi = 0; _fi < CL_CTR_JOIN_FAIL_TABLE_SZ; _fi++) {
            if (cl->join_fail_tbl[_fi].ip_num == _ip_num) {
                memset(&cl->join_fail_tbl[_fi], 0, sizeof(cl->join_fail_tbl[_fi]));
                break;
            }
        }
    }

    /* Send KEY_GRANT first (bootstrap key) so joiner can derive session_key,
     * then NODE_ASSIGN + MEMBER_LIST (session key). */
    if (noise_msg1)   /* Noise msg 1 present -> run responder, answer msg 2 */
        cl_ctr_send_key_grant(sock, src_ip, cl, noise_msg1, noise_msg1_len,
                          src, src_len);

    lock_start_write(cl->peers->lock);

    /* Send NODE_ASSIGN for joining node */
    /* the newcomer's assignment must reach every member - multicast (a member
     * that misses it self-heals via the membership digest). */
    cl_ctr_send_node_assign(sock, src_ip, new_id, bin_cnt,
                        (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])bin_socks,
                        pkt_inc, cl, NULL, 0);

    /* Send NODE_ASSIGN for each existing peer so the joining node learns all
     * current node_ids and BIN sockets.  Only the joiner needs these, so unicast
     * them to it rather than re-multicasting to the whole cluster; a member that
     * would once have re-learned a peer from this burst now self-heals via the
     * membership digest instead. */
    for (i = 0; i < cl->peers->count; i++) {
	cl_ctr_peer_t *e = &cl->peers->entries[i];
	if (strcmp(e->ip, src_ip) == 0 || e->node_id == 0)
	    continue;
	cl_ctr_send_node_assign(sock, e->ip, e->node_id, e->bin_count,
	                    (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])e->bin_sockets,
	                    strcmp(e->ip, my_ip) == 0 ? cl_ctr_incarnation
	                                              : e->incarnation,
	                    cl, src, src_len);
    }

    /* A current master NEVER hands mastership to a joining node during the
     * join handshake - doing so forced the joiner to broadcast MASTER_ALIVE
     * before it had adopted the cluster key, producing a key-mismatch loop.
     *
     * Instead we stay master and designate ourselves in the MEMBER_LIST.  The
     * joiner adopts our session key via the KEY_GRANT sent above and joins as
     * a member.  If it has a higher IP it will win the very next ALIVE-driven
     * election (cl_ctr_handle_alive) - but by then it holds the key, so when it
     * takes over it broadcasts with a key every member already has.  This
     * keeps the deterministic "highest IP is master" outcome while deferring
     * the actual takeover until after the key has been transferred.         */
    lock_stop_write(cl->peers->lock);
    LM_INFO("clusterer_controller: [cluster %d] I am master, "
            "new node %s assigned node_id=%u\n",
            cl->cluster_id, src_ip, new_id);
    /* the joiner's authoritative snapshot - unicast to it (a member that misses
     * it self-heals via the membership digest; the joiner, via its JOIN_REQ retry). */
    cl_ctr_send_list_pkt(sock, CL_CTR_PKT_MEMBER_LIST, cl, src, src_len);

    /* ...and tell the REST of the cluster that this node joined, with the
     * incarnation it was admitted at (see cl_ctr_announce_full_state() for
     * why that must reach everyone).  Coalesced (and deferred, never dropped)
     * inside cl_ctr_announce_full_state. */
    {
        char why[64];
        snprintf(why, sizeof why, "node %s joined", src_ip);
        cl_ctr_announce_full_state(cl, why);
    }
}

/**
 * cl_ctr_handle_member_list() - process a CL_CTR_PKT_MEMBER_LIST from the master.
 *
 * This is THE authoritative packet for cluster state.  All nodes - both
 * the joining node and existing active members - update their peer tables
 * and master designation directly from this list.  No independent election
 * is run; the master's word is final.
 *
 * Joining node (CL_CTR_NODE_NEW):
 *   - Replaces its empty peer table with the master's list.
 *   - Transitions to CL_CTR_NODE_ACTIVE.
 *   - If the list designates us as master (our IP has is_master=1): we
 *     accept mastership immediately and log accordingly.
 *
 * Active member / old master (CL_CTR_NODE_ACTIVE):
 *   - Upserts any new peers from the list.
 *   - Applies master designation from the list (may demote old master).
 *   - Logs who is now master.
 */
void cl_ctr_handle_member_list(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl)
{
    uint16_t      count;
    uint16_t      forced_node_id;
    int           i;
    const char   *p;
    char          designated_master[CL_CTR_MAX_IP_LEN + 1];

    /* MEMBER_LIST is authoritative cluster state and must only come from the
     * current master.  Any cluster member holding the session key could forge
     * one; accepting it would let an insider demote the real master, inject
     * fake peers, or trigger spurious re-elections.
     * Own loopback (sender == my_ip) is allowed when we are the master. */
    if (strcmp(sender_ip, my_ip) == 0) {
	LM_DBG("clusterer_controller: ignoring own MEMBER_LIST loopback\n");
	return;
    }
    {
	int _from_master;
	lock_start_read(cl->peers->lock);
	_from_master = (cl->peers->last_master[0] != '\0' &&
	                strcmp(sender_ip, cl->peers->last_master) == 0);
	lock_stop_read(cl->peers->lock);
	if (!_from_master) {
	    /* Also allow during CL_CTR_NODE_NEW: we have no master yet, so any
	     * MEMBER_LIST is our first authoritative view of the cluster.  */
	    int _is_new;
	    lock_start_read(cl->peers->lock);
	    _is_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
	    lock_stop_read(cl->peers->lock);
	    if (!_is_new) {
		LM_WARN("clusterer_controller: MEMBER_LIST from non-master %s "
		        "(master is %s), dropping\n",
		        sender_ip,
		        cl->peers->last_master[0] ? cl->peers->last_master : "(none)");
		return;
	    }
	}
    }

    designated_master[0] = '\0';

    if (payload_len < CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ) {
	LM_WARN("clusterer_controller: MEMBER_LIST too short\n");
	return;
    }

    {
	uint16_t count_be, forced_be;
	memcpy(&count_be, payload, CL_CTR_LIST_COUNT_SZ);
	count = ntohs(count_be);
	/* forced-shtag node_id follows the count (0 = automatic allocation) */
	memcpy(&forced_be, payload + CL_CTR_LIST_COUNT_SZ, CL_CTR_NODE_ID_SZ);
	forced_node_id = ntohs(forced_be);
    }

    if (count > CL_CTR_MAX_PEERS) {
	LM_WARN("clusterer_controller: MEMBER_LIST count %u exceeds "
	        "max peers %d, dropping\n", count, CL_CTR_MAX_PEERS);
	return;
    }

    if (payload_len < CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ
                      + (int)count * CL_CTR_IP_ENTRY_SZ) {
	LM_WARN("clusterer_controller: MEMBER_LIST truncated "
	        "(count=%u, got %d bytes)\n", count, payload_len);
	return;
    }

    p = payload + CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ;

    /* Ordering.  The guard above admits lists only from the master we follow,
     * but not every list from it is current: a list from that same address's
     * EARLIER mastership can arrive late, and two lists of one mastership can
     * arrive in the wrong order - the replay window accepts a delayed packet
     * it has not seen, so applying it would wind state back (an operator's
     * clusterer_controller:shtag_force undone by the list that preceded it, for one).
     * Drop a list whose term is older than the master's MASTER_ALIVE term or
     * the last applied list's term, or that is not newer than the last list
     * applied from the same term.  The record is per master and is cleared
     * when the master changes or restarts (its MASTER_ALIVE then carries a
     * lower term).  A node still joining takes whatever it is given.  Lists
     * without a stamp (none exist on wire version 2) are applied as before. */
    {
	const char *st = p + (int)count * CL_CTR_IP_ENTRY_SZ;
	if (payload_len >= (int)(st - payload) + CL_CTR_LIST_STAMP_SZ) {
	    uint32_t t_be, s_be, lterm, lseq;
	    int is_new, stale;

	    memcpy(&t_be, st, 4);      lterm = ntohl(t_be);
	    memcpy(&s_be, st + 4, 4);  lseq  = ntohl(s_be);
	    lock_start_write(cl->peers->lock);
	    is_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
	    if (!cl_ctr_term_sane(cl, lterm, sender_ip)) {
		lock_stop_write(cl->peers->lock);
		return;
	    }
	    stale  = !is_new &&
	             (lterm < cl->peers->master_term ||
	              lterm < cl->peers->list_term_seen ||
	              (lterm == cl->peers->list_term_seen &&
	               lseq <= cl->peers->list_seq_seen));
	    if (!stale) {
		cl->peers->list_term_seen = lterm;
		cl->peers->list_seq_seen  = lseq;
	    }
	    lock_stop_write(cl->peers->lock);
	    if (stale) {
		LM_INFO("clusterer_controller: [cluster %d] MEMBER_LIST from %s "
		        "is older than the cluster state already applied (term "
		        "%u seq %u; master term %u, last applied term %u seq %u) - "
		        "dropped\n", cl->cluster_id, sender_ip, lterm, lseq,
		        cl->peers->master_term, cl->peers->list_term_seen,
		        cl->peers->list_seq_seen);
		return;
	    }
	}
    }

    /* First pass: collect designated master IP */
    for (i = 0; i < (int)count; i++) {
	const char   *entry     = p + i * CL_CTR_IP_ENTRY_SZ;
	unsigned char is_master = (unsigned char)entry[CL_CTR_IP_ENTRY_SZ - 1];
	if (is_master) {
	    memcpy(designated_master, entry, CL_CTR_MAX_IP_LEN);
	    designated_master[CL_CTR_MAX_IP_LEN] = '\0';
	    break;
	}
    }

    lock_start_write(cl->peers->lock);

    /* Second pass: learn the listed peers.  Their replay windows are NOT
     * reset here any more: a restarted peer is recognised by the higher
     * incarnation on its own packets (cl_ctr_check_and_update_seq), and
     * resetting every listed peer on every list re-admitted one replayed
     * packet per peer each time a list went out. */
    for (i = 0; i < (int)count; i++, p += CL_CTR_IP_ENTRY_SZ) {
	char ip_buf[CL_CTR_MAX_IP_LEN + 1];
	memcpy(ip_buf, p, CL_CTR_MAX_IP_LEN);
	ip_buf[CL_CTR_MAX_IP_LEN] = '\0';
	if (ip_buf[0] == '\0')
	    continue;
	/* Membership, not liveness - see cl_ctr_learn_peer_locked().  And never
	 * from our OWN echo: IP_MULTICAST_LOOP delivers the master's list back
	 * to the master, and learning from it re-inserts a peer the master just
	 * purged.  That closed a loop: the re-seeded copy kept the roster
	 * naming the dead node, every receiver re-learned it each window, and
	 * the purge could never converge (observed live as 'new peer' every
	 * 35 s for a node whose control plane was provably blocked).  The
	 * packet was built FROM this table; it cannot teach us anything. */
	if (strcmp(sender_ip, my_ip) != 0)
	    cl_ctr_learn_peer_locked(ip_buf, cl);
    }

    /* Snapshot master status BEFORE cl_ctr_apply_master_from_list_locked clears it */
    int was_master_before = cl_ctr_i_am_master_locked(cl);

    /* Apply the master designation from the list - no local election */
    if (designated_master[0] != '\0')
	cl_ctr_apply_master_from_list_locked(designated_master, cl);

    /* The master is authoritative for the shtag override too. */
    cl->peers->shtag_forced_node_id = forced_node_id;

    int was_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
    if (was_new) {
	/* Only act as master if the list designates us AND we already hold the
	 * cluster key.  Incumbent masters no longer hand over during a join, so
	 * in normal operation a MEMBER_LIST never designates a NEW node - this
	 * guard is defensive: without a key we would broadcast MASTER_ALIVE that
	 * no member can decrypt.  Without the key we join as a plain member and
	 * let a later election promote us once KEY_GRANT has landed.           */
	int _taking_over = (designated_master[0] != '\0'
	                    && strcmp(designated_master, my_ip) == 0
	                    && cl->have_session_key);
	cl->peers->node_state = CL_CTR_NODE_ACTIVE;
	if (_taking_over) {
	    lock_stop_write(cl->peers->lock);
	    LM_INFO("clusterer_controller: received MEMBER_LIST (%u members) "
	            "from existing master %s - taking over mastership "
	            "(my IP %s is higher)\n",
	            count, sender_ip, my_ip);
	} else {
	    lock_stop_write(cl->peers->lock);
	    LM_INFO("clusterer_controller: received MEMBER_LIST (%u members) "
	            "from %s - joined cluster as member, master is %s\n",
	            count, sender_ip,
	            designated_master[0] ? designated_master : "(none)");
	}
	cl_ctr_transition_to_active(cl);
	if (_taking_over)
	    cl_ctr_arm_master_timers(cl, 1);  /* start MASTER_ALIVE, disarm dead watchdog */
    } else {
	/* Active node - log the master update (may be self-demotion) */
	int i_am_master = (designated_master[0] != '\0' &&
	                   strcmp(designated_master, my_ip) == 0);
	lock_stop_write(cl->peers->lock);
	if (i_am_master) {
	    LM_INFO("clusterer_controller: MEMBER_LIST received - "
	            "I am master (%d members)\n", count);
	} else if (was_master_before) {
	    /* A genuine demotion: we held mastership until this MEMBER_LIST. */
	    LM_INFO("clusterer_controller: demoted to member - new master is %s "
	            "(%d members in cluster)\n",
	            designated_master[0] ? designated_master : "(none)",
	            count);
	    /* Fix up keepalive timers: stop sending MASTER_ALIVE, arm watchdog. */
	    cl_ctr_arm_master_timers(cl, 0);
	} else {
	    /* Already a member - this is just a routine MEMBER_LIST refresh (e.g.
	     * a periodic re-broadcast or a shtag-override update).  No role change,
	     * so don't cry "demoted"; log quietly at debug level. */
	    LM_DBG("clusterer_controller: MEMBER_LIST refreshed - master is %s "
	           "(%d members)\n",
	           designated_master[0] ? designated_master : "(none)", count);
	}
    }

    /* (Re)apply the shtag decision now that the forced-node override and the
     * master designation from this MEMBER_LIST have both been stored. */
    cl_ctr_apply_shtags(cl);
}

/**
 * cl_ctr_handle_node_assign() - process a CL_CTR_PKT_NODE_ASSIGN from the master.
 *
 * Payload: [node_id 2B BE][ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 *
 * All nodes (including master via loopback) apply the assignment:
 *   - Learn the peer entry if not already present, WITHOUT claiming liveness
 *     (see the note at the call site - the loopback made this a self-refresh).
 *   - Store node_id and BIN sockets.
 *   - If ip == my_ip: record my_node_id.
 */
void cl_ctr_handle_node_assign(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl)
{
    const char *p   = payload;
    const char *end = payload + payload_len;
    uint16_t    node_id;
    char        ip[CL_CTR_MAX_IP_LEN + 1];
    char        bin_socks[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
    uint8_t     bin_cnt = 0;
    uint64_t    inc = 0;
    int         ip_len, i;

    if (payload_len < (int)(CL_CTR_NODE_ID_SZ + 2)) {
	LM_WARN("clusterer_controller: NODE_ASSIGN payload too short\n");
	return;
    }

    /* node_id (2B BE) */
    memcpy(&node_id, p, CL_CTR_NODE_ID_SZ);
    node_id = ntohs(node_id);
    p += CL_CTR_NODE_ID_SZ;

    /* IP */
    ip_len = (int)strnlen(p, CL_CTR_MAX_IP_LEN);
    memcpy(ip, p, ip_len);
    ip[ip_len] = '\0';
    p += ip_len + 1;

    /* BIN sockets */
    memset(bin_socks, 0, sizeof(bin_socks));
    if (p < end) {
	bin_cnt = (uint8_t)*p++;
	if (bin_cnt > CL_CTR_MAX_BIN_SOCKETS)
	    bin_cnt = CL_CTR_MAX_BIN_SOCKETS;
	for (i = 0; i < (int)bin_cnt && p < end; i++) {
	    int slen = (int)strnlen(p, CL_CTR_MAX_BIN_SOCK_LEN - 1);
	    memcpy(bin_socks[i], p, slen);
	    bin_socks[i][slen] = '\0';
	    p += slen + 1;
	}
    }
    /* the incarnation the master admitted that node at */
    if (p + CL_CTR_INC_SZ <= end)
	for (i = 0; i < CL_CTR_INC_SZ; i++)
	    inc = (inc << 8) | (unsigned char)*p++;

    lock_start_write(cl->peers->lock);
    /* Membership, not liveness - the same distinction cl_ctr_learn_peer_locked()
     * exists for on the MEMBER_LIST path.  'ip' here comes from the PAYLOAD (the
     * node being assigned), not from sender_ip, so it is not evidence that that
     * node is reachable - only that the master still lists it.
     *
     * Upserting here was strictly worse than the member-list case, because it is
     * a SELF-loop rather than a peer-to-peer echo: IP_MULTICAST_LOOP means the
     * master receives its own NODE_ASSIGN, so every roster announcement refreshed
     * last_seen for every node it named, including a dead one.  The master is the
     * node that must prune, so cl_ctr_prune_stale() could never fire and the
     * corpse was immortal - measured on a 3-node staging cluster: a node isolated
     * for 4 minutes against a 30 s deadline was still a member on every survivor. */
    /* Same self-echo rule as the member-list path: the master must not
     * re-learn a peer from its own looped-back announcement. Receivers other
     * than the author still learn membership here as before. */
    if (strcmp(sender_ip, my_ip) != 0)
	cl_ctr_learn_peer_locked(ip, cl);
    cl_ctr_update_peer_bin_locked(ip, node_id, bin_cnt,
                               (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])bin_socks,
                               cl);
    /* Take the incarnation the master admitted this node at.  Normally we have
     * it already, from the node's own first packet after its restart; this is
     * what still works when that node's clock was stepped back across the
     * restart, so that its new incarnation reads LOWER than its old one and its
     * own packets would be refused as replays. */
    if (inc != 0 && strcmp(ip, my_ip) != 0 && strcmp(sender_ip, my_ip) != 0) {
	cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, ip);
	if (e && e->incarnation != inc) {
	    /* A restart is worth one line whichever path notices it first -
	     * usually this one, since the master announces the rejoin before
	     * the restarted node's own traffic reaches us. */
	    if (e->incarnation != 0)
		LM_INFO("clusterer_controller: [cluster %d] %s restarted "
		        "(incarnation %llu -> %llu, announced by master %s) - its "
		        "sequence numbers start again\n", cl->cluster_id, ip,
		        (unsigned long long)e->incarnation,
		        (unsigned long long)inc, sender_ip);
	    e->incarnation = inc;
	    cl_ctr_replay_reset(&e->replay);
	    cl_ctr_replay_reset(&e->replay_consumer);
	}
    }
    lock_stop_write(cl->peers->lock);

    /* Record our own node_id - also the first signal that a master exists */
    if (strcmp(ip, my_ip) == 0) {
	/* Always our own entry - update identity regardless of my_node_id */
	if (my_node_id == 0) {
	    int is_joining;
	    lock_start_read(cl->peers->lock);
	    is_joining = (cl->peers->node_state == CL_CTR_NODE_NEW);
	    lock_stop_read(cl->peers->lock);
	    if (is_joining)
		LM_INFO("clusterer_controller: [cluster %d] found existing master "
		        "at %s - receiving cluster state\n",
		        cl->cluster_id, sender_ip);
	}
	my_node_id = node_id;
	LM_INFO("clusterer_controller: [cluster %d] master %s assigned us "
	        "node_id=%u\n", cl->cluster_id, sender_ip, node_id);
	/* Correct the optimistic node_id=1 set at startup if needed */
	if (clctl_loaded) {
	    str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	    clctl.update_identity(cl->cluster_id, node_id, &url);
	}
    } else {
	LM_INFO("clusterer_controller: [cluster %d] master %s assigned "
	        "node_id=%u to %s\n", cl->cluster_id, sender_ip, node_id, ip);
	/* Add peer to clusterer */
	if (clctl_loaded && bin_cnt > 0) {
	    str url = {bin_socks[0], (int)strlen(bin_socks[0])};
	    clctl.add_node(cl->cluster_id, node_id, &url);
	}
    }
}

/**
 * cl_ctr_handle_key_grant() - process CL_CTR_PKT_KEY_GRANT from master.
 * Payload: [target_ip NUL][master_pubkey 32B][join_nonce 16B][wrapped_salt 32B]
 *
 * Recover master_salt via ECDH unwrap, derive session_key, update shm.
 * Only processed if target_ip == my_ip (multicast - all nodes receive it).
 */
void cl_ctr_handle_key_grant(const char *payload, int payload_len,
                                const char *sender_ip, cl_ctr_cluster_t *cl,
                                uint32_t in_seq, const unsigned char *pkt_cid,
                                const struct sockaddr *src, socklen_t src_len)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           target_ip[CL_CTR_MAX_IP_LEN + 1];
    unsigned char  new_salt[CL_CTR_MASTER_SALT_SZ];
    int            ip_len;

    /* Parse target_ip */
    ip_len = (int)strnlen(p, CL_CTR_MAX_IP_LEN);
    if (p + ip_len >= end) return;
    memcpy(target_ip, p, ip_len); target_ip[ip_len] = '\0';
    p += ip_len + 1;

    /* Only process if addressed to us */
    if (strcmp(target_ip, my_ip) != 0) return;

    /* Masters are the key source - they never accept KEY_GRANTs.
     * Without this guard a stale KEY_GRANT (from the previous master,
     * responding to a JOIN_REQ we sent while CL_CTR_NODE_NEW) can arrive
     * after we self-promoted via cl_ctr_on_join_tfd and overwrite the
     * session key we just generated, causing a key-mismatch loop. */
    {
        int _im;
        lock_start_read(cl->peers->lock);
        _im = cl_ctr_i_am_master_locked(cl);
        lock_stop_read(cl->peers->lock);
        if (_im) {
            LM_DBG("clusterer_controller: KEY_GRANT from %s ignored - "
                   "I am master\n", sender_ip);
            return;
        }
    }

    if (p + CL_CTR_NOISE_MSG2_SZ > end) {
        LM_WARN("clusterer_controller: KEY_GRANT too short\n");
        return;
    }

    /* Complete the Noise handshake: read msg 2 with the initiator state stored
     * when we sent the JOIN_REQ.  Its AEAD payload is the master_salt.  A stale
     * KEY_GRANT (for a superseded JOIN_REQ) fails here and is dropped - this
     * subsumes the old join_nonce echo check. */
    if (!cl->noise_hs_valid ||
        cl_ctr_noise_read2(&cl->noise_hs, cl->noise_e_priv,
                       (const unsigned char *)p, CL_CTR_NOISE_MSG2_SZ, new_salt) < 0) {
        LM_DBG("clusterer_controller: KEY_GRANT from %s did not complete the "
               "Noise handshake (stale or wrong key) - dropping\n", sender_ip);
        /* Clear join_pending so the next decryption failure or rejoin_tfd can
         * issue a fresh JOIN_REQ. */
        cl->join_pending = 0;
        /* If we already hold a session key, this is a duplicate of a KEY_GRANT
         * we handled whose ACK was lost - re-ACK so the master stops retrying. */
        if (cl->have_session_key)
            cl_ctr_send_ack(cl->sock, cl, in_seq, CL_CTR_PKT_KEY_GRANT,
                            1/*bootstrap*/, src, src_len);
        return;
    }
    cl->noise_hs_valid = 0;   /* handshake consumed */

    /* Apply: write to shm, derive session_key */
    lock_start_write(cl->peers->lock);
    memcpy(cl->peers->master_salt, new_salt, CL_CTR_MASTER_SALT_SZ);
    cl_ctr_derive_session_key(cl);
    lock_stop_write(cl->peers->lock);

    cl->join_pending           = 0;
    cl->bootstrap_auth_fails   = 0;
    cl->join_attempt_count     = 0;
    cl->auth_fail_pkts         = 0;   /* authenticated: clear wrong-password evidence */
    cl->auth_defer_count       = 0;
    lock_start_read(cl->peers->lock);
    if (cl->peers->node_state == CL_CTR_NODE_NEW) {
        memcpy(cl->granted_by, sender_ip, strnlen(sender_ip, CL_CTR_MAX_IP_LEN));
        cl->granted_by[strnlen(sender_ip, CL_CTR_MAX_IP_LEN)] = '\0';
    }
    lock_stop_read(cl->peers->lock);
    LM_INFO("clusterer_controller: [cluster %d] KEY_GRANT from %s - "
            "session key updated\n", cl->cluster_id, sender_ip);
    /* The master's cluster id came with its key, in the authenticated header
     * of this very packet: joining a cluster is adopting its identity. */
    if (pkt_cid && !cl_ctr_cid_is_zero(pkt_cid))
        cl_ctr_cid_adopt(cl, pkt_cid, "joined via KEY_GRANT");
    /* Acknowledge to the master (bootstrap key class, matching KEY_GRANT) so it
     * stops retransmitting.  Best-effort: a lost ACK just draws a retransmit,
     * which we re-ACK via the duplicate path above; never gates our join. */
    cl_ctr_send_ack(cl->sock, cl, in_seq, CL_CTR_PKT_KEY_GRANT,
                            1/*bootstrap*/, src, src_len);
}

/**
 * cl_ctr_handle_key_handoff() - process CL_CTR_PKT_KEY_HANDOFF.
 * Only acted on by the node that wins the next election (highest IP).
 * Payload: [next_master_ip NUL][crypto_box_seal(master_salt)]
 */
void cl_ctr_handle_key_handoff(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           target_ip[CL_CTR_MAX_IP_LEN + 1];
    unsigned char  new_salt[CL_CTR_MASTER_SALT_SZ];
    int            ip_len;

    ip_len = (int)strnlen(p, CL_CTR_MAX_IP_LEN);
    if (p + ip_len >= end) return;
    memcpy(target_ip, p, ip_len); target_ip[ip_len] = '\0';
    p += ip_len + 1;

    /* Only the intended next master unwraps this */
    if (strcmp(target_ip, my_ip) != 0) return;

    if (p + (int)(crypto_box_SEALBYTES + CL_CTR_MASTER_SALT_SZ) > end) {
        LM_WARN("clusterer_controller: KEY_HANDOFF too short\n");
        return;
    }
    /* Open the anonymous sealed box with our own long-lived keypair. */
    if (crypto_box_seal_open(new_salt, (const unsigned char *)p,
                             crypto_box_SEALBYTES + CL_CTR_MASTER_SALT_SZ,
                             cl->my_pubkey, cl->my_privkey) != 0) {
        LM_WARN("clusterer_controller: [cluster %d] KEY_HANDOFF from %s did not "
                "open - dropping\n", cl->cluster_id, sender_ip);
        return;
    }

    /* Store salt and re-derive so session_key is guaranteed consistent with
     * the adopted salt (the incoming master's salt may differ from ours). */
    lock_start_write(cl->peers->lock);
    memcpy(cl->peers->master_salt, new_salt, CL_CTR_MASTER_SALT_SZ);
    cl_ctr_derive_session_key(cl);   /* sets have_session_key = 1 */
    lock_stop_write(cl->peers->lock);

    LM_INFO("clusterer_controller: [cluster %d] KEY_HANDOFF from %s - "
            "master_salt preserved for seamless transition\n",
            cl->cluster_id, sender_ip);
}

/* -- Join-reject helpers ----------------------------------------------------
 *
 * Security model: JOIN_REJECT is sent as a normal CL_CTR_BOOTSTRAP_MAGIC packet
 * (XChaCha20-Poly1305 authenticated with the bootstrap key).  An attacker
 * without the cluster password cannot forge an authenticated reject, so they
 * cannot kick nodes out or block joins.  cl_ctr_handle_join_reject() also guards
 * on CL_CTR_NODE_NEW state so that even a legitimate cluster member with the
 * correct password cannot send a JOIN_REJECT to an already-active node.
 *
 * cl_ctr_join_fail_check() - master: track per-IP BOOTSTRAP_MAGIC decrypt failures.
 * Returns 1 the first time a source IP reaches CL_CTR_JOIN_FAIL_LIMIT failures.
 *
 * cl_ctr_send_join_reject() - master: send encrypted JOIN_REJECT via BOOTSTRAP_MAGIC.
 * Wire payload: [target_ip NUL]
 *
 * cl_ctr_handle_join_reject() - joiner: stop OpenSIPS if the reject is for us and
 * we are still in CL_CTR_NODE_NEW (i.e., have not successfully joined yet).
 *
 * WRONG-PASSWORD fallback: if the joiner has the wrong password it cannot
 * decrypt the encrypted JOIN_REJECT.  Instead it detects the situation
 * through bootstrap_auth_fails (incremented on any BOOTSTRAP_MAGIC decrypt
 * failure during CL_CTR_NODE_NEW) combined with join_attempt_count.  After
 * CL_CTR_JOIN_FAIL_LIMIT rejoin retries with at least one bootstrap failure
 * observed, the joiner concludes the master rejected it and exits.
 */

int cl_ctr_join_fail_check(const char *src_ip, cl_ctr_cluster_t *cl)
{
    uint32_t ip_num = ip_to_num(src_ip);
    int      evict  = 0;   /* index of lowest-count slot for eviction */
    int      i;

    if (ip_num == 0)
        return 0;

    for (i = 0; i < CL_CTR_JOIN_FAIL_TABLE_SZ; i++) {
        if (cl->join_fail_tbl[i].ip_num != ip_num)
            continue;
        if (cl->join_fail_tbl[i].rejected)
            return 0;   /* reject already sent; don't repeat */
        cl->join_fail_tbl[i].count++;
        if (cl->join_fail_tbl[i].count >= CL_CTR_JOIN_FAIL_LIMIT) {
            cl->join_fail_tbl[i].rejected = 1;
            return 1;
        }
        return 0;
    }

    /* Not found - insert, evicting the slot with the smallest count */
    for (i = 1; i < CL_CTR_JOIN_FAIL_TABLE_SZ; i++) {
        if (cl->join_fail_tbl[i].count < cl->join_fail_tbl[evict].count)
            evict = i;
    }
    memset(&cl->join_fail_tbl[evict], 0, sizeof(cl->join_fail_tbl[evict]));
    cl->join_fail_tbl[evict].ip_num = ip_num;
    snprintf(cl->join_fail_tbl[evict].ip, sizeof(cl->join_fail_tbl[evict].ip),
             "%s", src_ip);
    cl->join_fail_tbl[evict].count = 1;
    return 0;
}

void cl_ctr_send_join_reject(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                                int reason)
{
    /* +1 reason byte, +2 the master's MTU, +CL_CTR_CONFIG_SZ the master's
     * config triple.  All three are diagnostic only - NOT cluster state the
     * joiner adopts; they exist so the refused node's own log can name both
     * sides instead of leaving an operator to guess which is wrong, and so it
     * can refuse a refusal that contradicts itself (see
     * cl_ctr_handle_join_reject).  The MTU came first; the config triple is
     * the same idea applied to the reason an operator actually meets. */
    char               pkt[CL_CTR_SMALL_PKT_SZ + 1 + CL_CTR_MTU_SZ
                          + CL_CTR_CONFIG_SZ];
    uint32_t           seq = htonl(++cl->peers->my_seq);

    cl_ctr_note_join_refused(cl, target_ip,
                             reason == CL_CTR_REJECT_CONFIG ? "config"
                             : reason == CL_CTR_REJECT_MTU ? "mtu" : "refused");
    int                ip_len, plain_len;

    ip_len = (int)strnlen(target_ip, CL_CTR_MAX_IP_LEN);

    memcpy(pkt, CL_CTR_BOOTSTRAP_MAGIC, CL_CTR_MAGIC_SZ);
    pkt[CL_CTR_WIRE_HDR_SZ] = (char)CL_CTR_PKT_JOIN_REJECT;
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + 1, &seq, CL_CTR_SEQ_SZ);
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ, target_ip, ip_len);
    pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + ip_len]     = '\0';
    /* reason byte follows the NUL-terminated target IP */
    pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + ip_len + 1] = (char)reason;
    /* then our MTU, so a rejected node can log what it should have been */
    {
        uint16_t m = htons(cl_ctr_mtu_wire(cc_mtu));
        memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + ip_len + 2,
               &m, CL_CTR_MTU_SZ);
    }

    /* then our config triple, encoded exactly as JOIN_REQ carries the
     * joiner's: [manage 1B][stickiness 1B][query_time 2B BE] */
    {
	char    *c  = pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
	              + ip_len + 2 + CL_CTR_MTU_SZ;
	uint16_t qt = htons((uint16_t)(query_time & 0xFFFF));
	c[0] = (char)(cl->manage_shtags ? 1 : 0);
	c[1] = (char)(cl->master_stickiness ? 1 : 0);
	memcpy(c + 2, &qt, 2);
    }
    plain_len = CL_CTR_PLAIN_HDR_SZ + ip_len + 1 + 1 + CL_CTR_MTU_SZ
                + CL_CTR_CONFIG_SZ;
    if (cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->key, CL_CTR_PKT_JOIN_REJECT) == 0)
        LM_WARN("clusterer_controller: [cluster %d] sent JOIN_REJECT to %s (%s)\n",
                cl->cluster_id, target_ip,
                reason == CL_CTR_REJECT_CONFIG ? "different cluster settings" :
                reason == CL_CTR_REJECT_MTU    ? "different cluster-plane MTU"
                                           : "repeated auth failure - wrong password?");
}

void cl_ctr_handle_join_reject(const char *payload, int payload_len,
                                   const char *sender_ip, cl_ctr_cluster_t *cl)
{
    char target_ip[CL_CTR_MAX_IP_LEN + 1];
    int  l, still_new;

    /* Only act during the initial join phase.  An active member receiving a
     * JOIN_REJECT (e.g. from a cluster peer with the correct password who
     * wanted to test the mechanism, or a stale in-flight packet) must ignore
     * it - this prevents any cluster member from silently evicting another. */
    lock_start_read(cl->peers->lock);
    still_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
    lock_stop_read(cl->peers->lock);
    /* cl->join_pending is set whenever we have an admission request in flight -
     * including the split-brain merge, where cl_ctr_rejoin_superior_master()
     * sends a JOIN_REQ from the ACTIVE state to fetch the superior master's
     * key.  Testing node_state alone missed exactly that case: on a
     * simultaneous cold start BOTH nodes reach the join deadline, BOTH
     * self-promote, and the loser then merges - so it is ACTIVE, not NEW, when
     * its JOIN_REQ is refused, and it went on running with the reject
     * discarded.  A node that ASKED to be admitted must act on the refusal of
     * that request whatever state it thinks it is in - a NEW node by shutting
     * down, an ACTIVE one by abandoning the merge (below).  A settled member
     * with no request outstanding still ignores rejects, which is what stops
     * one member from evicting another. */
    if (!still_new && !cl->join_pending) return;

    l = (int)strnlen(payload, CL_CTR_MAX_IP_LEN);
    if (l >= payload_len) return;
    memcpy(target_ip, payload, l);
    target_ip[l] = '\0';

    if (strcmp(target_ip, my_ip) != 0)
        return;   /* not addressed to this node */

    /* reason byte follows the NUL-terminated target IP (older senders omit it) */
    {
        int reason = CL_CTR_REJECT_GENERIC;
        int their_mtu = 0;
        /* the master's config triple, absent on older senders */
        int cfg_present = 0, r_manage = 0, r_stick = 0, r_qt = 0;
        if (payload_len > l + 1)
            reason = (unsigned char)payload[l + 1];
        if (payload_len >= l + 2 + CL_CTR_MTU_SZ) {
            uint16_t m_be;
            memcpy(&m_be, payload + l + 2, CL_CTR_MTU_SZ);
            their_mtu = ntohs(m_be);
        }
        if (payload_len >= l + 2 + CL_CTR_MTU_SZ + CL_CTR_CONFIG_SZ) {
            const char *c = payload + l + 2 + CL_CTR_MTU_SZ;
            uint16_t    qt_be;
            r_manage = (unsigned char)c[0];
            r_stick  = (unsigned char)c[1];
            memcpy(&qt_be, c + 2, 2);
            r_qt        = ntohs(qt_be);
            cfg_present = 1;
        }
        /* Only act if the refusal is self-consistent with what WE measure: the
         * master says the cluster runs at X, and our own interface really is
         * not X.  A reject quoting our own MTU back at us is bogus and is
         * ignored - we check the kernel, not the sender's assertion. */
        if (reason == CL_CTR_REJECT_MTU && their_mtu > 0 && their_mtu == cc_mtu) {
            LM_WARN("clusterer_controller: [cluster %d] ignoring an MTU "
                    "JOIN_REJECT from %s that quotes %d - which is exactly this "
                    "node's own MTU, so the refusal contradicts itself\n",
                    cl->cluster_id, sender_ip, their_mtu);
            return;
        }
        /* Same self-consistency rule the MTU branch uses, for the same
         * reason: act on a refusal only if it disagrees with what WE hold.  A
         * CONFIG reject quoting our own triple back at us is bogus - a real
         * master only sends this reason when the values DIFFER - so it is
         * either a stale packet or a peer asserting something untrue, and
         * acting on it would let any PSK holder end a merging master. */
        if (reason == CL_CTR_REJECT_CONFIG && cfg_present
                && r_manage == (cl->manage_shtags ? 1 : 0)
                && r_stick  == (cl->master_stickiness ? 1 : 0)
                && r_qt     == (query_time & 0xFFFF)) {
            LM_WARN("clusterer_controller: [cluster %d] ignoring a CONFIG "
                    "JOIN_REJECT from %s that quotes manage_shtags=%d "
                    "master_stickiness=%d query_time=%d - which is exactly what "
                    "this node runs, so the refusal contradicts itself\n",
                    cl->cluster_id, sender_ip, r_manage, r_stick, r_qt);
            return;
        }
        /* An ESTABLISHED node was refused while merging into another
         * partition (cl_ctr_rejoin_superior_master()).  It does not exit: it
         * is a running member, possibly carrying calls, and its own partition
         * is still intact - so it stays there, as if it had never tried.  The
         * beacon now carries the settings and MTU, so a mismatched merge is
         * normally never attempted; this is the backstop.  Only a node that
         * has not yet joined anything (still NEW) still shuts down below:
         * for it, a refusal means it cannot be part of this cluster at all. */
        if (!still_new) {
            int  now_master;
            char diff[160];

            if (reason == CL_CTR_REJECT_CONFIG && cfg_present)
                cl_ctr_fmt_cfg_diff(diff, sizeof(diff), sender_ip, "this node",
                                    r_manage, cl->manage_shtags ? 1 : 0,
                                    r_stick,  cl->master_stickiness ? 1 : 0,
                                    r_qt,     query_time & 0xFFFF);
            else if (reason == CL_CTR_REJECT_MTU)
                snprintf(diff, sizeof(diff), "MTU %s=%d this node=%d",
                         sender_ip, their_mtu, cc_mtu);
            else
                snprintf(diff, sizeof(diff), "reason %d", reason);
            LM_WARN("clusterer_controller: [cluster %d] master %s refused to "
                    "admit this node while merging partitions (%s) - staying "
                    "with our own partition, and not trying %s again for %ds\n",
                    cl->cluster_id, sender_ip, diff, sender_ip,
                    CL_CTR_MERGE_REFUSE_SECS);
            snprintf(cl->merge_refused_ip, sizeof(cl->merge_refused_ip), "%s",
                     sender_ip);
            cl->merge_refused_until = cl_ctr_now() + CL_CTR_MERGE_REFUSE_SECS;
            cl->join_pending = 0;

            /* Undo what the merge attempt did: forget the refusing master
             * and elect among our own partition again. */
            lock_start_write(cl->peers->lock);
            cl_ctr_drop_peer_locked(sender_ip, cl);
            if (strcmp(cl->peers->last_master, sender_ip) == 0)
                cl->peers->last_master[0] = '\0';
            cl_ctr_elect_master(cl);
            now_master = cl_ctr_i_am_master_locked(cl);
            lock_stop_write(cl->peers->lock);
            if (now_master && cl->have_session_key)
                cl_ctr_arm_master_timers(cl, 1);
            cl_ctr_apply_shtags(cl);
            return;
        }
        if (reason == CL_CTR_REJECT_MTU)
            LM_CRIT("clusterer_controller: [cluster %d] JOIN_REJECT from %s - the "
                    "cluster runs at MTU %d, this node has %d on %s. Every member "
                    "must agree, because an oversized datagram is dropped silently "
                    "by the smaller link. Change the MTU of %s to %d (and persist "
                    "it in the boot config) or move this node to a matching "
                    "segment; shutting down\n",
                    cl->cluster_id, sender_ip, their_mtu, cc_mtu,
                    my_interface_buf[0] ? my_interface_buf : "(unknown interface)",
                    my_interface_buf[0] ? my_interface_buf : "the cluster interface",
                    their_mtu);
        else if (reason == CL_CTR_REJECT_CONFIG) {
            /* Name the values when the master sent them.  The node that dies is
             * the one an operator looks at first, and "settings differ" without
             * numbers sends them to read two config files by hand. */
            char diff[160];
            if (cfg_present) {
                cl_ctr_fmt_cfg_diff(diff, sizeof(diff), "cluster", "this node",
                                r_manage, cl->manage_shtags ? 1 : 0,
                                r_stick,  cl->master_stickiness ? 1 : 0,
                                r_qt,     query_time & 0xFFFF);
                LM_CRIT("clusterer_controller: [cluster %d] JOIN_REJECT from %s - "
                        "the running cluster has different settings than this node "
                        "(%s); fix the local config to match and restart; shutting "
                        "down\n", cl->cluster_id, sender_ip, diff);
            } else {
                LM_CRIT("clusterer_controller: [cluster %d] JOIN_REJECT from %s - the "
                        "running cluster has different settings than this node; fix the "
                        "local config (manage_shtags/master_stickiness/query_time) to "
                        "match and restart; shutting down\n",
                        cl->cluster_id, sender_ip);
            }
        }
        else
            LM_CRIT("clusterer_controller: [cluster %d] JOIN_REJECT from %s - "
                    "wrong password or unauthorized node; shutting down\n",
                    cl->cluster_id, sender_ip);
    }
    exit(-1);
}
