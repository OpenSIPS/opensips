/*
 * clusterer_controller - join protocol, both sides
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
#include "cl_ctr_stats.h"

/* timer side of NEW -> ACTIVE, on the join deadline or the master's
 * MEMBER_LIST; call with cl->peers->lock NOT held */
void cl_ctr_transition_to_active(cl_ctr_cluster_t *cl)
{
    cl_ctr_arm_tfd(cl->join_tfd,   0, 0);              /* disarm one-shot deadline */
    cl_ctr_arm_tfd(cl->rejoin_tfd, 0, 0);              /* disarm JOIN_REQ retry    */
    cl->granted_by[0]    = '\0';                        /* joined: forget the grant */
    cl->grant_wait_count = 0;
    cl->active_since_ms  = cl_ctr_now_ms();
    cl_ctr_send_alive(cl->sock, cl);
    cl_ctr_arm_tfd(cl->alive_tfd, query_time, query_time);
    cl_ctr_arm_tfd(cl->beat_tfd, CL_CTR_BEAT_SECS, CL_CTR_BEAT_SECS);
}

/* only the consistency-critical settings that differ, e.g.
 * "manage_shtags cluster=1 node=0"; la/lb label the local and peer side */
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

/* on_config_mismatch=adopt: a non-master takes the master's settings;
 * call WITHOUT cl->peers->lock held */
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

    /* query_time is per-process after fork, one worker per cluster, so this
     * changes only this cluster; election window and purge read it live */
    if (new_qt >= 1 && new_qt != query_time) {
        query_time = new_qt;
        if (is_active)
            cl_ctr_arm_tfd(cl->alive_tfd, query_time, query_time);
    }

    /* effective values, for clusterer:list_config in the MI process */
    cl->peers->eff_manage_shtags     = new_manage ? 1 : 0;
    cl->peers->eff_master_stickiness = cl->master_stickiness;
    cl->peers->eff_query_time        = query_time;

    if ((new_manage ? 1 : 0) != old_manage) {
        cl->manage_shtags = new_manage ? 1 : 0;
        if (clctl_loaded) {
            if (cl->manage_shtags)
                clusterer_ctrl_set_shtag_managed(cl->cluster_id);
            else
                clusterer_ctrl_unset_shtag_managed(cl->cluster_id);
        }
        /* Reconcile tag state under the new policy (no-op when now unmanaged). */
        cl_ctr_apply_shtags(cl);
    }
}

/* election is highest-IP and MTU-blind, so a wrong-MTU master refuses the
 * fleet: after several distinct refusals while alone, say it is us */
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

    /* warn only: stepping down on others' word would let a bootstrap-key
     * holder force re-elections */
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

/* config analogue of cl_ctr_mtu_note_reject(): election is just as blind to
 * manage_shtags, master_stickiness and query_time */
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

/* payload: [ip NUL][bin_count 1B][sock NUL]..., then optional Noise msg 1,
 * config, MTU and requested node_id; only an active master admits */
void cl_ctr_handle_join_req(int sock, const char *payload, int payload_len,
                               uint64_t pkt_inc, const unsigned char *req_nonce,
                               const char *sender_ip, cl_ctr_cluster_t *cl,
                               const struct sockaddr *src, socklen_t src_len)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           src_ip[CL_CTR_MAX_IP_LEN + 1];
    char           bin_socks[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
    const unsigned char *noise_msg1 = NULL;   /* points into payload */
    int            noise_msg1_len = 0;
    struct sockaddr_in joiner;
    uint8_t        bin_cnt   = 0;
    int            ip_len, was_master, i;
    int            j_cfg_present = 0, j_manage = 0, j_stick = 0, j_qt = 0;
    int            j_mtu = 0;
    uint16_t       j_prop = 0;  /* the id it asks for; 0 = none (older build) */
    uint32_t       j_caps = 0;  /* CL_CTR_CAP_*; 0 = none (older build) */
    uint16_t       j_qlen = 0;
    int            admit;
    uint16_t       new_id;

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
    if (!cl_ctr_ip_valid(src_ip)) {
	LM_WARN("clusterer_controller: [cluster %d] JOIN_REQ from %s names no "
	        "valid address, dropping\n", cl->cluster_id, sender_ip);
	return;
    }
    /* a node asks to be admitted for itself, and no other */
    if (strcmp(src_ip, sender_ip) != 0) {
	LM_DBG("clusterer_controller: [cluster %d] JOIN_REQ for %s sealed by "
	       "%s, dropping\n", cl->cluster_id, src_ip, sender_ip);
	return;
    }
    /* reply to the joiner's own address, not the datagram source, so a JOIN_REQ
     * replayed from elsewhere cannot aim our replies at someone else */
    if (cl_ctr_node_addr(cl, src_ip, &joiner) < 0)
	return;
    src     = (const struct sockaddr *)&joiner;
    src_len = sizeof(joiner);

    memset(bin_socks, 0, sizeof(bin_socks));
    if (p < end) {
	bin_cnt = (uint8_t)*p++;
	if (bin_cnt > CL_CTR_MAX_BIN_SOCKETS)
	    bin_cnt = CL_CTR_MAX_BIN_SOCKETS;
	for (i = 0; i < (int)bin_cnt && p < end; i++) {
	    /* bounded by the payload too, and the NUL must lie inside it */
	    int room = (int)(end - p);
	    int slen = (int)strnlen(p, room < CL_CTR_MAX_BIN_SOCK_LEN - 1
	                               ? (size_t)room : CL_CTR_MAX_BIN_SOCK_LEN - 1);
	    if (slen >= room)
		break;
	    memcpy(bin_socks[i], p, slen);
	    bin_socks[i][slen] = '\0';
	    p += slen + 1;
	}
	bin_cnt = (uint8_t)i;
    }

    if (p + CL_CTR_NOISE_MSG1_SZ <= end) {
	noise_msg1     = (const unsigned char *)p;
	noise_msg1_len = CL_CTR_NOISE_MSG1_SZ;
	p += CL_CTR_NOISE_MSG1_SZ;
    }

    if (p + CL_CTR_CONFIG_SZ <= end) {
	uint16_t qt_be;
	j_manage = (unsigned char)p[0];
	j_stick  = (unsigned char)p[1];
	memcpy(&qt_be, p + 2, 2);
	j_qt          = ntohs(qt_be);
	j_cfg_present = 1;
	p += CL_CTR_CONFIG_SZ;
    }

    if (p + CL_CTR_MTU_SZ <= end) {
	uint16_t m_be;
	memcpy(&m_be, p, CL_CTR_MTU_SZ);
	j_mtu = ntohs(m_be);
	p += CL_CTR_MTU_SZ;
    }

    if (p + CL_CTR_PROPOSAL_SZ <= end) {
	uint16_t pr_be;
	memcpy(&pr_be, p, CL_CTR_PROPOSAL_SZ);
	j_prop = ntohs(pr_be);
	p += CL_CTR_PROPOSAL_SZ;
    }

    if (p + CL_CTR_JOIN_CAPS_SZ <= end) {
	uint32_t c_be;
	memcpy(&c_be, p, CL_CTR_JOIN_CAPS_SZ);
	j_caps = ntohl(c_be);
    }

    LM_INFO("clusterer_controller: [cluster %d] JOIN_REQ from %s "
            "(%d BIN socket(s))\n", cl->cluster_id, src_ip, bin_cnt);

    lock_start_write(cl->peers->lock);

    was_master = (cl->peers->node_state == CL_CTR_NODE_ACTIVE) &&
                 cl_ctr_i_am_master_locked(cl);

    if (!was_master) {
	int jw = 0;

	/* still joining: record the other joiner so the join-deadline election defers
	 * to the highest-IP starter instead of each self-promoting with its own key */
	if (cl->peers->node_state == CL_CTR_NODE_NEW) {
	    cl_ctr_upsert_peer_locked(src_ip, cl);
	    /* a higher-IP joiner is alive: restart our defer budget; join_defer_total
	     * still grows, capping how long a stuck peer can stall us */
	    if (ip_to_num(src_ip) > ip_to_num(my_ip))
		cl->join_defer_count = 0;
	} else if (cl->peers->node_state == CL_CTR_NODE_ACTIVE) {
	    /* a member hearing no master: the joiner is told to wait, so it does
	     * not found a cluster of its own while this one elects */
	    long long ref = cl->master_heard_ms > cl->active_since_ms
	                    ? cl->master_heard_ms : cl->active_since_ms;
	    if (cl->peers->last_master[0] == '\0' ||
	            cl_ctr_now_ms() - ref > CL_CTR_JW_MASTER_SILENT_MS)
		jw = cl_ctr_join_wait_due(cl, src_ip);
	}
	lock_stop_write(cl->peers->lock);
	if (jw) {
	    LM_INFO("clusterer_controller: [cluster %d] no master heard - telling "
	            "joiner %s to wait for one\n", cl->cluster_id, src_ip);
	    cl_ctr_send_join_wait(sock, src_ip, cl, 0, 0, req_nonce, src, src_len);
	} else {
	    LM_DBG("clusterer_controller: non-master ignoring JOIN_REQ from %s\n",
	           src_ip);
	}
	return;
    }

    /* policy reject: a joiner with other settings is refused and shuts down;
     * warn/adopt admit it, and it acts on the master's ALIVE */
    if (j_cfg_present && on_config_mismatch == CL_CTR_CFGMISMATCH_REJECT) {
	int loc_manage = cl->manage_shtags ? 1 : 0;
	int loc_stick  = cl->master_stickiness ? 1 : 0;
	if (j_manage != loc_manage || j_stick != loc_stick || j_qt != query_time) {
	    char diff[160];
	    /* drop it before unlocking: upserted while we were NEW, it would count as a
	     * member held and keep cl_ctr_cfg_note_reject() from firing */
	    cl_ctr_drop_peer_locked(src_ip, cl);
	    lock_stop_write(cl->peers->lock);
	    cl_ctr_fmt_cfg_diff(diff, sizeof(diff), "cluster", "node",
	                    loc_manage, j_manage, loc_stick, j_stick,
	                    query_time, j_qt);
	    LM_WARN("clusterer_controller: [cluster %d] rejecting JOIN_REQ from %s: "
	            "different settings than the running cluster (%s)\n",
	            cl->cluster_id, src_ip, diff);
	    cl_ctr_send_join_reject(sock, src_ip, cl, CL_CTR_REJECT_CONFIG, req_nonce);
	    cl_ctr_cfg_note_reject(src_ip, cl);
	    return;
	}
    }

    /* one MTU per cluster: an oversized datagram dies silently on the smaller
     * link (no ICMP on one segment), so catch it while handshake packets fit */
    if (j_mtu > 0 && cc_mtu > 0 && j_mtu != cc_mtu) {
	/* before KEY_GRANT, so it never gets the group key; no policy knob - a node
	 * that cannot take part must not serve SIP */
	cl_ctr_drop_peer_locked(src_ip, cl);
	lock_stop_write(cl->peers->lock);
	LM_WARN("clusterer_controller: [cluster %d] rejecting JOIN_REQ from %s: "
	        "its cluster-plane MTU is %d, this cluster runs at %d. Every "
	        "member must agree, because an oversized datagram is dropped "
	        "silently by the smaller link.\n",
	        cl->cluster_id, src_ip, j_mtu, cc_mtu);
	cl_ctr_send_join_reject(sock, src_ip, cl, CL_CTR_REJECT_MTU, req_nonce);
	cl_ctr_mtu_note_reject(src_ip, cl);
	return;
    }
    /* table full: refuse a new IP; a known one rejoining keeps its slot */
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
	    cl_ctr_send_join_reject(sock, src_ip, cl, CL_CTR_REJECT_GENERIC, req_nonce);
	    return;
	}
    }

    admit = cl_ctr_admit_gate_locked(cl, src_ip, &j_qlen);
    if (admit > 0) {
	lock_stop_write(cl->peers->lock);
	cl_ctr_send_join_wait(sock, src_ip, cl, (uint16_t)admit, j_qlen, req_nonce,
	                      src, src_len);
	return;
    }

    /* a rejoining IP keeps its node_id, so clusterer stays in sync */
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
	    new_id = cl_ctr_alloc_node_id_locked(cl, src_ip, j_prop);
    }
    cl_ctr_update_peer_bin_locked(src_ip, new_id,
                               bin_cnt,
                               (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])bin_socks,
                               cl);

    /* reset here too: a joiner whose clock stepped back restarts with a LOWER
     * incarnation, which its own packets cannot reset */
    {
	cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, src_ip);
	if (e && pkt_inc != 0 && e->incarnation != pkt_inc) {
	    e->incarnation = pkt_inc;
	    cl_ctr_replay_reset(&e->replay);
	}
	/* CONNECTING; its JOIN_REQ's caps stand until its first ALIVE, so the
	 * cluster keeps its capabilities meanwhile */
	if (e) {
	    if (!e->connecting) {
		e->conn_since_ms = cl_ctr_now_ms();
		e->conn_warned   = 0;
		e->conn_parked   = 0;
	    }
	    e->connecting = 1;
	    e->caps       = j_caps;
	    e->caps_ms    = cl_ctr_now_ms();
	}
    }

    lock_stop_write(cl->peers->lock);
    LM_INFO("clusterer_controller: [cluster %d] admitting %s - CONNECTING "
            "until its links to every member are up\n", cl->cluster_id, src_ip);
    cl_ctr_note_admission(cl, src_ip, new_id, "connecting");

    /* authenticated: forget its failures, so a fixed password is not refused */
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

    /* the newcomer's assignment must reach every member - multicast (a member
     * that misses it self-heals via the membership digest). */
    cl_ctr_send_node_assign(sock, src_ip, new_id, bin_cnt,
                        (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])bin_socks,
                        pkt_inc, cl, NULL, 0);

    /* no handover in the handshake: a higher-IP joiner takes over at the next
     * ALIVE election, once it holds the key */
    lock_stop_write(cl->peers->lock);
    LM_INFO("clusterer_controller: [cluster %d] I am master, "
            "new node %s assigned node_id=%u\n",
            cl->cluster_id, src_ip, new_id);
    /* every existing peer's assignment, to the joiner only, within this second's
     * budget: a cold start would otherwise cost one per pair */
    if (cl_ctr_state_unicast_due(cl))
        cl_ctr_send_assigns_to(cl, src_ip, src, src_len);
    else
        LM_DBG("clusterer_controller: [cluster %d] %s gets the others' "
               "assignments from the next full state\n", cl->cluster_id, src_ip);
    /* the joiner's snapshot, unicast to it; its JOIN_REQ retry recovers a lost one */
    cl_ctr_send_list_pkt(sock, CL_CTR_PKT_MEMBER_LIST, cl, src, src_len);

    /* the rest of the cluster learns the admitted incarnation too - see
     * cl_ctr_announce_full_state() for why; it coalesces */
    {
        char why[64];
        snprintf(why, sizeof why, "node %s joined", src_ip);
        cl_ctr_announce_full_state(cl, why);
    }
}

/* the master's authoritative cluster state: every node applies it as is,
 * with no local election; a NEW node becomes ACTIVE on it */
void cl_ctr_handle_member_list(const char *payload, int payload_len,
                                  const char *sender_ip, cl_ctr_cluster_t *cl)
{
    uint16_t      count;
    uint16_t      forced_node_id;
    int           i;
    const char   *p;
    char          designated_master[CL_CTR_MAX_IP_LEN + 1];

    /* only from the master we follow: any session-key holder could forge one
     * to demote the master or inject peers */
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
	    /* still NEW: no master yet, so any list is our first view */
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

    /* the replay window admits a late list, which would wind state back (an
     * undone shtag_force): drop one not newer by (term, seq) unless joining */
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

    /* second pass: learn the peers but leave their replay windows - resetting
     * them would re-admit one replayed packet per peer per list */
    for (i = 0; i < (int)count; i++, p += CL_CTR_IP_ENTRY_SZ) {
	char ip_buf[CL_CTR_MAX_IP_LEN + 1];
	memcpy(ip_buf, p, CL_CTR_MAX_IP_LEN);
	ip_buf[CL_CTR_MAX_IP_LEN] = '\0';
	if (ip_buf[0] == '\0')
	    continue;
	/* membership, not liveness; never from our own looped-back list, which would
	 * re-insert a peer we just purged so the purge never converges */
	if (strcmp(sender_ip, my_ip) != 0)
	    cl_ctr_learn_peer_locked(ip_buf, cl);
    }

    /* Snapshot master status BEFORE cl_ctr_apply_master_from_list_locked clears it */
    int was_master_before = cl_ctr_i_am_master_locked(cl);

    if (designated_master[0] != '\0')
	cl_ctr_apply_master_from_list_locked(designated_master, cl);

    /* The master is authoritative for the shtag override too. */
    cl->peers->shtag_forced_node_id = forced_node_id;

    int was_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
    /* queued, it could not read its master's keepalive, and the joiners it
     * heard are no members: the list sets the window, or it elects itself */
    if (was_new && designated_master[0] != '\0' &&
            strcmp(sender_ip, designated_master) == 0) {
	const char *lp = payload + CL_CTR_LIST_COUNT_SZ + CL_CTR_NODE_ID_SZ;
	int k, j, listed;

	cl_ctr_upsert_peer_locked(sender_ip, cl);
	for (k = 0; k < cl->peers->count; k++) {
	    cl_ctr_peer_t *e = &cl->peers->entries[k];
	    if (strcmp(e->ip, my_ip) == 0)
		continue;
	    for (j = 0, listed = 0; j < (int)count && !listed; j++)
		listed = (strncmp(e->ip, lp + j * CL_CTR_IP_ENTRY_SZ,
		                  CL_CTR_MAX_IP_LEN) == 0);
	    if (!listed) {
		e->last_seen   = 0;
		e->in_election = 0;
	    }
	}
    }
    if (was_new) {
	/* defensive, a list never names a NEW node master: without the key our
	 * MASTER_ALIVE would be unreadable, so join as a member until KEY_GRANT */
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
	    LM_INFO("clusterer_controller: demoted to member - new master is %s "
	            "(%d members in cluster)\n",
	            designated_master[0] ? designated_master : "(none)",
	            count);
	    /* Fix up keepalive timers: stop sending MASTER_ALIVE, arm watchdog. */
	    cl_ctr_arm_master_timers(cl, 0);
	} else {
	    /* routine refresh (re-broadcast, shtag override): no role change */
	    LM_DBG("clusterer_controller: MEMBER_LIST refreshed - master is %s "
	           "(%d members)\n",
	           designated_master[0] ? designated_master : "(none)", count);
	}
    }

    /* (Re)apply the shtag decision now that the forced-node override and the
     * master designation from this MEMBER_LIST have both been stored. */
    cl_ctr_apply_shtags(cl);
}

/* payload: [node_id 2B BE][ip NUL][bin_count 1B][sock NUL]..[incarnation 8B];
 * every node applies it, the master too (multicast loop) */
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

    memcpy(&node_id, p, CL_CTR_NODE_ID_SZ);
    node_id = ntohs(node_id);
    p += CL_CTR_NODE_ID_SZ;

    ip_len = (int)strnlen(p, CL_CTR_MAX_IP_LEN);
    if (p + ip_len >= end) {
	LM_WARN("clusterer_controller: NODE_ASSIGN payload truncated\n");
	return;
    }
    memcpy(ip, p, ip_len);
    ip[ip_len] = '\0';
    p += ip_len + 1;
    /* a master assigns ids 1..CL_CTR_MAX_PEERS to addresses, nothing else */
    if (node_id == 0 || node_id > CL_CTR_MAX_PEERS || !cl_ctr_ip_valid(ip)) {
	LM_WARN("clusterer_controller: [cluster %d] NODE_ASSIGN from %s names "
	        "no valid node_id and address, dropping\n", cl->cluster_id,
	        sender_ip);
	return;
    }

    memset(bin_socks, 0, sizeof(bin_socks));
    if (p < end) {
	bin_cnt = (uint8_t)*p++;
	if (bin_cnt > CL_CTR_MAX_BIN_SOCKETS)
	    bin_cnt = CL_CTR_MAX_BIN_SOCKETS;
	for (i = 0; i < (int)bin_cnt && p < end; i++) {
	    /* bounded by the payload too, and the NUL must lie inside it */
	    int room = (int)(end - p);
	    int slen = (int)strnlen(p, room < CL_CTR_MAX_BIN_SOCK_LEN - 1
	                               ? (size_t)room : CL_CTR_MAX_BIN_SOCK_LEN - 1);
	    if (slen >= room)
		break;
	    memcpy(bin_socks[i], p, slen);
	    bin_socks[i][slen] = '\0';
	    p += slen + 1;
	}
	bin_cnt = (uint8_t)i;
    }
    /* the incarnation the master admitted that node at */
    if (p + CL_CTR_INC_SZ <= end)
	for (i = 0; i < CL_CTR_INC_SZ; i++)
	    inc = (inc << 8) | (unsigned char)*p++;

    /* Our own entry: before anything is written */
    if (strcmp(ip, my_ip) == 0) {
	int follow;
	lock_start_read(cl->peers->lock);
	follow = cl->peers->node_state == CL_CTR_NODE_NEW || cl->join_pending
	         || strcmp(sender_ip, my_ip) == 0
	         || strcmp(sender_ip, cl->peers->last_master) == 0;
	lock_stop_read(cl->peers->lock);
	/* only the master we follow, or answer while joining, may re-identify us -
	 * not another node, nor a recording sent again */
	if (!follow) {
	    LM_DBG("clusterer_controller: [cluster %d] NODE_ASSIGN for this node "
	           "from %s, which is not the master it follows - ignored\n",
	           cl->cluster_id, sender_ip);
	    return;
	}
    }

    lock_start_write(cl->peers->lock);
    /* membership, not liveness: 'ip' is the payload's, not the sender; never
     * from our own looped-back announcement, as on the member-list path */
    if (strcmp(sender_ip, my_ip) != 0)
	cl_ctr_learn_peer_locked(ip, cl);
    {
	/* two addresses on one id can only come from a confusion upstream -
	 * say so, once a minute; the assignment still applies */
	static time_t dup_warned_at;
	int k;
	for (k = 0; k < cl->peers->count; k++) {
	    cl_ctr_peer_t *o = &cl->peers->entries[k];
	    if (o->node_id == node_id && strcmp(o->ip, ip) != 0) {
		time_t now = cl_ctr_now();
		if (dup_warned_at == 0 || now - dup_warned_at >= CL_CTR_WIRE_WARN_IVL) {
		    dup_warned_at = now;
		    LM_WARN("clusterer_controller: [cluster %d] %s assigned "
		            "node_id %u to %s, which %s holds\n", cl->cluster_id,
		            sender_ip, node_id, ip, o->ip);
		}
		break;
	    }
	}
    }
    cl_ctr_update_peer_bin_locked(ip, node_id, bin_cnt,
                               (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])bin_socks,
                               cl);
    /* the admitted incarnation: covers a node whose clock stepped back, whose
     * own packets would be refused as replays */
    if (inc != 0 && strcmp(ip, my_ip) != 0 && strcmp(sender_ip, my_ip) != 0) {
	cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, ip);
	if (e && e->incarnation != inc) {
	    /* logged here: the master's announcement usually beats the node's own traffic */
	    if (e->incarnation != 0)
		LM_INFO("clusterer_controller: [cluster %d] %s restarted "
		        "(incarnation %llu -> %llu, announced by master %s) - its "
		        "sequence numbers start again\n", cl->cluster_id, ip,
		        (unsigned long long)e->incarnation,
		        (unsigned long long)inc, sender_ip);
	    e->incarnation = inc;
	    cl_ctr_replay_reset(&e->replay);
	}
    }
    lock_stop_write(cl->peers->lock);

    /* Record our own node_id - also the first signal that a master exists */
    if (strcmp(ip, my_ip) == 0) {
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
	    clusterer_ctrl_update_identity(cl->cluster_id, node_id, &url);
	}
    } else {
	LM_INFO("clusterer_controller: [cluster %d] master %s assigned "
	        "node_id=%u to %s\n", cl->cluster_id, sender_ip, node_id, ip);
	if (clctl_loaded && bin_cnt > 0) {
	    str url = {bin_socks[0], (int)strlen(bin_socks[0])};
	    clusterer_ctrl_add_node(cl->cluster_id, node_id, &url);
	}
    }
}

/* payload: [target_ip NUL][Noise msg 2, carrying master_salt]; multicast, so
 * only the node it names acts on it */
void cl_ctr_handle_key_grant(const char *payload, int payload_len,
                                const char *sender_ip, cl_ctr_cluster_t *cl,
                                uint32_t in_seq, const unsigned char *pkt_cid,
                                const struct sockaddr *src, socklen_t src_len)
{
    const char    *p         = payload;
    const char    *end       = payload + payload_len;
    char           target_ip[CL_CTR_MAX_IP_LEN + 1];
    unsigned char  new_salt[CL_CTR_MASTER_SALT_SZ];
    cl_ctr_symstate_t hs;
    int            ip_len;

    ip_len = (int)strnlen(p, CL_CTR_MAX_IP_LEN);
    if (p + ip_len >= end) return;
    memcpy(target_ip, p, ip_len); target_ip[ip_len] = '\0';
    p += ip_len + 1;

    if (strcmp(target_ip, my_ip) != 0) return;

    /* masters never take a KEY_GRANT: a stale one arriving after we
     * self-promoted would overwrite the key we just generated */
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

    /* read msg 2 on a copy of our JOIN_REQ's state: a stale or replayed grant
     * fails the tag but would spoil the state for the genuine one */
    hs = cl->noise_hs;
    if (!cl->noise_hs_valid ||
        cl_ctr_noise_read2(&hs, cl->noise_e_priv,
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
    /* ACK under the bootstrap key so the master stops retransmitting; a lost one
     * is re-ACKed on the duplicate path above */
    cl_ctr_send_ack(cl->sock, cl, in_seq, CL_CTR_PKT_KEY_GRANT,
                            1/*bootstrap*/, src, src_len);
}

/* payload: [next_master_ip NUL][crypto_box_seal(master_salt)]; only the
 * node it names, the next master, opens it */
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

/* master: count bootstrap decrypt failures per IP; 1 the first time one
 * reaches CL_CTR_JOIN_FAIL_LIMIT */
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

/* payload: [target_ip NUL][reason][MTU 2B][config 4B][nonce 24B], sealed
 * with the bootstrap key, so only a password holder can forge a refusal */
void cl_ctr_send_join_reject(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                                int reason, const unsigned char *req_nonce)
{
    /* MTU and config are diagnostic, never adopted: the refused node logs both
     * sides and can ignore a refusal that contradicts itself */
    char               pkt[CL_CTR_SMALL_PKT_SZ + 1 + CL_CTR_MTU_SZ
                          + CL_CTR_CONFIG_SZ + CL_CTR_NONCE_SZ];
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
    pkt[CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + ip_len + 1] = (char)reason;
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

    /* last, the nonce of the packet refused: the joiner acts only on a
     * refusal of a request it sent itself (cl_ctr_handle_join_reject) */
    memcpy(pkt + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ + ip_len + 2
               + CL_CTR_MTU_SZ + CL_CTR_CONFIG_SZ, req_nonce, CL_CTR_NONCE_SZ);
    plain_len = CL_CTR_PLAIN_HDR_SZ + ip_len + 1 + 1 + CL_CTR_MTU_SZ
                + CL_CTR_CONFIG_SZ + CL_CTR_NONCE_SZ;
    if (cl_ctr_seal_and_send(sock, cl, pkt, plain_len, cl->key, CL_CTR_PKT_JOIN_REJECT) == 0)
        LM_WARN("clusterer_controller: [cluster %d] sent JOIN_REJECT to %s (%s)\n",
                cl->cluster_id, target_ip,
                reason == CL_CTR_REJECT_CONFIG ? "different cluster settings" :
                reason == CL_CTR_REJECT_MTU    ? "different cluster-plane MTU"
                                           : "repeated auth failure - wrong password?");
}

/* Is @n the nonce of one of our last JOIN_REQs? */
int cl_ctr_join_nonce_ours(cl_ctr_cluster_t *cl, const unsigned char *n)
{
    int i;

    for (i = 0; i < cl->join_nonces_n; i++)
        if (memcmp(cl->join_nonces[i], n, CL_CTR_NONCE_SZ) == 0)
            return 1;
    return 0;
}

/* a joiner with the wrong password cannot read this: it exits after
 * CL_CTR_JOIN_FAIL_LIMIT retries once a bootstrap failure was seen instead */
void cl_ctr_handle_join_reject(const char *payload, int payload_len,
                                   const char *sender_ip, cl_ctr_cluster_t *cl)
{
    char target_ip[CL_CTR_MAX_IP_LEN + 1];
    int  l, still_new;

    lock_start_read(cl->peers->lock);
    still_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
    lock_stop_read(cl->peers->lock);
    /* act only with an admission request out - NEW, or merging via
     * cl_ctr_rejoin_superior_master(); so no member can evict a settled one */
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
        /* bootstrap packets have no replay window: drop a refusal echoing none of our
         * recent nonces; an older master echoes none - then only MTU/CONFIG count */
        {
            static time_t warned_at;
            int  echo_off = l + 2 + CL_CTR_MTU_SZ + CL_CTR_CONFIG_SZ;
            int  stale    = payload_len >= echo_off + CL_CTR_NONCE_SZ
                            && !cl_ctr_join_nonce_ours(cl,
                                   (const unsigned char *)payload + echo_off);
            int  unbound  = payload_len < echo_off + CL_CTR_NONCE_SZ
                            && reason != CL_CTR_REJECT_MTU
                            && reason != CL_CTR_REJECT_CONFIG;
            time_t now    = cl_ctr_now();

            if (stale || unbound) {
                if (warned_at == 0 || now - warned_at >= CL_CTR_WIRE_WARN_IVL) {
                    warned_at = now;
                    LM_WARN("clusterer_controller: [cluster %d] ignoring a "
                            "JOIN_REJECT from %s that %s\n", cl->cluster_id,
                            sender_ip, stale
                            ? "refuses none of this node's JOIN_REQs - sent "
                              "again, or stale"
                            : "names no JOIN_REQ of this node (an older "
                              "master?) and no reason this node can check");
                }
                return;
            }
        }
        /* a refusal quoting our own MTU back contradicts itself - we trust the kernel */
        if (reason == CL_CTR_REJECT_MTU && their_mtu > 0 && their_mtu == cc_mtu) {
            LM_WARN("clusterer_controller: [cluster %d] ignoring an MTU "
                    "JOIN_REJECT from %s that quotes %d - which is exactly this "
                    "node's own MTU, so the refusal contradicts itself\n",
                    cl->cluster_id, sender_ip, their_mtu);
            return;
        }
        /* likewise CONFIG: a real master sends it only when values differ, and a
         * forged one would let any PSK holder end a merging master */
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
        /* refused while merging: a running member keeps its own partition rather
         * than exit (a backstop - the beacon normally prevents such a merge) */
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
            /* name the values: the dying node's log is the one an operator reads first */
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
