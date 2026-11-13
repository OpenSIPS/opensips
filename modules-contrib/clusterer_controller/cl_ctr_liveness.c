/*
 * clusterer_controller - ALIVE, GOODBYE, MASTER_ALIVE, beacons and resync
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
#include "cl_ctr_caps.h"
#include "cl_ctr_stats.h"

static void cl_ctr_rejoin_superior_master(cl_ctr_cluster_t *cl, const char *superior_ip,
                                      const char *via);

/* master path: every peer's NODE_ASSIGN but skip_ip's, to dest (NULL: the
 * group); call without cl->peers->lock held */
void cl_ctr_send_assigns_to(cl_ctr_cluster_t *cl, const char *skip_ip,
                            const struct sockaddr *dest, socklen_t destlen)
{
    int i;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (e->node_id == 0 || (skip_ip && strcmp(e->ip, skip_ip) == 0))
            continue;
        cl_ctr_send_node_assign(cl->sock, e->ip, e->node_id, e->bin_count,
                            (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])e->bin_sockets,
                            strcmp(e->ip, my_ip) == 0 ? cl_ctr_incarnation
                                                      : e->incarnation,
                            cl, dest, destlen);
    }
    lock_stop_read(cl->peers->lock);
}

/* master: 1 while this second's CL_CTR_STATE_UNICAST_PER_SEC unicast full
 * states are not spent, counting this one */
int cl_ctr_state_unicast_due(cl_ctr_cluster_t *cl)
{
    time_t now = cl_ctr_now();

    if (cl->state_uni_sec != now) {
        cl->state_uni_sec = now;
        cl->state_uni_n   = 0;
    }
    if (cl->state_uni_n >= CL_CTR_STATE_UNICAST_PER_SEC)
        return 0;
    cl->state_uni_n++;
    return 1;
}

/* master path; a broadcast coalesced away is owed (full_state_pending): its
 * NODE_ASSIGNs admit a restarted node whose clock stepped back */
void cl_ctr_announce_full_state(cl_ctr_cluster_t *cl, const char *why)
{
    utime_t now = get_uticks();

    if ((utime_t)(now - cl->last_full_state_us) < CL_CTR_FULL_STATE_MIN_US) {
        cl->full_state_pending = 1;
        snprintf(cl->full_state_why, sizeof cl->full_state_why, "%s", why);
        LM_DBG("clusterer_controller: [cluster %d] %s - full-state broadcast "
               "coalesced, owed to the cluster\n", cl->cluster_id, why);
        return;
    }
    cl->last_full_state_us  = now;
    cl->full_state_pending  = 0;
    LM_INFO("clusterer_controller: [cluster %d] %s - broadcasting full state "
            "to the cluster\n", cl->cluster_id, why);
    cl_ctr_send_assigns_to(cl, NULL, NULL, 0);
    cl_ctr_send_member_list(cl->sock, cl);
}

/* a member's membership digest did not match the master's: the full state to
 * it alone - a broadcast per RESYNC overran every member's rate limit */
void cl_ctr_handle_resync(const char *sender_ip, cl_ctr_cluster_t *cl,
                          const struct sockaddr *src, socklen_t src_len)
{
    int   i_am_master;
    int   member;

    lock_start_read(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    member      = cl_ctr_peer_by_ip_locked(cl, sender_ip) != NULL;
    lock_stop_read(cl->peers->lock);
    if (!i_am_master || !member)
        return;
    if (!cl_ctr_state_unicast_due(cl)) {
        LM_DBG("clusterer_controller: [cluster %d] RESYNC from %s - this "
               "second's full states are spent, it asks again\n",
               cl->cluster_id, sender_ip);
        return;
    }

    LM_INFO("clusterer_controller: [cluster %d] RESYNC from %s - sending it "
            "the full state\n", cl->cluster_id, sender_ip);
    cl_ctr_send_assigns_to(cl, NULL, src, src_len);
    cl_ctr_send_list_pkt(cl->sock, CL_CTR_PKT_MEMBER_LIST, cl, src, src_len);
}

/* also dispatched while joining (cl_ctr_recv_one), so the peer table builds
 * up before the join timeout */
void cl_ctr_handle_alive(const char *src_ip,
                            const unsigned char *pubkey, /* may be NULL */
                            int cfg_present, int peer_manage,
                            int peer_stick, int peer_qt,
                            int peer_mtu, int peer_maint,
                            uint32_t peer_caps,
                            cl_ctr_cluster_t *cl)
{
    int  prev_master, now_master;
    int  warn = 0, adopt = 0, is_active = 0, ent = -1;
    int  mtu_warn = 0, mtu_seen = 0;
    char warn_ip[CL_CTR_MAX_IP_LEN + 1] = "";
    int  loc_manage = cl->manage_shtags ? 1 : 0;
    int  loc_stick  = cl->master_stickiness ? 1 : 0;
    int  loc_qt     = query_time;
    int  mism = 0, changed = 0, maint_changed = 0, maint_old = 0;
    uint16_t maint_nid = 0;

    lock_start_write(cl->peers->lock);
    prev_master = cl_ctr_i_am_master_locked(cl);
    cl_ctr_upsert_peer_locked(src_ip, cl);
    {
        int _i;
        for (_i = 0; _i < cl->peers->count; _i++) {
            cl_ctr_peer_t *e = &cl->peers->entries[_i];
            if (strcmp(e->ip, src_ip) != 0)
                continue;
            ent = _i;
            /* Store pubkey so master can use it for KEY_HANDOFF / KEY_GRANT */
            if (pubkey)
                memcpy(e->pubkey, pubkey, CL_CTR_PUBKEY_SZ);
            if (cfg_present) {
                changed = (!e->cfg_known
                           || e->cfg_manage_shtags     != peer_manage
                           || e->cfg_master_stickiness != peer_stick
                           || e->cfg_query_time        != peer_qt);
                mism = (peer_manage != loc_manage
                        || peer_stick != loc_stick
                        || peer_qt   != loc_qt);
                e->cfg_known             = 1;
                e->cfg_manage_shtags     = peer_manage;
                e->cfg_master_stickiness = peer_stick;
                e->cfg_query_time        = peer_qt;
            }
            /* MTU mismatch: warn only - the peer's drift poll removes it;
             * acting here would let one `ip link set mtu` take down all */
            if (peer_mtu > 0) {
                if (cc_mtu > 0 && peer_mtu != cc_mtu && !e->mtu_warned) {
                    e->mtu_warned = 1;
                    mtu_warn      = 1;
                    mtu_seen      = peer_mtu;
                } else if (cc_mtu > 0 && peer_mtu == cc_mtu) {
                    e->mtu_warned = 0;   /* re-arm once it agrees again */
                }
                e->mtu = peer_mtu;
            }
            /* what its build implements, as of this ALIVE (an upgrade or a
             * downgrade changes it) */
            e->caps     = peer_caps;
            e->caps_ms  = cl_ctr_now_ms();
            e->heard_ms = e->caps_ms;
            /* the node's own word on its maintenance state */
            if (e->maint != (uint8_t)peer_maint) {
                maint_old     = e->maint;
                e->maint      = (uint8_t)peer_maint;
                maint_changed = (strcmp(src_ip, my_ip) != 0);
                maint_nid     = e->node_id;
                /* our master handing over for maintenance: its successor
                 * may raise the term (PreVote) */
                if (maint_changed && peer_maint != CL_CTR_MAINT_NONE &&
                        strcmp(src_ip, cl->peers->last_master) == 0)
                    cl->term_confirmed = 1;
            }
            break;
        }
    }
    cl_ctr_elect_master(cl);
    now_master = cl_ctr_i_am_master_locked(cl);
    is_active  = (cl->peers->node_state == CL_CTR_NODE_ACTIVE);
    /* 'adopt': a non-master takes the master's settings, else warn once per
     * peer.  cl_ctr_elect_master() does not reorder, so ent stays valid */
    if (cfg_present && ent >= 0) {
        cl_ctr_peer_t *e = &cl->peers->entries[ent];
        int sender_is_master = (cl->peers->last_master[0] != '\0'
                                && strcmp(src_ip, cl->peers->last_master) == 0);
        if (!mism) {
            e->cfg_warned = 0;
        } else if (on_config_mismatch == CL_CTR_CFGMISMATCH_ADOPT
                   && sender_is_master && !now_master) {
            adopt = 1;
            e->cfg_warned = 0;
        } else if (changed || !e->cfg_warned) {
            warn = 1;
            e->cfg_warned = 1;
            memcpy(warn_ip, e->ip, sizeof(warn_ip));
        }
    }
    lock_stop_write(cl->peers->lock);

    if (warn) {
        char diff[160];
        cl_ctr_note_config_mismatch(cl, warn_ip);
        cl_ctr_fmt_cfg_diff(diff, sizeof(diff), "local", "peer",
                        loc_manage, peer_manage, loc_stick, peer_stick,
                        loc_qt, peer_qt);
        LM_WARN("clusterer_controller: [cluster %d] CONFIG MISMATCH with peer %s "
                "- all nodes of a cluster MUST use identical settings; mismatched "
                "values cause inconsistent failover/sharing-tag behaviour (%s)\n",
                cl->cluster_id, warn_ip, diff);
    }
    if (mtu_warn)
        LM_WARN("clusterer_controller: [cluster %d] peer %s now advertises MTU %d "
                "but this cluster runs at %d. Traffic larger than the smaller of "
                "the two is dropped silently in that direction. NOT acting on it "
                "here - that peer detects its own change and removes itself; "
                "terminating on someone else's reading would turn one `ip link` "
                "command into a fleet outage\n",
                cl->cluster_id, src_ip, mtu_seen, cc_mtu);
    if (adopt)
        cl_ctr_adopt_config(cl, peer_manage, peer_stick, peer_qt, is_active);
    if (maint_changed) {
        cl_ctr_maint_changed(cl, maint_nid, maint_old, peer_maint);
        cl_ctr_maint_peer_changed(cl, maint_nid, peer_maint);
    }
    /* a master without the cluster key (KEY_GRANT lost in the join) re-keys
     * instead of sending an undecryptable MASTER_ALIVE */
    if (now_master && !cl->have_session_key) {
        cl_ctr_request_rekey(cl);
        return;
    }
    if (prev_master != now_master) {
        cl_ctr_arm_master_timers(cl, now_master);
        cl_ctr_apply_shtags(cl);
    }
}

/* re-elects at once only when alone or when cl_ctr_ip_beats_master_locked()
 * (the master left, or our IP is higher); else the next ALIVE round does */
void cl_ctr_handle_goodbye(int sock, const char *src_ip, cl_ctr_cluster_t *cl)
{
    int      i, i_am_master, master_unchanged, remaining;
    char     prev_master[CL_CTR_MAX_IP_LEN + 1];
    char     new_master[CL_CTR_MAX_IP_LEN + 1];
    uint16_t departed_node_id = 0;

    LM_INFO("clusterer_controller: GOODBYE from %s\n", src_ip);

    lock_start_write(cl->peers->lock);

    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, src_ip) == 0) {
	    departed_node_id = cl->peers->entries[i].node_id;
	    cl_ctr_reserve_id_locked(cl, src_ip, departed_node_id);
	    cl_ctr_note_member(cl, src_ip, departed_node_id, 0, "goodbye");
	    cl->peers->count--;
	    if (i < cl->peers->count)
		cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
	    memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cl_ctr_peer_t));
	    break;
	}
    }

    /* If the operator-forced shtag holder departed, drop the override so
     * automatic allocation resumes rather than leaving no active holder. */
    if (departed_node_id != 0 &&
        cl->peers->shtag_forced_node_id == departed_node_id) {
	LM_WARN("clusterer_controller: [cluster %d] forced shtag node %u "
	        "departed - resuming automatic allocation\n",
	        cl->cluster_id, departed_node_id);
	cl->peers->shtag_forced_node_id = 0;
    }

    remaining = cl->peers->count;
    /* the master said goodbye: its successor may raise the term (PreVote) */
    if (cl->peers->last_master[0] != '\0' &&
            strcmp(src_ip, cl->peers->last_master) == 0)
        cl->term_confirmed = 1;

    if (remaining <= 1) {
	int was_master = cl_ctr_i_am_master_locked(cl);
	cl_ctr_apply_master_from_list_locked(my_ip, cl);
	lock_stop_write(cl->peers->lock);
	if (was_master) {
	    LM_INFO("clusterer_controller: %s departed - I am the only "
	            "node remaining, I remain master\n", src_ip);
	} else {
	    LM_INFO("clusterer_controller: %s departed - I am the only "
	            "node remaining, promoted myself to master\n", src_ip);
	}
	if (clctl_loaded && departed_node_id > 0)
	    clusterer_ctrl_remove_node(cl->cluster_id, departed_node_id);
	cl_ctr_apply_shtags(cl);
	return;
    }

    if (cl_ctr_ip_beats_master_locked(ip_to_num(my_ip), cl)) {
	if (strcmp(src_ip, cl->peers->last_master) == 0) {
	    LM_INFO("clusterer_controller: %s departed - it was the master, "
	            "triggering re-election\n", src_ip);
	} else {
	    LM_INFO("clusterer_controller: %s departed - our IP %s is higher "
	            "than current master %s, triggering re-election\n",
	            src_ip, my_ip,
	            cl->peers->last_master[0] ? cl->peers->last_master : "(none)");
	}
    } else {
	/* Snapshot before releasing - must not read last_master after unlock */
	{
	    size_t _l = strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN);
	    memcpy(prev_master, cl->peers->last_master, _l);
	    prev_master[_l] = '\0';
	}
	lock_stop_write(cl->peers->lock);
	LM_INFO("clusterer_controller: %s departed - master %s still "
	        "active, no re-election needed (%d node(s) remaining)\n",
	        src_ip,
	        prev_master[0] ? prev_master : "(none)",
	        remaining);
	if (clctl_loaded && departed_node_id > 0)
	    clusterer_ctrl_remove_node(cl->cluster_id, departed_node_id);
	/* Re-apply shtag policy: the still-active master takes over the
	 * departed node's tags, unless an operator override is in effect. */
	cl_ctr_apply_shtags(cl);
	return;
    }

    memcpy(prev_master, cl->peers->last_master,
           strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN));
    prev_master[strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN)] = '\0';

    cl_ctr_elect_master(cl);

    master_unchanged = (strcmp(prev_master, cl->peers->last_master) == 0);
    i_am_master      = cl_ctr_i_am_master_locked(cl);
    {
	size_t _l = strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN);
	memcpy(new_master, cl->peers->last_master, _l);
	new_master[_l] = '\0';
    }

    lock_stop_write(cl->peers->lock);

    if (i_am_master) {
	if (master_unchanged) {
	    LM_INFO("clusterer_controller: re-election complete - "
	            "I remain master (%d node(s) in cluster)\n", remaining);
	} else {
	    LM_INFO("clusterer_controller: re-election complete - "
	            "I reclaimed mastership after %s departed "
	            "(%d node(s) remaining)\n",
	            src_ip, remaining);
	    cl_ctr_arm_master_timers(cl, 1);
	    /* no MEMBER_LIST: every member elected the same master on this GOODBYE
	     * and the digest repairs the rest; the O(N) list fragments at large N */
	}
    } else {
	/* our own role change is logged by cl_ctr_elect_master() */
	LM_INFO("clusterer_controller: re-election complete - "
	        "master is %s (%d node(s) remaining)\n",
	        new_master[0] ? new_master : "(none)",
	        remaining);
    }
    if (clctl_loaded && departed_node_id > 0)
	clusterer_ctrl_remove_node(cl->cluster_id, departed_node_id);
    cl_ctr_apply_shtags(cl);
}

/* the keepalive is the authoritative "who is master" signal (more frequent
 * than MEMBER_LIST); a master outranked by its sender yields */
void cl_ctr_handle_master_alive(const char *sender_ip, cl_ctr_cluster_t *cl,
                                   const char *payload, int payload_len,
                                   const struct sockaddr *src, socklen_t src_len)
{
    int      i_am_master, yielded = 0, ignored = 0;
    int      from_self = (strcmp(sender_ip, my_ip) == 0);
    uint16_t adv_cnt = 0, my_cnt, adv_live = 0, my_live, cmp_adv, cmp_mine;
    uint32_t adv_term = 0;
    int      adv_unraised = 0;
    uint64_t my_hash;

    /* A master that refused to admit us: neither follow it nor yield to it
     * for a while - re-merging would only be refused again. */
    if (!from_self && cl->merge_refused_until > cl_ctr_now() &&
        strcmp(sender_ip, cl->merge_refused_ip) == 0)
        return;

    /* The claimant's member count (the digest's first field) and term. */
    if (payload_len >= CL_CTR_DIGEST_SZ)
        adv_cnt = (uint16_t)(((unsigned char)payload[0] << 8)
                             | (unsigned char)payload[1]);
    if (payload_len >= CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ + CL_CTR_TERM_SZ) {
        uint32_t t_be;
        memcpy(&t_be, payload + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ,
               CL_CTR_TERM_SZ);
        adv_term = ntohl(t_be);
    }
    /* ... and the members it hears now (after the maintenance relay) */
    if (payload_len >= CL_CTR_DIGEST_SZ + 2 * CL_CTR_ALIVE_BITMAP_SZ
                       + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ) {
        uint16_t l_be;
        memcpy(&l_be, payload + CL_CTR_DIGEST_SZ + 2 * CL_CTR_ALIVE_BITMAP_SZ
                      + CL_CTR_TERM_SZ, CL_CTR_LIVE_SZ);
        adv_live = ntohs(l_be);
    }
    /* ... and whether its mastership left the term unraised (after the bitmaps) */
    if (payload_len >= CL_CTR_DIGEST_SZ + 4 * CL_CTR_ALIVE_BITMAP_SZ + CL_CTR_TERM_SZ
                       + CL_CTR_LIVE_SZ + CL_CTR_CAPS_SZ + CL_CTR_UNRAISED_SZ)
        adv_unraised = payload[CL_CTR_DIGEST_SZ + 4 * CL_CTR_ALIVE_BITMAP_SZ
                               + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ + CL_CTR_CAPS_SZ] != 0;
    /* counts no cluster can have were not sent by a master; ranked on what
     * they claim they would outrank every real one */
    if (adv_cnt > CL_CTR_MAX_PEERS || adv_live > CL_CTR_MAX_PEERS) {
        LM_DBG("clusterer_controller: [cluster %d] MASTER_ALIVE from %s counts "
               "%u members, %u live - out of range, dropping\n",
               cl->cluster_id, sender_ip, adv_cnt, adv_live);
        return;
    }
    /* our own counts, for the same comparison - taken before the write lock,
     * since both take the read lock themselves */
    cl_ctr_membership_digest(cl, &my_cnt, &my_hash);
    my_live = cl_ctr_live_count(cl);
    /* rank on live members when the claimant announced them, else on table
     * counts on both sides - like with like */
    cmp_adv  = adv_live ? adv_live : adv_cnt;
    cmp_mine = adv_live ? my_live  : my_cnt;

    lock_start_write(cl->peers->lock);
    if (!from_self && !cl_ctr_term_sane(cl, adv_term, sender_ip)) {
        lock_stop_write(cl->peers->lock);
        return;
    }
    i_am_master = cl_ctr_i_am_master_locked(cl);
    if (!from_self)
        cl_ctr_note_term(cl, adv_term);

    if (i_am_master) {
        if (!from_self &&
            cl_ctr_master_outranks(cmp_adv, adv_term, adv_unraised, sender_ip,
                                   cmp_mine, cl->peers->my_term,
                                   cl->master_unconfirmed, my_ip)) {
            /* split-brain, outranked: yield - demotion happens below, outside
             * the lock (cl_ctr_rejoin_superior_master() must not hold it) */
            yielded = 1;
        }
        /* else: my own loopback, or a claimant that will yield to us */
    } else if (!from_self) {
        /* ignore a claimant not outranking the master we follow: it will
         * yield (no flapping); cl_ctr_on_master_dead_tfd forgets a dead one */
        if (cl->peers->last_master[0] != '\0' &&
            strcmp(sender_ip, cl->peers->last_master) != 0 &&
            !cl_ctr_master_outranks(
                    (adv_live && cl->peers->master_live) ? adv_live : adv_cnt,
                    adv_term, adv_unraised, sender_ip,
                    (adv_live && cl->peers->master_live)
                        ? cl->peers->master_live : cl->peers->master_count,
                    cl->peers->master_term, cl->peers->master_unraised,
                    cl->peers->last_master)) {
            ignored = 1;
        } else {
            /* follow the sender: all agree despite a missed MEMBER_LIST,
             * and a sticky cl_ctr_elect_master() keeps the right master */
            cl_ctr_upsert_peer_locked(sender_ip, cl);
            cl_ctr_apply_master_from_list_locked(sender_ip, cl);
            /* a lower term than its lists carried: the master restarted and its
             * lists start afresh (old-life packets fail the replay check) */
            if (adv_term < cl->peers->list_term_seen) {
                cl->peers->list_term_seen = 0;
                cl->peers->list_seq_seen  = 0;
            }
            cl->peers->master_term  = adv_term;
            cl->peers->master_count = adv_cnt;
            cl->peers->master_live  = adv_live;
            cl->peers->master_unraised = (uint8_t)adv_unraised;
        }
    }
    lock_stop_write(cl->peers->lock);

    if (ignored) {
        LM_DBG("clusterer_controller: [cluster %d] ignoring MASTER_ALIVE from "
               "%s (members %u, term %u) - it does not outrank the master we "
               "follow\n", cl->cluster_id, sender_ip, adv_cnt, adv_term);
        return;
    }

    if (yielded) {
        LM_INFO("clusterer_controller: [cluster %d] yielding mastership to %s "
                "(members %u, term %u) over ourselves (members %u, term %u) - "
                "split-brain resolution\n", cl->cluster_id, sender_ip,
                cmp_adv, adv_term, cmp_mine, cl->peers->my_term);
        /* yielding is not a merge: the winner knows us as node_id 0 until a
         * JOIN_REQ (else a RESYNC-per-second livelock); rejoin also demotes */
        cl_ctr_rejoin_superior_master(cl, sender_ip, "MASTER_ALIVE");
    }

    /* non-masters learn the keepalive's rhythm; one arriving mid-probe
     * proves the suspicion false */
    if (!i_am_master && !from_self) {
        if (cl->probing)
            cl_ctr_ka_false_suspicion(cl, "its keepalive arrived while asking");
        cl_ctr_ka_sample(cl, sender_ip);
    }
    if (!i_am_master || yielded)
        cl_ctr_arm_master_watchdog(cl);
    /* ... and remember when they last heard it, for peers that probe; a
     * keepalive also ends any probe round or election hold. */
    if (!i_am_master && !from_self) {
        cl->master_heard_ms    = cl_ctr_now_ms();
        cl->probing            = 0;
        cl->hold_since_ms      = 0;
        cl->probe_quiet_rounds = 0;
        cl->term_confirmed     = 0;
    }

    /* liveness relay */
    if (!i_am_master && !from_self &&
        payload_len >= CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ)
        cl_ctr_apply_alive_bitmap(cl,
            (const unsigned char *)payload + CL_CTR_DIGEST_SZ);

    /* missing from the master's relay: it purged this node (paused, or cut off
     * past the purge window) - only a JOIN_REQ gives the node_id back */
    if (!i_am_master && !from_self && cl->have_session_key &&
        payload_len >= CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ) {
        const unsigned char *bm = (const unsigned char *)payload + CL_CTR_DIGEST_SZ;
        uint16_t me = 0;
        int      k;

        lock_start_read(cl->peers->lock);
        for (k = 0; k < cl->peers->count; k++)
            if (strcmp(cl->peers->entries[k].ip, my_ip) == 0)
                me = cl->peers->entries[k].node_id;
        lock_stop_read(cl->peers->lock);
        if (me != 0 && me <= CL_CTR_MAX_PEERS &&
                !(bm[me >> 3] & (unsigned char)(1u << (me & 7)))) {
            if (++cl->unlisted >= 2 && !cl->join_pending) {
                LM_INFO("clusterer_controller: [cluster %d] master %s no longer "
                        "lists this node (node_id %u) - re-joining to be "
                        "re-admitted\n", cl->cluster_id, sender_ip, me);
                cl->unlisted     = 0;
                cl->join_pending = 1;
                cl_ctr_send_join_req(cl->sock, cl);
            }
        } else {
            cl->unlisted = 0;
            if (cl->unheard && me != 0 && me <= CL_CTR_MAX_PEERS) {
                cl->unheard = 0;
                LM_INFO("clusterer_controller: [cluster %d] master %s hears "
                        "this node again - it may be elected again\n",
                        cl->cluster_id, sender_ip);
            }
        }
    }

    /* What every live member shares, as the master hears them all;
     * an older master relays nothing, and shares nothing it does not know. */
    if (!i_am_master && !from_self) {
        uint32_t c = 0;
        if (payload_len >= CL_CTR_DIGEST_SZ + 3 * CL_CTR_ALIVE_BITMAP_SZ
                           + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ + CL_CTR_CAPS_SZ) {
            uint32_t c_be;
            memcpy(&c_be, payload + CL_CTR_DIGEST_SZ + 3 * CL_CTR_ALIVE_BITMAP_SZ
                          + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ, CL_CTR_CAPS_SZ);
            c = ntohl(c_be);
        }
        lock_start_write(cl->peers->lock);
        cl->peers->cluster_caps = c;
        lock_stop_write(cl->peers->lock);
        /* and which nodes are CONNECTING - none from an older master */
        cl_ctr_apply_conn_bitmap(cl,
                payload_len >= CL_CTR_DIGEST_SZ + 4 * CL_CTR_ALIVE_BITMAP_SZ
                               + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ + CL_CTR_CAPS_SZ
                ? (const unsigned char *)payload + CL_CTR_DIGEST_SZ
                  + 3 * CL_CTR_ALIVE_BITMAP_SZ + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ
                  + CL_CTR_CAPS_SZ
                : NULL);
    }

    /* maintenance relay; a master that just entered maintenance sends this as
     * its last keepalive - elect its successor now, not on the watchdog */
    if (!i_am_master && !from_self &&
        payload_len >= CL_CTR_DIGEST_SZ + 2 * CL_CTR_ALIVE_BITMAP_SZ
                       + CL_CTR_TERM_SZ &&
        cl_ctr_apply_maint_bitmap(cl, (const unsigned char *)payload
                                      + CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ
                                      + CL_CTR_TERM_SZ,
                                  payload_len >= CL_CTR_DIGEST_SZ
                                      + 3 * CL_CTR_ALIVE_BITMAP_SZ
                                      + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ
                                  ? (const unsigned char *)payload
                                      + CL_CTR_DIGEST_SZ
                                      + 2 * CL_CTR_ALIVE_BITMAP_SZ
                                      + CL_CTR_TERM_SZ + CL_CTR_LIVE_SZ
                                  : NULL, sender_ip))
    {
        cl->term_confirmed = 1;     /* the master handed over (PreVote) */
        cl_ctr_reelect_now(cl, "the master went into maintenance");
    }

    /* digest mismatch: we may have missed a NODE_ASSIGN - pull a rate-limited
     * RESYNC (members holding the key only) */
    if (!i_am_master && !from_self && cl->have_session_key &&
        payload_len >= CL_CTR_DIGEST_SZ) {
        const unsigned char *d = (const unsigned char *)payload;
        uint16_t adv_cnt = (uint16_t)((d[0] << 8) | d[1]);
        uint16_t my_cnt;
        uint64_t adv_hash = 0, my_hash;
        int      k;
        for (k = 0; k < 8; k++) adv_hash = (adv_hash << 8) | d[2 + k];
        cl_ctr_membership_digest(cl, &my_cnt, &my_hash);
        if (adv_cnt != my_cnt || adv_hash != my_hash) {
            utime_t now = get_uticks();
            if ((utime_t)(now - cl->last_resync_us) >= CL_CTR_RESYNC_MIN_US) {
                cl->last_resync_us = now;
                LM_DBG("clusterer_controller: [cluster %d] membership digest "
                       "mismatch with master %s (theirs %u, ours %u) - RESYNC\n",
                       cl->cluster_id, sender_ip, adv_cnt, my_cnt);
                cl_ctr_send_resync(cl->sock, cl, src, src_len);
            }
        }
    }
}

/* demote and follow superior_ip, then JOIN_REQ for its NODE_ASSIGN and
 * KEY_GRANT (its session key); call without cl->peers->lock held */
static void cl_ctr_rejoin_superior_master(cl_ctr_cluster_t *cl, const char *superior_ip,
                                      const char *via)
{
    int was_master;

    lock_start_write(cl->peers->lock);
    was_master = cl_ctr_i_am_master_locked(cl);
    cl_ctr_upsert_peer_locked(superior_ip, cl);
    cl_ctr_apply_master_from_list_locked(superior_ip, cl);
    cl->peers->node_state = CL_CTR_NODE_ACTIVE;
    lock_stop_write(cl->peers->lock);
    cl_ctr_note_merge(cl, superior_ip, was_master);

    if (was_master) {
        LM_INFO("clusterer_controller: [cluster %d] superior master %s found via "
                "%s - demoting and merging (split-brain resolution)\n",
                cl->cluster_id, superior_ip, via);
        cl_ctr_arm_master_timers(cl, 0);   /* stop MASTER_ALIVE, arm dead watchdog */
    } else {
        LM_INFO("clusterer_controller: [cluster %d] moving to superior master %s "
                "via %s (split-brain merge)\n", cl->cluster_id, superior_ip, via);
    }

    /* Drop any locally-held active shtag now that we are no longer master. */
    cl_ctr_apply_shtags(cl);

    /* Fetch the superior master's session key.  join_pending guards the nonce
     * so a beacon storm cannot stomp an exchange already in flight. */
    if (!cl->join_pending) {
        cl->join_pending = 1;
        cl_ctr_send_join_req(cl->sock, cl);
    }
    cl_ctr_arm_master_watchdog(cl);
}

/* bootstrap-key beacon: merge into a master outranking our partition, else
 * ignore it (it yields on our beacon); our own master's is a no-op */
void cl_ctr_handle_master_beacon(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl)
{
    int      i_am_master, is_new, superior;
    uint16_t our_count, sender_count = 0, sender_live = 0, our_live;
    uint32_t our_term, sender_term = 0;
    int      sender_unraised = 0, our_unraised;
    uint64_t our_hash;
    char     our_master[CL_CTR_MAX_IP_LEN + 1];
    int      cfg_present = 0, b_manage = 0, b_stick = 0, b_qt = 0, b_mtu = 0;
    int      cfg_differs, mtu_differs;

    if (strcmp(sender_ip, my_ip) == 0)
        return;                     /* our own beacon looped back */
    if (cl->merge_refused_until > cl_ctr_now() &&
        strcmp(sender_ip, cl->merge_refused_ip) == 0)
        return;                     /* it refused us; not trying again yet */

    if (payload_len >= 2)
        sender_count = (uint16_t)(((unsigned char)payload[0] << 8)
                                  | (unsigned char)payload[1]);
    if (payload_len >= 2 + CL_CTR_TERM_SZ) {
        uint32_t t_be;
        memcpy(&t_be, payload + 2, CL_CTR_TERM_SZ);
        sender_term = ntohl(t_be);
    }
    if (payload_len >= 2 + CL_CTR_TERM_SZ + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ) {
        const char *c = payload + 2 + CL_CTR_TERM_SZ;
        uint16_t    qt_be, m_be;
        b_manage = (unsigned char)c[0];
        b_stick  = (unsigned char)c[1];
        memcpy(&qt_be, c + 2, 2);
        b_qt     = ntohs(qt_be);
        memcpy(&m_be, c + CL_CTR_CONFIG_SZ, CL_CTR_MTU_SZ);
        b_mtu    = ntohs(m_be);
        cfg_present = 1;
    }
    if (payload_len >= 2 + CL_CTR_TERM_SZ + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ
                       + CL_CTR_LIVE_SZ) {
        uint16_t l_be;
        memcpy(&l_be, payload + 2 + CL_CTR_TERM_SZ + CL_CTR_CONFIG_SZ
                      + CL_CTR_MTU_SZ, CL_CTR_LIVE_SZ);
        sender_live = ntohs(l_be);
    }
    if (payload_len >= 2 + CL_CTR_TERM_SZ + CL_CTR_CONFIG_SZ + CL_CTR_MTU_SZ
                       + CL_CTR_LIVE_SZ + CL_CTR_UNRAISED_SZ)
        sender_unraised = payload[2 + CL_CTR_TERM_SZ + CL_CTR_CONFIG_SZ
                                  + CL_CTR_MTU_SZ + CL_CTR_LIVE_SZ] != 0;
    /* every build of this wire version sends count, term, settings and MTU;
     * one without them or with an impossible count is no master's */
    if (!cfg_present || sender_count == 0 || sender_count > CL_CTR_MAX_PEERS
            || sender_live > CL_CTR_MAX_PEERS) {
        LM_DBG("clusterer_controller: [cluster %d] malformed beacon from %s "
               "(%d bytes, count %u), dropping\n", cl->cluster_id, sender_ip,
               payload_len, sender_count);
        return;
    }

    /* the tests its cl_ctr_handle_join_req() applies (settings under 'reject',
     * MTU always), before ranking: never demote into a merge it refuses */
    cfg_differs = on_config_mismatch == CL_CTR_CFGMISMATCH_REJECT
                  && (b_manage != (cl->manage_shtags ? 1 : 0)
                      || b_stick != (cl->master_stickiness ? 1 : 0)
                      || b_qt    != (query_time & 0xFFFF));
    mtu_differs = b_mtu > 0 && cc_mtu > 0
                  && b_mtu != cl_ctr_mtu_wire(cc_mtu);
    if (cfg_differs || mtu_differs) {
        time_t now = cl_ctr_now();
        if (cl->merge_warned_at == 0
                || now - cl->merge_warned_at >= CL_CTR_WIRE_WARN_IVL) {
            char diff[160];
            cl->merge_warned_at = now;
            if (cfg_differs)
                cl_ctr_fmt_cfg_diff(diff, sizeof(diff), "this node", sender_ip,
                                    cl->manage_shtags ? 1 : 0, b_manage,
                                    cl->master_stickiness ? 1 : 0, b_stick,
                                    query_time & 0xFFFF, b_qt);
            else
                snprintf(diff, sizeof(diff), "MTU this node=%d %s=%d",
                         cl_ctr_mtu_wire(cc_mtu), sender_ip, b_mtu);
            LM_WARN("clusterer_controller: [cluster %d] another master, %s, "
                    "leads a partition of cluster_id %d with different "
                    "settings (%s) - NOT merging with it.  Two masters will "
                    "remain on this cluster until the settings are made "
                    "identical on every node\n", cl->cluster_id, sender_ip,
                    cl->cluster_id, diff);
        }
        return;
    }

    cl_ctr_membership_digest(cl, &our_count, &our_hash);
    our_live = cl_ctr_live_count(cl);

    lock_start_write(cl->peers->lock);
    if (!cl_ctr_term_sane(cl, sender_term, sender_ip)) {
        lock_stop_write(cl->peers->lock);
        return;
    }
    cl_ctr_note_term(cl, sender_term);
    lock_stop_write(cl->peers->lock);

    lock_start_read(cl->peers->lock);
    is_new      = (cl->peers->node_state == CL_CTR_NODE_NEW);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    our_term    = i_am_master ? cl->peers->my_term : cl->peers->master_term;
    our_unraised = i_am_master ? cl->master_unconfirmed : cl->peers->master_unraised;
    if (i_am_master) {
        size_t l = strnlen(my_ip, CL_CTR_MAX_IP_LEN);
        memcpy(our_master, my_ip, l); our_master[l] = '\0';
    } else {
        size_t l = strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN);
        memcpy(our_master, cl->peers->last_master, l); our_master[l] = '\0';
    }
    lock_stop_read(cl->peers->lock);

    /* Still running the join protocol - a JOIN_REQ is already outstanding. */
    if (is_new)
        return;

    /* Already following the beacon's sender: normal steady state, nothing to do. */
    if (our_master[0] != '\0' && strcmp(sender_ip, our_master) == 0)
        return;

    if (our_master[0] == '\0')
        superior = 1;                                   /* we have no master yet */
    else
        superior = cl_ctr_master_outranks(
                       sender_live ? sender_live : sender_count,
                       sender_term, sender_unraised, sender_ip,
                       sender_live ? our_live : our_count,
                       our_term, our_unraised, our_master);

    if (!superior)
        return;   /* we outrank the sender; it will yield to us on our beacon */

    cl_ctr_rejoin_superior_master(cl, sender_ip, "beacon");
}

/* master: of the other members in the election window, how many asked within
 * CL_CTR_PROBED_WINDOW_MS whether anyone still hears us */
static int cl_ctr_probed_me_locked(cl_ctr_cluster_t *cl, int *others)
{
    long long now = cl_ctr_now_ms();
    int       i, n = 0;

    *others = 0;
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (!e->in_election || strcmp(e->ip, my_ip) == 0)
            continue;
        (*others)++;
        if (e->probed_me_ms && now - e->probed_me_ms <= CL_CTR_PROBED_WINDOW_MS)
            n++;
    }
    return n;
}

/* answers how long ago this node last heard the master asked about, or
 * CL_CTR_PROBE_NOT_HEARD when it does not follow that master */
void cl_ctr_handle_master_probe(const char *sender_ip, const char *payload,
                                int payload_len, cl_ctr_cluster_t *cl,
                                const struct sockaddr *src, socklen_t src_len)
{
    char     m[CL_CTR_MAX_IP_LEN + 1];
    int      l = (int)strnlen(payload, payload_len < CL_CTR_MAX_IP_LEN
                                       ? payload_len : CL_CTR_MAX_IP_LEN);
    uint32_t ago = CL_CTR_PROBE_NOT_HEARD;
    int      follows, is_me, askers = 0, others = 0;
    cl_ctr_peer_t *e;
    struct sockaddr_in to;

    if (l == 0 || l >= payload_len || strcmp(sender_ip, my_ip) == 0)
        return;
    memcpy(m, payload, l);
    m[l] = '\0';
    lock_start_write(cl->peers->lock);
    e       = cl_ctr_peer_by_ip_locked(cl, sender_ip);
    is_me   = cl_ctr_i_am_master_locked(cl) && strcmp(m, my_ip) == 0;
    follows = !cl_ctr_i_am_master_locked(cl) &&
              strcmp(cl->peers->last_master, m) == 0;
    if (e && is_me) {
        e->probed_me_ms = cl_ctr_now_ms();
        askers = cl_ctr_probed_me_locked(cl, &others);
    }
    lock_stop_write(cl->peers->lock);
    if (!e)
        return;
    if (is_me) {
        /* not answered: only whether the others hear us counts.  Most of
         * them asking, this master is the one unheard; one, a warning */
        static time_t warned_at;
        time_t now = cl_ctr_now();

        if (2 * askers > others) {
            cl_ctr_step_down(cl, askers, others);
            return;
        }
        if (now - warned_at >= CL_CTR_WIRE_WARN_IVL) {
            warned_at = now;
            LM_WARN("clusterer_controller: [cluster %d] member %s cannot hear "
                    "this master's keepalives (it is asking the cluster "
                    "whether anyone still does) - a one-sided fault between "
                    "the two\n", cl->cluster_id, sender_ip);
        }
        return;
    }
    /* answered to members only, at their own address: no reflector */
    if (cl_ctr_node_addr(cl, sender_ip, &to) < 0)
        return;
    if (follows && cl->master_heard_ms) {
        long long d = cl_ctr_now_ms() - cl->master_heard_ms;
        ago = d < 0 ? 0 : (d > 0x7FFFFFFF ? 0x7FFFFFFF : (uint32_t)d);
    }
    (void)src; (void)src_len;
    cl_ctr_send_master_probe_ack(cl, m, ago, (const struct sockaddr *)&to,
                                 sizeof(to));
}

void cl_ctr_handle_master_probe_ack(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl)
{
    int      l = (int)strnlen(payload, payload_len < CL_CTR_MAX_IP_LEN
                                       ? payload_len : CL_CTR_MAX_IP_LEN);
    uint32_t ago_be;

    /* a master answering for itself says nothing of the others hearing it */
    if (!cl->probing || l == 0 || payload_len < l + 1 + 4 ||
            strncmp(payload, cl->probe_master, l) != 0 ||
            cl->probe_master[l] != '\0' ||
            strcmp(sender_ip, cl->probe_master) == 0)
        return;
    memcpy(&ago_be, payload + l + 1, 4);
    /* the answer is itself proof the answering peer is alive - and this
     * node, cut off from the master, hears no relay that would say so */
    {
        int    k;
        time_t t = cl_ctr_now();
        lock_start_write(cl->peers->lock);
        for (k = 0; k < cl->peers->count; k++)
            if (strcmp(cl->peers->entries[k].ip, sender_ip) == 0)
                cl->peers->entries[k].last_seen = t;
        lock_stop_write(cl->peers->lock);
    }
    if (ntohl(ago_be) > CL_CTR_PROBE_FRESH_MS) {
        cl->probe_silent++;
    } else {
        cl->probe_heard++;
        LM_DBG("clusterer_controller: [cluster %d] %s still hears master %s "
               "(%u ms ago)\n", cl->cluster_id, sender_ip, cl->probe_master,
               ntohl(ago_be));
    }
}

/* TCP's gains (1/8 mean, 1/4 deviation); the margin decays by
 * 1/CL_CTR_KA_MARGIN_DECAY; a new master starts afresh.  Worker only */
void cl_ctr_ka_sample(cl_ctr_cluster_t *cl, const char *master_ip)
{
    long long now = cl_ctr_now_ms(), gap, err;

    if (strcmp(cl->ka_master, master_ip) != 0) {
        size_t l = strnlen(master_ip, CL_CTR_MAX_IP_LEN);
        memcpy(cl->ka_master, master_ip, l);
        cl->ka_master[l] = '\0';
        cl->ka_samples   = 0;
        cl->ka_mean_ms   = CL_CTR_MASTER_KA_INTERVAL * 1000;
        cl->ka_dev_ms    = 0;
        cl->ka_margin_ms = 0;
        cl->ka_last_ms   = now;
        return;
    }
    gap = now - cl->ka_last_ms;
    cl->ka_last_ms = now;
    if (gap <= 0)
        return;
    if (cl->ka_samples == 0) {
        cl->ka_mean_ms = gap;
        cl->ka_dev_ms  = gap / 2;
    } else {
        err = gap - cl->ka_mean_ms;
        cl->ka_mean_ms += err / 8;
        cl->ka_dev_ms  += ((err < 0 ? -err : err) - cl->ka_dev_ms) / 4;
    }
    if (cl->ka_samples < 1000000)
        cl->ka_samples++;
    cl->ka_margin_ms -= cl->ka_margin_ms / CL_CTR_KA_MARGIN_DECAY;
    cl->peers->ka_mean_ms   = (int)cl->ka_mean_ms;
    cl->peers->ka_dev_ms    = (int)cl->ka_dev_ms;
    cl->peers->ka_margin_ms = (int)cl->ka_margin_ms;
}

/* A suspicion of the master turned out false: widen the margin (once per
 * suspicion; bounded by the watchdog's maximum anyway).  Worker only. */
void cl_ctr_ka_false_suspicion(cl_ctr_cluster_t *cl, const char *why)
{
    cl->ka_margin_ms += CL_CTR_KA_MARGIN_STEP_MS;
    if (cl->ka_margin_ms > CL_CTR_KA_TIMEOUT_MAX_MS)
        cl->ka_margin_ms = CL_CTR_KA_TIMEOUT_MAX_MS;
    cl->peers->ka_margin_ms = (int)cl->ka_margin_ms;
    cl->peers->ka_false_suspicions++;
    LM_INFO("clusterer_controller: [cluster %d] master %s was suspected but is "
            "alive (%s) - its watchdog now waits %lld ms\n", cl->cluster_id,
            cl->ka_master[0] ? cl->ka_master : "(unknown)", why,
            cl_ctr_master_timeout_ms(cl));
}

/* MAINT_SET: an operator (on any node) asked node [node_id] to change its
 * maintenance state; only that node acts, on itself. */
void cl_ctr_handle_maint_set(const char *sender_ip, const char *payload,
                             int payload_len, cl_ctr_cluster_t *cl)
{
    uint16_t nid_be;
    int      st, me = 0, k;

    if (payload_len < 3)
        return;
    memcpy(&nid_be, payload, 2);
    st = (unsigned char)payload[2];
    if (st > CL_CTR_MAINT_FULL)
        return;
    lock_start_read(cl->peers->lock);
    for (k = 0; k < cl->peers->count; k++)
        if (strcmp(cl->peers->entries[k].ip, my_ip) == 0)
            me = cl->peers->entries[k].node_id;
    lock_stop_read(cl->peers->lock);
    if (me == 0 || ntohs(nid_be) != me || cl->peers->my_maint == st)
        return;
    LM_INFO("clusterer_controller: [cluster %d] %s asks this node into "
            "maintenance state %s\n", cl->cluster_id, sender_ip,
            cl_ctr_maint_name(st));
    lock_start_write(cl->peers->lock);
    cl->peers->my_maint = (uint8_t)st;
    lock_stop_write(cl->peers->lock);
    cl_ctr_maint_sync(cl);
}
