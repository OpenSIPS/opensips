/*
 * clusterer_controller - ALIVE, GOODBYE, MASTER_ALIVE, beacons and resync
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
#include "cl_ctr_caps.h"
#include "cl_ctr_stats.h"

static void cl_ctr_rejoin_superior_master(cl_ctr_cluster_t *cl, const char *superior_ip,
                                      const char *via);

/*
 * cl_ctr_broadcast_full_state() - master re-multicasts every peer's NODE_ASSIGN
 * (node_id + BIN mapping) followed by the MEMBER_LIST.  This is the same state a
 * join emits; here it repairs members that missed a NODE_ASSIGN.  Master path.
 */
static void cl_ctr_broadcast_full_state(cl_ctr_cluster_t *cl)
{
    int i;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (e->node_id == 0)
            continue;
        cl_ctr_send_node_assign(cl->sock, e->ip, e->node_id, e->bin_count,
                            (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])e->bin_sockets,
                            strcmp(e->ip, my_ip) == 0 ? cl_ctr_incarnation
                                                      : e->incarnation,
                            cl, NULL, 0);   /* re-broadcast to the group */
    }
    lock_stop_read(cl->peers->lock);
    cl_ctr_send_member_list(cl->sock, cl);
}

/*
 * cl_ctr_handle_resync() - a member reported a membership mismatch.  Only the
 * master answers, and coalesces a burst of RESYNCs into one full-state
 * re-broadcast per CL_CTR_RESYNC_MIN_US.
 */
/**
 * cl_ctr_announce_full_state() - master: publish cluster state to EVERYONE.
 *
 * Master path only.  Coalesced to one broadcast per CL_CTR_RESYNC_MIN_US, and
 * an announcement suppressed by that window is REMEMBERED (full_state_pending)
 * so the keepalive tick emits it a moment later instead of losing it.
 *
 * Why the pending flag matters: the announcement carries each node's
 * NODE_ASSIGN, and with it the incarnation the master admitted that node at.
 * A restarted node is normally recognised by the higher incarnation on its
 * own packets (cl_ctr_check_and_update_seq), but one whose clock was stepped
 * back across the restart reads LOWER than its previous life, and only this
 * announcement tells the others to accept it.  History: before incarnations,
 * a MEMBER_LIST was the only thing that reset a restarted node's replay
 * windows, and a master that unicast it to the joiner alone left the third
 * node black-holing 100% of the restarted node's consumer traffic for ten
 * hours in production.  Coalescing away a second join inside the same window
 * would leave that second node unannounced, which is why a suppressed
 * announcement is deferred rather than dropped.
 */
void cl_ctr_announce_full_state(cl_ctr_cluster_t *cl, const char *why)
{
    utime_t now = get_uticks();

    if ((utime_t)(now - cl->last_full_state_us) < CL_CTR_RESYNC_MIN_US) {
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
    cl_ctr_broadcast_full_state(cl);
}

void cl_ctr_handle_resync(const char *sender_ip, cl_ctr_cluster_t *cl)
{
    int   i_am_master;
    char  why[64];

    lock_start_read(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    lock_stop_read(cl->peers->lock);
    if (!i_am_master)
        return;

    snprintf(why, sizeof why, "RESYNC from %s", sender_ip);
    cl_ctr_announce_full_state(cl, why);
}

/**
 * cl_ctr_handle_alive() - process a CL_CTR_PKT_ALIVE packet.
 *
 * Regular heartbeat path: upsert the sender, re-elect.
 * Only called in CL_CTR_NODE_ACTIVE state; ignored while joining (cl_ctr_recv_one
 * still dispatches them so the peer table builds up before the timeout).
 */
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
            /* A peer whose MTU no longer matches ours: WARN ONLY, never act.
             * That peer's own drift poll will notice and remove itself, which
             * is the node terminating on its OWN condition.  Terminating here
             * instead would mean one `ip link set mtu` on any single host
             * taking down every other node that heard about it. */
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
            e->caps = peer_caps;
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
    /* Config-consistency handling, decided once the master is known.  In
     * 'adopt' mode a non-master node takes the master's settings; otherwise a
     * mismatch is logged once per peer (re-logged only if the peer's advertised
     * config changes, cleared when it matches).  cl_ctr_elect_master does not
     * reorder entries, so the captured index stays valid. */
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
    /* Defer acting as master until we hold the cluster key.  In normal
     * operation a higher-IP joiner has already adopted the key via KEY_GRANT
     * before winning here, so this only guards the pathological case where the
     * KEY_GRANT was lost during the join.  Request a re-key instead of
     * broadcasting an undecryptable MASTER_ALIVE. */
    if (now_master && !cl->have_session_key) {
        cl_ctr_request_rekey(cl);
        return;
    }
    if (prev_master != now_master) {
        cl_ctr_arm_master_timers(cl, now_master);
        cl_ctr_apply_shtags(cl);
    }
}

/**
 * cl_ctr_handle_goodbye() - process a CL_CTR_PKT_GOODBYE packet.
 *
 * Remove the departing node from the peer table immediately.
 *
 * Re-election is triggered ONLY when:
 *   1. Only one node remains - we are alone and must assume mastership.
 *   2. Our IP is higher than the current master's IP, or the master entry
 *      no longer exists because the departing node was the master.
 *      cl_ctr_ip_beats_master_locked() covers both cases: it returns 1 when
 *      no is_master entry is present (departed master) or when our IP
 *      numerically exceeds the current master's.
 *
 * All other departures (a member leaves while a higher-IP master is alive)
 * require no immediate action - the next periodic ALIVE cycle runs
 * cl_ctr_elect_master(cl) within query_time seconds and self-corrects if needed.
 */
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

    /* --- Decide whether re-election is warranted --- */
    if (remaining <= 1) {
	/* We are the only node left - no election needed, promote directly. */
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
	    clctl.remove_node(cl->cluster_id, departed_node_id);
	cl_ctr_apply_shtags(cl);
	return;
    }

    if (cl_ctr_ip_beats_master_locked(ip_to_num(my_ip), cl)) {
	/* Two sub-cases both return 1 from cl_ctr_ip_beats_master_locked:
	 *   a) departing node was the master (no master entry remains)
	 *   b) our IP is genuinely higher than the current master (anomaly) */
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
	    clctl.remove_node(cl->cluster_id, departed_node_id);
	/* Re-apply shtag policy: the still-active master takes over the
	 * departed node's tags, unless an operator override is in effect. */
	cl_ctr_apply_shtags(cl);
	return;
    }

    memcpy(prev_master, cl->peers->last_master,
           strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN));
    prev_master[strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN)] = '\0';

    {
        cl_ctr_elect_master(cl);
        i_am_master = cl_ctr_i_am_master_locked(cl);
    }

    master_unchanged = (strcmp(prev_master, cl->peers->last_master) == 0);
    i_am_master      = cl_ctr_i_am_master_locked(cl);
    /* Snapshot post-election master before releasing - used in member log */
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
	    /* No full MEMBER_LIST is broadcast: every member re-elected the same
	     * deterministic master locally on this same GOODBYE, MASTER_ALIVE
	     * re-asserts it within a keepalive, and the membership digest
	     * reconciles anyone who missed the departure - so the O(N) re-broadcast
	     * (which fragments at large N) is redundant. */
	}
    } else {
	/* This node's own role change (if any) is logged separately by
	 * cl_ctr_elect_master() as a "my role changed" transition line. */
	LM_INFO("clusterer_controller: re-election complete - "
	        "master is %s (%d node(s) remaining)\n",
	        new_master[0] ? new_master : "(none)",
	        remaining);
    }
    if (clctl_loaded && departed_node_id > 0)
	clctl.remove_node(cl->cluster_id, departed_node_id);
    cl_ctr_apply_shtags(cl);
}

/**
 * cl_ctr_handle_master_alive() - process a master keepalive.
 *
 * Beyond rearming the master-dead watchdog, this keeps every node agreeing on
 * the master's identity (the 1s keepalive is more frequent than MEMBER_LIST,
 * so it is the authoritative "who is master" signal) and resolves split-brain:
 * if this node also believes it is master and the announcing node outranks it
 * (cl_ctr_master_outranks(): member count, then term, then IP), it yields.  The
 * beacon path ranks by the same order, so two masters (e.g. after a network
 * partition heals) can never both stick, nor each yield to the other.
 */
void cl_ctr_handle_master_alive(const char *sender_ip, cl_ctr_cluster_t *cl,
                                   const char *payload, int payload_len,
                                   const struct sockaddr *src, socklen_t src_len)
{
    int      i_am_master, yielded = 0, ignored = 0;
    int      from_self = (strcmp(sender_ip, my_ip) == 0);
    uint16_t adv_cnt = 0, my_cnt, adv_live = 0, my_live, cmp_adv, cmp_mine;
    uint32_t adv_term = 0;
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
            cl_ctr_master_outranks(cmp_adv, adv_term, sender_ip,
                                   cmp_mine, cl->peers->my_term, my_ip)) {
            /* Split-brain: another master outranks us - yield.  The actual
             * demotion happens below, OUTSIDE the lock, through
             * cl_ctr_rejoin_superior_master(), which must not be called with
             * the peers lock held. */
            yielded = 1;
        }
        /* else: my own loopback, or a claimant that will yield to us */
    } else if (!from_self) {
        /* Follow the announcing node unless it is a second claimant that does
         * NOT outrank the master we already follow - that one will yield, and
         * switching to it first would make this node flap between the two
         * (and refresh the watchdog for a master that is about to stand
         * down).  The master we follow is forgotten when its keepalives stop
         * (cl_ctr_on_master_dead_tfd), so a genuine successor is never kept
         * out. */
        if (cl->peers->last_master[0] != '\0' &&
            strcmp(sender_ip, cl->peers->last_master) != 0 &&
            !cl_ctr_master_outranks(
                    (adv_live && cl->peers->master_live) ? adv_live : adv_cnt,
                    adv_term, sender_ip,
                    (adv_live && cl->peers->master_live)
                        ? cl->peers->master_live : cl->peers->master_count,
                    cl->peers->master_term, cl->peers->last_master)) {
            ignored = 1;
        } else {
            /* Track the announcing node as the current master so all nodes
             * agree even if a MEMBER_LIST was missed, and so sticky
             * cl_ctr_elect_master preserves the correct current master. */
            cl_ctr_upsert_peer_locked(sender_ip, cl);
            cl_ctr_apply_master_from_list_locked(sender_ip, cl);
            /* the master we follow announcing a LOWER term than its lists
             * carried has restarted (a packet from its previous life is
             * refused by the replay check): its lists start afresh */
            if (adv_term < cl->peers->list_term_seen) {
                cl->peers->list_term_seen = 0;
                cl->peers->list_seq_seen  = 0;
            }
            cl->peers->master_term  = adv_term;
            cl->peers->master_count = adv_cnt;
            cl->peers->master_live  = adv_live;
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
        /* Yielding alone is NOT a merge.  The winner learned us only from this
         * packet's sender-upsert, i.e. as a peer with node_id 0, and the ONLY
         * place a node_id is ever assigned is its handle_join_req().  Without
         * a JOIN_REQ we would sit in its table as id 0 forever: never named in
         * a NODE_ASSIGN, so never added to clusterer anywhere, while our
         * membership digest never matches its MASTER_ALIVE - a RESYNC-per-
         * second livelock, observed live on the 3-node staging cluster after
         * a partition heal.  So re-join properly, exactly as the beacon merge
         * path does; rejoin also demotes us and arms the dead watchdog. */
        cl_ctr_rejoin_superior_master(cl, sender_ip, "MASTER_ALIVE");
    }

    /* Non-masters learn the keepalive's rhythm - a keepalive arriving while
     * this node was asking whether anyone still hears the master proves the
     * suspicion was false - and watch it, for as long as that rhythm says. */
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

    /* Liveness relay: the master reports which node_ids it has seen in-window;
     * refresh those peers' last_seen so our election window stays populated even
     * though a settled non-master no longer hears the peers' ALIVEs directly. */
    if (!i_am_master && !from_self &&
        payload_len >= CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ)
        cl_ctr_apply_alive_bitmap(cl,
            (const unsigned char *)payload + CL_CTR_DIGEST_SZ);

    /* Does the master still know this node?  Its liveness relay lists every
     * member by node_id; a member it purged - this node was paused, or cut
     * off longer than the purge window, and carried on without noticing - is
     * missing from it, and comes back in its table without an id when its
     * next ALIVE arrives.  Nothing on the master's side gives the id back:
     * only a JOIN_REQ does.  So after two keepalives without itself, the
     * member re-joins, and gets its reserved node_id back. */
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
        }
    }

    /* What every live member shares (CC-11), as the master hears them all;
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
    }

    /* Maintenance relay: which nodes are in maintenance.  When the master
     * itself just went into maintenance this is its last keepalive - elect
     * its successor now rather than on the watchdog. */
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

    /* Membership digest: if the master advertises a set we do not match, we may
     * have missed a NODE_ASSIGN (a peer known from its ALIVE but with node_id/BIN
     * unknown).  Pull a rate-limited RESYNC.  Only as a member holding the key,
     * and never off our own loopback. */
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

/**
 * cl_ctr_rejoin_superior_master() - abandon our current allegiance and merge into
 * the partition led by 'superior_ip', adopting its session key.
 *
 * Used by the split-brain merge (cl_ctr_handle_master_beacon): our node - whether a
 * lone/independent master or a member of a smaller partition - records
 * superior_ip as master, stops asserting mastership, and issues a JOIN_REQ so
 * the superior master answers with NODE_ASSIGN + KEY_GRANT.  Once the KEY_GRANT
 * lands we can decrypt the superior partition's session traffic and are fully
 * merged.  Call WITHOUT cl->peers->lock held.
 */
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

/**
 * cl_ctr_handle_master_beacon() - process a CL_CTR_PKT_MASTER_BEACON (bootstrap key).
 *
 * A master announced itself on the bootstrap layer.  If it outranks our own
 * partition we merge into it; otherwise we ignore it (that master will yield to
 * us when it hears our beacon).  Ranking: cl_ctr_master_outranks() - member count,
 * then term, then IP - the same order the keepalive path uses, so exactly one
 * master survives.  A healthy single-master cluster sees only its own master's
 * beacon (sender == our master) and never acts, so this adds no churn.
 */
void cl_ctr_handle_master_beacon(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl)
{
    int      i_am_master, is_new, superior;
    uint16_t our_count, sender_count = 0, sender_live = 0, our_live;
    uint32_t our_term, sender_term = 0;
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
    /* Every build of this wire version sends the count, term, settings and
     * MTU.  A beacon without them, or counting no members or more than a
     * cluster holds, was not sent by a master - and ranked on what it
     * claims, it could draw this node into a merge with nobody. */
    if (!cfg_present || sender_count == 0 || sender_count > CL_CTR_MAX_PEERS
            || sender_live > CL_CTR_MAX_PEERS) {
        LM_DBG("clusterer_controller: [cluster %d] malformed beacon from %s "
               "(%d bytes, count %u), dropping\n", cl->cluster_id, sender_ip,
               payload_len, sender_count);
        return;
    }

    /* Would a merge with this master be refused?  The same tests its
     * cl_ctr_handle_join_req() would apply to our JOIN_REQ: the settings
     * only when the policy is 'reject' (warn/adopt admit a mismatch), the
     * MTU always.  Checked BEFORE ranking, and on both masters, so neither
     * side demotes itself into a merge the other side refuses - which used
     * to end with the merging node's exit(-1), and if the misconfigured side
     * was the larger partition, that took down the correctly configured
     * nodes.  Two masters with different settings now stay two partitions,
     * and both say why, until an operator fixes one of them. */
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

    /* Rank the sender's partition against ours - the same ordering the
     * keepalive path uses, so the two masters cannot each yield to the
     * other. */
    if (our_master[0] == '\0')
        superior = 1;                                   /* we have no master yet */
    else
        superior = cl_ctr_master_outranks(
                       sender_live ? sender_live : sender_count,
                       sender_term, sender_ip,
                       sender_live ? our_live : our_count,
                       our_term, our_master);

    if (!superior)
        return;   /* we outrank the sender; it will yield to us on our beacon */

    cl_ctr_rejoin_superior_master(cl, sender_ip, "beacon");
}

/*
 * cl_ctr_handle_master_probe() - a peer's master went silent and it asks
 * whether this node still hears it.  Answers with how long ago this node
 * last heard that master, or CL_CTR_PROBE_NOT_HEARD if it is not the master
 * this node follows.
 */
void cl_ctr_handle_master_probe(const char *sender_ip, const char *payload,
                                int payload_len, cl_ctr_cluster_t *cl,
                                const struct sockaddr *src, socklen_t src_len)
{
    char     m[CL_CTR_MAX_IP_LEN + 1];
    int      l = (int)strnlen(payload, payload_len < CL_CTR_MAX_IP_LEN
                                       ? payload_len : CL_CTR_MAX_IP_LEN);
    uint32_t ago = CL_CTR_PROBE_NOT_HEARD;
    int      follows, is_me;

    if (l == 0 || l >= payload_len || strcmp(sender_ip, my_ip) == 0)
        return;
    memcpy(m, payload, l);
    m[l] = '\0';
    lock_start_read(cl->peers->lock);
    is_me   = cl_ctr_i_am_master_locked(cl) && strcmp(m, my_ip) == 0;
    follows = !cl_ctr_i_am_master_locked(cl) &&
              strcmp(cl->peers->last_master, m) == 0;
    lock_stop_read(cl->peers->lock);
    if (is_me) {
        /* asked about ourselves: we are alive - and a member cannot hear our
         * keepalives, which is worth saying here, where the fault may be */
        static time_t warned_at;
        time_t now = cl_ctr_now();
        ago = 0;
        if (now - warned_at >= CL_CTR_WIRE_WARN_IVL) {
            warned_at = now;
            LM_WARN("clusterer_controller: [cluster %d] member %s cannot hear "
                    "this master's keepalives (it is asking the cluster "
                    "whether anyone still does) - a one-sided fault between "
                    "the two\n", cl->cluster_id, sender_ip);
        }
    } else if (follows && cl->master_heard_ms) {
        long long d = cl_ctr_now_ms() - cl->master_heard_ms;
        ago = d < 0 ? 0 : (d > 0x7FFFFFFF ? 0x7FFFFFFF : (uint32_t)d);
    }
    cl_ctr_send_master_probe_ack(cl, m, ago, src, src_len);
}

/* cl_ctr_handle_master_probe_ack() - one peer's answer to our probe. */
void cl_ctr_handle_master_probe_ack(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl)
{
    int      l = (int)strnlen(payload, payload_len < CL_CTR_MAX_IP_LEN
                                       ? payload_len : CL_CTR_MAX_IP_LEN);
    uint32_t ago_be;

    if (!cl->probing || l == 0 || payload_len < l + 1 + 4 ||
            strncmp(payload, cl->probe_master, l) != 0 ||
            cl->probe_master[l] != '\0')
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

/*
 * cl_ctr_ka_sample() - a keepalive from the master followed arrived: learn
 * its rhythm.  Smoothed gap and mean deviation with TCP's gains (1/8, 1/4);
 * the false-suspicion margin decays by 1/CL_CTR_KA_MARGIN_DECAY.  A different master starts
 * afresh.  Worker only.
 */
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
