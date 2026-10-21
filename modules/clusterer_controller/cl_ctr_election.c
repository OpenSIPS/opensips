/*
 * clusterer_controller - master election, terms and sharing-tag decisions
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

/**
 * cl_ctr_election_cutoff() - quantized stale cutoff for master election.
 *
 * All NTP-synchronized nodes compute the same value at the same second,
 * so they always evaluate the identical eligible-peer set and elect the
 * same master.
 */
static time_t cl_ctr_election_cutoff(void)
{
    time_t now = cl_ctr_now();
    return (now / (time_t)query_time) * (time_t)query_time
           - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
}

/**
 * cl_ctr_master_outranks() - which of two claimants to mastership survives.
 *
 * When two masters meet - a partition healing, or a takeover in progress -
 * BOTH ends must reach the same verdict, or each yields to the other and
 * neither keeps the role.  There used to be two rules: the keepalive path
 * yielded to the higher IP, the beacon path to the larger member count and
 * then the higher IP, so a higher-IP master of a smaller partition and a
 * lower-IP master of a larger one could each yield to the other at once.
 * This one ordering now serves both paths:
 *
 *   1. member count - the larger partition wins, so a heal disturbs as few
 *      nodes as possible.  It is the count each master HEARS (inside its
 *      election window, CL_CTR_LIVE_SZ) when both announce one, not its
 *      table: an isolated node still lists peers it has not purged yet, and
 *      could out-count a majority that has already purged it;
 *   2. term - the more recently established mastership wins.  A node that
 *      takes over (stickiness 0, or after a failover) asserts a term above
 *      every one it has seen, which is what makes it win over the master it
 *      replaces without either side consulting IPs;
 *   3. IP - a total tiebreak.
 *
 * Count deliberately comes BEFORE term.  A node whose link flaps promotes
 * itself each time it is cut off, and each promotion is a new, higher term:
 * with term first, every flap would hand the cluster - and its sharing tags -
 * to the least reliable node in it.
 *
 * Returns 1 if (c1, t1, ip1) outranks (c2, t2, ip2).
 */
int cl_ctr_master_outranks(uint16_t c1, uint32_t t1, const char *ip1,
                                  uint16_t c2, uint32_t t2, const char *ip2)
{
    if (c1 != c2)
        return c1 > c2;
    if (t1 != t2)
        return t1 > t2;
    return ip_to_num(ip1) > ip_to_num(ip2);
}

/* Record a term announced by a master; the next mastership we assert goes
 * above it. */
void cl_ctr_note_term(cl_ctr_cluster_t *cl, uint32_t term)
{
    if (term > cl->peers->term_seen)
        cl->peers->term_seen = term;
}

/* Is @term (announced by @from) a plausible term?  Refuses one more than
 * CL_CTR_TERM_JUMP_MAX above the highest term this node knows; a node that
 * knows none yet (0) has nothing to judge by and accepts it.  Counts and
 * logs (once a minute) what it refuses.  Must be called with
 * cl->peers->lock held for WRITE. */
int cl_ctr_term_sane(cl_ctr_cluster_t *cl, uint32_t term, const char *from)
{
    uint32_t known = cl->peers->term_seen;
    time_t   now;

    if (cl->peers->my_term > known)     known = cl->peers->my_term;
    if (cl->peers->master_term > known) known = cl->peers->master_term;
    if (known == 0 || term <= known || term - known <= CL_CTR_TERM_JUMP_MAX)
        return 1;
    cl->peers->terms_refused++;
    now = cl_ctr_now();
    if (cl->peers->terms_refused_warned_at == 0 ||
            now - cl->peers->terms_refused_warned_at >= CL_CTR_WIRE_WARN_IVL) {
        cl->peers->terms_refused_warned_at = now;
        LM_WARN("clusterer_controller: [cluster %d] %s announced term %u, "
                "more than %u above the highest term this node knows (%u) - "
                "terms rise by one per election, so the packet is ignored; "
                "%lu refused so far\n", cl->cluster_id, from, term,
                CL_CTR_TERM_JUMP_MAX, known, cl->peers->terms_refused);
    }
    return 0;
}

/**
 * cl_ctr_elect_master(cl) - mark the peer with the highest IP as master.
 *
 * Uses the quantized election window so all NTP-synchronized nodes evaluate
 * the same eligible set and elect the same master.
 *
 * Also tracks two state transitions and logs them at INFO:
 *
 *   in_election 1->0  A peer's last_seen fell outside the election window -
 *                    the node is considered down.  Logged immediately so the
 *                    operator sees the event without waiting for cl_ctr_prune_stale(cl)
 *                    (which only fires at CL_CTR_PURGE_FACTOR x query_time).
 *
 *   last_master      The elected master IP changed - either because the
 *                    previous master went down, or a higher-IP node joined.
 *
 * Must be called with cl->peers->lock held.
 */
void cl_ctr_elect_master(cl_ctr_cluster_t *cl)
{
    time_t       cutoff    = cl_ctr_election_cutoff();
    unsigned int top_num   = 0;
    int          i, n_in = 0, top_idx = -1, cur_master_idx = -1, master_idx = -1;
    int          n_maint = 0, allow_maint = 0;
    int          i_am_elected = 0;
    char         prev_master[CL_CTR_MAX_IP_LEN + 1];
    char         prev_backup[CL_CTR_MAX_IP_LEN + 1];

    prev_backup[0] = '\0';
    /* Snapshot the master we had before this election, for change reporting. */
    {
	size_t _l = strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN);
	memcpy(prev_master, cl->peers->last_master, _l);
	prev_master[_l] = '\0';
    }

    for (i = 0; i < cl->peers->count; i++) {
	cl_ctr_peer_t *e       = &cl->peers->entries[i];
	int        now_in  = (e->last_seen >= cutoff);

	/* Detect peer dropping out of the election window */
	if (e->in_election && !now_in)
	    LM_INFO("clusterer_controller: peer %s went down "
	            "(last seen %lds ago)\n",
	            e->ip, (long)(cl_ctr_now() - e->last_seen));

	e->in_election = now_in;

	/* Remember the live current master and the previous backup before
	 * clearing the flags - used for sticky election and change logging. */
	if (e->is_master && now_in)
	    cur_master_idx = i;
	if (e->is_backup) {
	    size_t _l = strnlen(e->ip, CL_CTR_MAX_IP_LEN);
	    memcpy(prev_backup, e->ip, _l);
	    prev_backup[_l] = '\0';
	}

	e->is_master = 0;
	e->is_backup = 0;

	if (now_in) {
	    n_in++;
	    if (e->maint != CL_CTR_MAINT_NONE)
		n_maint++;
	    else if (e->ip_num > top_num) {
		top_num = e->ip_num;
		top_idx = i;
	    }
	}
    }

    /* A node in maintenance is no candidate - for master (a live current
     * master in maintenance is not kept, which is the handover) nor for
     * backup.  Only when every node in the window is in maintenance does the
     * cluster take one anyway: it must have a master. */
    if (cur_master_idx >= 0 &&
        cl->peers->entries[cur_master_idx].maint != CL_CTR_MAINT_NONE)
	cur_master_idx = -1;
    if (top_idx < 0 && n_maint > 0) {
	for (i = 0; i < cl->peers->count; i++) {
	    cl_ctr_peer_t *e = &cl->peers->entries[i];
	    if (e->in_election && e->ip_num > top_num) {
		top_num = e->ip_num;
		top_idx = i;
	    }
	}
	allow_maint = 1;
    }

    /* Choose the master:
     *   master_stickiness == 1 (default, sticky): a live current master keeps the
     *     role - a higher-IP peer does NOT preempt it (fewer handovers).  Only
     *     when there is no live master do we elect the highest-IP peer.
     *   master_stickiness == 0: pure highest-IP election - the highest-IP peer
     *     always wins, preempting any lower-IP current master.
     * Split-brain (two live masters, e.g. after a partition heal) is resolved
     * separately, by cl_ctr_master_outranks() on both the keepalive and the
     * beacon path.                                                           */
    if (cl->master_stickiness == 1 && cur_master_idx >= 0)
	master_idx = cur_master_idx;
    else
	master_idx = top_idx;

    if (master_idx >= 0) {
	const char  *m_ip, *b_ip, *why;
	int          b_idx = -1, master_changed, backup_changed;
	unsigned int b_num = 0;
	int          j;

	cl->peers->entries[master_idx].is_master = 1;
	m_ip = cl->peers->entries[master_idx].ip;
	i_am_elected = (strcmp(m_ip, my_ip) == 0);

	/* Designate the BACKUP: the highest-IP in-window peer that is not the
	 * master.  Deterministic across all nodes, so everyone agrees who takes
	 * over next; on master failure cl_ctr_elect_master (no live current master)
	 * promotes exactly this node.                                         */
	for (j = 0; j < cl->peers->count; j++) {
	    cl_ctr_peer_t *e = &cl->peers->entries[j];
	    if (j == master_idx || !e->in_election)
		continue;
	    if (e->maint != CL_CTR_MAINT_NONE && !allow_maint)
		continue;
	    if (e->ip_num > b_num) {
		b_num = e->ip_num;
		b_idx = j;
	    }
	}
	if (b_idx >= 0)
	    cl->peers->entries[b_idx].is_backup = 1;
	b_ip = (b_idx >= 0) ? cl->peers->entries[b_idx].ip : NULL;

	master_changed = (strcmp(prev_master, m_ip) != 0);
	backup_changed = (strcmp(prev_backup, b_ip ? b_ip : "") != 0);

	/* Persist the elected master for the next round / other handlers. */
	{
	    size_t _l = strnlen(m_ip, CL_CTR_MAX_IP_LEN);
	    memcpy(cl->peers->last_master, m_ip, _l);
	    cl->peers->last_master[_l] = '\0';
	}

	/* One clear line whenever the master or backup role changes, stating
	 * who holds each role, which is this node, and WHY the master was
	 * chosen (highest IP, sticky current master kept over a higher-IP peer, or
	 * sole surviving node).                                               */
	if (master_changed || backup_changed) {
	    if (allow_maint)
		why = "every node in the window is in maintenance";
	    else if (n_in <= 1)
		why = "sole node in window";
	    else if (cl->master_stickiness == 1 && master_idx == cur_master_idx &&
	             top_idx >= 0 && top_idx != master_idx)
		why = "sticky: current master kept over higher-IP node";
	    else
		why = "highest IP in window";

	    LM_INFO("clusterer_controller: [cluster %d] roles: MASTER=%s%s (%s); "
	            "BACKUP=%s%s (highest-IP non-master); %d node(s) in window\n",
	            cl->cluster_id,
	            m_ip,
	            strcmp(m_ip, my_ip) == 0 ? " [me]" : "",
	            why,
	            b_ip ? b_ip : "(none)",
	            (b_ip && strcmp(b_ip, my_ip) == 0) ? " [me]" : "",
	            n_in);
	}

	/* Log this node's own role transition (member/backup/master) whenever
	 * it changes, so a failover or a peer (re)joining that demotes/promotes
	 * us gets its own line rather than being implied by the roles list. */
	{
	    int my_new_role = i_am_elected ? CL_CTR_ROLE_MASTER :
	        ((b_ip && strcmp(b_ip, my_ip) == 0) ? CL_CTR_ROLE_BACKUP :
	         CL_CTR_ROLE_MEMBER);
	    if (my_new_role != cl->my_role) {
		LM_INFO("clusterer_controller: [cluster %d] my role changed: "
		        "%s -> %s\n", cl->cluster_id,
		        cl_ctr_role_name(cl->my_role), cl_ctr_role_name(my_new_role));
		cl->my_role = my_new_role;
	    }
	}
    } else {
	/* No eligible peer - cluster has no master; we are a plain member. */
	if (cl->my_role != CL_CTR_ROLE_MEMBER) {
	    LM_INFO("clusterer_controller: [cluster %d] my role changed: %s -> "
	            "member\n", cl->cluster_id, cl_ctr_role_name(cl->my_role));
	    cl->my_role = CL_CTR_ROLE_MEMBER;
	}
	if (cl->peers->last_master[0] != '\0') {
	    LM_INFO("clusterer_controller: [cluster %d] master lost (%s), "
	            "no eligible peers in election window\n",
	            cl->cluster_id, cl->peers->last_master);
	    cl->peers->last_master[0] = '\0';
	}
    }

    /* Invariant: MASTER_ALIVE keepalive armed <=> I am the elected master.
     * If this election demoted us (someone else won, or no master at all) but
     * our keepalive is still running, stop it now - otherwise we keep
     * broadcasting MASTER_ALIVE as a phantom master and lower-IP peers
     * oscillate between two masters.  Only disarm here: promoting a new master
     * (arming) is done by the became-master paths, which also establish the
     * session key.  cl_ctr_arm_master_timers() only issues timerfd syscalls, so it
     * is safe under cl->peers->lock. */
    if (!i_am_elected && cl->master_ka_armed)
	cl_ctr_arm_master_timers(cl, 0);
}

/**
 * cl_ctr_i_am_master_locked(cl) - return 1 if my_ip is currently elected master.
 * Must be called with cl->peers->lock held.
 */
int cl_ctr_i_am_master_locked(cl_ctr_cluster_t *cl)
{
    time_t cutoff = cl_ctr_election_cutoff();
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].is_master &&
	    cl->peers->entries[i].last_seen >= cutoff &&
	    strcmp(cl->peers->entries[i].ip, my_ip) == 0)
	    return 1;
    }
    return 0;
}

/**
 * cl_ctr_ip_beats_master_locked() - check whether a candidate IP would displace
 *                                the current master in an election.
 *
 * Returns 1 (re-election is worth running) when:
 *   - ip_num is strictly greater than the current master's ip_num, OR
 *   - there is no current master in the election window (no-one to defend).
 *
 * Returns 0 when the current master has a higher or equal IP - it would
 * win the election anyway, so running one is pointless.
 *
 * Must be called with cl->peers->lock held.
 */
int cl_ctr_ip_beats_master_locked(unsigned int ip_num, cl_ctr_cluster_t *cl)
{
    time_t cutoff = cl_ctr_election_cutoff();
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].is_master &&
	    cl->peers->entries[i].last_seen >= cutoff)
	    return (ip_num > cl->peers->entries[i].ip_num);
    }
    return 1;   /* no master in the election window - election is needed */
}

/**
 * cl_ctr_apply_shtags_decision() - (de)activate this node's sharing tags per policy.
 *
 * Decides whether THIS node should be the active sharing-tag holder for the
 * cluster and calls clusterer accordingly.  Idempotent (activate/force-backup
 * are no-ops when already in that state), so it is safe to call on any relevant
 * event.  Takes NO lock - the caller passes the state it already read, so this
 * is safe both inside and outside cl->peers->lock (clctl uses its own locks).
 *
 *   forced != 0 : the operator pinned node_id 'forced' as the active holder
 *                 (clusterer_controller:shtag_force).  Only that node activates; all others go
 *                 to backup.  Automatic allocation is suspended.
 *   forced == 0 : automatic mode - the current master is the active holder.
 */
void cl_ctr_apply_shtags_decision(cl_ctr_cluster_t *cl, int i_am_master,
                                     uint16_t forced)
{
    int activate;

    if (!cl->manage_shtags || !clctl_loaded || !clctl.activate_backup_shtags)
        return;

    if (forced != 0)
        activate = (my_node_id != 0 && (uint16_t)my_node_id == forced);
    else
        activate = i_am_master;
    /* cut off from most of the cluster (release_tag_when_isolated): hold no
     * active tag, the majority's master holds it */
    if (cl->tag_released)
        activate = 0;

    /* Log the reason on this node, but only when the decision or its cause
     * changes - cl_ctr_apply_shtags_decision() is called on every relevant event
     * and clusterer's own activate/force calls are idempotent, so logging
     * unconditionally would flood.  This makes the "why" visible on EVERY
     * node (master, forced holder, and passive backups alike).             */
    if (activate != cl->shtag_last_active || forced != cl->shtag_last_forced) {
        if (activate && forced != 0)
            LM_INFO("clusterer_controller: [cluster %d] activating sharing tags "
                    "- operator forced this node (node_id %u) as active holder\n",
                    cl->cluster_id, forced);
        else if (activate)
            LM_INFO("clusterer_controller: [cluster %d] activating sharing tags "
                    "- this node is the cluster master\n", cl->cluster_id);
        else if (forced != 0)
            LM_INFO("clusterer_controller: [cluster %d] keeping sharing tags in "
                    "backup - operator forced node_id %u as active holder\n",
                    cl->cluster_id, forced);
        else
            LM_INFO("clusterer_controller: [cluster %d] keeping sharing tags in "
                    "backup - active holder is the cluster master\n",
                    cl->cluster_id);
        cl->shtag_last_active = activate;
        cl->shtag_last_forced = forced;
    }

    if (activate)
        clctl.activate_backup_shtags(cl->cluster_id);
    else if (clctl.force_backup_shtags)
        clctl.force_backup_shtags(cl->cluster_id);
}

/**
 * cl_ctr_apply_shtags() - convenience wrapper that reads the current state under a
 * read lock and applies the shtag decision.  Call WITHOUT cl->peers->lock held.
 */
void cl_ctr_apply_shtags(cl_ctr_cluster_t *cl)
{
    int      i_am_master;
    uint16_t forced;

    lock_start_read(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    forced      = cl->peers->shtag_forced_node_id;
    lock_stop_read(cl->peers->lock);

    cl_ctr_apply_shtags_decision(cl, i_am_master, forced);
}

/* =========================================================================
 * State transition helper
 * ========================================================================= */

/**
 * cl_ctr_on_became_master() - side effects when this node wins an election.
 * Generates fresh master_salt, derives session_key, arms MASTER_ALIVE timer,
 * disarms master_dead watchdog.  Must be called with cl->peers->lock held WRITE.
 */
void cl_ctr_on_became_master(cl_ctr_cluster_t *cl)
{
    cl->join_pending = 0;   /* any pending re-key join is now moot */
    if (cl_ctr_random_bytes(cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ) != 0) {
        LM_ERR("clusterer_controller: [cluster %d] RNG for master_salt failed\n",
               cl->cluster_id);
        return;
    }
    cl_ctr_derive_session_key(cl);   /* reads cl->peers->master_salt */
    LM_INFO("clusterer_controller: [cluster %d] became master - "
            "new master_salt generated, session key rotated\n", cl->cluster_id);
    /* Timer ops outside lock (timerfd is worker-local, no shm concern) */
}

/**
 * cl_ctr_arm_master_timers() - arm/disarm keepalive timers after election.
 * Call WITHOUT cl->peers->lock held.
 * i_am_master: 1 = we won, arm MASTER_ALIVE, disarm dead-watchdog.
 *              0 = we lost, arm dead-watchdog, disarm MASTER_ALIVE.
 */
void cl_ctr_arm_master_timers(cl_ctr_cluster_t *cl, int i_am_master)
{
    /* A new mastership asserts a term above every one this node has heard
     * of - that is what lets it win cl_ctr_master_outranks() against the
     * master it replaces.  Re-arming an existing mastership keeps its term. */
    if (i_am_master && !cl->master_ka_armed) {
        /* PreVote, as in Raft: raise the term only when something confirmed
         * that the old master is gone (or there never was one).  A node that
         * elects itself unconfirmed - nobody answered its question, or there
         * was nobody to ask - is most likely the one cut off, and keeps the
         * term: at the heal it cannot outrank the cluster on it, however long
         * the cut lasted. */
        int raise = cl->term_confirmed || cl->peers->term_seen == 0;

        cl->peers->my_term     = cl->peers->term_seen + (raise ? 1 : 0);
        cl->peers->term_seen   = cl->peers->my_term;
        cl->peers->master_term = cl->peers->my_term;
        cl->term_confirmed     = 0;
        if (raise)
            LM_INFO("clusterer_controller: [cluster %d] asserting mastership "
                    "at term %u\n", cl->cluster_id, cl->peers->my_term);
        else
            LM_INFO("clusterer_controller: [cluster %d] asserting mastership "
                    "at term %u, unconfirmed - nobody confirmed the old master "
                    "is gone, so the term is not raised\n", cl->cluster_id,
                    cl->peers->my_term);
    } else if (!i_am_master) {
        cl->peers->my_term = 0;
    }
    cl->master_ka_armed = i_am_master ? 1 : 0;
    if (i_am_master) {
        cl_ctr_arm_tfd(cl->master_alive_tfd, CL_CTR_MASTER_KA_INTERVAL, CL_CTR_MASTER_KA_INTERVAL);
        cl_ctr_arm_tfd(cl->master_dead_tfd,  0, 0);   /* disarm watchdog */
    } else {
        /* No longer master: drop any queued master->joiner retransmits so a
         * demoted node can't keep pushing a joiner onto a now-stale key. */
        cl_ctr_retx_flush(cl);
        cl_ctr_arm_tfd(cl->master_alive_tfd, 0, 0);   /* disarm sender   */
        cl_ctr_arm_master_watchdog(cl);
    }
}

/**
 * cl_ctr_request_rekey() - ask the current key-holder for the session key.
 * Sends a single JOIN_REQ (bootstrap key), guarded by join_pending so a fresh
 * nonce is not stomped while one exchange is in flight.  Used when a node is
 * elected master but has not yet adopted the cluster key (KEY_GRANT lost).
 * Call WITHOUT cl->peers->lock held.
 */
void cl_ctr_request_rekey(cl_ctr_cluster_t *cl)
{
    if (cl->join_pending)
        return;
    cl->join_pending = 1;
    cl_ctr_send_join_req(cl->sock, cl);
}

/* =========================================================================
 * Maintenance mode
 * ========================================================================= */

const char *cl_ctr_maint_name(int st)
{
    return st == CL_CTR_MAINT_EVICTED ? "evicted" : "none";
}

/* "evicted"/"on"/"1" -> CL_CTR_MAINT_EVICTED, "none"/"off"/"0" -> NONE, else -1 */
int cl_ctr_maint_parse(const char *s, int len)
{
    if ((len == 7 && strncasecmp(s, "evicted", 7) == 0) ||
        (len == 2 && strncasecmp(s, "on", 2) == 0) ||
        (len == 1 && s[0] == '1'))
        return CL_CTR_MAINT_EVICTED;
    if ((len == 4 && strncasecmp(s, "none", 4) == 0) ||
        (len == 3 && strncasecmp(s, "off", 3) == 0) ||
        (len == 1 && s[0] == '0'))
        return CL_CTR_MAINT_NONE;
    return -1;
}

/* Request this node's maintenance state @st (MI or script, any process):
 * stored in shm and handed to the worker, which applies and announces it.
 * Returns 0, or -1 when the worker is not up yet. */
int cl_ctr_set_my_maint(cl_ctr_cluster_t *cl, int st)
{
    int proc_no;

    lock_start_write(cl->peers->lock);
    cl->peers->my_maint = (uint8_t)st;
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);
    if (proc_no < 0)
        return -1;
    return ipc_send_rpc(proc_no, cl_ctr_rpc_maint, cl) < 0 ? -1 : 0;
}

/* Run the election now and act on its result, as the ALIVE tick would.
 * Call WITHOUT cl->peers->lock held. */
void cl_ctr_reelect_now(cl_ctr_cluster_t *cl, const char *why)
{
    int prev, now;

    lock_start_write(cl->peers->lock);
    prev = cl_ctr_i_am_master_locked(cl);
    cl_ctr_elect_master(cl);
    now = cl_ctr_i_am_master_locked(cl);
    lock_stop_write(cl->peers->lock);
    LM_INFO("clusterer_controller: [cluster %d] re-electing now - %s\n",
            cl->cluster_id, why);
    if (now && !cl->have_session_key) {
        cl_ctr_request_rekey(cl);
        return;
    }
    if (prev != now)
        cl_ctr_arm_master_timers(cl, now);
    cl_ctr_apply_shtags(cl);
}

/*
 * cl_ctr_maint_sync() - apply this node's requested maintenance state.
 *
 * Worker only.  Records it in this node's own entry, announces it at once
 * (an ALIVE, so the master learns it now and relays it), and when this node
 * is the master going into maintenance, sends one last keepalive carrying it
 * - the members elect a successor as soon as they read it - and steps down.
 */
void cl_ctr_maint_sync(cl_ctr_cluster_t *cl)
{
    int i, st, was_master = 0;

    lock_start_write(cl->peers->lock);
    st = cl->peers->my_maint;
    if (st == cl->maint_adv) {
        lock_stop_write(cl->peers->lock);
        return;
    }
    cl->maint_adv = (uint8_t)st;
    for (i = 0; i < cl->peers->count; i++)
        if (strcmp(cl->peers->entries[i].ip, my_ip) == 0) {
            cl->peers->entries[i].maint = (uint8_t)st;
            was_master = cl->peers->entries[i].is_master;
        }
    lock_stop_write(cl->peers->lock);

    LM_INFO("clusterer_controller: [cluster %d] this node %s maintenance (%s)%s\n",
            cl->cluster_id, st == CL_CTR_MAINT_NONE ? "leaves" : "enters",
            cl_ctr_maint_name(st),
            was_master && st != CL_CTR_MAINT_NONE
                ? " - it is the master and hands over" : "");
    cl_ctr_raise_maint_event(cl, my_node_id, st);
    cl_ctr_send_alive(cl->sock, cl);
    if (was_master && st != CL_CTR_MAINT_NONE) {
        cl_ctr_send_master_alive(cl->sock, cl);
        cl_ctr_reelect_now(cl, "this node went into maintenance");
    }
}

/* IPC job: run cl_ctr_maint_sync() in the worker. */
void cl_ctr_rpc_maint(int sender, void *param)
{
    cl_ctr_maint_sync((cl_ctr_cluster_t *)param);
}

/*
 * cl_ctr_maint_peer_changed() - a peer announced a new maintenance state
 * (master path: heard in its ALIVE).  Raises the event, and when it went
 * into maintenance while holding an operator's sharing-tag pin, clears the
 * pin - automatic allocation resumes - and tells the cluster.
 */
void cl_ctr_maint_peer_changed(cl_ctr_cluster_t *cl, uint16_t node_id, int st)
{
    int cleared = 0, im;

    cl_ctr_raise_maint_event(cl, node_id, st);
    if (st == CL_CTR_MAINT_NONE || node_id == 0)
        return;
    lock_start_write(cl->peers->lock);
    im = cl_ctr_i_am_master_locked(cl);
    if (im && cl->peers->shtag_forced_node_id == node_id) {
        cl->peers->shtag_forced_node_id = 0;
        cleared = 1;
    }
    lock_stop_write(cl->peers->lock);
    if (cleared) {
        LM_WARN("clusterer_controller: [cluster %d] node %u holding the forced "
                "sharing tag went into maintenance - resuming automatic "
                "allocation\n", cl->cluster_id, node_id);
        cl_ctr_send_member_list(cl->sock, cl);
        cl_ctr_apply_shtags(cl);
    }
}

/*
 * cl_ctr_isolation_round() - once per ALIVE round: is this master cut off
 * from most of its cluster?
 *
 * It remembers the live membership it held steadily (stable_live: grows at
 * once, shrinks only when a smaller membership of at least half has lasted
 * three rounds - members that left or were purged).  Hearing strictly
 * FEWER than half of it for a whole election window means the rest of the
 * cluster is elsewhere and has most likely elected a master of its own; with
 * release_tag_when_isolated set, this master then releases the active
 * sharing tag (it stays master for the control plane) so that two masters do
 * not both hold it, and takes it back once it hears a majority again.  A
 * two-node cluster never releases: one of two is not fewer than half.
 */
void cl_ctr_isolation_round(cl_ctr_cluster_t *cl, int i_am_master)
{
    long long now = cl_ctr_now_ms();
    uint16_t  live;

    if (!i_am_master) {
        cl->stable_live       = 0;
        cl->below_rounds      = 0;
        cl->isolated_since_ms = 0;
        if (cl->tag_released) {
            cl->tag_released = 0;
            cl->peers->tag_released = 0;
        }
        return;
    }
    live = cl_ctr_live_count(cl);
    if (cl->stable_live == 0 || live >= cl->stable_live) {
        cl->stable_live  = live;
        cl->below_rounds = 0;
    }
    if (2 * (int)live < (int)cl->stable_live) {
        if (!cl->isolated_since_ms)
            cl->isolated_since_ms = now;
        if (release_tag_when_isolated && !cl->tag_released &&
                now - cl->isolated_since_ms
                    >= (long long)query_time * CL_CTR_ELECT_FACTOR * 1000) {
            cl->tag_released        = 1;
            cl->peers->tag_released = 1;
            LM_WARN("clusterer_controller: [cluster %d] this master hears only "
                    "%u of the %u members it held for %d s - it is cut off "
                    "from most of the cluster, which has most likely elected "
                    "another master: releasing the active sharing tag until "
                    "it hears a majority again\n", cl->cluster_id, live,
                    cl->stable_live, query_time * CL_CTR_ELECT_FACTOR);
            cl_ctr_apply_shtags(cl);
        }
        return;
    }
    cl->isolated_since_ms = 0;
    if (live < cl->stable_live && ++cl->below_rounds >= 3) {
        cl->stable_live  = live;
        cl->below_rounds = 0;
    }
    if (cl->tag_released) {
        cl->tag_released        = 0;
        cl->peers->tag_released = 0;
        LM_INFO("clusterer_controller: [cluster %d] this master hears %u of "
                "%u members again - taking the active sharing tag back\n",
                cl->cluster_id, live, cl->stable_live);
        cl_ctr_apply_shtags(cl);
    }
}
