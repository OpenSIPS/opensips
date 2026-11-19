/*
 * clusterer_controller - master election, terms and sharing-tag decisions
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
#include "cl_ctr_events.h"

/* quantized to query_time: NTP-synced nodes get the same cutoff in the same
 * second, so all see the same eligible set and elect the same master */
static time_t cl_ctr_election_cutoff(void)
{
    time_t now = cl_ctr_now();
    return (now / (time_t)query_time) * (time_t)query_time
           - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
}

/* one order for the keepalive and beacon paths, so both masters reach the same
 * verdict: the member count each hears (not its table), then term, then a term
 * raised over one that was not (@u: unraised), then IP */
int cl_ctr_master_outranks(uint16_t c1, uint32_t t1, int u1, const char *ip1,
                           uint16_t c2, uint32_t t2, int u2, const char *ip2)
{
    /* count first: a flapping node raises its term at every cut-off and
     * would otherwise win the cluster and its sharing tags */
    if (c1 != c2)
        return c1 > c2;
    if (t1 != t2)
        return t1 > t2;
    /* a node that could not confirm the old master gone, likely itself cut
     * off, keeps the term it knew: once healed it must not win on its IP */
    if (!u1 != !u2)
        return !u1;
    return ip_to_num(ip1) > ip_to_num(ip2);
}

/* the next mastership this node asserts goes above every term noted here */
void cl_ctr_note_term(cl_ctr_cluster_t *cl, uint32_t term)
{
    if (term > cl->peers->term_seen)
        cl->peers->term_seen = term;
}

/* refuses a term more than CL_CTR_TERM_JUMP_MAX above the highest known, even
 * from 0 (terms rise by one per election); call with peers->lock for WRITE */
int cl_ctr_term_sane(cl_ctr_cluster_t *cl, uint32_t term, const char *from)
{
    uint32_t known = cl->peers->term_seen;
    time_t   now;

    if (cl->peers->my_term > known)     known = cl->peers->my_term;
    if (cl->peers->master_term > known) known = cl->peers->master_term;
    if (term <= known || term - known <= CL_CTR_TERM_JUMP_MAX)
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

/* no candidate: maintenance, CONNECTING, or this node while it is unheard */
#define CL_CTR_NO_CANDIDATE(cl, e) (CL_CTR_NO_ROLE(e) || \
	((cl)->unheard && strcmp((e)->ip, my_ip) == 0))

/* caller holds cl->peers->lock */
void cl_ctr_elect_master(cl_ctr_cluster_t *cl)
{
    time_t       cutoff    = cl_ctr_election_cutoff();
    unsigned int top_num   = 0;
    int          i, n_in = 0, top_idx = -1, cur_master_idx = -1, master_idx = -1;
    int          n_maint = 0, allow_maint = 0;
    int          i_am_elected = 0;
    char         prev_master[CL_CTR_MAX_IP_LEN + 1];
    char         prev_backup[CL_CTR_MAX_IP_LEN + 1];

    /* granted the key, a joiner follows that master until its list comes:
     * unheard while queued, the master would lose this election */
    if (cl->peers->node_state == CL_CTR_NODE_NEW && cl->granted_by[0] != '\0')
	return;
    /* just online, its window is still filling from heartbeats: it follows the
     * master that admitted it for one dead time */
    if (cl->peers->node_state == CL_CTR_NODE_ACTIVE && cl->active_since_ms &&
            cl->peers->last_master[0] != '\0' &&
            strcmp(cl->peers->last_master, my_ip) != 0 &&
            cl_ctr_now_ms() - cl->active_since_ms < CL_CTR_DEAD_MS)
	return;

    prev_backup[0] = '\0';
    {
	size_t _l = strnlen(cl->peers->last_master, CL_CTR_MAX_IP_LEN);
	memcpy(prev_master, cl->peers->last_master, _l);
	prev_master[_l] = '\0';
    }

    for (i = 0; i < cl->peers->count; i++) {
	cl_ctr_peer_t *e       = &cl->peers->entries[i];
	int        now_in  = (e->last_seen >= cutoff);

	/* logged now, not at the purge (CL_CTR_PURGE_FACTOR x query_time) */
	if (e->in_election && !now_in)
	    LM_INFO("clusterer_controller: peer %s went down "
	            "(last seen %lds ago)\n",
	            e->ip, (long)(cl_ctr_now() - e->last_seen));

	e->in_election = now_in;

	/* before the flags are cleared: for stickiness and change logging */
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
	    if (CL_CTR_NO_CANDIDATE(cl, e))
		n_maint++;
	    else if (e->ip_num > top_num) {
		top_num = e->ip_num;
		top_idx = i;
	    }
	}
    }

    /* a node in maintenance or CONNECTING is no candidate (a master entering
     * maintenance is not kept: the handover) unless all in the window are */
    if (cur_master_idx >= 0 &&
        CL_CTR_NO_CANDIDATE(cl, &cl->peers->entries[cur_master_idx]))
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

    /* stickiness 1: a live master keeps the role over a higher IP; 0: the
     * highest IP always wins.  Two live masters: cl_ctr_master_outranks() */
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

	/* backup: the highest-IP in-window non-master - every node agrees, and it is
	 * the one promoted when the master fails */
	for (j = 0; j < cl->peers->count; j++) {
	    cl_ctr_peer_t *e = &cl->peers->entries[j];
	    if (j == master_idx || !e->in_election)
		continue;
	    if (CL_CTR_NO_CANDIDATE(cl, e) && !allow_maint)
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

	{
	    size_t _l = strnlen(m_ip, CL_CTR_MAX_IP_LEN);
	    memcpy(cl->peers->last_master, m_ip, _l);
	    cl->peers->last_master[_l] = '\0';
	}

	if (master_changed)
	    cl_ctr_note_master(cl, m_ip, cl->peers->entries[master_idx].node_id);
	/* a new master to watch: an expiry armed for the old one must not drop it */
	if (master_changed && !i_am_elected) {
	    cl->probing            = 0;
	    cl->hold_since_ms      = 0;
	    cl->probe_quiet_rounds = 0;
	    cl_ctr_arm_master_watchdog(cl);
	}
	if (i_am_elected)
	    cl->unheard = 0;
	if (master_changed || backup_changed) {
	    if (n_in <= 1)
		why = "sole node in window";
	    else if (allow_maint)
		why = "every node in the window is in maintenance";
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

	{
	    int my_new_role = i_am_elected ? CL_CTR_ROLE_MASTER :
	        ((b_ip && strcmp(b_ip, my_ip) == 0) ? CL_CTR_ROLE_BACKUP :
	         CL_CTR_ROLE_MEMBER);
	    if (my_new_role != cl->my_role) {
		LM_INFO("clusterer_controller: [cluster %d] my role changed: "
		        "%s -> %s\n", cl->cluster_id,
		        cl_ctr_role_name(cl->my_role), cl_ctr_role_name(my_new_role));
		cl_ctr_note_role(cl, cl->my_role, my_new_role);
		cl->my_role = my_new_role;
	    }
	}
    } else {
	if (cl->my_role != CL_CTR_ROLE_MEMBER) {
	    LM_INFO("clusterer_controller: [cluster %d] my role changed: %s -> "
	            "member\n", cl->cluster_id, cl_ctr_role_name(cl->my_role));
	    cl_ctr_note_role(cl, cl->my_role, CL_CTR_ROLE_MEMBER);
	    cl->my_role = CL_CTR_ROLE_MEMBER;
	}
	if (cl->peers->last_master[0] != '\0') {
	    LM_INFO("clusterer_controller: [cluster %d] master lost (%s), "
	            "no eligible peers in election window\n",
	            cl->cluster_id, cl->peers->last_master);
	    cl->peers->last_master[0] = '\0';
	}
    }

    /* keepalive armed <=> elected master; only disarm here (arming goes with
     * the session key) - timerfd syscalls only, safe under cl->peers->lock */
    if (!i_am_elected && cl->master_ka_armed)
	cl_ctr_arm_master_timers(cl, 0);
}

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

/* 1 when ip_num is above the live master's or there is none: only then can a
 * re-election change anything */
int cl_ctr_ip_beats_master_locked(unsigned int ip_num, cl_ctr_cluster_t *cl)
{
    time_t cutoff = cl_ctr_election_cutoff();
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].is_master &&
	    cl->peers->entries[i].last_seen >= cutoff)
	    return (ip_num > cl->peers->entries[i].ip_num);
    }
    return 1;
}

/* takes no lock (the caller passes the state it read), so it runs inside or
 * outside cl->peers->lock; idempotent, safe to call on any event */
void cl_ctr_apply_shtags_decision(cl_ctr_cluster_t *cl, int i_am_master,
                                     uint16_t forced)
{
    int activate;

    if (!cl->manage_shtags || !clctl_loaded)
        return;

    if (forced != 0)
        activate = (my_node_id != 0 && (uint16_t)my_node_id == forced);
    else
        activate = i_am_master;
    /* cut off from most of the cluster (release_tag_when_isolated): hold no
     * active tag, the majority's master holds it */
    if (cl->tag_released)
        activate = 0;

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
        clusterer_ctrl_activate_backup_shtags(cl->cluster_id);
    else
        clusterer_ctrl_force_backup_shtags(cl->cluster_id);
}

/* call without cl->peers->lock held */
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

/* state transitions */

/* call with cl->peers->lock held for WRITE; the timers are armed outside it
 * (cl_ctr_arm_master_timers()) */
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
}

/* call without cl->peers->lock held; 1 = arm MASTER_ALIVE and disarm the
 * dead-watchdog, 0 = the reverse */
void cl_ctr_arm_master_timers(cl_ctr_cluster_t *cl, int i_am_master)
{
    /* a new mastership asserts a term above every one heard, which lets it
     * outrank the master it replaces; re-arming keeps its term */
    if (i_am_master && !cl->master_ka_armed) {
        /* PreVote, as in Raft: raise the term only if the old master was
         * confirmed gone - one electing itself unconfirmed is likely cut off */
        int raise = cl->term_confirmed || cl->peers->term_seen == 0;

        /* the last term there is stays the last: never wrap to 0 */
        if (cl->peers->term_seen == UINT32_MAX)
            raise = 0;

        cl->peers->my_term     = cl->peers->term_seen + (raise ? 1 : 0);
        cl->peers->term_seen   = cl->peers->my_term;
        cl->peers->master_term = cl->peers->my_term;
        cl->term_confirmed     = 0;
        cl->master_since_ms    = cl_ctr_now_ms();
        cl->master_unconfirmed = !raise;
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

/* for a master elected before it adopted the key (KEY_GRANT lost); call
 * without cl->peers->lock.  join_pending: one nonce in flight at a time */
void cl_ctr_request_rekey(cl_ctr_cluster_t *cl)
{
    if (cl->join_pending)
        return;
    cl->join_pending = 1;
    cl_ctr_send_join_req(cl->sock, cl);
}

/* maintenance mode */

const char *cl_ctr_maint_name(int st)
{
    return st == CL_CTR_MAINT_FULL    ? "full"
         : st == CL_CTR_MAINT_EVICTED ? "evicted" : "none";
}

int cl_ctr_maint_parse(const char *s, int len)
{
    if (len == 4 && strncasecmp(s, "full", 4) == 0)
        return CL_CTR_MAINT_FULL;
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

/* any process: stores @st in shm for the worker to apply and announce;
 * -1 when the worker is not up yet */
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

/* worker only; a master entering maintenance sends one last keepalive
 * carrying it (members elect a successor on reading it) and steps down */
void cl_ctr_maint_sync(cl_ctr_cluster_t *cl)
{
    int i, st, old_st, was_master = 0;
    uint16_t me = 0;

    lock_start_write(cl->peers->lock);
    st = cl->peers->my_maint;
    if (st == cl->maint_adv) {
        lock_stop_write(cl->peers->lock);
        return;
    }
    old_st        = cl->maint_adv;
    cl->maint_adv = (uint8_t)st;
    for (i = 0; i < cl->peers->count; i++)
        if (strcmp(cl->peers->entries[i].ip, my_ip) == 0) {
            cl->peers->entries[i].maint = (uint8_t)st;
            was_master = cl->peers->entries[i].is_master;
            me = cl->peers->entries[i].node_id;
        }
    lock_stop_write(cl->peers->lock);

    LM_INFO("clusterer_controller: [cluster %d] this node %s maintenance (%s)%s\n",
            cl->cluster_id, st == CL_CTR_MAINT_NONE ? "leaves" : "enters",
            cl_ctr_maint_name(st),
            was_master && st != CL_CTR_MAINT_NONE
                ? " - it is the master and hands over" : "");
    cl_ctr_maint_changed(cl, me, old_st, st);
    cl_ctr_send_alive(cl->sock, cl);
    if (was_master && st != CL_CTR_MAINT_NONE) {
        cl_ctr_send_master_alive(cl->sock, cl);
        cl_ctr_reelect_now(cl, "this node went into maintenance");
    }
}

void cl_ctr_rpc_maint(int sender, void *param)
{
    cl_ctr_maint_sync((cl_ctr_cluster_t *)param);
    cl_ctr_events_flush();
}

/* a request for ANOTHER node's maintenance: the worker multicasts it (it owns
 * the sequence space), the named node applies it (cl_ctr_handle_maint_set()) */
typedef struct {
    cl_ctr_cluster_t *cl;
    uint16_t          node_id;
    uint8_t           st;
} cl_ctr_maint_req_t;

static void cl_ctr_rpc_maint_remote(int sender, void *param)
{
    cl_ctr_maint_req_t *r = (cl_ctr_maint_req_t *)param;

    if (cl_ctr_send_maint_set(r->cl, r->node_id, r->st) < 0)
        LM_WARN("clusterer_controller: [cluster %d] could not send the request "
                "for node %u to go into maintenance state %s\n",
                r->cl->cluster_id, r->node_id, cl_ctr_maint_name(r->st));
    else
        LM_INFO("clusterer_controller: [cluster %d] asked node %u into "
                "maintenance state %s\n", r->cl->cluster_id, r->node_id,
                cl_ctr_maint_name(r->st));
    shm_free(r);
}

/* any process; -1 when the worker is not up yet or out of memory */
int cl_ctr_set_node_maint(cl_ctr_cluster_t *cl, uint16_t node_id, int st)
{
    cl_ctr_maint_req_t *r;
    int proc_no;

    lock_start_read(cl->peers->lock);
    proc_no = cl->peers->worker_proc_no;
    lock_stop_read(cl->peers->lock);
    if (proc_no < 0)
        return -1;
    r = shm_malloc(sizeof *r);
    if (!r)
        return -1;
    r->cl      = cl;
    r->node_id = node_id;
    r->st      = (uint8_t)st;
    if (ipc_send_rpc(proc_no, cl_ctr_rpc_maint_remote, r) < 0) {
        shm_free(r);
        return -1;
    }
    return 0;
}

/* master path, from a peer's ALIVE: a peer entering maintenance while holding
 * the operator's sharing-tag pin loses it - automatic allocation resumes */
void cl_ctr_maint_peer_changed(cl_ctr_cluster_t *cl, uint16_t node_id, int st)
{
    int cleared = 0, im;

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

/* hearing fewer than half of stable_live for an election window means the rest
 * likely elected another master: release the tag (release_tag_when_isolated) */
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
    if (cl->stable_live == 0) {
        /* new master: start from its old master's live count - a member cut
         * off alone hears only itself (a lone survivor releases too) */
        uint16_t known;

        lock_start_read(cl->peers->lock);
        known = cl->peers->master_live;
        lock_stop_read(cl->peers->lock);
        cl->stable_live  = live > known ? live : known;
        cl->below_rounds = 0;
    } else if (live >= cl->stable_live) {
        cl->stable_live  = live;
        cl->below_rounds = 0;
    }
    /* strictly fewer than half: a two-node cluster never releases */
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
    /* at least half but fewer for 3 rounds: members left or were purged */
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

/* most members asked whether anyone still hears this master: they cannot and
 * elect another, so the role and the tags go now, not when it is heard again.
 * Call without the lock */
void cl_ctr_step_down(cl_ctr_cluster_t *cl, int askers, int others)
{
    int now_master;

    LM_WARN("clusterer_controller: [cluster %d] %d of the %d other members "
            "asked whether anyone still hears this master - they cannot: "
            "stepping down, the sharing tags in backup, until a master hears "
            "this node again\n", cl->cluster_id, askers, others);
    lock_start_write(cl->peers->lock);
    cl->unheard = 1;
    cl_ctr_elect_master(cl);
    now_master = cl_ctr_i_am_master_locked(cl);
    lock_stop_write(cl->peers->lock);
    cl_ctr_arm_master_timers(cl, now_master);
    cl_ctr_apply_shtags(cl);
}

/* raises the event; another node entering/leaving 'full' is disabled/enabled
 * in this node's clusterer so replication skips it.  Call without the lock */
void cl_ctr_maint_changed(cl_ctr_cluster_t *cl, uint16_t node_id, int old_st,
                          int st)
{
    uint16_t me = 0;
    int k;

    cl_ctr_ev_maintenance(cl, node_id, st);
    if (node_id == 0 || !cl_api_loaded || !cl_api.set_state)
        return;
    /* this node's id in THIS cluster (it may differ per cluster): disabling
     * ourselves in clusterer would cut every link we have */
    lock_start_read(cl->peers->lock);
    for (k = 0; k < cl->peers->count; k++)
        if (strcmp(cl->peers->entries[k].ip, my_ip) == 0)
            me = cl->peers->entries[k].node_id;
    lock_stop_read(cl->peers->lock);
    if (node_id == me)
        return;
    if (st == CL_CTR_MAINT_FULL && old_st != CL_CTR_MAINT_FULL) {
        if (cl_api.set_state(cl->cluster_id, node_id, STATE_DISABLED) == 0)
            LM_INFO("clusterer_controller: [cluster %d] node %u is in full "
                    "maintenance - disabled in clusterer here\n",
                    cl->cluster_id, node_id);
    } else if (old_st == CL_CTR_MAINT_FULL && st != CL_CTR_MAINT_FULL) {
        if (cl_api.set_state(cl->cluster_id, node_id, STATE_ENABLED) == 0)
            LM_INFO("clusterer_controller: [cluster %d] node %u left full "
                    "maintenance - enabled in clusterer here\n",
                    cl->cluster_id, node_id);
    }
}
