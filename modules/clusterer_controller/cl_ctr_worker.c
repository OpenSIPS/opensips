/*
 * clusterer_controller - worker process, reactor and timers
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


/* =========================================================================
 * timerfd helpers
 * ========================================================================= */

/* Drain the expiration counter so the fd stops being readable. */
/* Returns how many times the timer expired since last read - 0 when it did
 * not: a timer re-armed by another handler in the same reactor round still
 * reports readable once, and its handler must not act on that. */
uint64_t cl_ctr_drain_tfd(int tfd)
{
    uint64_t exp = 0;
    if (read(tfd, &exp, sizeof(exp)) < 0) {
        if (errno != EAGAIN)
            LM_WARN("clusterer_controller: timerfd read: %s\n", strerror(errno));
        return 0;
    }
    return exp;
}

/* Arm a timerfd.  Pass sec_value=0 to disarm. */
void cl_ctr_arm_tfd(int tfd, time_t sec_value, time_t sec_interval)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec    = sec_value;
    its.it_interval.tv_sec = sec_interval;
    if (timerfd_settime(tfd, 0, &its, NULL) < 0)
        LM_WARN("clusterer_controller: timerfd_settime: %s\n", strerror(errno));
}

/* =========================================================================
 * Background worker process
 * ========================================================================= */

/* =========================================================================
 * Reactor callbacks - one per event source
 * ========================================================================= */

/* The master watchdog's timeout now: learned keepalive rhythm plus margin,
 * clamped (see CL_CTR_KA_TIMEOUT_MIN_MS). */
long long cl_ctr_master_timeout_ms(cl_ctr_cluster_t *cl)
{
    long long t = CL_CTR_KA_TIMEOUT_MIN_MS;

    if (cl->ka_samples >= 2)
        t = cl->ka_mean_ms + CL_CTR_KA_DEV_K * cl->ka_dev_ms;
    t += cl->ka_margin_ms;
    if (t < CL_CTR_KA_TIMEOUT_MIN_MS)
        t = CL_CTR_KA_TIMEOUT_MIN_MS;
    if (t > CL_CTR_KA_TIMEOUT_MAX_MS)
        t = CL_CTR_KA_TIMEOUT_MAX_MS;
    /* a node in trouble waits longer before it suspects anyone */
    if (cl->lhm > 0) {
        t *= (cl->lhm + 1);
        if (t > CL_CTR_LHM_TIMEOUT_CAP_MS)
            t = CL_CTR_LHM_TIMEOUT_CAP_MS;
    }
    return t;
}

/* (Re)arm the master watchdog for the current adaptive timeout. */
void cl_ctr_arm_master_watchdog(cl_ctr_cluster_t *cl)
{
    struct itimerspec its;
    long long         t = cl_ctr_master_timeout_ms(cl);

    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec  = (time_t)(t / 1000);
    its.it_value.tv_nsec = (long)((t % 1000) * 1000000L);
    if (timerfd_settime(cl->master_dead_tfd, 0, &its, NULL) < 0)
        LM_WARN("clusterer_controller: timerfd_settime: %s\n", strerror(errno));
    cl->peers->ka_timeout_ms = (int)t;
}

/* This node noticed trouble of its own: raise its Local Health Multiplier. */
void cl_ctr_lhm_event(cl_ctr_cluster_t *cl, const char *why)
{
    cl->lhm_trouble++;
    if (cl->lhm >= CL_CTR_LHM_MAX)
        return;
    if (cl->lhm++ == 0)
        LM_WARN("clusterer_controller: [cluster %d] this node is in trouble "
                "(%s) - it waits longer before judging its peers until it "
                "recovers\n", cl->cluster_id, why);
    cl->peers->local_health = cl->lhm;
}

/* Once per ALIVE round: account kernel drops since the last round, and lower
 * the multiplier when the round passed without trouble. */
void cl_ctr_lhm_round(cl_ctr_cluster_t *cl)
{
    unsigned long drops = cl->peers->rx_kernel_drops;

    if (drops > cl->lhm_drops_seen) {
        cl->lhm_drops_seen = drops;
        cl_ctr_lhm_event(cl, "the kernel dropped cluster datagrams");
    }
    if (cl->lhm_trouble == 0 && cl->lhm > 0) {
        if (--cl->lhm == 0)
            LM_INFO("clusterer_controller: [cluster %d] this node is healthy "
                    "again - normal timeouts\n", cl->cluster_id);
        cl->peers->local_health = cl->lhm;
    }
    cl->lhm_trouble = 0;
}

/*
 * cl_ctr_stall_check() - was this worker itself stopped?
 *
 * A peer is judged dead by how long ago it was last heard, which is only
 * evidence if this node was listening all that time.  A process paused by
 * SIGSTOP, a VM pause or a live migration, or starved of CPU, wakes with every
 * timer expired at once: it would declare the master dead, find every peer
 * outside the election window, elect itself and purge the rest - although
 * nobody else changed at all.
 *
 * So the loop records when it last ran (a CL_CTR_STALL_TICK_MS tick keeps that
 * fresh), and every handler that acts on a peer's silence calls this first,
 * since after a pause the expired timers fire in no particular order.  A gap
 * over CL_CTR_STALL_MS gives every peer it could not hear a full timeout from
 * now, as if just heard, and restarts the master watchdog; peers that really
 * died meanwhile are then found by the normal timeouts, one timeout later.
 * A peer already aged out (last_seen 0: a master declared dead) stays out.
 *
 * Returns 1 when a stall was found and handled.
 */
static int cl_ctr_stall_check(cl_ctr_cluster_t *cl)
{
    long long now = cl_ctr_now_ms(), gap;
    time_t    t_now;
    int       i, follow, was_master = 0, step_down;

    gap = cl->loop_seen_ms ? now - cl->loop_seen_ms : 0;
    cl->loop_seen_ms = now;
    if (gap <= CL_CTR_STALL_MS) {
        if (gap > CL_CTR_LATE_MS)
            cl_ctr_lhm_event(cl, "its timers ran late");
        return 0;
    }
    cl_ctr_lhm_event(cl, "the process was paused or starved");

    /* A master gone longer than its members wait (the keepalive timeout and
     * one probe round) has been replaced, or is about to be: they elected
     * without it.  Coming back and announcing would make it compete with the
     * master they chose - and win on a member count it never re-checked.  It
     * stands down silently instead and follows whichever master announces
     * next; if none does within the watchdog, the normal election runs. */
    step_down = gap > CL_CTR_MASTER_KA_TIMEOUT * 1000LL + CL_CTR_PROBE_WAIT_MS;

    t_now = cl_ctr_now();
    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (strcmp(e->ip, my_ip) == 0)
            was_master = e->is_master;
        if (e->last_seen != 0)
            e->last_seen = t_now;
    }
    cl->peers->self_stalls++;
    cl->rate_grace_until_ms = now + CL_CTR_STALL_GRACE_MS;
    cl->forgiven_at         = t_now;
    if (gap > cl->peers->self_stall_max_ms)
        cl->peers->self_stall_max_ms = gap;
    step_down = step_down && was_master;
    if (step_down) {
        for (i = 0; i < cl->peers->count; i++)
            cl->peers->entries[i].is_master = 0;
        cl->peers->last_master[0] = '\0';
    }
    follow = !was_master && cl->peers->last_master[0] != '\0';
    lock_stop_write(cl->peers->lock);

    LM_WARN("clusterer_controller: [cluster %d] this node did not run for "
            "%lld ms (process paused or starved of CPU) - not treating peers "
            "it could not hear meanwhile as dead; they get a full timeout "
            "from now%s\n", cl->cluster_id, gap,
            step_down ? "; it was master and stands down, to follow whichever "
                        "master the others chose" : "");
    if (step_down) {
        cl_ctr_arm_master_timers(cl, 0);  /* stop announcing, arm the watchdog */
        cl_ctr_apply_shtags(cl);          /* release the active tag */
    } else if (follow) {
        cl_ctr_arm_master_watchdog(cl);
    }
    return 1;
}

/*
 * cl_ctr_probe_step() - before electing on a silent master, ask the cluster.
 *
 * A master that stopped reaching THIS node is not necessarily dead: a fault
 * between the two (one NIC, one switch port, a host firewall rule) looks
 * the same from here, and so does this node itself being cut off.  So on the
 * first expiry of the master watchdog it asks the whole group, in one
 * multicast datagram, who still hears the master, waits CL_CTR_PROBE_WAIT_MS,
 * and on the next expiry decides on the answers:
 *
 *   - anyone heard it within CL_CTR_PROBE_FRESH_MS (the master itself answers
 *     that it is alive): a fault between this node and the master - hold
 *     the election and watch again, for at most CL_CTR_PROBE_HOLD_MAX_S;
 *   - CL_CTR_PROBE_CONFIRM of them (or every live peer, if fewer) did not
 *     hear it either: independent confirmation - elect now;
 *   - nobody, or too few, answered: this node is the likeliest fault - wait
 *     one more watchdog period and ask again, and elect only if it is still
 *     quiet.
 *
 * With nobody to ask it elects at once, as before - and so it does while
 * not every live member answers the question (CL_CTR_CAP_PROBE, as the
 * master relayed it): an older build drops it, and counting such a peer
 * would turn every failover in a mixed cluster into "too few answered" and
 * an extra watchdog period.  Returns 1 when the election is deferred (the
 * watchdog is re-armed).
 */
static int cl_ctr_probe_step(cl_ctr_cluster_t *cl)
{
    long long now = cl_ctr_now_ms();
    int       i, n = 0, need;
    time_t    cutoff;

    if (cl->probing) {
        /* the answers are in */
        cl->probing = 0;
        if (cl->probe_heard > 0) {
            /* Liveness by proxy, as the master's relay gives every member:
             * the master stays in this node's election window while its
             * peers hear it, or the ALIVE tick's election would replace it
             * regardless. */
            lock_start_write(cl->peers->lock);
            cl->peers->election_holds++;
            {
                int    k;
                time_t t = cl_ctr_now();
                for (k = 0; k < cl->peers->count; k++)
                    if (strcmp(cl->peers->entries[k].ip, cl->probe_master) == 0)
                        cl->peers->entries[k].last_seen = t;
            }
            lock_stop_write(cl->peers->lock);
            LM_WARN("clusterer_controller: [cluster %d] no keepalive from "
                    "master %s for %lld ms, but %d node(s) still hear it - "
                    "holding the election (a fault between this node and the "
                    "master, not a dead master); %lld s of %d held so far\n",
                    cl->cluster_id, cl->probe_master,
                    cl_ctr_master_timeout_ms(cl), cl->probe_heard,
                    (now - cl->hold_since_ms) / 1000, CL_CTR_PROBE_HOLD_MAX_S);
            cl->probe_quiet_rounds = 0;
            cl_ctr_ka_false_suspicion(cl, "peers still hear the master");
            cl_ctr_arm_master_watchdog(cl);
            return 1;
        }
        need = cl->probe_peers < CL_CTR_PROBE_CONFIRM ? cl->probe_peers
                                                       : CL_CTR_PROBE_CONFIRM;
        if (cl->probe_silent >= need) {
            LM_INFO("clusterer_controller: [cluster %d] %d peer(s) confirm "
                    "that master %s is silent - electing\n", cl->cluster_id,
                    cl->probe_silent, cl->probe_master);
            cl->term_confirmed     = 1;
            cl->hold_since_ms      = 0;
            cl->probe_quiet_rounds = 0;
            return 0;
        }
        if (cl->probe_quiet_rounds == 0) {
            cl->probe_quiet_rounds = 1;
            cl_ctr_lhm_event(cl, "nobody answered its question about the master");
            LM_WARN("clusterer_controller: [cluster %d] master %s is silent "
                    "and only %d of %d peer(s) answered whether they hear it - "
                    "this node may be the one cut off; waiting one more "
                    "watchdog period before electing\n", cl->cluster_id,
                    cl->probe_master, cl->probe_silent, cl->probe_peers);
            cl_ctr_arm_master_watchdog(cl);
            return 1;
        }
        LM_WARN("clusterer_controller: [cluster %d] master %s still silent and "
                "the peers still do not answer - electing\n", cl->cluster_id,
                cl->probe_master);
        cl->hold_since_ms      = 0;
        cl->probe_quiet_rounds = 0;
        return 0;
    }

    if (cl->hold_since_ms &&
            now - cl->hold_since_ms >= CL_CTR_PROBE_HOLD_MAX_S * 1000LL) {
        LM_WARN("clusterer_controller: [cluster %d] master %s unreachable "
                "from this node for over %d s although peers still hear it - "
                "electing\n", cl->cluster_id, cl->probe_master,
                CL_CTR_PROBE_HOLD_MAX_S);
        cl->hold_since_ms      = 0;
        cl->probe_quiet_rounds = 0;
        return 0;
    }

    cl->probe_master[0] = '\0';
    /* Count the peers that could answer - any not yet purged: a member cut
     * off from the master also stops hearing the relay that keeps its peers
     * in the election window. */
    cutoff = cl_ctr_now() - (time_t)query_time * CL_CTR_PURGE_FACTOR;
    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        if (strcmp(e->ip, my_ip) == 0)
            continue;
        if (e->is_master) {
            memcpy(cl->probe_master, e->ip, sizeof(cl->probe_master));
            continue;
        }
        if (e->last_seen >= cutoff)
            n++;
    }
    lock_stop_read(cl->peers->lock);
    if (cl->probe_master[0] == '\0' || n == 0)
        return 0;
    if (!(cl_ctr_cluster_caps(cl) & CL_CTR_CAP_PROBE)) {
        LM_INFO("clusterer_controller: [cluster %d] master %s is silent and not "
                "every member's build answers a question about it - electing "
                "without asking\n", cl->cluster_id, cl->probe_master);
        return 0;
    }

    cl_ctr_send_master_probe(cl, cl->probe_master);
    cl->probing      = 1;
    cl->probe_heard  = 0;
    cl->probe_silent = 0;
    cl->probe_peers  = n;
    if (!cl->hold_since_ms)
        cl->hold_since_ms = now;
    {
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_sec  = CL_CTR_PROBE_WAIT_MS / 1000;
        its.it_value.tv_nsec = (CL_CTR_PROBE_WAIT_MS % 1000) * 1000000L;
        if (timerfd_settime(cl->master_dead_tfd, 0, &its, NULL) < 0)
            LM_WARN("clusterer_controller: timerfd_settime: %s\n", strerror(errno));
    }
    LM_INFO("clusterer_controller: [cluster %d] no keepalive from master %s "
            "for %lld ms - asking the cluster whether anyone still hears it "
            "(%d peer(s) could answer)\n", cl->cluster_id, cl->probe_master,
            cl_ctr_master_timeout_ms(cl), n);
    return 1;
}

static int cl_ctr_on_stall_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_drain_tfd(fd);
    cl_ctr_stall_check((cl_ctr_cluster_t *)param);
    return 0;
}

static int cl_ctr_on_sock(int fd, void *param, int was_timeout)
{
    cl_ctr_stall_check((cl_ctr_cluster_t *)param);
    cl_ctr_recv_one(fd, (cl_ctr_cluster_t *)param, NULL, 0, NULL);
    return 0;
}

static int cl_ctr_on_alive_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    int prev_master, now_master;
    if (!cl_ctr_drain_tfd(fd))
        return 0;
    cl_ctr_stall_check(cl);
    cl_ctr_lhm_round(cl);
    cl_ctr_maint_sync(cl);      /* a requested state the IPC job missed */
    cl_ctr_cid_tick(cl);

    /* --- Has our OWN link changed under us? ---------------------------------
     * Nothing notifies this module: cc_mtu is read once at mod_init.  Poll it
     * here rather than subscribing to netlink RTM_NEWLINK, because netlink
     * DROPS events on ENOBUFS - so a reconcile poll would have to exist anyway,
     * and a missed MTU change is exactly the silent failure this is meant to
     * remove.  One ioctl per query_time is free.
     *
     * Terminate rather than warn, because SHRINKING an MTU breaks RECEIVE, not
     * send: the kernel still fragments on egress, so this node keeps emitting
     * ALIVEs and looks perfectly healthy to everyone while silently no longer
     * receiving anything larger than its new MTU.  CL_CTR_LIST_PKT_MAX_SZ
     * scales with CL_CTR_MAX_PEERS, so MEMBER_LIST on a real cluster is well
     * over 1500 - the node would sit on stale membership and an incomplete BIN
     * mesh, invisible to its peers, while the LB kept handing it calls.
     *
     * This is the node acting on its OWN condition, which is what makes it safe
     * to act at all - it reads its own interface, and a switch-side change does
     * not move /sys/class/net/X/mtu; only a host-local action does. */
    if (cc_mtu > 0) {
        int now_mtu = cl_ctr_read_iface_mtu();
        const char *ifn = my_interface_buf[0] ? my_interface_buf : "(unknown)";

        /* Advertise only a reading we actually got.  A failed read must not
         * push a zero out to peers as though the link had changed. */
        if (now_mtu > 0)
            cc_mtu_now = now_mtu;

        switch (cl_ctr_mtu_step(now_mtu, cc_mtu, &cc_mtu_drift_strikes,
                                &cc_mtu_read_fails)) {
        case CL_CTR_MTU_STEP_CONFIRMED:
            LM_CRIT("clusterer_controller: [cluster %d] the MTU of %s changed "
                    "from %d to %d and stayed there for %d checks. This node "
                    "joined at %d and every other member still uses it, so it "
                    "can no longer RECEIVE full-size cluster traffic - it would "
                    "keep sending heartbeats and look healthy while silently "
                    "missing membership updates. Shutting down; restore the MTU "
                    "to %d and restart\n",
                    cl->cluster_id, ifn, cc_mtu, now_mtu,
                    cc_mtu_drift_strikes, cc_mtu, cc_mtu);
            exit(-1);
        case CL_CTR_MTU_STEP_DRIFTING:
            LM_WARN("clusterer_controller: [cluster %d] MTU of %s reads %d, this "
                    "node joined at %d (%d/%d consecutive) - confirming before "
                    "acting, since a bond failover or driver reset can report a "
                    "transient value\n",
                    cl->cluster_id, ifn, now_mtu, cc_mtu,
                    cc_mtu_drift_strikes, CL_CTR_MTU_DRIFT_STRIKES);
            break;
        case CL_CTR_MTU_STEP_RECOVERED:
            LM_INFO("clusterer_controller: [cluster %d] MTU of %s reads %d again, "
                    "matching what this node joined at - the earlier readings "
                    "were a transient\n", cl->cluster_id, ifn, cc_mtu);
            break;
        case CL_CTR_MTU_STEP_UNREADABLE:
            /* Deliberately NOT fatal, and deliberately not a reset.
             *
             * Not a reset because a read that failed is not a link that
             * recovered - the strike count is left exactly where it was, so a
             * drift already under way still confirms on the next real reading.
             *
             * Not fatal, even though mod_init refuses to START without an MTU,
             * and the asymmetry is intentional: at startup the node has no
             * membership and nothing to lose by refusing, while here it is an
             * established member carrying calls, and an ioctl we could not
             * complete is evidence about our own visibility, not about the
             * link. The drift this poll exists to catch - a host-local `ip
             * link` change - leaves the interface perfectly readable. A reading
             * that fails instead means the interface was renamed or removed,
             * which announces itself far more loudly elsewhere.
             *
             * Say so on the first failure and then rarely, so a persistently
             * blind poll cannot masquerade as a quiet healthy one. */
            if (cc_mtu_read_fails == 1
                || cc_mtu_read_fails % CL_CTR_MTU_READ_FAIL_LOUD == 0)
                LM_WARN("clusterer_controller: [cluster %d] cannot read the MTU "
                        "of %s (%s) - %d consecutive attempts. This node is not "
                        "verifying that it still matches the cluster's %d; it "
                        "keeps running on its last good reading, and any drift "
                        "already being confirmed is NOT cancelled by this\n",
                        cl->cluster_id, ifn, strerror(errno),
                        cc_mtu_read_fails, cc_mtu);
            break;
        default:
            break;                      /* steady - the common case, silent */
        }
    }
    /* ALIVE transport: a settled non-master unicasts its heartbeat to the master,
     * which relays liveness to the whole group via the MASTER_ALIVE bitmap - so
     * the old all-to-all O(N^2) becomes O(N).  During formation (no settled master
     * or key yet) fall back to multicast for discovery; the master itself keeps
     * multicasting its own ALIVE so its liveness and config still reach everyone. */
    {
        int  _im, _active;
        char _lm[CL_CTR_MAX_IP_LEN + 1];
        lock_start_read(cl->peers->lock);
        _im     = cl_ctr_i_am_master_locked(cl);
        _active = (cl->peers->node_state == CL_CTR_NODE_ACTIVE);
        memcpy(_lm, cl->peers->last_master, sizeof(_lm));
        lock_stop_read(cl->peers->lock);
        if (!_im && _active && cl->have_session_key && _lm[0] != '\0') {
            struct sockaddr_in d;
            cl_ctr_sockaddr_in(_lm, cl->multicast_port, &d);
            cl_ctr_send_alive_to(cl->sock, cl, (struct sockaddr *)&d, sizeof(d));
        } else {
            cl_ctr_send_alive(cl->sock, cl);
        }
    }
    lock_start_write(cl->peers->lock);
    /* Refresh our own liveness first: a settled non-master unicasts its ALIVE to
     * the master and no longer hears a multicast loopback, so without this it
     * would age itself out of its own election window once the master is gone
     * and briefly find "no eligible peers" during a failover. */
    cl_ctr_upsert_peer_locked(my_ip, cl);
    prev_master = cl_ctr_i_am_master_locked(cl);
    cl_ctr_prune_stale(cl);
    cl_ctr_elect_master(cl);
    now_master = cl_ctr_i_am_master_locked(cl);
    lock_stop_write(cl->peers->lock);
    /* Do not broadcast MASTER_ALIVE before we hold the cluster key -
     * request a re-key from the current key-holder instead. */
    if (now_master && !cl->have_session_key) {
        cl_ctr_request_rekey(cl);
        return 0;
    }
    if (prev_master != now_master) {
        cl_ctr_arm_master_timers(cl, now_master);
        cl_ctr_apply_shtags(cl);
    }
    cl_ctr_isolation_round(cl, now_master);

    /* Belt-and-suspenders identity registration (covers paths where
     * cl_ctr_handle_node_assign has not yet run).                      */
    if (!cl->identity_registered && clctl_loaded && my_node_id > 0) {
	str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	clctl.update_identity(cl->cluster_id, my_node_id, &url);
	cl->identity_registered = 1;
    }

    /* Bootstrap shtag activation: only for fresh clusters
     * (shtag_bootstrapped == -1).  Retries until we are master. */
    if (cl->manage_shtags && clctl_loaded && cl->shtag_bootstrapped == -1
        && clctl.activate_backup_shtags) {
	int _im;
	lock_start_read(cl->peers->lock);
	_im = cl_ctr_i_am_master_locked(cl);
	lock_stop_read(cl->peers->lock);
	if (_im) {
	    cl_ctr_apply_shtags(cl);   /* override-aware */
	    cl->shtag_bootstrapped = 1;
	}
    }
    return 0;
}

static int cl_ctr_on_join_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    if (!cl_ctr_drain_tfd(fd))
	return 0;

    int was_new, auth_fails;
    lock_start_write(cl->peers->lock);
    was_new    = (cl->peers->node_state == CL_CTR_NODE_NEW);
    auth_fails = cl->auth_fail_pkts;

    /* Wrong-password / unauthorized guard: if we are still joining at the
     * deadline AND we received packets from peers we could not decrypt, then a
     * cluster whose key we do not share exists on this multicast group.
     * Self-promoting would create a split-brain lone master (and, with managed
     * shtags, a duplicate active tag).  A wrong-password node also cannot read
     * the master's JOIN_REJECT, so this is where it must shut down.          */
    if (was_new && auth_fails >= CL_CTR_JOIN_FAIL_LIMIT) {
	/* We could not decrypt traffic from peers on our cluster_id: a cluster
	 * using a different password (or we do) shares this group.  Do NOT
	 * self-terminate on the first deadline - a KEY_GRANT that is merely slow, a
	 * brief burst of start-up noise, or a flood of crafted garbage would
	 * otherwise kill a healthy node.  Defer and keep re-joining: a real
	 * KEY_GRANT arriving in the grace window resets auth_fail_pkts
	 * (cl_ctr_handle_key_grant) and we join normally.  Only give up after
	 * CL_CTR_JOIN_DEFER_MAX rounds still short of authentication - by then the
	 * wrong-password / foreign-cluster condition is sustained, not transient,
	 * and self-promoting would create a split-brain lone master.             */
	if (cl->auth_defer_count < CL_CTR_JOIN_DEFER_MAX) {
	    cl->auth_defer_count++;
	    lock_stop_write(cl->peers->lock);
	    LM_WARN("clusterer_controller: [cluster %d] %d undecryptable packet(s) "
	            "on cluster_id %d (%s:%d) - cannot authenticate yet, deferring "
	            "self-promotion (%d/%d); a slow KEY_GRANT would clear this\n",
	            cl->cluster_id, auth_fails, cl->cluster_id,
	            cl->multicast_address, cl->multicast_port,
	            cl->auth_defer_count, CL_CTR_JOIN_DEFER_MAX);
	    cl->join_pending = 0;
	    cl_ctr_send_join_req(cl->sock, cl);
	    cl_ctr_arm_tfd(cl->join_tfd, CL_CTR_JOIN_DEFER_SECS, 0);
	    return 0;
	}
	lock_stop_write(cl->peers->lock);
	LM_CRIT("clusterer_controller: [cluster %d] cannot authenticate on %s:%d - "
	        "%d packet(s) stayed undecryptable and no KEY_GRANT arrived across %d "
	        "re-join round(s) (wrong password, or a foreign cluster on "
	        "cluster_id %d). Shutting down.\n",
	        cl->cluster_id, cl->multicast_address, cl->multicast_port,
	        auth_fails, cl->auth_defer_count, cl->cluster_id);
	exit(-1);
    }

    /* Split-brain PREVENTION: if a higher-IP node is also still joining (we
     * learned it from its JOIN_REQ), defer self-promotion so it becomes the
     * single master and we join it, rather than both self-promoting with
     * independent session keys.  Bounded by CL_CTR_JOIN_DEFER_MAX so a higher-IP
     * node that was heard but never finished starting cannot stall us.        */
    if (was_new && cl->join_defer_count < CL_CTR_JOIN_DEFER_MAX
                && cl->join_defer_total < CL_CTR_JOIN_DEFER_HARDMAX) {
	unsigned int my_ipn = ip_to_num(my_ip);
	int          higher_seen = 0, _i;
	for (_i = 0; _i < cl->peers->count; _i++) {
	    if (strcmp(cl->peers->entries[_i].ip, my_ip) == 0)
		continue;
	    if (cl->peers->entries[_i].ip_num > my_ipn) {
		higher_seen = 1;
		break;
	    }
	}
	if (higher_seen) {
	    cl->join_defer_count++;
	    cl->join_defer_total++;
	    lock_stop_write(cl->peers->lock);
	    LM_INFO("clusterer_controller: [cluster %d] join deadline: a higher-IP "
	            "node is still joining - deferring self-promotion (%d/%d) to "
	            "avoid split brain\n",
	            cl->cluster_id, cl->join_defer_count, CL_CTR_JOIN_DEFER_MAX);
	    /* Re-send a JOIN_REQ now (clear join_pending so it is not suppressed)
	     * so the higher-IP node answers as soon as it becomes master, then
	     * extend the join window for one more short round. */
	    cl->join_pending = 0;
	    cl_ctr_send_join_req(cl->sock, cl);
	    cl_ctr_arm_tfd(cl->join_tfd, CL_CTR_JOIN_DEFER_SECS, 0);
	    return 0;
	}
    }

    /* A master has already granted us the session key: the cluster exists and
     * its NODE_ASSIGN is on the way (or was lost, and the JOIN_REQ re-sent
     * here asks for it again).  Founding now would give this node an id the
     * master has handed to someone else and a mastership nobody follows. */
    if (was_new && cl->granted_by[0] != '\0'
                && cl->grant_wait_count < CL_CTR_JOIN_DEFER_MAX) {
	cl->grant_wait_count++;
	lock_stop_write(cl->peers->lock);
	LM_INFO("clusterer_controller: [cluster %d] join deadline: master %s "
	        "granted the key but its NODE_ASSIGN has not arrived - waiting "
	        "(%d/%d)\n", cl->cluster_id, cl->granted_by,
	        cl->grant_wait_count, CL_CTR_JOIN_DEFER_MAX);
	cl->join_pending = 0;
	cl_ctr_send_join_req(cl->sock, cl);
	cl_ctr_arm_tfd(cl->join_tfd, CL_CTR_JOIN_DEFER_SECS, 0);
	return 0;
    }

    if (was_new) {
	LM_INFO("clusterer_controller: [cluster %d] join deadline expired, "
	        "no master found - transitioning to CL_CTR_NODE_ACTIVE\n",
	        cl->cluster_id);
	cl->granted_by[0]    = '\0';
	cl->grant_wait_count = 0;
	cl->join_defer_count = 0;     /* leaving NEW state */
	cl->join_defer_total = 0;
	cl->shtag_bootstrapped = -1; /* fresh cluster: eligible to claim active */
	cl_ctr_upsert_peer_locked(my_ip, cl);
	my_node_id = cl_ctr_alloc_node_id_locked(cl, my_ip);
	{
	    char self_sock[1][CL_CTR_MAX_BIN_SOCK_LEN];
	    memcpy(self_sock[0], cl->bin_socket, CL_CTR_MAX_BIN_SOCK_LEN);
	    cl_ctr_update_peer_bin_locked(my_ip, my_node_id, 1,
	                              (const char (*)[CL_CTR_MAX_BIN_SOCK_LEN])
	                              self_sock, cl);
	}
	cl->peers->node_state = CL_CTR_NODE_ACTIVE;
	/* Run election first so is_master and last_master are set before
	 * cl_ctr_on_became_master.  Without this, cl_ctr_handle_alive would see
	 * is_master=0 on the loopback ALIVE and call cl_ctr_on_became_master
	 * a second time, regenerating the session key unnecessarily.     */
	cl_ctr_elect_master(cl);
	cl_ctr_on_became_master(cl);
	cl_ctr_cid_found(cl);          /* a new cluster: it gets an identity */
    }
    lock_stop_write(cl->peers->lock);
    if (!was_new)
	return 0;  /* already active via MEMBER_LIST - nothing to do */
    cl_ctr_transition_to_active(cl);
    cl_ctr_arm_master_timers(cl, 1);

    if (!cl->identity_registered && clctl_loaded && my_node_id > 0) {
	str url = {cl->bin_socket, (int)strlen(cl->bin_socket)};
	clctl.update_identity(cl->cluster_id, my_node_id, &url);
	cl->identity_registered = 1;
    }
    return 0;
}

static int cl_ctr_on_rejoin_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    int still_new;

    cl_ctr_drain_tfd(fd);
    lock_start_read(cl->peers->lock);
    still_new = (cl->peers->node_state == CL_CTR_NODE_NEW);
    lock_stop_read(cl->peers->lock);
    if (still_new && !cl->join_pending) {
	cl->join_attempt_count++;

	/* Wrong-password fallback: if the master keeps sending bootstrap
	 * packets we cannot decrypt (bootstrap_auth_fails > 0) and we have
	 * already retried CL_CTR_JOIN_FAIL_LIMIT times, give up.  This fires when
	 * the encrypted JOIN_REJECT from the master was lost in transit (if it
	 * arrived intact, cl_ctr_handle_join_reject would have already exited).   */
	if (cl->join_attempt_count >= CL_CTR_JOIN_FAIL_LIMIT
	        && cl->bootstrap_auth_fails > 0) {
	    LM_CRIT("clusterer_controller: [cluster %d] join failed after %d "
	            "attempts with %d bootstrap auth error(s) - wrong password? "
	            "Shutting down.\n",
	            cl->cluster_id, cl->join_attempt_count,
	            cl->bootstrap_auth_fails);
	    exit(-1);
	}

	cl_ctr_send_join_req(cl->sock, cl);
	cl->join_pending = 1;
	LM_DBG("clusterer_controller: [cluster %d] resending JOIN_REQ "
	       "(attempt %d)\n", cl->cluster_id, cl->join_attempt_count);
    }
    return 0;
}

static int cl_ctr_on_master_alive_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    cl_ctr_drain_tfd(fd);
    /* Woken from a stall: say nothing this round.  If the stall made this
     * node stand down, a keepalive now - with a member count it never
     * re-checked - would make the master elected meanwhile yield to it. */
    if (cl_ctr_stall_check(cl) || !cl->master_ka_armed)
        return 0;
    cl_ctr_send_master_alive(cl->sock, cl);
    /* An announcement the coalescing window swallowed is still owed - emit it
     * as soon as the window allows.  This timer only runs on the master, which
     * is the only node that announces. */
    if (cl->full_state_pending &&
        (utime_t)(get_uticks() - cl->last_full_state_us) >= CL_CTR_RESYNC_MIN_US) {
        char why[64];
        snprintf(why, sizeof why, "%s", cl->full_state_why);
        cl->full_state_pending = 0;
        cl_ctr_announce_full_state(cl, why);
    }
    /* Emit a bootstrap-key beacon every CL_CTR_MASTER_BEACON_EVERY ticks so any
     * peer master holding a different session key can find us and merge. */
    if (++cl->beacon_tick >= CL_CTR_MASTER_BEACON_EVERY) {
        cl->beacon_tick = 0;
        cl_ctr_send_master_beacon(cl->sock, cl);
    }
    return 0;
}

static int cl_ctr_on_master_dead_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl     = (cl_ctr_cluster_t *)param;
    int           now_master;
    char          dead_master[CL_CTR_MAX_IP_LEN + 1];

    /* re-armed meanwhile (a keepalive, the stall check): not expired */
    if (!cl_ctr_drain_tfd(fd))
        return 0;

    /* the master's silence means nothing if this node was the one stopped;
     * the check has restarted the watchdog */
    if (cl_ctr_stall_check(cl))
        return 0;
    /* ... and may be a fault between it and this node only: ask first */
    if (cl_ctr_probe_step(cl))
        return 0;

    dead_master[0] = '\0';

    lock_start_write(cl->peers->lock);
    /* The master has been silent for the watchdog timeout.  Age the silent
     * master OUT of the election window before re-electing, otherwise
     * cl_ctr_elect_master would just re-select it: the election window is
     * query_time * CL_CTR_ELECT_FACTOR (~15s), far longer than the keepalive
     * timeout, so a just-declared-dead master stays "eligible" and keeps
     * winning - delaying real failover by ~12s.  Zeroing its last_seen makes
     * the immediate re-election pick the next-highest LIVE peer.  If the
     * master was only briefly unreachable, its next MASTER_ALIVE/ALIVE
     * refreshes last_seen and the normal highest-IP election restores it. */
    {
        int _i;
        for (_i = 0; _i < cl->peers->count; _i++) {
            if (cl->peers->entries[_i].is_master &&
                strcmp(cl->peers->entries[_i].ip, my_ip) != 0) {
                size_t _l = strnlen(cl->peers->entries[_i].ip, CL_CTR_MAX_IP_LEN);
                memcpy(dead_master, cl->peers->entries[_i].ip, _l);
                dead_master[_l] = '\0';
                cl->peers->entries[_i].last_seen   = 0;
                cl->peers->entries[_i].in_election = 0;
            }
            cl->peers->entries[_i].is_master = 0;
        }
        cl->peers->last_master[0] = '\0';
    }

    LM_INFO("clusterer_controller: [cluster %d] master %s went silent "
            "(no keepalive for %lld ms) - re-electing\n",
            cl->cluster_id,
            dead_master[0] ? dead_master : "(unknown)",
            cl_ctr_master_timeout_ms(cl));

    /* cl_ctr_elect_master logs the resulting MASTER/BACKUP roles and why. */
    cl_ctr_elect_master(cl);
    now_master = cl_ctr_i_am_master_locked(cl);
    lock_stop_write(cl->peers->lock);

    /* Preserve-key recovery: every surviving member already holds the session
     * key, so the winner has it too.  Guard defensively against the impossible
     * keyless-winner case rather than broadcasting an undecryptable MEMBER_LIST. */
    if (now_master && !cl->have_session_key) {
        LM_WARN("clusterer_controller: [cluster %d] elected master after "
                "keepalive timeout but hold no session key - deferring\n",
                cl->cluster_id);
        return 0;
    }

    cl_ctr_arm_master_timers(cl, now_master);
    /* the tags follow the new master now - not when the old one is purged */
    cl_ctr_apply_shtags(cl);

    /* No full MEMBER_LIST is broadcast: every surviving member ran the same
     * deterministic re-election on its own keepalive timeout, MASTER_ALIVE
     * (which the new master now emits) re-asserts the winner, and the
     * membership digest reconciles any divergence - so the O(N) re-broadcast
     * (which fragments at large N) is redundant.  A node still joining reaches
     * the new master through its own JOIN_REQ retry. */
    return 0;
}

/**
 * cl_ctr_worker() - the single dedicated background process.
 *
 * JOIN PROTOCOL:
 *   1. Open socket, join multicast group.
 *   2. Send CL_CTR_PKT_JOIN_REQ and set state = CL_CTR_NODE_NEW with a deadline
 *      of (now + query_time).
 *   3. Listen for incoming packets.  If CL_CTR_PKT_MEMBER_LIST arrives:
 *        -> cl_ctr_handle_member_list() sets state = CL_CTR_NODE_ACTIVE.
 *      If deadline expires with no MEMBER_LIST:
 *        -> no master exists yet; transition to CL_CTR_NODE_ACTIVE and
 *          join the normal election cycle.
 *
 * ACTIVE LOOP:
 *   Fully event-driven via OpenSIPS reactor (epoll by default).
 *   Each event source is a registered fd with a dedicated callback:
 *     cl_ctr_on_sock       - incoming UDP packet
 *     cl_ctr_on_alive_tfd  - periodic ALIVE heartbeat (query_time seconds)
 *     cl_ctr_on_join_tfd   - one-shot join deadline
 *     cl_ctr_on_rejoin_tfd - 1-second JOIN_REQ retry while in CL_CTR_NODE_NEW
 *   reactor_proc_init() also wires in IPC (shutdown, load stats, reload).
 */
void cl_ctr_worker(int rank)
{
    cl_ctr_cluster_t *cl;

    if (rank >= cl_ctr_cluster_count) {
	/* Extra process slot - no cluster assigned, exit cleanly */
	return;
    }
    cl = &cl_ctr_clusters[rank];

    LM_INFO("clusterer_controller: [cluster %d] worker started (pid=%d)\n",
            cl->cluster_id, getpid());

    /* Publish our process index so MI handlers (other processes) can reach us
     * via ipc_send_rpc() to apply operator-driven shtag overrides promptly. */
    cl->peers->worker_proc_no = process_no;

    cl->shtag_last_active = -1;   /* unknown - first decision logs its reason */
    cl->shtag_last_forced = 0;

    cl->sock = cl_ctr_setup_socket(cl);
    if (cl->sock < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] cannot open multicast socket, "
	        "worker exits\n", cl->cluster_id);
	exit(-1);
    }

    /* Generate ephemeral X25519 keypair - private key never leaves this process */
    if (cl_ctr_gen_ecdh_keypair(cl->my_privkey, cl->my_pubkey) < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] ECDH keypair generation failed\n",
	        cl->cluster_id);
	exit(-1);
    }

    /* Store our pubkey in peer table entry for ourselves so MEMBER_LIST broadcasts it */
    lock_start_write(cl->peers->lock);
    {
        int _i;
        for (_i = 0; _i < cl->peers->count; _i++) {
            if (strcmp(cl->peers->entries[_i].ip, my_ip) == 0) {
                memcpy(cl->peers->entries[_i].pubkey, cl->my_pubkey, CL_CTR_PUBKEY_SZ);
                break;
            }
        }
    }
    lock_stop_write(cl->peers->lock);

    cl->alive_tfd        = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->join_tfd         = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->rejoin_tfd       = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->master_alive_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->master_dead_tfd  = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->retx_tfd         = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    cl->stall_tfd        = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (cl->alive_tfd < 0 || cl->join_tfd < 0 || cl->rejoin_tfd < 0 ||
        cl->master_alive_tfd < 0 || cl->master_dead_tfd < 0 || cl->retx_tfd < 0 ||
        cl->stall_tfd < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] timerfd_create: %s\n",
	        cl->cluster_id, strerror(errno));
	exit(-1);
    }

    cl->rate_tbl = pkg_malloc(CL_CTR_RATE_TBL_SZ * sizeof(cl_ctr_rate_entry_t));
    if (!cl->rate_tbl) {
	LM_CRIT("clusterer_controller: [cluster %d] no pkg memory for rate table\n",
	        cl->cluster_id);
	exit(-1);
    }
    memset(cl->rate_tbl, 0, CL_CTR_RATE_TBL_SZ * sizeof(cl_ctr_rate_entry_t));

    /* ---- Phase 1: join protocol ---- */
    lock_start_write(cl->peers->lock);
    cl->peers->node_state    = CL_CTR_NODE_NEW;
    cl->peers->join_deadline = cl_ctr_now() + (time_t)query_time;
    lock_stop_write(cl->peers->lock);

    cl_ctr_send_join_req(cl->sock, cl);
    cl_ctr_arm_tfd(cl->join_tfd,   (time_t)query_time, 0); /* one-shot deadline  */
    cl_ctr_arm_tfd(cl->rejoin_tfd, 1, 1);                  /* retry every 1 s    */
    {
        struct itimerspec its;                             /* stall-check tick   */
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec    = CL_CTR_STALL_TICK_MS * 1000000L;
        its.it_interval.tv_nsec = CL_CTR_STALL_TICK_MS * 1000000L;
        if (timerfd_settime(cl->stall_tfd, 0, &its, NULL) < 0)
            LM_WARN("clusterer_controller: timerfd_settime: %s\n", strerror(errno));
        cl->loop_seen_ms = cl_ctr_now_ms();
    }
    /* alive_tfd left disarmed - armed by cl_ctr_transition_to_active() */

    LM_INFO("clusterer_controller: [cluster %d] sent JOIN_REQ, waiting up to %ds "
            "for master response\n", cl->cluster_id, query_time);

    /* ---- Register with reactor and enter event loop ---- */
    if (reactor_proc_init("clusterer_controller worker") < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] reactor_proc_init failed\n",
	        cl->cluster_id);
	exit(-1);
    }

    if (reactor_proc_add_fd(cl->sock,            cl_ctr_on_sock,            cl) < 0 ||
        reactor_proc_add_fd(cl->alive_tfd,       cl_ctr_on_alive_tfd,       cl) < 0 ||
        reactor_proc_add_fd(cl->join_tfd,        cl_ctr_on_join_tfd,        cl) < 0 ||
        reactor_proc_add_fd(cl->rejoin_tfd,      cl_ctr_on_rejoin_tfd,      cl) < 0 ||
        reactor_proc_add_fd(cl->master_alive_tfd, cl_ctr_on_master_alive_tfd, cl) < 0 ||
        reactor_proc_add_fd(cl->master_dead_tfd,  cl_ctr_on_master_dead_tfd,  cl) < 0 ||
        reactor_proc_add_fd(cl->retx_tfd,         cl_ctr_on_retx_tfd,         cl) < 0 ||
        reactor_proc_add_fd(cl->stall_tfd,        cl_ctr_on_stall_tfd,        cl) < 0) {
	LM_CRIT("clusterer_controller: [cluster %d] reactor_proc_add_fd failed\n",
	        cl->cluster_id);
	exit(-1);
    }

    reactor_proc_loop();

    /* ---- Graceful shutdown epilogue ---- */
    {
        int i_am_master;
        lock_start_read(cl->peers->lock);
        i_am_master = cl_ctr_i_am_master_locked(cl);
        lock_stop_read(cl->peers->lock);

        if (i_am_master && cl->peers->count > 1) {
            /* Find the peer that will win the next election (highest IP, not us) */
            unsigned int  best_ip   = 0;
            int           best_idx  = -1;
            int           _i;
            lock_start_read(cl->peers->lock);
            for (_i = 0; _i < cl->peers->count; _i++) {
                cl_ctr_peer_t *e = &cl->peers->entries[_i];
                if (strcmp(e->ip, my_ip) == 0) continue;
                if (e->ip_num > best_ip) { best_ip = e->ip_num; best_idx = _i; }
            }
            if (best_idx >= 0) {
                char           next_ip[CL_CTR_MAX_IP_LEN + 1];
                unsigned char  next_pub[CL_CTR_PUBKEY_SZ];
                memcpy(next_ip, cl->peers->entries[best_idx].ip, CL_CTR_MAX_IP_LEN + 1);
                memcpy(next_pub, cl->peers->entries[best_idx].pubkey, CL_CTR_PUBKEY_SZ);
                lock_stop_read(cl->peers->lock);
                cl_ctr_send_key_handoff(cl->sock, next_ip, next_pub, cl);
            } else {
                lock_stop_read(cl->peers->lock);
            }
        }
    }

    close(cl->sock);
    close(cl->alive_tfd);
    close(cl->join_tfd);
    close(cl->rejoin_tfd);
    close(cl->master_alive_tfd);
    close(cl->master_dead_tfd);
    close(cl->stall_tfd);
}
