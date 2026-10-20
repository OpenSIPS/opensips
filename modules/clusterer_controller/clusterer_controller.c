/*
 * clusterer_controller - zero-config HA control of the clusterer module
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

static void cl_ctr_upsert_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl);
static void cl_ctr_reserve_id_locked(cl_ctr_cluster_t *cl, const char *ip,
                                     uint16_t node_id);
static void cl_ctr_retx_flush(cl_ctr_cluster_t *cl);
static void cl_ctr_retx_enqueue(cl_ctr_cluster_t *cl, uint32_t seq, unsigned char type,
                            const unsigned char *pkt, int pkt_len,
                            const struct sockaddr *dest, socklen_t destlen);
static void cl_ctr_send_join_req_pkt(int sock, cl_ctr_cluster_t *cl);
static void cl_ctr_arm_master_timers(cl_ctr_cluster_t *cl, int i_am_master);
static void cl_ctr_rejoin_superior_master(cl_ctr_cluster_t *cl, const char *superior_ip,
                                      const char *via);
static void cl_ctr_send_join_reject(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
                                int reason);
static void cl_ctr_maybe_forward(const char *buf, int n,
                             const struct sockaddr_in *src, uint16_t pkt_cid,
                             cl_ctr_cluster_t *from);
static void cl_ctr_rpc_forward(int sender, void *param);
static void cl_ctr_worker(int rank);
static mi_response_t *mi_cl_ctr_members(const mi_params_t *params,
                                     struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_node_info(const mi_params_t *params,
                                      struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_config(const mi_params_t *params,
                                     struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_shtag_force(const mi_params_t *params,
                                        struct mi_handler *hdl);
static mi_response_t *mi_cl_ctr_shtag_auto(const mi_params_t *params,
                                       struct mi_handler *hdl);
static int mod_init(void);
static int cl_ctr_child_init(int rank);
static void mod_destroy(void);
static const unsigned char CL_CTR_PACKET_MAGIC[CL_CTR_MAGIC_SZ]    = { CL_CTR_WIRE_MAGIC0, 0x00 };
static const unsigned char CL_CTR_BOOTSTRAP_MAGIC[CL_CTR_MAGIC_SZ] = { CL_CTR_WIRE_MAGIC0, 0x01 };
/* Consumer traffic carries its own magic.  It is encrypted with the same
 * session key as everything else - the distinction exists purely so the
 * rate limiter, which runs BEFORE decryption and therefore cannot see a
 * packet's type, can charge consumer data against its own budget instead
 * of the control plane's.  Without this, a consumer sending faster than
 * the control-plane limit is silently throttled, and control packets and
 * data compete for one allowance. */
const unsigned char CL_CTR_CONSUMER_MAGIC[CL_CTR_MAGIC_SZ]  = { CL_CTR_WIRE_MAGIC0, 0x02 };

cl_ctr_cluster_t  cl_ctr_clusters[CL_CTR_MAX_CLUSTERS];
int           cl_ctr_cluster_count = 0;

/* Raw "cluster" strings collected during modparam parsing */
static char *cl_ctr_cluster_strs[CL_CTR_MAX_CLUSTERS];
static int   cl_ctr_cluster_str_count = 0;

/* =========================================================================
 * Module parameters
 * ========================================================================= */

/* Global modparams - apply to all clusters unless overridden per-cluster */
char *my_ip             = NULL;  /* explicit IP, or NULL for auto-detect */
static char *my_interface      = NULL;  /* explicit interface name, or NULL      */
static int   query_time        = 5;
static char *password          = CL_CTR_DEFAULT_PASSWORD; /* default; falls back per cluster */
static char *on_config_mismatch_s = NULL;              /* raw modparam string   */
static int   on_config_mismatch   = CL_CTR_CFGMISMATCH_REJECT; /* resolved; default reject */

/* Resolved at mod_init time - always valid after cl_ctr_resolve_local_identity() */
static char my_ip_buf[INET_ADDRSTRLEN];
/* which of the three resolution paths produced my_ip - reported through
 * clctr_api.get_my_ip() so a consumer can show it without guessing */
const char *my_ip_src = "unresolved";
char my_interface_buf[IF_NAMESIZE];

/* Maximum consumer payload in bytes, derived from the interface MTU at
 * mod_init time.  Replaces the compile-time CLCTR_MAX_PAYLOAD constant so
 * jumbo-frame interfaces (MTU 9000) are not artificially limited to 1300 B.
 * Read-only after mod_init; safe to access from any process. */
int cc_max_payload = CLCTR_MAX_PAYLOAD;
/* This node's cluster-plane MTU as read from my_interface_buf at mod_init.
 * 0 only before mod_init has resolved it; after that it is always a real
 * kernel-reported value, because mod_init refuses to start otherwise. */
static int cc_mtu = 0;
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
static int cc_mtu_now = 0;
/* Consecutive polls that disagreed with cc_mtu (see CL_CTR_MTU_DRIFT_STRIKES). */
static int cc_mtu_drift_strikes = 0;
/* Consecutive polls that could not read the MTU at all.  Tracked separately
 * from the drift strikes because a failed read is not evidence of anything -
 * see cl_ctr_mtu_step(). */
static int cc_mtu_read_fails = 0;

/**
 * cl_ctr_read_iface_mtu() - current MTU of the interface we run the plane on.
 *
 * Returns the kernel's value, or -1 if it cannot be read.  This is the ONLY
 * source of MTU truth in the module; there is no configured alternative to
 * fall back to, by design.
 */
static int cl_ctr_read_iface_mtu(void)
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
static int cl_ctr_mtu_step(int now_mtu, int joined_mtu, int *strikes, int *fails)
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

/* Largest packet the retransmit cache will hold, raised in mod_init once the
 * MTU is known.  Provisional value covers the control plane, which is all that
 * can be sent before then anyway. */
static int cl_ctr_retx_pkt_max = CL_CTR_NODE_ASSIGN_MAX_SZ;


/* Local node identity - populated at mod_init by scanning the config file */
uint16_t my_node_id                              = 0;
/* This process's incarnation (see CL_CTR_INC_SZ) - set once in mod_init and
 * inherited across fork, so the worker and mod_destroy's GOODBYE agree. */
static uint64_t cl_ctr_incarnation                      = 0;

/* clusterer integration - loaded at mod_init if clusterer use_controller=1 */
static clusterer_ctrl_binds_t clctl;
static int                    clctl_loaded  = 0;
static int                    manage_shtags = 1;
static int                    consumer_retries = CL_CTR_CONSUMER_RETRIES_DEFAULT;
static int                    consumer_retry_ms = CL_CTR_CONSUMER_RETRY_MS_DEFAULT;
/*
 * enable_reliable_send - kill switch for the consumer ARQ (ACK + retransmit).
 *
 * ON by default, which it was NOT when it was first added hours earlier: the
 * flag then could not work on a channel carrying concurrent messages, and
 * failed silently when it did not. A retransmit reuses its original seq, and
 * the receiver's anti-replay guard was a bare high-water mark, so once any
 * later message had been accepted the repair copy was rejected as
 * out-of-order AND re-ACKed - which stopped the sender retransmitting and left
 * it believing it had delivered. Measured on the cross-node cache pull channel
 * under 40% reply loss: plain 61.2% delivered, RELIABLE 49.4%, at two to three
 * times the packets, with not one retransmitted payload ever delivered.
 *
 * The replay window (cl_ctr_replay_t) removes that: a seq below the mark whose
 * bit is clear was never delivered, so its retransmit is accepted, while a seq
 * whose bit is set is a true duplicate and is re-ACKed without being delivered
 * twice. The flag now does what it says on any channel.
 *
 * The switch survives the fix rather than being deleted with it, because ARQ
 * still has a cost the operator may not want on a given fleet: a reliable
 * broadcast draws one ACK per member, so on a large cluster a single message
 * becomes an event. Turning this off degrades every reliable send to a plain
 * one - lossy, but cheap and never silent about it.
 */
int                    enable_reliable_send = 1;
/* master_stickiness (global default; per-cluster override via "cluster" string):
 *   1 (default) = the master is "sticky": a live master keeps the role and is
 *                 NOT displaced when a higher-IP node joins.  The highest-IP
 *                 non-master is designated BACKUP and takes over only when the
 *                 master fails.  A higher-IP joiner just replaces the backup.
 *                 Result: fewer master handovers.
 *   0           = not sticky - pure highest-IP election, so a higher-IP node
 *                 takes over as master as soon as it appears (more handovers). */
static int                    master_stickiness = 1;
static int      consumer_rate_limit = CL_CTR_CONSUMER_RATE_DEFAULT;
static char     my_bin_sockets[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
static int      my_bin_count                            = 0;


/**
 * cl_ctr_add_cluster_param() - collect "cluster" modparam strings.
 * Actual parsing happens in mod_init() after all params are set.
 */
static int cl_ctr_add_cluster_param(modparam_t type, void *val)
{
    if (cl_ctr_cluster_str_count >= CL_CTR_MAX_CLUSTERS) {
	LM_ERR("clusterer_controller: too many clusters (max %d)\n",
	       CL_CTR_MAX_CLUSTERS);
	return -1;
    }
    {
	size_t _len = strlen((char *)val) + 1;
	cl_ctr_cluster_strs[cl_ctr_cluster_str_count] = pkg_malloc(_len);
	if (!cl_ctr_cluster_strs[cl_ctr_cluster_str_count]) {
	    LM_ERR("clusterer_controller: pkg_malloc failed\n");
	    return -1;
	}
	memcpy(cl_ctr_cluster_strs[cl_ctr_cluster_str_count], (char *)val, _len);
    }
    cl_ctr_cluster_str_count++;
    return 0;
}

static const param_export_t params[] = {
    {"cluster",    STR_PARAM | USE_FUNC_PARAM, (void *)cl_ctr_add_cluster_param},
    {"my_ip",      STR_PARAM, &my_ip},
    {"interface",  STR_PARAM, &my_interface},
    {"query_time", INT_PARAM, &query_time},
    {"password",      STR_PARAM, &password},
    {"consumer_rate_limit", INT_PARAM, &consumer_rate_limit},
    {"consumer_retries",    INT_PARAM, &consumer_retries},
    {"consumer_retry_ms",   INT_PARAM, &consumer_retry_ms},
    {"enable_reliable_send", INT_PARAM, &enable_reliable_send},
    {"manage_shtags", INT_PARAM, &manage_shtags},
    {"master_stickiness", INT_PARAM, &master_stickiness},
    {"on_config_mismatch", STR_PARAM, &on_config_mismatch_s},
    {0, 0, 0}
};


/* =========================================================================
 * timerfd helpers
 * ========================================================================= */

/* Drain the expiration counter so the fd stops being readable. */
static void cl_ctr_drain_tfd(int tfd)
{
    uint64_t exp;
    if (read(tfd, &exp, sizeof(exp)) < 0 && errno != EAGAIN)
        LM_WARN("clusterer_controller: timerfd read: %s\n", strerror(errno));
}

/* Arm a timerfd.  Pass sec_value=0 to disarm. */
static void cl_ctr_arm_tfd(int tfd, time_t sec_value, time_t sec_interval)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec    = sec_value;
    its.it_interval.tv_sec = sec_interval;
    if (timerfd_settime(tfd, 0, &its, NULL) < 0)
        LM_WARN("clusterer_controller: timerfd_settime: %s\n", strerror(errno));
}

/* =========================================================================
 * Extra-process export  (layout from mi_fifo.c)
 * ========================================================================= */

static proc_export_t procs[] = {
    /* NEEDS_SCRIPT because a message arriving for the script's channel
     * raises an event here, and an event route is script: without it the
     * route structures are not set up in this process and running one
     * crashes. */
    {"clusterer_controller worker", 0, 0, cl_ctr_worker, 1,
        PROC_FLAG_INITCHILD | PROC_FLAG_HAS_IPC | PROC_FLAG_NEEDS_SCRIPT},
    {0, 0, 0, 0, 0, 0}
};

/* =========================================================================
 * Module dependency
 * ========================================================================= */

static const dep_export_t deps = {
    {
	/* proto_bin must load before us so its listeners are registered */
	{ MOD_TYPE_DEFAULT, "proto_bin",  DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "clusterer", DEP_ABORT },
	{ MOD_TYPE_NULL, NULL, 0 },
    },
    { { NULL, NULL } },
};

/* =========================================================================
 * MI command export table
 * ========================================================================= */

static const mi_export_t mi_cmds[] = {
    {
	"cl_ctr_list_members",
	"List all current cluster members with node_id, status and BIN sockets",
	0, 0,
	{
	    {mi_cl_ctr_members, {0}},
	    {EMPTY_MI_RECIPE}
	}, {0}
    },
    {
	"cl_ctr_node_info",
	"Return full info for a node_id across all clusters",
	0, 0,
	{
	    {mi_cl_ctr_node_info, {"node_id", 0}},
	    {EMPTY_MI_RECIPE}
	}, {0}
    },
    {
	"cl_ctr_list_config",
	"List all configured clusters and their resolved settings",
	0, 0,
	{
	    {mi_cl_ctr_config, {0}},
	    {EMPTY_MI_RECIPE}
	}, {0}
    },
    {
	"cl_ctr_shtag_force",
	"Force a node to hold the active sharing tag (master only); "
	"suspends automatic allocation until cl_ctr_shtag_auto",
	0, 0,
	{
	    {mi_cl_ctr_shtag_force, {"cluster_id", "node_id", 0}},
	    {EMPTY_MI_RECIPE}
	}, {0}
    },
    {
	"cl_ctr_shtag_auto",
	"Resume automatic master-driven sharing-tag allocation (master only)",
	0, 0,
	{
	    {mi_cl_ctr_shtag_auto, {"cluster_id", 0}},
	    {EMPTY_MI_RECIPE}
	}, {0}
    },
    {EMPTY_MI_EXPORT}
};

/* -------------------------------------------------------------------------
 * Per-peer lookups: query a *specific* node in a cluster.  These are script
 * FUNCTIONS, not pseudo-variables, because they take two arguments
 * (cluster_id, node_id) - a comma inside a pvar's parentheses is ambiguous to
 * the config parser when the pvar is used as a function argument.  Boolean
 * checks return true/false for use in if(); value lookups write an output var.
 * ------------------------------------------------------------------------- */

/* Find peer (cluster_id, node_id); cid<=0 => the sole configured cluster.
 * Returns 0 and fills the requested out params on success, -1 if the cluster
 * or node is unknown.  Caller must not hold the peers lock. */
int cl_ctr_find_peer(int cid, int nid, int *is_master, int *is_backup,
                        char *ipbuf, int ipbuf_sz)
{
    cl_ctr_cluster_t *cl = NULL;
    int i, rc = -1;

    if (cid <= 0) {
	if (cl_ctr_cluster_count == 1)
	    cl = &cl_ctr_clusters[0];
    } else {
	for (i = 0; i < cl_ctr_cluster_count; i++)
	    if (cl_ctr_clusters[i].cluster_id == cid) {
		cl = &cl_ctr_clusters[i];
		break;
	    }
    }
    if (!cl || !cl->peers)
	return -1;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
	cl_ctr_peer_t *e = &cl->peers->entries[i];
	if (e->node_id != nid)
	    continue;
	if (is_master) *is_master = e->is_master;
	if (is_backup) *is_backup = e->is_backup;
	if (ipbuf) {
	    strncpy(ipbuf, e->ip, ipbuf_sz - 1);
	    ipbuf[ipbuf_sz - 1] = '\0';
	}
	rc = 0;
	break;
    }
    lock_stop_read(cl->peers->lock);
    return rc;
}

/* =========================================================================
 * module_exports
 * ========================================================================= */

struct module_exports exports = {
    "clusterer_controller",
    MOD_TYPE_DEFAULT,
    MODULE_VERSION,
    DEFAULT_DLFLAGS,
    0,
    &deps,
    cl_ctr_cmds,          /* cmds - per-peer lookup functions */
    0,                /* acmds   */
    params,
    0,                /* stats   */
    mi_cmds,
    cl_ctr_mod_vars,      /* pvs - read-only $cl_ctr_* variables */
    0,                /* transforms */
    procs,
    0,                /* pre_init_f */
    mod_init,
    0,                /* response_f */
    mod_destroy,
    cl_ctr_child_init,    /* child_init_f */
    0                 /* reload_confirm_f */
};

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static unsigned int ip_to_num(const char *ip)
{
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0)
	return 0;
    return ntohl(addr.s_addr);
}

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
 *      nodes as possible;
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
static int cl_ctr_master_outranks(uint16_t c1, uint32_t t1, const char *ip1,
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
static void cl_ctr_note_term(cl_ctr_cluster_t *cl, uint32_t term)
{
    if (term > cl->peers->term_seen)
        cl->peers->term_seen = term;
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
static void cl_ctr_elect_master(cl_ctr_cluster_t *cl)
{
    time_t       cutoff    = cl_ctr_election_cutoff();
    unsigned int top_num   = 0;
    int          i, n_in = 0, top_idx = -1, cur_master_idx = -1, master_idx = -1;
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
	    if (e->ip_num > top_num) {
		top_num = e->ip_num;
		top_idx = i;
	    }
	}
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
	    if (n_in <= 1)
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
static int cl_ctr_i_am_master_locked(cl_ctr_cluster_t *cl)
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
static int cl_ctr_ip_beats_master_locked(unsigned int ip_num, cl_ctr_cluster_t *cl)
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
 *                 (cl_ctr_shtag_force).  Only that node activates; all others go
 *                 to backup.  Automatic allocation is suspended.
 *   forced == 0 : automatic mode - the current master is the active holder.
 */
static void cl_ctr_apply_shtags_decision(cl_ctr_cluster_t *cl, int i_am_master,
                                     uint16_t forced)
{
    int activate;

    if (!cl->manage_shtags || !clctl_loaded || !clctl.activate_backup_shtags)
        return;

    if (forced != 0)
        activate = (my_node_id != 0 && (uint16_t)my_node_id == forced);
    else
        activate = i_am_master;

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
static void cl_ctr_apply_shtags(cl_ctr_cluster_t *cl)
{
    int      i_am_master;
    uint16_t forced;

    lock_start_read(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    forced      = cl->peers->shtag_forced_node_id;
    lock_stop_read(cl->peers->lock);

    cl_ctr_apply_shtags_decision(cl, i_am_master, forced);
}

static void cl_ctr_prune_stale(cl_ctr_cluster_t *cl)
{
    time_t cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_PURGE_FACTOR);
    int    i;

    for (i = 0; i < cl->peers->count; i++) {
	if (cl->peers->entries[i].last_seen < cutoff) {
	    uint16_t pruned_id = cl->peers->entries[i].node_id;
	    LM_INFO("clusterer_controller: purging timed-out peer %s\n",
	            cl->peers->entries[i].ip);
	    cl_ctr_reserve_id_locked(cl, cl->peers->entries[i].ip, pruned_id);
	    cl->peers->count--;
	    if (i < cl->peers->count)
		cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
	    memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cl_ctr_peer_t));
	    i--;
	    /* cl_list_lock and cl->peers->lock are independent - no deadlock */
	    if (clctl_loaded && pruned_id > 0)
		clctl.remove_node(cl->cluster_id, pruned_id);
	    /* If the operator-forced shtag holder timed out, drop the override
	     * so automatic allocation resumes instead of leaving no active tag. */
	    if (pruned_id != 0 && cl->peers->shtag_forced_node_id == pruned_id) {
		LM_WARN("clusterer_controller: [cluster %d] forced shtag node "
		        "%u timed out - resuming automatic allocation\n",
		        cl->cluster_id, pruned_id);
		cl->peers->shtag_forced_node_id = 0;
	    }
	    /* Re-apply shtag policy (override-aware); inside the lock, so pass
	     * the state directly rather than calling the locking wrapper. */
	    cl_ctr_apply_shtags_decision(cl, cl_ctr_i_am_master_locked(cl),
	                             cl->peers->shtag_forced_node_id);
	}
    }
}

/**
 * cl_ctr_apply_master_from_list_locked() - apply master designation from a
 *                                      received MEMBER_LIST/MEMBER_LIST packet.
 *
 * Zeros all is_master flags in the peer table, then sets is_master=1 for
 * the entry matching master_ip.  Updates last_master accordingly.
 * Must be called with cl->peers->lock held.
 */
static void cl_ctr_apply_master_from_list_locked(const char *master_ip, cl_ctr_cluster_t *cl)
{
    int i;

    for (i = 0; i < cl->peers->count; i++) {
	if (strcmp(cl->peers->entries[i].ip, master_ip) == 0) {
	    cl->peers->entries[i].is_master = 1;
	} else {
	    cl->peers->entries[i].is_master = 0;
	}
    }

    /* list ordering is per master: a different master starts afresh */
    if (strcmp(cl->peers->last_master, master_ip) != 0) {
	cl->peers->list_term_seen = 0;
	cl->peers->list_seq_seen  = 0;
    }
    memcpy(cl->peers->last_master, master_ip,
           strnlen(master_ip, CL_CTR_MAX_IP_LEN));
    cl->peers->last_master[strnlen(master_ip, CL_CTR_MAX_IP_LEN)] = '\0';
}

/**
 * cl_ctr_peer_by_ip_locked() - find a peer entry by IP string.
 * Returns the entry pointer, or NULL if not present.
 * Must be called with cl->peers->lock held (read or write).
 */
static cl_ctr_peer_t *cl_ctr_peer_by_ip_locked(cl_ctr_cluster_t *cl, const char *ip)
{
    int i;
    for (i = 0; i < cl->peers->count; i++)
        if (strcmp(cl->peers->entries[i].ip, ip) == 0)
            return &cl->peers->entries[i];
    return NULL;
}

/**
 * cl_ctr_learn_peer_locked() - membership WITHOUT a liveness claim.
 *
 * A MEMBER_LIST says who BELONGS to the cluster, not who is reachable now: the
 * master lists a node until it prunes it, whether that node is up or not.
 * Refreshing last_seen from such a list - which is what upsert does - makes
 * every receiver believe it has just heard from peers it has never heard from.
 *
 * That is not cosmetic. cl_ctr_alive_bitmap() is built from last_seen, so a
 * backup holding refreshed timestamps for a dead node asserts that node is
 * alive to the entire cluster the moment it becomes master - and then nobody
 * can age it out. A node survived in a live cluster for about a day that way,
 * across a master change, while every TCP connect to it was refused.
 *
 * So: insert what we did not already know about, and leave last_seen of
 * anything we do track to direct evidence only - cl_ctr_upsert_peer_locked()
 * from a packet actually sent BY that peer, or the master's alive bitmap,
 * which the master derives from its own direct evidence.
 *
 * A newly learned peer is still seeded with last_seen = now, deliberately: it
 * gets one purge window to prove itself rather than being pruned on the next
 * tick. This terminates - once the master prunes a dead node it stops listing
 * it, and every receiver ages it out one window later.
 *
 * Must be called with cl->peers->lock held for write.
 */
static void cl_ctr_learn_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl)
{
    if (cl_ctr_peer_by_ip_locked(cl, src_ip))
        return;                 /* already known - membership adds nothing */
    cl_ctr_upsert_peer_locked(src_ip, cl);
}

/**
 * cl_ctr_upsert_peer_locked() - insert or refresh a peer entry.
 * Does NOT call cl_ctr_elect_master(cl); callers do that explicitly.
 * Must be called with cl->peers->lock held.
 */
static void cl_ctr_upsert_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl)
{
    unsigned int src_num = ip_to_num(src_ip);
    time_t       now     = cl_ctr_now();
    cl_ctr_peer_t   *found;

    if (src_num == 0) {
	LM_WARN("clusterer_controller: ignoring invalid IP '%s'\n", src_ip);
	return;
    }

    found = cl_ctr_peer_by_ip_locked(cl, src_ip);
    if (found) {
	found->last_seen = now;
	return;   /* updated */
    }

    /* New entry */
    if (cl->peers->count >= CL_CTR_MAX_PEERS) {
	/* Counted always, said once a minute: this runs per packet, and a
	 * flood of new sources (or a misconfiguration) must not turn a full
	 * table into a full disk.  cl_ctr_list_config reports the count. */
	cl->peers->peers_refused++;
	if (cl->peers->peers_refused_warned_at == 0
	        || now - cl->peers->peers_refused_warned_at >= 60) {
	    cl->peers->peers_refused_warned_at = now;
	    LM_WARN("clusterer_controller: [cluster %d] peer table full (%d of "
	            "%d) - ignoring %s and any other new address; %lu refused "
	            "so far\n", cl->cluster_id, cl->peers->count,
	            CL_CTR_MAX_PEERS, src_ip, cl->peers->peers_refused);
	}
	return;
    }
    {
	cl_ctr_peer_t *e = &cl->peers->entries[cl->peers->count];
	memcpy(e->ip, src_ip, strnlen(src_ip, CL_CTR_MAX_IP_LEN));
	e->ip[strnlen(src_ip, CL_CTR_MAX_IP_LEN)] = '\0';
	e->ip_num             = src_num;
	e->last_seen          = now;
	e->is_master          = 0;
	cl->peers->count++;
	LM_INFO("clusterer_controller: new peer %s (total=%d)\n",
	        src_ip, cl->peers->count);
    }
}

/**
 * cl_ctr_reserve_id_locked() - hold @node_id for @ip, which just left.
 * Replaces any older hold for the same address or the same id; when the table
 * is full the hold closest to expiry gives way.
 * Must be called with cl->peers->lock held for write.
 */
static void cl_ctr_reserve_id_locked(cl_ctr_cluster_t *cl, const char *ip,
                                     uint16_t node_id)
{
    cl_ctr_id_resv_t *r, *slot = NULL;
    time_t            now = cl_ctr_now();
    int               i;

    if (node_id == 0 || ip[0] == '\0')
        return;
    /* drop any older hold for this address or this id */
    for (i = 0; i < CL_CTR_MAX_PEERS; i++) {
        r = &cl->peers->id_resv[i];
        if (r->ip[0] != '\0' &&
            (strcmp(r->ip, ip) == 0 || r->node_id == node_id))
            r->ip[0] = '\0';
    }
    /* a free or expired slot ... */
    for (i = 0; i < CL_CTR_MAX_PEERS && !slot; i++) {
        r = &cl->peers->id_resv[i];
        if (r->ip[0] == '\0' || r->until <= now)
            slot = r;
    }
    /* ... or else the hold closest to expiry */
    if (!slot) {
        slot = &cl->peers->id_resv[0];
        for (i = 1; i < CL_CTR_MAX_PEERS; i++)
            if (cl->peers->id_resv[i].until < slot->until)
                slot = &cl->peers->id_resv[i];
    }
    snprintf(slot->ip, sizeof(slot->ip), "%s", ip);
    slot->node_id = node_id;
    slot->until   = now + CL_CTR_ID_RESERVE_SECS;
}

/* node_id currently used by a member of the peer table? */
static int cl_ctr_id_in_use_locked(cl_ctr_cluster_t *cl, uint16_t id)
{
    int i;
    for (i = 0; i < cl->peers->count; i++)
        if (cl->peers->entries[i].node_id == id)
            return 1;
    return 0;
}

/**
 * cl_ctr_alloc_node_id_locked() - choose a node_id for @ip.
 *
 * The id @ip held before it left, if that is still reserved for it and free;
 * otherwise the lowest id that is neither in use nor held for another node
 * that left recently; otherwise - every id held - the lowest not in use.
 * Must be called with cl->peers->lock held for write.
 */
static uint16_t cl_ctr_alloc_node_id_locked(cl_ctr_cluster_t *cl, const char *ip)
{
    time_t   now = cl_ctr_now();
    uint16_t id;
    int      i, held;

    for (i = 0; i < CL_CTR_MAX_PEERS; i++) {
        cl_ctr_id_resv_t *r = &cl->peers->id_resv[i];
        if (r->ip[0] != '\0' && r->until > now && strcmp(r->ip, ip) == 0) {
            id = r->node_id;
            r->ip[0] = '\0';                      /* claimed */
            if (!cl_ctr_id_in_use_locked(cl, id)) {
                LM_INFO("clusterer_controller: [cluster %d] %s rejoined - "
                        "giving it back node_id %u\n", cl->cluster_id, ip, id);
                return id;
            }
            break;
        }
    }
    for (id = 1; id < 65535; id++) {
        if (cl_ctr_id_in_use_locked(cl, id))
            continue;
        held = 0;
        for (i = 0; i < CL_CTR_MAX_PEERS; i++) {
            cl_ctr_id_resv_t *r = &cl->peers->id_resv[i];
            if (r->ip[0] != '\0' && r->until > now && r->node_id == id) {
                held = 1;
                break;
            }
        }
        if (!held)
            return id;
    }
    for (id = 1; id < 65535; id++)            /* everything is held */
        if (!cl_ctr_id_in_use_locked(cl, id))
            return id;
    return 0;   /* table full (shouldn't happen with CL_CTR_MAX_PEERS=256) */
}

/**
 * cl_ctr_update_peer_bin_locked() - store node_id and BIN sockets for a peer.
 * Must be called with cl->peers->lock held.
 */
static void cl_ctr_update_peer_bin_locked(const char *ip, uint16_t node_id,
                                      uint8_t bin_count,
                                      const char (*bin_sockets)[CL_CTR_MAX_BIN_SOCK_LEN],
                                      cl_ctr_cluster_t *cl)
{
    cl_ctr_peer_t *e = cl_ctr_peer_by_ip_locked(cl, ip);
    if (e) {
	e->node_id   = node_id;
	e->bin_count = bin_count;
	if (bin_count > 0)
	    memcpy(e->bin_sockets, bin_sockets, bin_count * CL_CTR_MAX_BIN_SOCK_LEN);
    }
}

/* =========================================================================
 * Packet encryption / decryption (AEAD)
 *
 * Every packet is fully encrypted and authenticated with XChaCha20-Poly1305
 * (libsodium).  A fresh random nonce per packet ensures that even identical
 * payloads produce different ciphertext.
 *
 * A 4-byte monotonic sequence number is included inside the plaintext.
 * Receivers track the highest sequence seen from each peer and reject any
 * packet whose sequence is not strictly greater.  This stops replays
 * without requiring NTP-synchronised clocks or a finite nonce cache.
 * The counter resets to 0 on every session key rotation; old packets
 * encrypted with the previous key fail AEAD authentication anyway.
 * Bootstrap-key packets (CL_CTR_BOOTSTRAP_MAGIC) skip the sequence check -
 * their per-exchange join_nonce provides equivalent replay protection.
 *
 * Wire layout:
 *   [magic 2B][cluster_id 2B][nonce 24B][ciphertext][Poly1305 tag 16B]
 * Plaintext:
 *   [type 1B][seq 4B][payload]
 * ========================================================================= */

/* cl_ctr_random_bytes() - fill buf with cryptographically secure random bytes
 * (libsodium's randombytes draws from the kernel CSPRNG). */
static int cl_ctr_random_bytes(unsigned char *buf, size_t len)
{
    randombytes_buf(buf, len);
    return 0;
}

/* RFC 5869 HKDF-SHA256 built on libsodium's HMAC-SHA256 (libsodium 1.0.18 has
 * no native HKDF; crypto_auth_hmacsha256_init accepts any key length).  Every
 * use in this module needs exactly 32 output bytes (= HashLen), so the expand
 * phase is a single iteration: OKM = HMAC(PRK, info || 0x01). */
static int cl_ctr_hkdf_sha256(const unsigned char *ikm,  size_t ikm_len,
                           const unsigned char *salt, size_t salt_len,
                           const char          *info,
                           unsigned char        out[32])
{
    crypto_auth_hmacsha256_state st;
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    static const unsigned char zeros[crypto_auth_hmacsha256_BYTES];
    const unsigned char ctr = 0x01;
    size_t info_len = info ? strlen(info) : 0;

    /* extract: PRK = HMAC(salt, IKM); an absent salt is HashLen zero bytes */
    if (crypto_auth_hmacsha256_init(&st, salt_len ? salt : zeros,
                                    salt_len ? salt_len : sizeof(zeros)) != 0)
        return -1;
    crypto_auth_hmacsha256_update(&st, ikm, (unsigned long long)ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);

    /* expand: T(1) = HMAC(PRK, info || 0x01) */
    if (crypto_auth_hmacsha256_init(&st, prk, sizeof(prk)) != 0)
        return -1;
    if (info_len)
        crypto_auth_hmacsha256_update(&st, (const unsigned char *)info,
                                      (unsigned long long)info_len);
    crypto_auth_hmacsha256_update(&st, &ctr, 1);
    crypto_auth_hmacsha256_final(&st, out);
    return 0;
}

static int cl_ctr_gen_ecdh_keypair(unsigned char *privkey, unsigned char *pubkey)
{
    randombytes_buf(privkey, CL_CTR_PUBKEY_SZ);
    if (crypto_scalarmult_base(pubkey, privkey) != 0) {
        LM_ERR("clusterer_controller: X25519 keygen failed\n");
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Noise_NNpsk0_25519_ChaChaPoly_SHA256 - the join handshake.
 *
 * NNpsk0: ephemeral-only, mutual authentication via a pre-shared key (the
 * Argon2id bootstrap key), forward secrecy via the ephemeral-ephemeral DH.
 *   -> psk, e         (JOIN_REQ carries msg 1)
 *   <- e, ee          (KEY_GRANT carries msg 2, whose AEAD payload = master_salt)
 * Both endpoints run this identical code, so byte-for-byte interop with other
 * Noise libraries is not required; the module verifies self-consistency and the
 * security properties in its own test harness.  See RFC "The Noise Protocol
 * Framework" rev 34.  HASHLEN = 32 (SHA-256), DHLEN = 32 (X25519).
 * ========================================================================= */
#define CL_CTR_NOISE_PROTO "Noise_NNpsk0_25519_ChaChaPoly_SHA256"

static void cl_ctr_hmac256(const unsigned char *key, size_t keylen,
                       const unsigned char *data, size_t datalen,
                       unsigned char out[CL_CTR_NOISE_HASHLEN])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, keylen);
    crypto_auth_hmacsha256_update(&st, data, datalen);
    crypto_auth_hmacsha256_final(&st, out);
}

/* Noise HKDF: chained HMAC outputs (num_outputs of 1..3, each HASHLEN bytes). */
static void cl_ctr_noise_hkdf(const unsigned char ck[CL_CTR_NOISE_HASHLEN],
                          const unsigned char *ikm, size_t ikm_len, int num_outputs,
                          unsigned char o1[CL_CTR_NOISE_HASHLEN],
                          unsigned char o2[CL_CTR_NOISE_HASHLEN],
                          unsigned char o3[CL_CTR_NOISE_HASHLEN])
{
    unsigned char tempkey[CL_CTR_NOISE_HASHLEN], buf[CL_CTR_NOISE_HASHLEN + 1];
    cl_ctr_hmac256(ck, CL_CTR_NOISE_HASHLEN, ikm, ikm_len, tempkey);   /* extract */
    buf[0] = 0x01;
    cl_ctr_hmac256(tempkey, CL_CTR_NOISE_HASHLEN, buf, 1, o1);
    if (num_outputs >= 2) {
        memcpy(buf, o1, CL_CTR_NOISE_HASHLEN); buf[CL_CTR_NOISE_HASHLEN] = 0x02;
        cl_ctr_hmac256(tempkey, CL_CTR_NOISE_HASHLEN, buf, CL_CTR_NOISE_HASHLEN + 1, o2);
    }
    if (num_outputs >= 3) {
        memcpy(buf, o2, CL_CTR_NOISE_HASHLEN); buf[CL_CTR_NOISE_HASHLEN] = 0x03;
        cl_ctr_hmac256(tempkey, CL_CTR_NOISE_HASHLEN, buf, CL_CTR_NOISE_HASHLEN + 1, o3);
    }
    sodium_memzero(tempkey, sizeof tempkey);
}

static void cl_ctr_cs_nonce(uint64_t n, unsigned char out[12])
{
    int i;
    memset(out, 0, 4);                          /* 32 bits of zeros            */
    for (i = 0; i < 8; i++) out[4 + i] = (unsigned char)(n >> (8 * i)); /* LE64 */
}
static int cl_ctr_cs_encrypt(cl_ctr_cipherstate_t *cs, const unsigned char *ad, size_t ad_len,
                         const unsigned char *pt, size_t pt_len, unsigned char *ct)
{
    unsigned char nonce[12]; unsigned long long clen = 0;
    /* pt may legitimately be NULL for an empty payload (Noise msg 1 sends
     * one); memcpy() is nonnull even for a zero length, so guard it. */
    if (!cs->has_key) { if (pt_len) memcpy(ct, pt, pt_len); return (int)pt_len; }
    cl_ctr_cs_nonce(cs->n, nonce);
    crypto_aead_chacha20poly1305_ietf_encrypt(ct, &clen, pt, pt_len,
                                              ad, ad_len, NULL, nonce, cs->k);
    cs->n++;
    return (int)clen;
}
static int cl_ctr_cs_decrypt(cl_ctr_cipherstate_t *cs, const unsigned char *ad, size_t ad_len,
                         const unsigned char *ct, size_t ct_len, unsigned char *pt)
{
    unsigned char nonce[12]; unsigned long long plen = 0;
    if (!cs->has_key) { if (ct_len) memcpy(pt, ct, ct_len); return (int)ct_len; }
    cl_ctr_cs_nonce(cs->n, nonce);
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &plen, NULL, ct, ct_len,
                                                  ad, ad_len, nonce, cs->k) != 0)
        return -1;
    cs->n++;
    return (int)plen;
}

static void cl_ctr_ss_mixhash(cl_ctr_symstate_t *s, const unsigned char *data, size_t len)
{
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, s->h, CL_CTR_NOISE_HASHLEN);
    crypto_hash_sha256_update(&st, data, len);
    crypto_hash_sha256_final(&st, s->h);
}
static void cl_ctr_ss_init(cl_ctr_symstate_t *s)
{
    size_t nl = strlen(CL_CTR_NOISE_PROTO);           /* <= HASHLEN, so pad it */
    memset(s->h, 0, CL_CTR_NOISE_HASHLEN);
    memcpy(s->h, CL_CTR_NOISE_PROTO, nl);
    memcpy(s->ck, s->h, CL_CTR_NOISE_HASHLEN);
    s->cs.has_key = 0; s->cs.n = 0;
}
static void cl_ctr_ss_mixkey(cl_ctr_symstate_t *s, const unsigned char *ikm, size_t ikm_len)
{
    unsigned char o1[CL_CTR_NOISE_HASHLEN], o2[CL_CTR_NOISE_HASHLEN], o3[CL_CTR_NOISE_HASHLEN];
    cl_ctr_noise_hkdf(s->ck, ikm, ikm_len, 2, o1, o2, o3);
    memcpy(s->ck, o1, CL_CTR_NOISE_HASHLEN);
    memcpy(s->cs.k, o2, 32); s->cs.n = 0; s->cs.has_key = 1;
}
static void cl_ctr_ss_mixkeyhash(cl_ctr_symstate_t *s, const unsigned char *ikm, size_t ikm_len)
{
    unsigned char o1[CL_CTR_NOISE_HASHLEN], o2[CL_CTR_NOISE_HASHLEN], o3[CL_CTR_NOISE_HASHLEN];
    cl_ctr_noise_hkdf(s->ck, ikm, ikm_len, 3, o1, o2, o3);
    memcpy(s->ck, o1, CL_CTR_NOISE_HASHLEN);
    cl_ctr_ss_mixhash(s, o2, CL_CTR_NOISE_HASHLEN);
    memcpy(s->cs.k, o3, 32); s->cs.n = 0; s->cs.has_key = 1;
}
static int cl_ctr_ss_encrypt_hash(cl_ctr_symstate_t *s, const unsigned char *pt, size_t pt_len,
                              unsigned char *ct)
{
    int cl = cl_ctr_cs_encrypt(&s->cs, s->h, CL_CTR_NOISE_HASHLEN, pt, pt_len, ct);
    cl_ctr_ss_mixhash(s, ct, cl);
    return cl;
}
static int cl_ctr_ss_decrypt_hash(cl_ctr_symstate_t *s, const unsigned char *ct, size_t ct_len,
                              unsigned char *pt)
{
    int pl = cl_ctr_cs_decrypt(&s->cs, s->h, CL_CTR_NOISE_HASHLEN, ct, ct_len, pt);
    if (pl < 0) return -1;
    cl_ctr_ss_mixhash(s, ct, ct_len);
    return pl;
}

/* Initiator: write msg 1 (-> psk, e).  Stores e keypair in @e_priv for msg 2. */
static int cl_ctr_noise_write1(cl_ctr_symstate_t *s, unsigned char e_priv[32],
                           const unsigned char psk[32],
                           const unsigned char *payload, size_t pl_len,
                           unsigned char *out)
{
    unsigned char e_pub[32];
    cl_ctr_ss_init(s);
    cl_ctr_ss_mixkeyhash(s, psk, 32);                 /* psk token (psk0) */
    randombytes_buf(e_priv, 32); crypto_scalarmult_base(e_pub, e_priv); /* e */
    memcpy(out, e_pub, 32); cl_ctr_ss_mixhash(s, e_pub, 32); cl_ctr_ss_mixkey(s, e_pub, 32);
    return 32 + cl_ctr_ss_encrypt_hash(s, payload, pl_len, out + 32);
}
/* Responder: read msg 1, then write msg 2 (<- e, ee) with @payload.  One-shot,
 * so no responder state is retained afterwards.  @out gets msg 2. */
static int cl_ctr_noise_respond(const unsigned char psk[32],
                            const unsigned char *msg1, size_t msg1_len,
                            const unsigned char *payload, size_t pl_len,
                            unsigned char *out)
{
    cl_ctr_symstate_t s;
    unsigned char re[32], e_priv[32], e_pub[32], dh[32], scratch[64];
    if (msg1_len < 32) return -1;
    cl_ctr_ss_init(&s);
    cl_ctr_ss_mixkeyhash(&s, psk, 32);
    memcpy(re, msg1, 32); cl_ctr_ss_mixhash(&s, re, 32); cl_ctr_ss_mixkey(&s, re, 32);
    if (cl_ctr_ss_decrypt_hash(&s, msg1 + 32, msg1_len - 32, scratch) < 0)
        return -1;                                /* bad msg 1 (wrong psk/tamper) */
    randombytes_buf(e_priv, 32); crypto_scalarmult_base(e_pub, e_priv);
    memcpy(out, e_pub, 32); cl_ctr_ss_mixhash(&s, e_pub, 32); cl_ctr_ss_mixkey(&s, e_pub, 32);
    if (crypto_scalarmult(dh, e_priv, re) != 0) return -1;   /* ee */
    cl_ctr_ss_mixkey(&s, dh, 32);
    return 32 + cl_ctr_ss_encrypt_hash(&s, payload, pl_len, out + 32);
}
/* Initiator: read msg 2 (-> e, ee), recover @payload (master_salt). */
static int cl_ctr_noise_read2(cl_ctr_symstate_t *s, const unsigned char e_priv[32],
                          const unsigned char *msg2, size_t msg2_len,
                          unsigned char *payload_out)
{
    unsigned char re2[32], dh[32], scratch[64];
    int pl;
    /* decrypt into a scratch large enough for the max ciphertext (mirrors
     * the scratch[64] on the write2 side), then hand back exactly the
     * master_salt.  Bounding the decrypt output here keeps a malformed or
     * oversized KEY_GRANT from ever writing past payload_out. */
    if (msg2_len < 32 || msg2_len - 32 > sizeof scratch) return -1;
    memcpy(re2, msg2, 32); cl_ctr_ss_mixhash(s, re2, 32); cl_ctr_ss_mixkey(s, re2, 32);
    if (crypto_scalarmult(dh, e_priv, re2) != 0) return -1;
    cl_ctr_ss_mixkey(s, dh, 32);
    pl = cl_ctr_ss_decrypt_hash(s, msg2 + 32, msg2_len - 32, scratch);
    if (pl != CL_CTR_MASTER_SALT_SZ) return -1;
    memcpy(payload_out, scratch, CL_CTR_MASTER_SALT_SZ);
    return pl;
}

/**
 * cl_ctr_derive_session_key() - derive group key from password + master_salt.
 * Reads master_salt from cl->peers->master_salt (shm, caller holds write lock).
 * Stores result in cl->session_key (worker-local cache).
 * Must be called with cl->peers->lock held for WRITE.
 */
static int cl_ctr_derive_session_key(cl_ctr_cluster_t *cl)
{
    int i;
    size_t pass_len = strlen(cl->password);
    if (cl_ctr_hkdf_sha256((unsigned char *)cl->password, pass_len,
                        cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ,
                        "cl_ctr_session", cl->session_key) < 0) {
        LM_ERR("clusterer_controller: [cluster %d] session key derivation failed\n",
               cl->cluster_id);
        return -1;
    }
    /* Reset sequence counters: old packets encrypted with the previous key
     * fail AEAD authentication, so starting from 0 is safe. */
    cl->peers->my_seq = 0;
    cl->peers->my_consumer_seq = 0;
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_replay_reset(&cl->peers->entries[i].replay);
        cl_ctr_replay_reset(&cl->peers->entries[i].replay_consumer);
    }
    cl->have_session_key = 1;   /* a valid group key now exists */
    /* The salt (and my_seq) just changed, so any queued retransmit is now stale. */
    cl_ctr_retx_flush(cl);
    return 0;
}


/**
 * cl_ctr_password_entropy_bits() - conservative estimate of a password's entropy.
 * bits ~= length * floor(log2(charset)), where charset is the union of the
 * character classes present.  floor() makes it a slight under-estimate, so the
 * weak-password warning errs toward firing.  No libm dependency.
 */
static int cl_ctr_password_entropy_bits(const char *p)
{
    int    have_lower = 0, have_upper = 0, have_digit = 0, have_sym = 0;
    int    charset, bits_per_char = 0, tmp;
    size_t i, len = strlen(p);

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if      (c >= 'a' && c <= 'z') have_lower = 1;
        else if (c >= 'A' && c <= 'Z') have_upper = 1;
        else if (c >= '0' && c <= '9') have_digit = 1;
        else                           have_sym   = 1;
    }
    charset = have_lower * 26 + have_upper * 26 + have_digit * 10 + have_sym * 33;
    if (charset < 2)
        charset = 2;
    for (tmp = charset; tmp > 1; tmp >>= 1)
        bits_per_char++;
    return (int)(len * (size_t)bits_per_char);
}

/**
 * cl_ctr_derive_key() - derive the 32-byte bootstrap (admission) key from the
 * shared password.  Used only for the join handshake (JOIN_REQ / KEY_GRANT /
 * JOIN_REJECT); normal traffic uses the ECDH-agreed session key.
 *
 * Uses scrypt (memory-hard) rather than a single SHA-256 so that a password
 * captured from a JOIN packet cannot be brute-forced cheaply offline.  Called
 * once per cluster from mod_init() in the main process before fork, so the
 * ~64 MiB scrypt working set is a transient startup cost only; workers inherit
 * the derived key and never run scrypt.
 */
static int cl_ctr_derive_key(cl_ctr_cluster_t *cl)
{
    char salt[64];
    int  saltlen, bits;

    /* Warn on a weak or default admission password.  scrypt raises the cost of
     * each offline guess, but only a high-entropy secret removes the risk. */
    if (strcmp(cl->password, CL_CTR_DEFAULT_PASSWORD) == 0) {
        LM_WARN("clusterer_controller: [cluster %d] using the built-in default "
                "password - set a strong 'password' (e.g. `openssl rand -base64 32`)\n",
                cl->cluster_id);
    } else {
        bits = cl_ctr_password_entropy_bits(cl->password);
        if (bits < CL_CTR_MIN_PASSWORD_BITS)
            LM_WARN("clusterer_controller: [cluster %d] weak password (~%d bits "
                    "of entropy) - an attacker who captures a JOIN packet can "
                    "brute-force it offline; use a long random string, e.g. "
                    "`openssl rand -base64 32`\n", cl->cluster_id, bits);
    }

    /* Per-cluster salt: a fixed domain-separation label plus the multicast
     * address, so the same password on different clusters yields different
     * bootstrap keys.  The salt is public by design - Argon2id's work factor,
     * not salt secrecy, is what defeats brute force.                        */
    saltlen = snprintf(salt, sizeof(salt), "opensips-cl-ctr-bootstrap-v1:%s",
                       cl->multicast_address);
    if (saltlen < 0 || saltlen >= (int)sizeof(salt))
        saltlen = (int)strlen(salt);

    /* Argon2id.  crypto_pwhash needs a fixed-length 16-byte salt, so fold our
     * variable-length domain-separation salt into one with BLAKE2b.           */
    {
        unsigned char salt16[crypto_pwhash_SALTBYTES];
        crypto_generichash(salt16, sizeof(salt16),
                           (const unsigned char *)salt, (size_t)saltlen, NULL, 0);
        if (crypto_pwhash(cl->key, 32,
                          cl->password, strlen(cl->password),
                          salt16, CL_CTR_ARGON2_OPSLIMIT, CL_CTR_ARGON2_MEMLIMIT,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            LM_ERR("clusterer_controller: key derivation (Argon2id) failed for "
                   "cluster %d (out of memory?)\n", cl->cluster_id);
            return -1;
        }
    }
    return 0;
}

/* =========================================================================
 * Founded cluster identity (CL_CTR_CID_*)
 * ========================================================================= */

static const char *cl_ctr_cid_state_name(int st)
{
    switch (st) {
    case CL_CTR_CID_PROVISIONAL: return "provisional";
    case CL_CTR_CID_ESTABLISHED: return "established";
    case CL_CTR_CID_PINNED:      return "pinned";
    default:                     return "none";
    }
}

/* "8-4-4-4-12" lowercase into @out (37 bytes) */
static void cl_ctr_cid_str(const unsigned char *cid, char *out)
{
    static const char hx[] = "0123456789abcdef";
    int i, o = 0;
    for (i = 0; i < CL_CTR_CID_SZ; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out[o++] = '-';
        out[o++] = hx[cid[i] >> 4];
        out[o++] = hx[cid[i] & 0x0F];
    }
    out[o] = '\0';
}

static int cl_ctr_cid_is_zero(const unsigned char *cid)
{
    int i;
    for (i = 0; i < CL_CTR_CID_SZ; i++)
        if (cid[i])
            return 0;
    return 1;
}

/* uuid= value: a UUID as written, or any other string hashed into a v8 UUID,
 * so a fleet can pin a readable name.  0 ok, -1 empty. */
static int cl_ctr_cid_parse_pin(const char *v, unsigned char *out)
{
    int i, n = 0, ok = (strlen(v) == 36);

    for (i = 0; ok && v[i]; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            ok = (v[i] == '-');
            continue;
        }
        if (!isxdigit((unsigned char)v[i])) {
            ok = 0;
            break;
        }
        if (n % 2 == 0)
            out[n / 2] = 0;
        out[n / 2] |= (unsigned char)((isdigit((unsigned char)v[i]) ? v[i] - '0'
                                     : (tolower((unsigned char)v[i]) - 'a' + 10))
                                     << (n % 2 ? 0 : 4));
        n++;
    }
    if (ok && n == 2 * CL_CTR_CID_SZ)
        return 0;
    if (!v[0])
        return -1;
    crypto_generichash(out, CL_CTR_CID_SZ, (const unsigned char *)v, strlen(v),
                       (const unsigned char *)"cl_ctr_cluster_uuid", 19);
    out[6] = (unsigned char)((out[6] & 0x0F) | 0x80);   /* version 8 */
    out[8] = (unsigned char)((out[8] & 0x3F) | 0x80);   /* RFC 9562 variant */
    return 0;
}

/* Take @cid as this cluster's identity, PROVISIONAL.  An established or
 * pinned identity is never replaced. */
static void cl_ctr_cid_adopt(cl_ctr_cluster_t *cl, const unsigned char *cid,
                             const char *how)
{
    char s1[37], s2[37];

    if (cl->peers->cid_state == CL_CTR_CID_ESTABLISHED
            || cl->peers->cid_state == CL_CTR_CID_PINNED)
        return;
    if (cl->peers->cid_state != CL_CTR_CID_NONE
            && memcmp(cl->peers->cid, cid, CL_CTR_CID_SZ) == 0)
        return;
    cl_ctr_cid_str(cid, s1);
    if (cl->peers->cid_state == CL_CTR_CID_PROVISIONAL) {
        cl_ctr_cid_str(cl->peers->cid, s2);
        LM_INFO("clusterer_controller: [cluster %d] cluster uuid %s (%s) - "
                "giving up provisional %s\n", cl->cluster_id, s1, how, s2);
    } else {
        LM_INFO("clusterer_controller: [cluster %d] cluster uuid %s (%s)\n",
                cl->cluster_id, s1, how);
    }
    memcpy(cl->peers->cid, cid, CL_CTR_CID_SZ);
    cl->peers->cid_state = CL_CTR_CID_PROVISIONAL;
    cl->peers->cid_since = cl_ctr_now();
}

/* Founding a cluster: into an id we have already heard from authenticated
 * traffic if there is one, otherwise a new UUID v7. */
static void cl_ctr_cid_found(cl_ctr_cluster_t *cl)
{
    unsigned char id[CL_CTR_CID_SZ];
    struct timeval tv;
    uint64_t ms;
    int i;

    if (cl->peers->cid_state != CL_CTR_CID_NONE)
        return;
    if (cl->heard_cid_set) {
        cl_ctr_cid_adopt(cl, cl->heard_cid, "founding into the cluster "
                         "already heard on this group");
        return;
    }
    gettimeofday(&tv, NULL);
    ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
    randombytes_buf(id, sizeof id);
    for (i = 0; i < 6; i++)
        id[i] = (unsigned char)(ms >> (40 - 8 * i));
    id[6] = (unsigned char)((id[6] & 0x0F) | 0x70);          /* version 7 */
    id[8] = (unsigned char)((id[8] & 0x3F) | 0x80);          /* variant */
    cl_ctr_cid_adopt(cl, id, "founded here");
}

/* Called on every ALIVE tick: a provisional id that has lasted the grace
 * period becomes permanent for this process. */
static void cl_ctr_cid_tick(cl_ctr_cluster_t *cl)
{
    char s1[37];

    if (cl->peers->cid_state != CL_CTR_CID_PROVISIONAL
            || cl_ctr_now() - cl->peers->cid_since < CL_CTR_CID_GRACE_SECS)
        return;
    cl->peers->cid_state = CL_CTR_CID_ESTABLISHED;
    cl_ctr_cid_str(cl->peers->cid, s1);
    LM_INFO("clusterer_controller: [cluster %d] cluster uuid %s established - "
            "traffic from any other cluster is refused from now on\n",
            cl->cluster_id, s1);
}

/**
 * cl_ctr_encrypt_pkt() - encrypt plaintext in-place and append the Poly1305 tag.
 *
 * On entry:  buf[0..CL_CTR_MAGIC_SZ-1]   = magic (set by caller)
 *            buf[plain_off..]        = plaintext to encrypt; its incarnation
 *                                      field is filled in here
 * On return: buf[CL_CTR_MAGIC_SZ..]      = cleartext cluster_id (BE)
 *            buf[CL_CTR_NONCE_OFF..]     = random nonce
 *            buf[plain_off..]        = ciphertext (same length)
 *            buf[plain_off+plain_len..+CL_CTR_TAG_SZ-1] = Poly1305 tag
 *
 * @return total packet length, or -1 on error
 */
static int cl_ctr_encrypt_pkt(char *buf, int plain_off, int plain_len,
                          const unsigned char *key, int cluster_id,
                          const unsigned char *cid)
{
    uint16_t      cid_be = htons((uint16_t)cluster_id);
    unsigned char *inc   = (unsigned char *)buf + plain_off + 1 + CL_CTR_SEQ_SZ;
    int           k;

    memcpy(buf + CL_CTR_MAGIC_SZ, &cid_be, CL_CTR_CLUSTER_ID_SZ);  /* cleartext selector */
    if (cid)
        memcpy(buf + CL_CTR_CID_OFF, cid, CL_CTR_CID_SZ);
    else
        memset(buf + CL_CTR_CID_OFF, 0, CL_CTR_CID_SZ);
    /* Every packet carries this process's incarnation, stamped here - the
     * single path all packets take - so no builder can forget it. */
    for (k = 0; k < CL_CTR_INC_SZ; k++)
        inc[k] = (unsigned char)(cl_ctr_incarnation >> (56 - 8 * k));

    /* AAD = cleartext header (magic + cluster_id + cluster uuid): binding it
     * to the tag stops
     * a captured packet being re-stamped with another cluster_id on a shared
     * multicast+password group (cross-cluster injection).  The nonce is the
     * AEAD IV, already bound.  XChaCha20's 192-bit nonce makes random nonces
     * collision-safe outright.                                                */
    {
        unsigned char      nonce[CL_CTR_NONCE_SZ];
        unsigned long long clen = 0;
        randombytes_buf(nonce, CL_CTR_NONCE_SZ);
        memcpy(buf + CL_CTR_NONCE_OFF, nonce, CL_CTR_NONCE_SZ);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                (unsigned char *)buf + plain_off, &clen,
                (const unsigned char *)buf + plain_off, (unsigned long long)plain_len,
                (const unsigned char *)buf, CL_CTR_AAD_SZ,
                NULL, nonce, key) != 0) {
            LM_ERR("clusterer_controller: XChaCha20-Poly1305 encrypt failed\n");
            return -1;
        }
        return plain_off + (int)clen;   /* clen = plain_len + CL_CTR_TAG_SZ */
    }
}

/**
 * cl_ctr_decrypt_pkt() - authenticate and decrypt a received packet in-place.
 *
 * On entry:  buf = [magic 2B][cluster_id 2B][nonce][ciphertext][tag 16B]
 * On return: buf[CL_CTR_WIRE_HDR_SZ..] = plaintext (type + seq + payload)
 *
 * AAD must match cl_ctr_encrypt_pkt(): the cleartext header (magic, cluster_id
 * and cluster uuid), so
 * a packet re-stamped with another cluster_id fails authentication.
 *
 * @return 0 on success, -1 to drop (wrong key, tampered, or too short)
 */
static int cl_ctr_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
                          const unsigned char *key, int is_bootstrap)
{
    ssize_t cipher_len = n - CL_CTR_WIRE_HDR_SZ - CL_CTR_TAG_SZ;   /* plaintext length */

    if (cipher_len <= 0) {
	LM_INFO("clusterer_controller: packet from %s too short to decrypt "
	        "(%zd bytes)\n", sender_ip, n);
	return -1;
    }

    {
        unsigned char     *nonce = (unsigned char *)buf + CL_CTR_NONCE_OFF;
        unsigned long long mlen  = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                (unsigned char *)buf + CL_CTR_WIRE_HDR_SZ, &mlen, NULL,
                (const unsigned char *)buf + CL_CTR_WIRE_HDR_SZ,
                (unsigned long long)(cipher_len + CL_CTR_TAG_SZ),
                (const unsigned char *)buf, CL_CTR_AAD_SZ,
                nonce, key) != 0) {
            if (is_bootstrap)
                LM_WARN("clusterer_controller: bootstrap decryption failed "
                        "from %s - wrong password, foreign cluster, or "
                        "tampered packet\n", sender_ip);
            else
                LM_DBG("clusterer_controller: session packet from %s did not "
                       "decrypt - transient key mismatch during (re)key or "
                       "split-brain heal\n", sender_ip);
            return -1;
        }
    }
    return 0;
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
static int cl_ctr_check_and_update_seq(const char *sender_ip, uint32_t pkt_seq,
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

static int cl_ctr_setup_socket(cl_ctr_cluster_t *cl)
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

/* =========================================================================
 * Reliable delivery: ACK + bounded retransmit for 1:1 handshake packets.
 * All of this runs only in the controller worker, so the queue needs no lock.
 * ========================================================================= */

/* Arm a timerfd with microsecond resolution (one-shot; 0/0 disarms). */
static void cl_ctr_arm_tfd_us(int tfd, uint64_t usec_value, uint64_t usec_interval)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec     = (time_t)(usec_value / 1000000);
    its.it_value.tv_nsec    = (long)((usec_value % 1000000) * 1000);
    its.it_interval.tv_sec  = (time_t)(usec_interval / 1000000);
    its.it_interval.tv_nsec = (long)((usec_interval % 1000000) * 1000);
    if (timerfd_settime(tfd, 0, &its, NULL) < 0)
        LM_WARN("clusterer_controller: timerfd_settime(us): %s\n", strerror(errno));
}

/*
 * Release an entry and give its packet buffer back.  Every path that clears
 * `used` goes through here - an entry cleared without freeing would leak the
 * buffer, and the next enqueue into that slot memsets the pointer away.
 */
static void cl_ctr_retx_release(cl_ctr_cluster_t *cl, cl_ctr_retx_entry_t *e)
{
    if (e->pkt) {
        pkg_free(e->pkt);
        e->pkt = NULL;
    }
    if (e->used) {
        e->used = 0;
        if (cl->retx_count > 0)
            cl->retx_count--;
    }
}

/*
 * A reliable send too large to cache goes out once and is never repaired.
 * That is a downgrade of the guarantee the caller asked for, so it is a
 * warning rather than the debug line it used to be - rate limited per process,
 * because whatever is oversized will be oversized every time.
 */
static void cl_ctr_retx_too_big(cl_ctr_cluster_t *cl, int pkt_len)
{
    static unsigned int last_warn;
    unsigned int now = get_ticks();

    if (last_warn == 0 || now - last_warn >= CL_CTR_RELIABLE_WARN_IVL) {
        last_warn = now;
        LM_WARN("clusterer_controller: [cluster %d] a %d-byte packet asked for "
                "reliable delivery but the retransmit cache holds %d - it was "
                "sent once, best-effort, and will not be repaired. The bound "
                "follows this interface's MTU, so a payload within "
                "cc_max_payload (%d) always fits.\n",
                cl->cluster_id, pkt_len, cl_ctr_retx_pkt_max, cc_max_payload);
    }
}

/*
 * Arm the shared retransmit timer for the EARLIEST deadline in the queue, or
 * disarm it when the queue is empty.
 *
 * Every arm has to go through here.  Arming it directly to "now + one
 * interval" on each enqueue - which is what the broadcast path used to do -
 * makes a steady stream of reliable sends push the deadline forward faster
 * than it can arrive: at fifty messages a second and a 40 ms retry gap, the
 * timer was re-armed every 20 ms to fire 40 ms later and therefore never fired
 * at all while traffic continued.  Measured on the two-node rig: 45 lost
 * messages produced 2 retransmits.  A reliable send is at its least reliable
 * exactly when the channel is busy, which is the opposite of what it promises.
 *
 * Deadline-driven rather than fixed-interval for the second reason too: with a
 * flat 250 ms sweep an entry due in 40 ms waited 250, so a consumer budget of
 * 2 x 40 ms was spent as 2 x 250 ms and every repair landed long after the
 * consumer had given up on it.
 */
static void cl_ctr_retx_rearm(cl_ctr_cluster_t *cl)
{
    utime_t now, first = 0;
    int i;

    if (cl->retx_count == 0) {
        cl_ctr_arm_tfd_us(cl->retx_tfd, 0, 0);      /* nothing pending */
        return;
    }

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (cl->retx_q[i].used &&
            (first == 0 || cl->retx_q[i].next_due_us < first))
            first = cl->retx_q[i].next_due_us;

    if (first == 0) {                                /* count/queue disagree */
        cl_ctr_arm_tfd_us(cl->retx_tfd, 0, 0);
        return;
    }

    now = get_uticks();
    /* Never 0 microseconds: that is timerfd's disarm, not "fire immediately",
     * and an already-due entry would then wait for the next enqueue to be
     * noticed at all. */
    cl_ctr_arm_tfd_us(cl->retx_tfd, first > now ? (uint64_t)(first - now) : 1, 0);
}

/*
 * Drop every outstanding retransmit.  Called on loss of mastership and on
 * session-key rotation, so a demoted or re-keyed node never keeps delivering a
 * stale master-keyed KEY_GRANT/NODE_ASSIGN that would push a joiner onto a dead
 * key - the split-brain guard for the ARQ layer.  ACKs never influence election
 * or membership, so dropping these entries can only stop redundant sends.
 */
static void cl_ctr_retx_flush(cl_ctr_cluster_t *cl)
{
    if (cl->retx_count == 0)
        return;
    LM_DBG("clusterer_controller: [cluster %d] flushing %d pending retransmit(s)\n",
           cl->cluster_id, cl->retx_count);
    {   /* release each, then clear: a bare memset over the array would drop
         * every entry's packet pointer on the floor. */
        int _i;
        for (_i = 0; _i < CL_CTR_RETX_QUEUE_SZ; _i++)
            cl_ctr_retx_release(cl, &cl->retx_q[_i]);
    }
    memset(cl->retx_q, 0, sizeof(cl->retx_q));
    cl->retx_count = 0;
    cl_ctr_arm_tfd_us(cl->retx_tfd, 0, 0);   /* disarm */
}

/*
 * Queue a just-sent 1:1 packet (already sealed in @pkt, @pkt_len bytes) for
 * retransmit until ACKed.  Best-effort: if the queue is full the packet still
 * went out once and the joiner's JOIN_REQ retry remains the backstop.
 */
/* Track a reliable broadcast: one entry, the members we expect to hear from,
 * and the sealed bytes to repair with.  The expected count is a snapshot - a
 * node that joins a moment later never saw the message and is not owed one. */
void cl_ctr_retx_enqueue_bcast(cl_ctr_cluster_t *cl, uint32_t seq,
                            const unsigned char *pkt, int pkt_len)
{
    cl_ctr_retx_entry_t *e = NULL;
    int i, n = 0;

    if (pkt_len <= 0 || pkt_len > cl_ctr_retx_pkt_max) {
        cl_ctr_retx_too_big(cl, pkt_len);
        return;
    }

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++)
        if (cl->peers->entries[i].node_id > 0 &&
            cl->peers->entries[i].node_id <= CL_CTR_MAX_PEERS)
            n++;
    lock_stop_read(cl->peers->lock);

    if (n == 0) {
        LM_DBG("clusterer_controller: [cluster %d] reliable broadcast with no "
               "peers to acknowledge it - nothing to wait for\n",
               cl->cluster_id);
        return;
    }

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (!cl->retx_q[i].used) { e = &cl->retx_q[i]; break; }
    if (!e) {
        LM_DBG("clusterer_controller: [cluster %d] retransmit queue full - the "
               "broadcast went out once, unacknowledged\n", cl->cluster_id);
        return;
    }

    memset(e, 0, sizeof(*e));   /* pkt was NULLed by the release that freed it */
    e->pkt = pkg_malloc(pkt_len);
    if (!e->pkt) {
        LM_ERR("clusterer_controller: [cluster %d] no pkg for a %d-byte "
               "retransmit cache entry - broadcast sent once, best-effort\n",
               cl->cluster_id, pkt_len);
        return;
    }
    e->used         = 1;
    e->seq          = seq;
    e->type         = CL_CTR_PKT_CONSUMER_REL;
    e->is_bcast     = 1;
    e->expect_n     = (uint16_t)n;
    e->retries_left = cl->consumer_retries;
    e->retries_cfg  = (uint8_t)cl->consumer_retries;
    e->retry_ivl_us = (utime_t)cl->consumer_retry_ms * 1000;
    e->next_due_us  = get_uticks() + e->retry_ivl_us;
    e->pkt_len      = pkt_len;
    memcpy(e->pkt, pkt, pkt_len);
    cl->retx_count++;
    /* Through the helper, never straight at the timer: this used to arm it
     * unconditionally to now + one interval, which under continuous broadcasts
     * pushed the sweep past every deadline it was meant to serve. */
    cl_ctr_retx_rearm(cl);
}

/* The consumer plane retransmits on its own schedule: the join handshake's
 * budget is pinned to the JOIN_REQ retry interval, which has nothing to say
 * about how long a consumer should wait.  Both are per-cluster, because one
 * cluster may cross a link where another does not. */
void cl_ctr_retx_enqueue_consumer(cl_ctr_cluster_t *cl, uint32_t seq,
                            unsigned char type, const unsigned char *pkt,
                            int pkt_len, const struct sockaddr *dest,
                            socklen_t destlen)
{
    int i;

    cl_ctr_retx_enqueue(cl, seq, type, pkt, pkt_len, dest, destlen);
    /* Re-arm the entry we just made with this cluster's consumer budget.
     * Enqueue does not take them as arguments because every other caller
     * wants the handshake numbers. */
    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (cl->retx_q[i].used && cl->retx_q[i].seq == seq &&
            cl->retx_q[i].type == type) {
            cl->retx_q[i].retries_left = cl->consumer_retries;
            cl->retx_q[i].retries_cfg  = (uint8_t)cl->consumer_retries;
            cl->retx_q[i].retry_ivl_us = (utime_t)cl->consumer_retry_ms * 1000;
            cl->retx_q[i].next_due_us  = get_uticks()
                                       + cl->retx_q[i].retry_ivl_us;
            break;
        }
    /* The deadline just moved in (consumer gaps are shorter than the
     * handshake's), so the timer enqueue armed has to be pulled forward. */
    cl_ctr_retx_rearm(cl);
}

static void cl_ctr_retx_enqueue(cl_ctr_cluster_t *cl, uint32_t seq, unsigned char type,
                            const unsigned char *pkt, int pkt_len,
                            const struct sockaddr *dest, socklen_t destlen)
{
    cl_ctr_retx_entry_t *e;
    int i, slot = -1;

    if (pkt_len <= 0 || pkt_len > cl_ctr_retx_pkt_max ||
        destlen == 0 || destlen > (socklen_t)sizeof(cl->retx_q[0].dest)) {
        if (pkt_len > cl_ctr_retx_pkt_max)
            cl_ctr_retx_too_big(cl, pkt_len);
        return;
    }

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++)
        if (!cl->retx_q[i].used) { slot = i; break; }
    if (slot < 0) {
        LM_DBG("clusterer_controller: [cluster %d] retransmit queue full, "
               "0x%02x sent best-effort\n", cl->cluster_id, type);
        return;
    }

    e = &cl->retx_q[slot];
    memset(e, 0, sizeof(*e));   /* pkt was NULLed by the release that freed it */
    e->pkt = pkg_malloc(pkt_len);
    if (!e->pkt) {
        LM_ERR("clusterer_controller: [cluster %d] no pkg for a %d-byte "
               "retransmit cache entry - 0x%02x sent once, best-effort\n",
               cl->cluster_id, pkt_len, type);
        return;
    }
    e->used         = 1;
    e->seq          = seq;
    e->type         = type;
    e->retries_left = CL_CTR_RETX_MAX_RETRIES;
    e->retry_ivl_us = CL_CTR_RETX_INTERVAL_US;
    e->next_due_us  = get_uticks() + e->retry_ivl_us;
    memcpy(&e->dest, dest, destlen);
    e->destlen      = destlen;
    memcpy(e->pkt, pkt, pkt_len);
    e->pkt_len      = pkt_len;
    cl->retx_count++;
    cl_ctr_retx_rearm(cl);
}

/* An ACK arrived: drop the queued packet whose seq it echoes. */
static void cl_ctr_handle_ack(const char *payload, int payload_len,
                              cl_ctr_cluster_t *cl, const char *sender_ip)
{
    uint32_t acked_be, acked;
    int      acked_type = -1;          /* -1: an older peer that sent no type */
    in_addr_t sender = inet_addr(sender_ip);
    int i;

    if (payload_len < (int)sizeof(uint32_t))
        return;
    memcpy(&acked_be, payload, sizeof(acked_be));
    acked = ntohl(acked_be);
    if (payload_len >= CL_CTR_ACK_SZ)
        acked_type = (unsigned char)payload[sizeof(acked_be)];

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++) {
        cl_ctr_retx_entry_t *e = &cl->retx_q[i];
        if (!e->used || e->seq != acked)
            continue;
        /* The number alone does not identify the packet.  Handshake packets
         * and consumer messages are counted by two independent sequences, so
         * the same number can be outstanding on both planes at once, and a
         * unicast entry is owed its ACK by ONE address - any other member
         * acknowledging the same number is acknowledging something else.
         * Matching on the number only let one peer's ACK release another
         * peer's pending entry, which then was never repaired. */
        if (acked_type >= 0 && e->type != (unsigned char)acked_type)
            continue;
        if (!e->is_bcast && e->dest.ss_family == AF_INET &&
            ((const struct sockaddr_in *)&e->dest)->sin_addr.s_addr != sender)
            continue;

        if (e->is_bcast) {
            /* Every member acknowledges the same sequence number, so this
             * entry lives until they all have (or the budget runs out). */
            uint16_t nid = 0;

            lock_start_read(cl->peers->lock);
            {
                cl_ctr_peer_t *p = cl_ctr_peer_by_ip_locked(cl, sender_ip);
                if (p)
                    nid = p->node_id;
            }
            lock_stop_read(cl->peers->lock);

            if (nid > 0 && nid <= CL_CTR_MAX_PEERS) {
                int byte = (nid - 1) / 8, bit = 1 << ((nid - 1) % 8);

                if (!(e->acked_map[byte] & bit)) {
                    e->acked_map[byte] |= bit;
                    e->acked_n++;
                }
            }
            if (e->acked_n < e->expect_n) {
                LM_DBG("clusterer_controller: [cluster %d] broadcast seq %u "
                       "acknowledged by %u of %u\n", cl->cluster_id, acked,
                       e->acked_n, e->expect_n);
                break;                       /* still waiting on others */
            }
            LM_DBG("clusterer_controller: [cluster %d] broadcast seq %u "
                   "acknowledged by all %u member(s) after %u of the %u "
                   "retries configured for this cluster\n", cl->cluster_id,
                   acked, e->expect_n,
                   (unsigned)(e->retries_cfg - e->retries_left),
                   (unsigned)e->retries_cfg);
        } else {
            /* Same number, same plane, from the address it was sent to:
             * this is the acknowledged packet; drop it. */
            LM_DBG("clusterer_controller: [cluster %d] ACK for 0x%02x seq %u\n",
                   cl->cluster_id, e->type, acked);
        }
        cl_ctr_retx_release(cl, e);
        break;
    }
    /* Dropping an entry can make a LATER one the earliest, so re-arm rather
     * than only disarming on empty. */
    cl_ctr_retx_rearm(cl);
}

/*
 * Retransmit sweep: resend every entry whose deadline has passed, one step of
 * its budget at a time; drop an entry once the budget is spent (the joiner's
 * JOIN_REQ retry is the outer backstop).  Re-arms only while work remains.
 */
static int cl_ctr_on_retx_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl  = (cl_ctr_cluster_t *)param;
    utime_t          now = get_uticks();
    int              i;
    (void)was_timeout;

    cl_ctr_drain_tfd(fd);

    for (i = 0; i < CL_CTR_RETX_QUEUE_SZ; i++) {
        cl_ctr_retx_entry_t *e = &cl->retx_q[i];
        if (!e->used || now < e->next_due_us)
            continue;

        if (e->is_bcast) {
            /* Repair, not rebroadcast.  Sending the multicast again would
             * reach the members that already have it, and - because a
             * duplicate that asked to be acknowledged is acknowledged again -
             * every one of them would answer a second time.  On a large
             * cluster the repair for two missing nodes would cost a packet to
             * everyone and an ACK back from everyone.  So the repair is
             * unicast, to exactly the nodes that still owe an answer. */
            int j, repaired = 0;

            lock_start_read(cl->peers->lock);
            for (j = 0; j < cl->peers->count; j++) {
                cl_ctr_peer_t     *p = &cl->peers->entries[j];
                struct sockaddr_in d;
                int byte, bit;

                if (p->node_id == 0 || p->node_id > CL_CTR_MAX_PEERS)
                    continue;
                byte = (p->node_id - 1) / 8;
                bit  = 1 << ((p->node_id - 1) % 8);
                if (e->acked_map[byte] & bit)
                    continue;                    /* this one answered */

                memset(&d, 0, sizeof d);
                d.sin_family = AF_INET;
                d.sin_port   = cl->mcast_dest.sin_port;
                if (inet_pton(AF_INET, p->ip, &d.sin_addr) != 1)
                    continue;
                if (sendto(cl->sock, e->pkt, e->pkt_len, 0,
                           (struct sockaddr *)&d, sizeof d) >= 0)
                    repaired++;
            }
            lock_stop_read(cl->peers->lock);
            LM_DBG("clusterer_controller: [cluster %d] broadcast seq %u: "
                   "repairing %d node(s) that have not acknowledged\n",
                   cl->cluster_id, e->seq, repaired);

        } else if (sendto(cl->sock, e->pkt, e->pkt_len, 0,
                   (struct sockaddr *)&e->dest, e->destlen) < 0 &&
            errno != EAGAIN && errno != EWOULDBLOCK) {
            LM_DBG("clusterer_controller: [cluster %d] retransmit 0x%02x: %s\n",
                   cl->cluster_id, e->type, strerror(errno));
        }

        if (--e->retries_left <= 0) {
            if (e->is_bcast)
                LM_INFO("clusterer_controller: [cluster %d] broadcast seq %u "
                        "reached %u of %u member(s), giving up after %u of the "
                        "%u retries configured for this cluster\n",
                        cl->cluster_id, e->seq, e->acked_n, e->expect_n,
                        (unsigned)e->retries_cfg, (unsigned)e->retries_cfg);
            else
                LM_DBG("clusterer_controller: [cluster %d] 0x%02x (seq %u) unacked "
                   "after %u retransmits, giving up - joiner will re-JOIN_REQ\n",
                   cl->cluster_id, e->type, e->seq,
                   (unsigned)(e->retries_cfg ? e->retries_cfg
                                             : CL_CTR_RETX_MAX_RETRIES));
            cl_ctr_retx_release(cl, e);
        } else {
            e->next_due_us = now + (e->retry_ivl_us ? e->retry_ivl_us
                                                    : CL_CTR_RETX_INTERVAL_US);
        }
    }

    cl_ctr_retx_rearm(cl);
    return 0;
}

/*
 * Send an ACK for @acked_seq back to @dest.  Sealed in the same key class as the
 * packet being acknowledged (@use_bootstrap: KEY_GRANT is bootstrap-keyed), so
 * the sender can read it without assuming the receiver already holds a key.
 */
static void cl_ctr_send_ack(int sock, cl_ctr_cluster_t *cl, uint32_t acked_seq,
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
static void cl_ctr_send_pkt_with_ip(int sock, unsigned char type, cl_ctr_cluster_t *cl,
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

#define cl_ctr_send_alive(sock, cl)    cl_ctr_send_pkt_with_ip((sock), CL_CTR_PKT_ALIVE, (cl), NULL, 0)
#define cl_ctr_send_alive_to(sock, cl, dest, dlen) \
        cl_ctr_send_pkt_with_ip((sock), CL_CTR_PKT_ALIVE, (cl), (dest), (dlen))
#define cl_ctr_send_join_req(sock, cl) cl_ctr_send_join_req_pkt((sock), (cl))

/**
 * cl_ctr_send_list_pkt() - encrypt and multicast the active peer table.
 *
 * Wire: [magic 2B][cluster_id 2B][nonce 24B][XChaCha20-Poly1305([type 1B][seq 4B][count 2B][entries...])][tag 16B]
 */
static void cl_ctr_send_list_pkt(int sock, unsigned char type, cl_ctr_cluster_t *cl,
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

#define cl_ctr_send_member_list(sock, cl) cl_ctr_send_list_pkt((sock), CL_CTR_PKT_MEMBER_LIST, (cl), NULL, 0)

/**
 * cl_ctr_send_join_req_pkt() - send CL_CTR_PKT_JOIN_REQ with BIN socket info.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 */
static void cl_ctr_send_join_req_pkt(int sock, cl_ctr_cluster_t *cl)
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
static void cl_ctr_send_node_assign(int sock, const char *ip, uint16_t node_id,
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


/*
 * Order-independent digest of the active peer set: the XOR of a per-peer FNV-1a
 * over (node_id, ip_num).  A member that missed a peer's NODE_ASSIGN carries
 * node_id 0 for it and so computes a different hash from the master's - which is
 * how the gap is detected.  Roles are deliberately excluded (they reconcile via
 * MASTER_ALIVE itself) to avoid spurious resyncs on transient role churn.
 * Takes the read lock itself - the caller must NOT hold cl->peers->lock.
 */
static void cl_ctr_membership_digest(cl_ctr_cluster_t *cl, uint16_t *count, uint64_t *hash)
{
    uint64_t h = 0;
    uint16_t c = 0;
    time_t   cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
    int      i, k;

    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e = &cl->peers->entries[i];
        uint64_t      ph = 1469598103934665603ULL;   /* FNV-1a offset basis */
        unsigned char b[6];
        if (e->last_seen < cutoff)
            continue;
        b[0] = (unsigned char)(e->node_id >> 8);  b[1] = (unsigned char)e->node_id;
        b[2] = (unsigned char)(e->ip_num >> 24);  b[3] = (unsigned char)(e->ip_num >> 16);
        b[4] = (unsigned char)(e->ip_num >> 8);   b[5] = (unsigned char)e->ip_num;
        for (k = 0; k < 6; k++) { ph ^= b[k]; ph *= 1099511628211ULL; }
        h ^= ph;
        c++;
    }
    lock_stop_read(cl->peers->lock);
    *count = c;
    *hash  = h;
}

/* Build a sockaddr_in for an IPv4 dotted string + port (for unicast sends). */
static void cl_ctr_sockaddr_in(const char *ip, int port, struct sockaddr_in *out)
{
    memset(out, 0, sizeof(*out));
    out->sin_family      = AF_INET;
    out->sin_port        = htons((uint16_t)port);
    out->sin_addr.s_addr = inet_addr(ip);
}

/* Fill @bm (CL_CTR_ALIVE_BITMAP_SZ bytes) with a bit set for every peer the
 * master has seen inside the election window - the liveness it relays. */
static void cl_ctr_build_alive_bitmap(cl_ctr_cluster_t *cl, unsigned char *bm)
{
    time_t cutoff = cl_ctr_now() - (time_t)(query_time * CL_CTR_ELECT_FACTOR);
    int    i;

    memset(bm, 0, CL_CTR_ALIVE_BITMAP_SZ);
    lock_start_read(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        if (e->last_seen < cutoff || nid == 0 || nid > CL_CTR_MAX_PEERS)
            continue;
        bm[nid >> 3] |= (unsigned char)(1u << (nid & 7));
    }
    lock_stop_read(cl->peers->lock);
}

/* Refresh last_seen for every peer whose node_id the master reports alive in @bm,
 * so a settled non-master keeps its election window populated without hearing the
 * peers' ALIVEs directly.  Only a non-master applies this. */
static void cl_ctr_apply_alive_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm)
{
    time_t now = cl_ctr_now();
    int    i;

    lock_start_write(cl->peers->lock);
    for (i = 0; i < cl->peers->count; i++) {
        cl_ctr_peer_t *e   = &cl->peers->entries[i];
        uint16_t       nid = e->node_id;
        if (nid == 0 || nid > CL_CTR_MAX_PEERS)
            continue;
        if (bm[nid >> 3] & (unsigned char)(1u << (nid & 7)))
            e->last_seen = now;
    }
    lock_stop_write(cl->peers->lock);
}

/**
 * cl_ctr_send_master_alive() - master-only keepalive.  Encrypted with session_key
 * (CL_CTR_PACKET_MAGIC).  Carries the membership digest ([count 2B][hash 8B]) so
 * members can detect a missed NODE_ASSIGN and pull a RESYNC.
 */
static void cl_ctr_send_master_alive(int sock, cl_ctr_cluster_t *cl)
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
static void cl_ctr_send_resync(int sock, cl_ctr_cluster_t *cl,
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
static void cl_ctr_announce_full_state(cl_ctr_cluster_t *cl, const char *why)
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

static void cl_ctr_handle_resync(const char *sender_ip, cl_ctr_cluster_t *cl)
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
 * cl_ctr_send_master_beacon() - master-only split-brain merge announcement.
 *
 * Encrypted with the BOOTSTRAP key (CL_CTR_BOOTSTRAP_MAGIC) - unlike MASTER_ALIVE,
 * which uses the per-cluster session key.  Every correctly-configured node
 * shares the bootstrap key, so two masters that hold *different* session keys
 * (e.g. after an all-node simultaneous cold start) can still read each other's
 * beacon and reconcile.  Payload is this partition's member count (2B BE); the
 * sender IP comes from the datagram source.  See cl_ctr_handle_master_beacon().
 */
static void cl_ctr_send_master_beacon(int sock, cl_ctr_cluster_t *cl)
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
static void cl_ctr_send_key_grant(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
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
static void cl_ctr_send_key_handoff(int sock, const char *next_master_ip,
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

/* =========================================================================
 * State transition helper
 * ========================================================================= */

/**
 * cl_ctr_on_became_master() - side effects when this node wins an election.
 * Generates fresh master_salt, derives session_key, arms MASTER_ALIVE timer,
 * disarms master_dead watchdog.  Must be called with cl->peers->lock held WRITE.
 */
static void cl_ctr_on_became_master(cl_ctr_cluster_t *cl)
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
static void cl_ctr_arm_master_timers(cl_ctr_cluster_t *cl, int i_am_master)
{
    /* A new mastership asserts a term above every one this node has heard
     * of - that is what lets it win cl_ctr_master_outranks() against the
     * master it replaces.  Re-arming an existing mastership keeps its term. */
    if (i_am_master && !cl->master_ka_armed) {
        cl->peers->my_term     = cl->peers->term_seen + 1;
        cl->peers->term_seen   = cl->peers->my_term;
        cl->peers->master_term = cl->peers->my_term;
        LM_INFO("clusterer_controller: [cluster %d] asserting mastership at "
                "term %u\n", cl->cluster_id, cl->peers->my_term);
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
        cl_ctr_arm_tfd(cl->master_dead_tfd,  CL_CTR_MASTER_KA_TIMEOUT, 0);
    }
}

/**
 * cl_ctr_request_rekey() - ask the current key-holder for the session key.
 * Sends a single JOIN_REQ (bootstrap key), guarded by join_pending so a fresh
 * nonce is not stomped while one exchange is in flight.  Used when a node is
 * elected master but has not yet adopted the cluster key (KEY_GRANT lost).
 * Call WITHOUT cl->peers->lock held.
 */
static void cl_ctr_request_rekey(cl_ctr_cluster_t *cl)
{
    if (cl->join_pending)
        return;
    cl->join_pending = 1;
    cl_ctr_send_join_req(cl->sock, cl);
}

/**
 * cl_ctr_transition_to_active() - switch from CL_CTR_NODE_NEW to CL_CTR_NODE_ACTIVE.
 *
 * Disarms the join-phase timers, sends the first ALIVE immediately, then
 * arms the periodic ALIVE timer.  Called from both:
 *   - the join_tfd handler (deadline expired, fresh cluster), and
 *   - cl_ctr_handle_member_list (master responded before deadline).
 * Must be called with cl->peers->lock NOT held.
 */
static void cl_ctr_transition_to_active(cl_ctr_cluster_t *cl)
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
static void cl_ctr_fmt_cfg_diff(char *out, int outsz, const char *la, const char *lb,
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
static void cl_ctr_adopt_config(cl_ctr_cluster_t *cl, int new_manage, int new_stick,
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

    /* Mirror the effective values into shm so cl_ctr_list_config (MI process)
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
 * cl_ctr_drop_peer_locked() - remove a peer from the table by IP.
 *
 * Needed because refusing a JOIN_REQ is not by itself enough to keep a node
 * out: while this node was still NEW it upserts every joiner it hears (the
 * split-brain defer path), so a peer can already be in the table by the time
 * we become master and refuse it.  Without this the master goes on counting a
 * node it just told to go away - and, worse, cl_ctr_mtu_note_reject() would
 * never see the "holding no members" condition that makes it speak up.
 *
 * Same swap-with-last removal cl_ctr_prune_stale uses.  Call WITH the write
 * lock held.
 */
static void cl_ctr_drop_peer_locked(const char *ip, cl_ctr_cluster_t *cl)
{
    int i;

    for (i = 0; i < cl->peers->count; i++) {
        uint16_t dropped_id;
        if (strcmp(cl->peers->entries[i].ip, ip) != 0)
            continue;
        dropped_id = cl->peers->entries[i].node_id;
        cl->peers->count--;
        if (i < cl->peers->count)
            cl->peers->entries[i] = cl->peers->entries[cl->peers->count];
        memset(&cl->peers->entries[cl->peers->count], 0, sizeof(cl_ctr_peer_t));
        if (clctl_loaded && dropped_id > 0)
            clctl.remove_node(cl->cluster_id, dropped_id);
        return;
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
 * cl_ctr_handle_alive() - process a CL_CTR_PKT_ALIVE packet.
 *
 * Regular heartbeat path: upsert the sender, re-elect.
 * Only called in CL_CTR_NODE_ACTIVE state; ignored while joining (cl_ctr_recv_one
 * still dispatches them so the peer table builds up before the timeout).
 */
static void cl_ctr_handle_alive(const char *src_ip,
                            const unsigned char *pubkey, /* may be NULL */
                            int cfg_present, int peer_manage,
                            int peer_stick, int peer_qt,
                            int peer_mtu,
                            cl_ctr_cluster_t *cl)
{
    int  prev_master, now_master;
    int  warn = 0, adopt = 0, is_active = 0, ent = -1;
    int  mtu_warn = 0, mtu_seen = 0;
    char warn_ip[CL_CTR_MAX_IP_LEN + 1] = "";
    int  loc_manage = cl->manage_shtags ? 1 : 0;
    int  loc_stick  = cl->master_stickiness ? 1 : 0;
    int  loc_qt     = query_time;
    int  mism = 0, changed = 0;

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
    /* Defer acting as master until we hold the cluster key.  In normal
     * operation a higher-IP joiner has already adopted the key via KEY_GRANT
     * before winning here, so this only guards the pathological case where the
     * KEY_GRANT was lost during the join.  Request a re-key instead of
     * broadcasting an undecryptable MASTER_ALIVE. */
    if (now_master && !cl->have_session_key) {
        cl_ctr_request_rekey(cl);
        return;
    }
    if (prev_master != now_master)
        cl_ctr_arm_master_timers(cl, now_master);
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
static void cl_ctr_handle_join_req(int sock, const char *payload, int payload_len,
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
static void cl_ctr_handle_member_list(const char *payload, int payload_len,
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
     * cl_ctr_shtag_force undone by the list that preceded it, for one).
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
static void cl_ctr_handle_goodbye(int sock, const char *src_ip, cl_ctr_cluster_t *cl)
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
static void cl_ctr_handle_node_assign(const char *payload, int payload_len,
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
static void cl_ctr_handle_master_alive(const char *sender_ip, cl_ctr_cluster_t *cl,
                                   const char *payload, int payload_len,
                                   const struct sockaddr *src, socklen_t src_len)
{
    int      i_am_master, yielded = 0, ignored = 0;
    int      from_self = (strcmp(sender_ip, my_ip) == 0);
    uint16_t adv_cnt = 0, my_cnt;
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
    /* our own count, for the same comparison - taken before the write lock,
     * since the digest takes the read lock itself */
    cl_ctr_membership_digest(cl, &my_cnt, &my_hash);

    lock_start_write(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    if (!from_self)
        cl_ctr_note_term(cl, adv_term);

    if (i_am_master) {
        if (!from_self &&
            cl_ctr_master_outranks(adv_cnt, adv_term, sender_ip,
                                   my_cnt, cl->peers->my_term, my_ip)) {
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
            !cl_ctr_master_outranks(adv_cnt, adv_term, sender_ip,
                                    cl->peers->master_count,
                                    cl->peers->master_term,
                                    cl->peers->last_master)) {
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
                adv_cnt, adv_term, my_cnt, cl->peers->my_term);
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

    /* Non-masters (including a node that just yielded) watch the keepalive. */
    if (!i_am_master || yielded)
        cl_ctr_arm_tfd(cl->master_dead_tfd, CL_CTR_MASTER_KA_TIMEOUT, 0);

    /* Liveness relay: the master reports which node_ids it has seen in-window;
     * refresh those peers' last_seen so our election window stays populated even
     * though a settled non-master no longer hears the peers' ALIVEs directly. */
    if (!i_am_master && !from_self &&
        payload_len >= CL_CTR_DIGEST_SZ + CL_CTR_ALIVE_BITMAP_SZ)
        cl_ctr_apply_alive_bitmap(cl,
            (const unsigned char *)payload + CL_CTR_DIGEST_SZ);

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
    cl_ctr_arm_tfd(cl->master_dead_tfd, CL_CTR_MASTER_KA_TIMEOUT, 0);
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
static void cl_ctr_handle_master_beacon(const char *sender_ip, const char *payload,
                                    int payload_len, cl_ctr_cluster_t *cl)
{
    int      i_am_master, is_new, superior;
    uint16_t our_count, sender_count = 0;
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

    /* Would a merge with this master be refused?  The same tests its
     * cl_ctr_handle_join_req() would apply to our JOIN_REQ: the settings
     * only when the policy is 'reject' (warn/adopt admit a mismatch), the
     * MTU always.  Checked BEFORE ranking, and on both masters, so neither
     * side demotes itself into a merge the other side refuses - which used
     * to end with the merging node's exit(-1), and if the misconfigured side
     * was the larger partition, that took down the correctly configured
     * nodes.  Two masters with different settings now stay two partitions,
     * and both say why, until an operator fixes one of them. */
    cfg_differs = cfg_present && on_config_mismatch == CL_CTR_CFGMISMATCH_REJECT
                  && (b_manage != (cl->manage_shtags ? 1 : 0)
                      || b_stick != (cl->master_stickiness ? 1 : 0)
                      || b_qt    != (query_time & 0xFFFF));
    mtu_differs = cfg_present && b_mtu > 0 && cc_mtu > 0
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

    lock_start_write(cl->peers->lock);
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
        superior = cl_ctr_master_outranks(sender_count, sender_term, sender_ip,
                                          our_count, our_term, our_master);

    if (!superior)
        return;   /* we outrank the sender; it will yield to us on our beacon */

    cl_ctr_rejoin_superior_master(cl, sender_ip, "beacon");
}

/**
 * cl_ctr_handle_key_grant() - process CL_CTR_PKT_KEY_GRANT from master.
 * Payload: [target_ip NUL][master_pubkey 32B][join_nonce 16B][wrapped_salt 32B]
 *
 * Recover master_salt via ECDH unwrap, derive session_key, update shm.
 * Only processed if target_ip == my_ip (multicast - all nodes receive it).
 */
static void cl_ctr_handle_key_grant(const char *payload, int payload_len,
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
static void cl_ctr_handle_key_handoff(const char *payload, int payload_len,
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

static int cl_ctr_join_fail_check(const char *src_ip, cl_ctr_cluster_t *cl)
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

static void cl_ctr_send_join_reject(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
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

static void cl_ctr_handle_join_reject(const char *payload, int payload_len,
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

static void cl_ctr_recv_one(int sock, cl_ctr_cluster_t *cl,
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
	n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
	             (struct sockaddr *)&src_addr, &src_len);
	if (n < 0) {
	    if (errno != EAGAIN && errno != EWOULDBLOCK)
		LM_ERR("clusterer_controller: recvfrom(): %s\n", strerror(errno));
	    return;
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
	    int            p_mtu = 0;
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
	    cl_ctr_handle_alive(ip_buf, pubkey, cfg_present, p_manage, p_stick, p_qt,
	                        p_mtu, cl);
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

	default:
	    LM_WARN("clusterer_controller: unknown packet type 0x%02x "
	            "from %s, dropping\n", pkt_type, sender_ip_buf);
	    break;
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

/* =========================================================================
 * Background worker process
 * ========================================================================= */

/* =========================================================================
 * Reactor callbacks - one per event source
 * ========================================================================= */

static int cl_ctr_on_sock(int fd, void *param, int was_timeout)
{
    cl_ctr_recv_one(fd, (cl_ctr_cluster_t *)param, NULL, 0, NULL);
    return 0;
}

static int cl_ctr_on_alive_tfd(int fd, void *param, int was_timeout)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    int prev_master, now_master;
    cl_ctr_drain_tfd(fd);
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
    if (prev_master != now_master)
        cl_ctr_arm_master_timers(cl, now_master);

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
    cl_ctr_drain_tfd(fd);

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

    cl_ctr_drain_tfd(fd);

    dead_master[0] = '\0';

    lock_start_write(cl->peers->lock);
    /* The master has been silent for CL_CTR_MASTER_KA_TIMEOUT (3s).  Age the silent
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
            "(no keepalive for %ds) - re-electing\n",
            cl->cluster_id,
            dead_master[0] ? dead_master : "(unknown)",
            CL_CTR_MASTER_KA_TIMEOUT);

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
static void cl_ctr_worker(int rank)
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
    if (cl->alive_tfd < 0 || cl->join_tfd < 0 || cl->rejoin_tfd < 0 ||
        cl->master_alive_tfd < 0 || cl->master_dead_tfd < 0 || cl->retx_tfd < 0) {
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
        reactor_proc_add_fd(cl->retx_tfd,         cl_ctr_on_retx_tfd,         cl) < 0) {
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
}

/* =========================================================================
 * MI command handlers
 * ========================================================================= */

/**
 * mi_cl_ctr_members() - list active cluster members with their role.
 *
 *   opensips-cli -x mi cl_ctr_list_members
 *
 *   [
 *     {"ip": "10.0.0.3", "status": "master"},
 *     {"ip": "10.0.0.1", "status": "member"},
 *     {"ip": "10.0.0.2", "status": "member"}
 *   ]
 *
 * Only peers within the current quantized election window are shown,
 * consistent with what cl_ctr_elect_master(cl) considers.
 */
static mi_response_t *mi_cl_ctr_members(const mi_params_t *params,
                                     struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *arr, *cl_obj, *members_arr, *peer_obj, *bin_arr;
    int             i, j, ci;
    cl_ctr_cluster_t   *cl;

    resp = init_mi_result_array(&arr);
    if (!resp)
	return NULL;

    for (ci = 0; ci < cl_ctr_cluster_count; ci++) {
	cl = &cl_ctr_clusters[ci];
	if (!cl->peers)
	    continue;

	cl_obj = add_mi_object(arr, NULL, 0);
	if (!cl_obj) goto error;

	if (add_mi_number(cl_obj, MI_SSTR("cluster_id"), cl->cluster_id) < 0)
	    goto error;

	members_arr = add_mi_array(cl_obj, MI_SSTR("members"));
	if (!members_arr) goto error;

	lock_start_read(cl->peers->lock);

	for (i = 0; i < cl->peers->count; i++) {
	    cl_ctr_peer_t *e = &cl->peers->entries[i];

	    peer_obj = add_mi_object(members_arr, NULL, 0);
	    if (!peer_obj) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }
	    if (add_mi_number(peer_obj, MI_SSTR("mtu"), e->mtu) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("ip"),
	                      e->ip, strlen(e->ip)) < 0 ||
	        add_mi_number(peer_obj, MI_SSTR("node_id"), e->node_id) < 0 ||
	        add_mi_string(peer_obj, MI_SSTR("status"),
	                      e->is_master ? "master" : (e->is_backup ? "backup" : "member"),
	                      6) < 0) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }

	    bin_arr = add_mi_array(peer_obj, MI_SSTR("bin_sockets"));
	    if (!bin_arr) {
		lock_stop_read(cl->peers->lock);
		goto error;
	    }
	    for (j = 0; j < (int)e->bin_count; j++) {
		if (add_mi_string(bin_arr, NULL, 0,
		                  e->bin_sockets[j],
		                  strlen(e->bin_sockets[j])) < 0) {
		    lock_stop_read(cl->peers->lock);
		    goto error;
		}
	    }
	}

	lock_stop_read(cl->peers->lock);
    }

    return resp;

error:
    LM_ERR("clusterer_controller: mi_cl_ctr_members: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_cl_ctr_node_info() - return full info for a specific node_id.
 *
 *   opensips-cli -x mi cl_ctr_node_info node_id=2
 */
static mi_response_t *mi_cl_ctr_node_info(const mi_params_t *params,
                                      struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *root, *bin_arr;
    int             target_id;
    int             i, j, ci;
    cl_ctr_cluster_t   *cl;
    cl_ctr_peer_t      *e;

    if (get_mi_int_param(params, "node_id", &target_id) < 0)
	return init_mi_param_error();

    for (ci = 0; ci < cl_ctr_cluster_count; ci++) {
	cl = &cl_ctr_clusters[ci];
	if (!cl->peers)
	    continue;

	lock_start_read(cl->peers->lock);
	for (i = 0; i < cl->peers->count; i++) {
	    e = &cl->peers->entries[i];
	    if ((int)e->node_id != target_id)
		continue;

	    resp = init_mi_result_object(&root);
	    if (!resp) {
		lock_stop_read(cl->peers->lock);
		return NULL;
	    }
	    if (add_mi_number(root, MI_SSTR("mtu"),        e->mtu)                 < 0 ||
	        add_mi_number(root, MI_SSTR("node_id"),    e->node_id)             < 0 ||
	        add_mi_string(root, MI_SSTR("ip"),         e->ip, strlen(e->ip))   < 0 ||
	        add_mi_number(root, MI_SSTR("cluster_id"), cl->cluster_id)          < 0 ||
	        add_mi_string(root, MI_SSTR("status"),
	                      e->is_master ? "master" : (e->is_backup ? "backup" : "member"),
	                      6)                                                     < 0) {
		lock_stop_read(cl->peers->lock);
		goto error_node;
	    }
	    bin_arr = add_mi_array(root, MI_SSTR("bin_sockets"));
	    if (!bin_arr) {
		lock_stop_read(cl->peers->lock);
		goto error_node;
	    }
	    for (j = 0; j < (int)e->bin_count; j++) {
		if (add_mi_string(bin_arr, NULL, 0,
		                  e->bin_sockets[j],
		                  strlen(e->bin_sockets[j])) < 0) {
		    lock_stop_read(cl->peers->lock);
		    goto error_node;
		}
	    }
	    lock_stop_read(cl->peers->lock);
	    return resp;
	}
	lock_stop_read(cl->peers->lock);
    }

    return init_mi_error(404, MI_SSTR("node_id not found"));

error_node:
    LM_ERR("clusterer_controller: mi_cl_ctr_node_info: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_cl_ctr_config() - list all configured clusters and their resolved settings.
 *
 *   opensips-cli -x mi cl_ctr_list_config
 *
 * Reports per cluster: id, multicast endpoint, master_stickiness,
 * manage_shtags, query_time, this node's BIN socket and current member count.
 * The password is intentionally NOT exposed.
 */
static mi_response_t *mi_cl_ctr_config(const mi_params_t *params,
                                     struct mi_handler *hdl)
{
    mi_response_t  *resp;
    mi_item_t      *arr, *cl_obj;
    int             ci, members;
    char            mcast[INET_ADDRSTRLEN + 8];  /* "IP:PORT" */
    char            shtag_mode[24];              /* "auto" / "override:<id>" */
    cl_ctr_cluster_t   *cl;

    resp = init_mi_result_array(&arr);
    if (!resp)
	return NULL;

    for (ci = 0; ci < cl_ctr_cluster_count; ci++) {
	cl = &cl_ctr_clusters[ci];

	cl_obj = add_mi_object(arr, NULL, 0);
	if (!cl_obj) goto error;

	snprintf(mcast, sizeof(mcast), "%s:%d",
	         cl->multicast_address, cl->multicast_port);

	members = 0;
	/* Report the EFFECTIVE (possibly adopted) settings from shm, so the
	 * values reflect what is actually in force after on_config_mismatch=
	 * adopt (the worker mirrors them there).  Fall back to the configured
	 * values if the peer table is not up yet. */
	int eff_manage = cl->manage_shtags, eff_stick = cl->master_stickiness,
	    eff_qt = query_time;
	unsigned int term = 0;
	char cid_s[37] = "";
	const char *cid_st = "none";
	unsigned long foreign = 0, refused = 0;
	{
	    uint16_t forced = 0;
	    if (cl->peers) {
		lock_start_read(cl->peers->lock);
		members    = cl->peers->count;
		term       = cl->peers->master_term;
		cid_st     = cl_ctr_cid_state_name(cl->peers->cid_state);
		if (cl->peers->cid_state != CL_CTR_CID_NONE)
		    cl_ctr_cid_str(cl->peers->cid, cid_s);
		foreign    = cl->peers->foreign_pkts;
		refused    = cl->peers->peers_refused;
		forced     = cl->peers->shtag_forced_node_id;
		eff_manage = cl->peers->eff_manage_shtags;
		eff_stick  = cl->peers->eff_master_stickiness;
		eff_qt     = cl->peers->eff_query_time;
		lock_stop_read(cl->peers->lock);
	    }
	    /* Current shtag allocation mode: "auto" = master-driven automatic
	     * allocation; "override:<node_id>" = operator forced a fixed holder
	     * via cl_ctr_shtag_force.  ("manual" is reserved for the future
	     * maintenance mode.)                                              */
	    if (forced)
		snprintf(shtag_mode, sizeof(shtag_mode), "override:%u", forced);
	    else
		snprintf(shtag_mode, sizeof(shtag_mode), "auto");
	}

	if (add_mi_number(cl_obj, MI_SSTR("cluster_id"),   cl->cluster_id)        < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("multicast"),    mcast, strlen(mcast))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("my_ip"),        my_ip, strlen(my_ip))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("bin_socket"),
	                  cl->bin_socket, strlen(cl->bin_socket))                 < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("mtu"),          cc_mtu)                 < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("interface"),
	                  my_interface_buf[0] ? my_interface_buf : "(unknown)",
	                  my_interface_buf[0] ? strlen(my_interface_buf) : 9)      < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("query_time"),   eff_qt)                < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("master_stickiness"), eff_stick)        < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("manage_shtags"), eff_manage)           < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("shtag_mode"),
	                  shtag_mode, strlen(shtag_mode))                         < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("member_count"), members)               < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("term"),         term)                  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("cluster_uuid"), cid_s, strlen(cid_s))  < 0 ||
	    add_mi_string(cl_obj, MI_SSTR("cluster_uuid_state"),
	                  cid_st, strlen(cid_st))                                 < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("foreign_packets"), foreign)            < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("peer_capacity"), CL_CTR_MAX_PEERS)     < 0 ||
	    add_mi_number(cl_obj, MI_SSTR("peers_refused"), refused)              < 0)
	    goto error;
    }

    return resp;

error:
    LM_ERR("clusterer_controller: mi_cl_ctr_config: failed to build response\n");
    free_mi_response(resp);
    return NULL;
}

/**
 * cl_ctr_rpc_apply_shtags() - IPC job run inside the cl_ctr_worker process.
 *
 * An MI handler (running in a different process) has already updated
 * cl->peers->shtag_forced_node_id in shm; this job makes the change take
 * effect promptly: it re-applies the local shtag decision and, if we are the
 * master, re-broadcasts the MEMBER_LIST so every member learns the new
 * override without waiting for the next periodic announcement.
 */
static void cl_ctr_rpc_apply_shtags(int sender, void *param)
{
    cl_ctr_cluster_t *cl = (cl_ctr_cluster_t *)param;
    int i_am_master;

    (void)sender;
    if (!cl || !cl->peers)
	return;

    cl_ctr_apply_shtags(cl);

    lock_start_read(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    lock_stop_read(cl->peers->lock);

    if (i_am_master && cl->sock >= 0)
	cl_ctr_send_member_list(cl->sock, cl);
}

/**
 * cl_ctr_mi_find_cluster() - locate a configured cluster by its cluster_id.
 * Returns NULL if no cluster matches.
 */
static cl_ctr_cluster_t *cl_ctr_mi_find_cluster(int cluster_id)
{
    int ci;
    for (ci = 0; ci < cl_ctr_cluster_count; ci++)
	if (cl_ctr_clusters[ci].cluster_id == cluster_id)
	    return &cl_ctr_clusters[ci];
    return NULL;
}

/**
 * mi_cl_ctr_shtag_force() - force a specific node to hold the active sharing tag.
 *
 *   opensips-cli -x mi cl_ctr_shtag_force cluster_id=1 node_id=2
 *
 * Must be issued on the current master.  Suspends automatic (master-driven)
 * shtag allocation until cl_ctr_shtag_auto is called; the chosen node becomes the
 * sole active shtag holder cluster-wide.  The override is propagated to every
 * member via the MEMBER_LIST and survives master fail-over, but is cleared
 * automatically if the forced node leaves or times out.
 */
static mi_response_t *mi_cl_ctr_shtag_force(const mi_params_t *params,
                                        struct mi_handler *hdl)
{
    int            cluster_id, node_id;
    cl_ctr_cluster_t  *cl;
    int            i_am_master, found = 0, proc_no;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0 ||
        get_mi_int_param(params, "node_id",    &node_id)    < 0)
	return init_mi_param_error();

    if (node_id <= 0 || node_id > 0xFFFF)
	return init_mi_error(400, MI_SSTR("node_id out of range"));

    cl = cl_ctr_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));

    if (!cl->manage_shtags)
	return init_mi_error(409,
	        MI_SSTR("shtag management is disabled for this cluster"));

    lock_start_write(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    if (i_am_master) {
	int i;
	for (i = 0; i < cl->peers->count; i++) {
	    if ((int)cl->peers->entries[i].node_id == node_id) {
		found = 1;
		break;
	    }
	}
	/* Every member is eligible.  Node maintenance mode (README, Planned
	 * Features) will refuse a node in maintenance here, and clear a pin
	 * that is already on one. */
	if (found)
	    cl->peers->shtag_forced_node_id = (uint16_t)node_id;
    }
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);

    if (!i_am_master)
	return init_mi_error(409,
	        MI_SSTR("not the master - issue cl_ctr_shtag_force on the master node"));
    if (!found)
	return init_mi_error(404, MI_SSTR("node_id not a member of this cluster"));

    /* Apply locally and broadcast the new override from the worker process. */
    if (proc_no >= 0)
	ipc_send_rpc(proc_no, cl_ctr_rpc_apply_shtags, cl);

    LM_INFO("clusterer_controller: [cluster %d] operator forced shtag onto "
            "node %d\n", cluster_id, node_id);
    return init_mi_result_ok();
}

/**
 * mi_cl_ctr_shtag_auto() - resume automatic (master-driven) shtag allocation.
 *
 *   opensips-cli -x mi cl_ctr_shtag_auto cluster_id=1
 *
 * Clears any operator override set by cl_ctr_shtag_force so the active shtag
 * follows the master again.  Must be issued on the current master.
 */
static mi_response_t *mi_cl_ctr_shtag_auto(const mi_params_t *params,
                                       struct mi_handler *hdl)
{
    int            cluster_id;
    cl_ctr_cluster_t  *cl;
    int            i_am_master, proc_no;

    if (get_mi_int_param(params, "cluster_id", &cluster_id) < 0)
	return init_mi_param_error();

    cl = cl_ctr_mi_find_cluster(cluster_id);
    if (!cl || !cl->peers)
	return init_mi_error(404, MI_SSTR("cluster_id not found"));

    lock_start_write(cl->peers->lock);
    i_am_master = cl_ctr_i_am_master_locked(cl);
    if (i_am_master)
	cl->peers->shtag_forced_node_id = 0;
    proc_no = cl->peers->worker_proc_no;
    lock_stop_write(cl->peers->lock);

    if (!i_am_master)
	return init_mi_error(409,
	        MI_SSTR("not the master - issue cl_ctr_shtag_auto on the master node"));

    if (proc_no >= 0)
	ipc_send_rpc(proc_no, cl_ctr_rpc_apply_shtags, cl);

    LM_INFO("clusterer_controller: [cluster %d] operator resumed automatic "
            "shtag allocation\n", cluster_id);
    return init_mi_result_ok();
}
/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * cl_ctr_resolve_local_identity() - determine my_ip and my_interface_buf.
 *
 * Three modes depending on which modparams were provided:
 *
 *   Mode 1 - ip= only:
 *     Walk getifaddrs() to find the interface that owns the given IP.
 *     Fails if no interface owns it.
 *
 *   Mode 2 - interface= only:
 *     Walk getifaddrs() to find the interface and take its first IPv4 address.
 *     Warns if the interface has multiple IPv4 addresses; uses the first one
 *     (the kernel's enumeration order matches `ip addr show`).
 *
 *   Mode 3 - neither:
 *     Connect a throw-away UDP socket to the multicast group (no data sent).
 *     getsockname() returns the source IP the kernel would select.
 *     Reverse-look up the interface name via getifaddrs().
 *
 * On success: my_ip points to a valid dotted-decimal IPv4 string and
 *             my_interface_buf holds the interface name (may be empty if the
 *             reverse lookup failed in mode 3 - non-fatal).
 */
/**
 * cl_ctr_parse_cluster_str() - parse one "cluster" modparam string into cl.
 *
 * Format: "id=N,multicast=A.B.C.D:PORT[,password=STRING][,bin_socket=bin:IP:PORT]"
 * - id= required, positive integer
 * - multicast= required, IPv4:port
 * - password= optional, falls back to global password modparam
 * - bin_socket= optional, BIN socket for this cluster; falls back to
 *   first discovered socket (or only socket if one exists)
 */
static int cl_ctr_parse_cluster_str(const char *str, cl_ctr_cluster_t *cl)
{
    char        buf[2048];
    char       *p, *tok, *key, *val, *colon;
    struct in_addr addr;
    unsigned char  first_octet;
    int         has_id = 0, has_mcast = 0;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Defaults */
    cl->multicast_port = 3333;
    strncpy(cl->password, password, sizeof(cl->password) - 1);
    cl->password[sizeof(cl->password) - 1] = '\0';
    cl->manage_shtags = -1; /* sentinel: inherit global default in mod_init */
    cl->consumer_retries = -1;
    cl->consumer_retry_ms = -1;
    cl->consumer_rate = -1;
    cl->master_stickiness = -1; /* sentinel: inherit global default in mod_init */

    for (tok = strtok_r(buf, ",", &p); tok; tok = strtok_r(NULL, ",", &p)) {
	while (*tok == ' ' || *tok == '\t') tok++;
	key = tok;
	val = strchr(tok, '=');
	if (!val) continue;
	*val++ = '\0';

	if (strcmp(key, "id") == 0) {
	    cl->cluster_id = atoi(val);
	    if (cl->cluster_id <= 0 || cl->cluster_id > 65535) {
		LM_ERR("clusterer_controller: cluster id must be 1..65535 "
		       "(carried as a 2-byte field on the wire)\n");
		return -1;
	    }
	    has_id = 1;

	} else if (strcmp(key, "multicast") == 0) {
	    colon = strrchr(val, ':');
	    if (colon) {
		*colon = '\0';
		cl->multicast_port = atoi(colon + 1);
		if (cl->multicast_port <= 0 || cl->multicast_port > 65535) {
		    LM_ERR("clusterer_controller: invalid port in cluster '%s'\n", str);
		    return -1;
		}
	    }
	    strncpy(cl->multicast_address, val, INET_ADDRSTRLEN - 1);
	    cl->multicast_address[INET_ADDRSTRLEN - 1] = '\0';
	    if (inet_aton(cl->multicast_address, &addr) == 0) {
		LM_ERR("clusterer_controller: invalid multicast address '%s'\n", val);
		return -1;
	    }
	    first_octet = (unsigned char)((ntohl(addr.s_addr) >> 24) & 0xFF);
	    if (first_octet < 224 || first_octet > 239) {
		LM_ERR("clusterer_controller: '%s' is not a multicast address\n", val);
		return -1;
	    }
	    has_mcast = 1;

	} else if (strcmp(key, "password") == 0) {
	    strncpy(cl->password, val, sizeof(cl->password) - 1);
	    cl->password[sizeof(cl->password) - 1] = '\0';

	} else if (strcmp(key, "bin_socket") == 0) {
	    if (strlen(val) >= CL_CTR_MAX_BIN_SOCK_LEN) {
		LM_ERR("clusterer_controller: bin_socket value too long\n");
		return -1;
	    }
	    strncpy(cl->bin_socket, val, CL_CTR_MAX_BIN_SOCK_LEN - 1);
	    cl->bin_socket[CL_CTR_MAX_BIN_SOCK_LEN - 1] = '\0';

	} else if (strcmp(key, "consumer_retries") == 0) {
	    cl->consumer_retries = atoi(val);
	    if (cl->consumer_retries < 0 || cl->consumer_retries > 10) {
		LM_ERR("clusterer_controller: consumer_retries must be 0..10 "
		       "in '%s'\n", str);
		return -1;
	    }

	} else if (strcmp(key, "consumer_retry_ms") == 0) {
	    cl->consumer_retry_ms = atoi(val);
	    if (cl->consumer_retry_ms < 5 || cl->consumer_retry_ms > 5000) {
		LM_ERR("clusterer_controller: consumer_retry_ms must be "
		       "5..5000 in '%s'\n", str);
		return -1;
	    }

	} else if (strcmp(key, "consumer_rate_limit") == 0) {
	    cl->consumer_rate = atoi(val);
	    if (cl->consumer_rate < 1) {
		LM_ERR("clusterer_controller: consumer_rate_limit must be "
		       "positive in '%s'\n", str);
		return -1;
	    }

	} else if (strcmp(key, "manage_shtags") == 0) {
	    cl->manage_shtags = atoi(val) ? 1 : 0;

	} else if (strcmp(key, "master_stickiness") == 0) {
	    cl->master_stickiness = atoi(val) ? 1 : 0;

	} else if (strcmp(key, "uuid") == 0) {
	    if (cl_ctr_cid_parse_pin(val, cl->cid_pin) < 0) {
		LM_ERR("clusterer_controller: empty uuid= in '%s'\n", str);
		return -1;
	    }
	    cl->cid_pinned = 1;
	}
    }

    if (!has_id) {
	LM_ERR("clusterer_controller: cluster string missing id= in '%s'\n", str);
	return -1;
    }
    if (!has_mcast) {
	LM_ERR("clusterer_controller: cluster string missing multicast= in '%s'\n", str);
	return -1;
    }
    return 0;
}

static int cl_ctr_resolve_local_identity(void)
{
    struct ifaddrs *ifap = NULL, *ifa;
    int             found = 0;

    if (getifaddrs(&ifap) < 0) {
	LM_ERR("clusterer_controller: getifaddrs() failed: %s\n",
	       strerror(errno));
	return -1;
    }

    if (my_ip && *my_ip) {
	/* ---- Mode 1: ip= explicitly provided - find owning interface ---- */
	struct in_addr target;

	if (inet_aton(my_ip, &target) == 0) {
	    LM_ERR("clusterer_controller: cannot parse 'my_ip' '%s'\n", my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
	            == target.s_addr) {
		strncpy(my_interface_buf, ifa->ifa_name, IF_NAMESIZE - 1);
		my_interface_buf[IF_NAMESIZE - 1] = '\0';
		found = 1;
		break;
	    }
	}
	if (!found) {
	    LM_ERR("clusterer_controller: no local interface owns IP '%s'\n",
	           my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
	my_ip_src = "my_ip modparam (explicit)";
	LM_INFO("clusterer_controller: using IP %s on interface %s\n",
	        my_ip, my_interface_buf);

    } else if (my_interface && *my_interface) {
	/* ---- Mode 2: interface= provided - derive IP from it ---- */
	int addr_count = 0;

	strncpy(my_interface_buf, my_interface, IF_NAMESIZE - 1);
	my_interface_buf[IF_NAMESIZE - 1] = '\0';

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (strcmp(ifa->ifa_name, my_interface) != 0)
		continue;
	    addr_count++;
	    if (addr_count == 1) {
		struct in_addr a =
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		inet_ntop(AF_INET, &a, my_ip_buf, sizeof(my_ip_buf));
		my_ip = my_ip_buf;
		found = 1;
	    }
	}
	if (!found) {
	    LM_ERR("clusterer_controller: interface '%s' not found or "
	           "has no IPv4 address\n", my_interface);
	    freeifaddrs(ifap);
	    return -1;
	}
	if (addr_count > 1)
	    LM_WARN("clusterer_controller: interface '%s' has %d IPv4 "
	            "addresses, using %s (first returned by kernel) - "
	            "use 'my_ip' modparam to override\n",
	            my_interface, addr_count, my_ip);
	else
	    LM_INFO("clusterer_controller: using IP %s on interface %s\n",
	            my_ip, my_interface_buf);
	my_ip_src = "interface modparam (IPv4 of that interface)";

    } else {
	/* ---- Mode 3: neither - auto-detect via kernel routing table ---- */
	struct sockaddr_in dest, local;
	socklen_t          local_len = sizeof(local);
	int                probe;

	memset(&dest, 0, sizeof(dest));
	dest.sin_family      = AF_INET;
	dest.sin_port        = htons((uint16_t)cl_ctr_clusters[0].multicast_port);
	dest.sin_addr.s_addr = inet_addr(cl_ctr_clusters[0].multicast_address);

	probe = socket(AF_INET, SOCK_DGRAM, 0);
	if (probe < 0) {
	    LM_ERR("clusterer_controller: auto-detect socket: %s\n",
	           strerror(errno));
	    freeifaddrs(ifap);
	    return -1;
	}
	if (connect(probe, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	    LM_ERR("clusterer_controller: auto-detect connect: %s\n",
	           strerror(errno));
	    close(probe);
	    freeifaddrs(ifap);
	    return -1;
	}
	memset(&local, 0, sizeof(local));
	if (getsockname(probe, (struct sockaddr *)&local, &local_len) < 0) {
	    LM_ERR("clusterer_controller: auto-detect getsockname: %s\n",
	           strerror(errno));
	    close(probe);
	    freeifaddrs(ifap);
	    return -1;
	}
	close(probe);

	inet_ntop(AF_INET, &local.sin_addr, my_ip_buf, sizeof(my_ip_buf));
	my_ip = my_ip_buf;
	my_ip_src = "auto-detected via default route to the multicast group";

	/* Reverse-look up the interface name */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
	            == local.sin_addr.s_addr) {
		strncpy(my_interface_buf, ifa->ifa_name, IF_NAMESIZE - 1);
		my_interface_buf[IF_NAMESIZE - 1] = '\0';
		found = 1;
		break;
	    }
	}
	if (found) {
	    LM_INFO("clusterer_controller: auto-detected IP %s on "
	            "interface %s\n", my_ip, my_interface_buf);
	} else {
	    /* Fatal, where it used to warn and continue.  The interface name is
	     * the only route to the MTU, and the MTU is what admission to the
	     * cluster is decided on - a node that cannot name its own interface
	     * cannot know whether it belongs, and would previously have run on
	     * the compile-time default as if it did.  Both explicit modes
	     * (my_ip, interface) always yield a name, so this is only reachable
	     * from auto-detection, and naming either one is the fix. */
	    LM_ERR("clusterer_controller: auto-detected IP %s but no interface "
	           "owns it, so its MTU cannot be read - and the cluster admits "
	           "only nodes whose MTU matches. Set the 'interface' modparam "
	           "(or 'my_ip') so the link is unambiguous\n", my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
    }

    freeifaddrs(ifap);
    return 0;
}

/**
 * cl_ctr_discover_bin_sockets() - enumerate BIN listeners via proto_bin.
 *
 * Walks the protos[PROTO_BIN].listeners list and collects every
 * entry with proto == PROTO_BIN.  proto_bin must be loaded before this
 * module so the listeners are already registered when mod_init() runs.
 *
 * Populates my_bin_sockets[] and my_bin_count.
 * Returns 0 on success, -1 if no BIN sockets are found.
 */
static int cl_ctr_discover_bin_sockets(void)
{
    struct socket_info_full *sif;
    struct socket_info *si;
    char                buf[CL_CTR_MAX_BIN_SOCK_LEN];
    int                 len;

    /* On devel, protos[].listeners is a list of socket_info_full (next/prev),
     * each embedding the socket_info as its first member. */
    for (sif = protos[PROTO_BIN].listeners; sif; sif = sif->next) {
	si = &sif->socket_info;
	/* all entries here are PROTO_BIN by construction */
	if (si->proto != PROTO_BIN)
	    continue;
	/* Reject wildcard - clusterer needs an explicit IP to set send_sock.
	 * Use socket=bin:IP:PORT instead of socket=bin:*:PORT.             */
	if (si->address_str.len == 0
	    || (si->address_str.len == 1 && si->address_str.s[0] == '*')
	    || (si->address_str.len == 7
	        && memcmp(si->address_str.s, "0.0.0.0", 7) == 0)) {
	    LM_ERR("clusterer_controller: wildcard BIN socket "
	           "(bin:*:%u) is not allowed - use an explicit IP "
	           "(e.g. socket=bin:%s:%u)\n",
	           si->port_no, my_ip ? my_ip : "YOUR_IP", si->port_no);
	    return -1;
	}
	if (my_bin_count >= CL_CTR_MAX_BIN_SOCKETS) {
	    LM_WARN("clusterer_controller: more than %d BIN sockets, "
	            "ignoring the rest\n", CL_CTR_MAX_BIN_SOCKETS);
	    break;
	}
	len = snprintf(buf, sizeof(buf), "bin:%.*s:%u",
	               si->address_str.len, si->address_str.s,
	               si->port_no);
	if (len <= 0 || len >= CL_CTR_MAX_BIN_SOCK_LEN) {
	    LM_WARN("clusterer_controller: BIN socket name too long, "
	            "skipping\n");
	    continue;
	}
	memcpy(my_bin_sockets[my_bin_count], buf, len + 1);
	LM_INFO("clusterer_controller: found BIN socket: %s\n", buf);
	my_bin_count++;
    }

    if (my_bin_count == 0) {
	LM_ERR("clusterer_controller: no BIN sockets found - "
	       "is proto_bin loaded and socket=bin: configured?\n");
	return -1;
    }

    return 0;
}

static int mod_init(void)
{
    struct in_addr addr;
    int            i, j;
    /* the script's messaging channel and its two events; done here so the
     * reserved name is claimed before any consumer module registers */
    if (cl_ctr_script_init() < 0) {
        LM_ERR("clusterer_controller: cannot set up script messaging\n");
        return -1;
    }


    LM_INFO("clusterer_controller: initialising\n");

    if (sodium_init() < 0) {
	LM_ERR("clusterer_controller: sodium_init() failed\n");
	return -1;
    }

    /* This process's incarnation: wall-clock start time in microseconds, so
     * every restart numbers above the one before it (see CL_CTR_INC_SZ).  A
     * clock stepped back across a restart would make the new life look older
     * than the last; the master's NODE_ASSIGN, sent when it re-admits us,
     * carries the incarnation it admitted and peers take it from there. */
    {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	cl_ctr_incarnation = (uint64_t)ts.tv_sec * 1000000ULL
	                     + (uint64_t)ts.tv_nsec / 1000ULL;
	if (cl_ctr_incarnation == 0)
	    cl_ctr_incarnation = 1;     /* 0 means "not seen yet" to peers */
    }

    /* Resolve the on_config_mismatch policy string. */
    if (on_config_mismatch_s) {
	if (strcasecmp(on_config_mismatch_s, "warn") == 0)
	    on_config_mismatch = CL_CTR_CFGMISMATCH_WARN;
	else if (strcasecmp(on_config_mismatch_s, "reject") == 0)
	    on_config_mismatch = CL_CTR_CFGMISMATCH_REJECT;
	else if (strcasecmp(on_config_mismatch_s, "adopt") == 0)
	    on_config_mismatch = CL_CTR_CFGMISMATCH_ADOPT;
	else {
	    LM_ERR("clusterer_controller: invalid on_config_mismatch '%s' "
	           "(expected warn|reject|adopt)\n", on_config_mismatch_s);
	    return -1;
	}
    }

    /* ---- Require at least one cluster ---------------------------------- */

    if (cl_ctr_cluster_str_count == 0) {
	LM_ERR("clusterer_controller: no 'cluster' modparam defined\n");
	return -1;
    }

    /* ---- Global param validation --------------------------------------- */

    if (query_time < 1) {
	LM_WARN("clusterer_controller: 'query_time' %d below min, clamping to 1s\n",
	        query_time);
	query_time = 1;
    } else if (query_time > 60) {
	LM_WARN("clusterer_controller: 'query_time' %d exceeds max, clamping to 60s\n",
	        query_time);
	query_time = 60;
    }

    /* ---- Parse and validate all cluster strings ------------------------ */

    for (i = 0; i < cl_ctr_cluster_str_count; i++) {
	cl_ctr_cluster_t *cl = &cl_ctr_clusters[i];
	if (cl_ctr_parse_cluster_str(cl_ctr_cluster_strs[i], cl) < 0)
	    return -1;
	/* Resolve the multicast destination once, in the main process, so both
	 * the forked workers (via fork) and mod_destroy's GOODBYE path (main
	 * process) can send without rebuilding it. */
	memset(&cl->mcast_dest, 0, sizeof(cl->mcast_dest));
	cl->mcast_dest.sin_family      = AF_INET;
	cl->mcast_dest.sin_port        = htons((uint16_t)cl->multicast_port);
	cl->mcast_dest.sin_addr.s_addr = inet_addr(cl->multicast_address);
	cl_ctr_cluster_count++;
	pkg_free(cl_ctr_cluster_strs[i]);
	cl_ctr_cluster_strs[i] = NULL;
    }

    /* Validate cluster_id / (multicast,port) uniqueness.  Every local controller
     * socket binds INADDR_ANY:multicast_port, so a unicast to my_ip:port is
     * demultiplexed by port alone - if two local clusters share a port (distinct
     * groups), a unicast can land on the wrong cluster's socket.  That is now
     * recovered at the receiver by the packet's cleartext cluster_id (see
     * cl_ctr_maybe_forward()), so shared ports stay fully unicast; we only note
     * it. */
    for (i = 0; i < cl_ctr_cluster_count; i++) {
	for (j = i + 1; j < cl_ctr_cluster_count; j++) {
	    if (cl_ctr_clusters[i].cluster_id == cl_ctr_clusters[j].cluster_id) {
		LM_ERR("clusterer_controller: duplicate cluster_id %d\n",
		       cl_ctr_clusters[i].cluster_id);
		return -1;
	    }
	    if (cl_ctr_clusters[i].multicast_port != cl_ctr_clusters[j].multicast_port)
		continue;
	    if (strcmp(cl_ctr_clusters[i].multicast_address,
	               cl_ctr_clusters[j].multicast_address) == 0) {
		LM_ERR("clusterer_controller: duplicate multicast %s:%d\n",
		       cl_ctr_clusters[i].multicast_address,
		       cl_ctr_clusters[i].multicast_port);
		return -1;
	    }
	    /* same port, different group: unicast is demuxed by port alone and
	     * routed to the right cluster by cluster_id at the receiver */
	    LM_INFO("clusterer_controller: clusters %d and %d share multicast "
	            "port %d - unicast is routed by cluster_id\n",
	            cl_ctr_clusters[i].cluster_id, cl_ctr_clusters[j].cluster_id,
	            cl_ctr_clusters[i].multicast_port);
	}
    }

    /* ---- Discover BIN sockets from opensips config file --------------- */
    /* Called after cl_ctr_resolve_local_identity() so my_ip is available for  */
    /* wildcard substitution (bin:*:PORT -> bin:my_ip:PORT).               */

    /* ---- Resolve local identity using first cluster for Mode 3 probe --- */

    if (cl_ctr_resolve_local_identity() < 0)
	return -1;

    /* Derive max consumer payload from the interface MTU so jumbo-frame
     * links (e.g. MTU 9000) are not capped at the 1500-byte default.
     * Overhead per consumer datagram:
     *   IP(20) + UDP(8) + wire_hdr(28) + plain_hdr(5) +
     *   consumer_hdr(3) + max_chan(31) + poly1305_tag(16) = 111 bytes. */
    {
	int _probe_mtu = cl_ctr_read_iface_mtu();
	if (_probe_mtu <= 0) {
	    /* No modparam can supply this: the MTU is detected, never
	     * configured, precisely so it cannot disagree with the kernel.
	     * Without it this node cannot know whether it may join, and a node
	     * that cannot participate must not serve SIP. */
	    LM_ERR("clusterer_controller: cannot read the MTU of %s (%s) - the "
	           "cluster admits only nodes whose MTU matches, so this node "
	           "cannot establish whether it belongs and will not start\n",
	           my_interface_buf[0] ? my_interface_buf : "(no interface)",
	           my_interface_buf[0] ? strerror(errno) : "interface unresolved");
	    return -1;
	}
	cc_mtu = cc_mtu_now = _probe_mtu;
    }
    if (my_interface_buf[0] != '\0') {
	struct ifreq _mtu_ifr;
	int _mtu_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (_mtu_sock >= 0) {
	    memset(&_mtu_ifr, 0, sizeof(_mtu_ifr));
	    memcpy(_mtu_ifr.ifr_name, my_interface_buf, strnlen(my_interface_buf, IF_NAMESIZE - 1));
	    if (ioctl(_mtu_sock, SIOCGIFMTU, &_mtu_ifr) == 0) {
		int _mtu = _mtu_ifr.ifr_mtu;
		int _overhead = 20 + 8 + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
		                + CL_CTR_CONSUMER_HDR_SZ + CLCTR_MAX_CHAN_LEN + CL_CTR_TAG_SZ;
		cc_max_payload = _mtu - _overhead;
		/* Do NOT pad this back up to CLCTR_MAX_PAYLOAD when the link is
		 * smaller than that. It used to, and the effect was that any
		 * interface under ~1435 MTU - a VPN, a GRE/IPIP tunnel, PPPoE,
		 * the usual 1400/1420/1436 - reported a bound ABOVE what the
		 * path carries, which is the exact inverse of why the MTU is
		 * consulted at all. Every full-size consumer datagram then IP
		 * fragments, and a fragmented datagram is lost entirely if any
		 * one fragment is, so the padding manufactured precisely the
		 * losses the retransmit machinery then has to repair.
		 *
		 * Honour the link and say so instead: the compile-time constant
		 * stays what a consumer sizes a buffer with, but it stops being
		 * a promise the network cannot keep. */
		if (cc_max_payload < CLCTR_MAX_PAYLOAD)
		    LM_WARN("clusterer_controller: interface %s has MTU %d, so a "
		            "consumer datagram carries at most %d bytes - below "
		            "the %d that CLCTR_MAX_PAYLOAD leads consumers to "
		            "expect. Sends above %d will be refused on this "
		            "link. Raise the MTU, or keep consumer payloads "
		            "under it; the bound is deliberately NOT padded up "
		            "to the constant, because that only fragments and a "
		            "lost fragment loses the whole message.\n",
		            my_interface_buf, _mtu, cc_max_payload,
		            (int)CLCTR_MAX_PAYLOAD, cc_max_payload);
		/* However large the MTU claims to be, one datagram still has
		 * to fit a UDP payload. Loopback reports 65536, which lands a
		 * byte past what sendto() accepts. */
		if (cc_max_payload > CL_CTR_UDP_PAYLOAD_MAX - CL_CTR_PKT_OVERHEAD)
		    cc_max_payload = CL_CTR_UDP_PAYLOAD_MAX - CL_CTR_PKT_OVERHEAD;
		if (cc_max_payload <= 0) {
		    LM_ERR("clusterer_controller: interface %s has MTU %d, which "
		           "cannot carry even the %d bytes of per-datagram "
		           "overhead - the cluster plane cannot run on it\n",
		           my_interface_buf, _mtu, _overhead);
		    return -1;
		}
		LM_INFO("clusterer_controller: interface %s MTU=%d, "
		        "max consumer payload=%d bytes - every cluster member "
		        "must run at this MTU; one that does not is refused at "
		        "join\n",
		        my_interface_buf, _mtu, cc_max_payload);
	    } else {
		LM_WARN("clusterer_controller: SIOCGIFMTU on %s failed: %s - "
		        "using default max payload %d\n",
		        my_interface_buf, strerror(errno), cc_max_payload);
	    }
	    close(_mtu_sock);
	}
    }

    /* Size the transmit buffers from the bound that gates them, now that the
     * MTU probe above has settled cc_max_payload. Doing it here rather than at
     * compile time is the whole point: a jumbo-frame link raises
     * cc_max_payload, and a CLCTR_MAX_PAYLOAD-sized buffer could not hold what
     * that bound then admits. */
    cl_ctr_script_buf_sz  = cc_max_payload;
    cl_ctr_consumer_pkt_sz = CL_CTR_PKT_OVERHEAD + cc_max_payload;
    /* The retransmit cache follows the same bound, for the same reason: a
     * reliable send that the transmit buffer accepts must also be one the
     * repair path can hold, or reliability quietly stops at a size the API
     * never mentions.  Whichever is larger - the control plane's biggest
     * handshake packet, or a full-MTU consumer message. */
    cl_ctr_retx_pkt_max = cl_ctr_consumer_pkt_sz > CL_CTR_NODE_ASSIGN_MAX_SZ
                          ? cl_ctr_consumer_pkt_sz : CL_CTR_NODE_ASSIGN_MAX_SZ;
    cl_ctr_script_buf  = pkg_malloc(cl_ctr_script_buf_sz);
    cl_ctr_consumer_pkt = pkg_malloc(cl_ctr_consumer_pkt_sz);
    if (!cl_ctr_script_buf || !cl_ctr_consumer_pkt) {
	LM_ERR("clusterer_controller: no pkg memory for the %d/%d byte "
	       "transmit buffers\n", cl_ctr_script_buf_sz,
	       cl_ctr_consumer_pkt_sz);
	return -1;
    }

    if (cl_ctr_discover_bin_sockets() < 0)
	return -1;

    if (strlen(my_ip) > CL_CTR_MAX_IP_LEN) {
	LM_ERR("clusterer_controller: resolved my_ip too long\n");
	return -1;
    }
    if (inet_aton(my_ip, &addr) == 0) {
	LM_ERR("clusterer_controller: cannot parse resolved my_ip '%s'\n", my_ip);
	return -1;
    }

    /* ---- Multi-cluster: each cluster must name its BIN socket ---------- */

    if (cl_ctr_cluster_count > 1) {
	for (i = 0; i < cl_ctr_cluster_count; i++) {
	    if (cl_ctr_clusters[i].bin_socket[0] == '\0') {
		LM_ERR("clusterer_controller: cluster %d has no bin_socket= "
		       "defined - required when multiple clusters are configured "
		       "(e.g. id=%d,multicast=...,bin_socket=bin:IP:PORT)\n",
		       cl_ctr_clusters[i].cluster_id, cl_ctr_clusters[i].cluster_id);
		return -1;
	    }
	}
    }

    /* ---- Per-cluster: resolve BIN socket, derive key, allocate peers --- */

    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl_ctr_cluster_t *cl = &cl_ctr_clusters[i];

	/* Resolve sentinels to the global default when the cluster string did
	 * not set them explicitly.  Done here (unconditionally, before workers
	 * fork and before any MI query) so every cl->* setting always holds a
	 * concrete 0/1 value regardless of whether clusterer is loaded - a mix
	 * of global and per-cluster overrides always reports correctly.        */
	if (cl->master_stickiness == -1)
	    cl->master_stickiness = master_stickiness ? 1 : 0;
	if (cl->manage_shtags == -1)
	    cl->manage_shtags = manage_shtags ? 1 : 0;
	if (cl->consumer_retries == -1)
	    cl->consumer_retries = consumer_retries;
	if (cl->consumer_retry_ms == -1)
	    cl->consumer_retry_ms = consumer_retry_ms;
	if (cl->consumer_rate == -1)
	    cl->consumer_rate = consumer_rate_limit;

	/* The replay window is a fixed number of MESSAGES, but what it has to
	 * span is a fixed amount of TIME - the retransmit horizon, which is
	 * configurable and can legally be set as high as 10 x 5000 ms.  Report
	 * the resulting per-peer rate ceiling rather than leaving an operator
	 * to meet it as unexplained loss.  Above the ceiling, a repair copy can
	 * arrive after its slot has been reused and is refused (and, on the
	 * reliable path, deliberately not acknowledged). */
	{
	    int horizon_ms = cl->consumer_retries * cl->consumer_retry_ms;
	    int ceiling = horizon_ms > 0
	                  ? (CL_CTR_REPLAY_WIN_BITS * 1000) / horizon_ms : 0;

	    if (horizon_ms > 0 && ceiling < 1000)
		LM_WARN("clusterer_controller: [cluster %d] consumer retransmit "
		        "horizon is %d ms (%d retries x %d ms), so the %d-slot "
		        "replay window only spans ~%d consumer messages/s from "
		        "any one peer; above that, retransmits arrive too late "
		        "to be judged and are dropped\n", cl->cluster_id,
		        horizon_ms, cl->consumer_retries, cl->consumer_retry_ms,
		        CL_CTR_REPLAY_WIN_BITS, ceiling);
	    else
		LM_DBG("clusterer_controller: [cluster %d] replay window spans "
		       "%d messages, ~%d msg/s per peer at a %d ms retransmit "
		       "horizon\n", cl->cluster_id, CL_CTR_REPLAY_WIN_BITS,
		       ceiling, horizon_ms);
	}

	/* Resolve which BIN socket to use for this cluster.
	 * Priority: explicit bin_socket= in cluster string >
	 *           sole discovered socket >
	 *           first discovered socket (warn if multiple) */
	if (cl->bin_socket[0] != '\0') {
	    /* Explicit override - validate it was actually discovered */
	    int found_bs = 0, bi;
	    for (bi = 0; bi < my_bin_count; bi++) {
		if (strcmp(my_bin_sockets[bi], cl->bin_socket) == 0) {
		    found_bs = 1;
		    break;
		}
	    }
	    if (!found_bs) {
	    	char _disc[CL_CTR_MAX_BIN_SOCKETS * (CL_CTR_MAX_BIN_SOCK_LEN + 2)];
	    	int  _o = 0, _b;
	    	_disc[0] = '\0';
	    	for (_b = 0; _b < my_bin_count; _b++)
	    		_o += snprintf(_disc + _o, sizeof(_disc) - _o, "%s%s",
	    		               _b ? ", " : "", my_bin_sockets[_b]);
	    	LM_ERR("clusterer_controller: cluster %d bin_socket='%s' does not "
	    	       "match any configured BIN listener (discovered: %s) - peers "
	    	       "cannot connect and clusterer replication would silently "
	    	       "fail; fix bin_socket= or the socket=bin: line\n",
	    	       cl->cluster_id, cl->bin_socket, _disc);
	    	return -1;
	    }
	} else if (my_bin_count == 1) {
	    /* Only one socket - unambiguous */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CL_CTR_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	} else {
	    /* Multiple sockets, no explicit override - use first, warn */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CL_CTR_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	    LM_WARN("clusterer_controller: cluster %d has no bin_socket= override "
	            "and multiple BIN sockets exist - using %s; add bin_socket= "
	            "to the cluster string to be explicit\n",
	            cl->cluster_id, cl->bin_socket);
	}
	LM_INFO("clusterer_controller: cluster %d: bin_socket=%s\n",
	        cl->cluster_id, cl->bin_socket);

	if (cl_ctr_derive_key(cl) < 0)
	    return -1;

	cl->peers = shm_malloc(sizeof(cl_ctr_peers_t));
	if (!cl->peers) {
	    LM_ERR("clusterer_controller: no shm memory for cluster %d peer table\n",
	           cl->cluster_id);
	    return -1;
	}
	memset(cl->peers, 0, sizeof(cl_ctr_peers_t));
	cl->peers->node_state = CL_CTR_NODE_NEW;
	cl->peers->worker_proc_no = -1;   /* published by cl_ctr_worker after fork */
	cl->peers->eff_manage_shtags     = cl->manage_shtags;
	cl->peers->eff_master_stickiness = cl->master_stickiness;
	cl->peers->eff_query_time        = query_time;
	if (cl->cid_pinned) {
	    char sp[37];
	    memcpy(cl->peers->cid, cl->cid_pin, CL_CTR_CID_SZ);
	    cl->peers->cid_state = CL_CTR_CID_PINNED;
	    cl->peers->cid_since = cl_ctr_now();
	    cl_ctr_cid_str(cl->cid_pin, sp);
	    LM_INFO("clusterer_controller: [cluster %d] cluster uuid pinned to %s\n",
	            cl->cluster_id, sp);
	}

	cl->peers->lock = lock_init_rw();
	if (!cl->peers->lock) {
	    LM_ERR("clusterer_controller: lock_init_rw() failed for cluster %d\n",
	           cl->cluster_id);
	    shm_free(cl->peers);
	    cl->peers = NULL;
	    return -1;
	}

	LM_INFO("clusterer_controller: cluster %d: multicast=%s:%d bin=%s\n",
	        cl->cluster_id, cl->multicast_address, cl->multicast_port,
	        cl->bin_socket);
    }

    LM_INFO("clusterer_controller: my_ip=%s interface=%s query_time=%ds "
            "clusters=%d bin_sockets=%d crypto=%s\n",
            my_ip, my_interface_buf[0] ? my_interface_buf : "(unknown)",
            query_time, cl_ctr_cluster_count, my_bin_count, CL_CTR_CRYPTO_SUITE);

    /* Set worker process count dynamically - one per cluster */
    procs[0].no = cl_ctr_cluster_count;

    /* Load clusterer controller API if clusterer.so is present and
     * use_controller=1 is set.  Soft dependency - controller works
     * standalone even without clusterer loaded.                     */
    {
	load_clusterer_ctrl_binds_f load_fn;
	load_fn = (load_clusterer_ctrl_binds_f)
	          find_export("load_clusterer_ctrl_binds", 0);
	if (load_fn && load_fn(&clctl) == 0) {
	    clctl_loaded = 1;
	    LM_INFO("clusterer_controller: clusterer API loaded - "
	            "topology will be driven dynamically\n");

	    /* The clusterer marks a cluster controller-managed with
	     * cluster_options use_controller=1; that pre-creates its stub, sets the
	     * controller_managed flag (so it never touches the DB), and arms the
	     * guard against hijacking a native cluster of the same id.  The set of
	     * clusterer-managed ids and the set of 'cluster' configs here must match
	     * exactly - either direction of mismatch is a hard error, since neither
	     * half is usable without the other (a managed id with no controller
	     * config has no bin socket or crypto params; a controller config for an
	     * unmanaged id has nothing legitimate to drive).  Abort naming the id. */

	    /* (a) clusterer marks a cluster managed that we have no config for */
	    {
		int m, k, found;
		for (m = 0; m < clctl.managed_count; m++) {
		    found = 0;
		    for (k = 0; k < cl_ctr_cluster_count; k++)
			if (cl_ctr_clusters[k].cluster_id == clctl.managed_ids[m]) {
			    found = 1;
			    break;
			}
		    if (!found) {
			LM_ERR("clusterer_controller: the clusterer marks cluster %d "
			       "controller-managed (cluster_options use_controller=1) "
			       "but this module has no configuration for it - add "
			       "modparam(\"clusterer_controller\", \"cluster\", "
			       "\"id=%d, ...\"), or drop use_controller for that "
			       "cluster.\n",
			       clctl.managed_ids[m], clctl.managed_ids[m]);
			return -1;
		    }
		}
	    }

	    /* (b) we have a config for a cluster the clusterer did not mark managed */
	    {
		int k, m, managed;
		for (k = 0; k < cl_ctr_cluster_count; k++) {
		    managed = 0;
		    for (m = 0; m < clctl.managed_count; m++)
			if (clctl.managed_ids[m] == cl_ctr_clusters[k].cluster_id) {
			    managed = 1;
			    break;
			}
		    if (!managed) {
			LM_ERR("clusterer_controller: cluster %d is configured here "
			       "but the clusterer did not mark it controller-managed "
			       "- add modparam(\"clusterer\", \"cluster_options\", "
			       "\"cluster_id=%d, use_controller=1\"), or remove this "
			       "module's 'cluster' config for it.\n",
			       cl_ctr_clusters[k].cluster_id, cl_ctr_clusters[k].cluster_id);
			return -1;
		    }
		}
	    }

	    /* When we manage sharing tags, start every tag as BACKUP and
	     * lock out MI/script changes - the controller master decides
	     * who becomes active.  (manage_shtags sentinels were already
	     * resolved to concrete 0/1 in the unconditional loop above.)  */
	    {
		int _ci;
		for (_ci = 0; _ci < cl_ctr_cluster_count; _ci++) {
		    if (!cl_ctr_clusters[_ci].manage_shtags)
			continue;
		    if (clctl.force_backup_shtags)
			clctl.force_backup_shtags(cl_ctr_clusters[_ci].cluster_id);
		    if (clctl.set_shtag_managed)
			clctl.set_shtag_managed(cl_ctr_clusters[_ci].cluster_id);
		}
	    }

	} else {
	    LM_DBG("clusterer_controller: clusterer not loaded or "
	           "use_controller not set - running standalone\n");
	}
    }

    return 0;
}

static int cl_ctr_child_init(int rank)
{
	/* Re-seed the CSPRNG after fork - each worker must have independent state. */
	randombytes_stir();

	/* Sync current_id from shared memory in every child process.
	 * The global current_id diverges after fork - each process needs
	 * to re-read the correct value from cluster->current_node.      */
	if (clctl_loaded && clctl.sync_current_id)
		clctl.sync_current_id();
	return 0;
}

static void mod_destroy(void)
{
    int            i, sock;
    unsigned char  ttl = 32;
    cl_ctr_cluster_t  *cl;

    if (!my_ip)
	goto cleanup;

    /* Send GOODBYE on each cluster's multicast group so peers re-elect */
    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl = &cl_ctr_clusters[i];
	if (!cl->peers)
	    continue;
	if (cl->peers->count <= 1) {
	    LM_INFO("clusterer_controller: [cluster %d] sole node, "
	            "skipping GOODBYE\n", cl->cluster_id);
	    continue;
	}
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
	    LM_ERR("clusterer_controller: [cluster %d] goodbye socket(): %s\n",
	           cl->cluster_id, strerror(errno));
	    continue;
	}
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	/* Derive session_key locally from master_salt in shm so we can encrypt
	 * GOODBYE - the worker's cl->session_key is in a different process. */
	{
	    size_t plen = strlen(cl->password);
	    cl_ctr_hkdf_sha256((unsigned char *)cl->password, plen,
	                   cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ,
	                   "cl_ctr_session", cl->session_key);
	}
	cl_ctr_send_pkt_with_ip(sock, CL_CTR_PKT_GOODBYE, cl, NULL, 0);
	close(sock);
	LM_INFO("clusterer_controller: [cluster %d] GOODBYE sent\n",
	        cl->cluster_id);
    }

cleanup:
    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl = &cl_ctr_clusters[i];
	if (!cl->peers)
	    continue;
	if (cl->peers->lock) {
	    lock_destroy_rw(cl->peers->lock);
	    cl->peers->lock = NULL;
	}
	shm_free(cl->peers);
	cl->peers = NULL;
    }
    LM_INFO("clusterer_controller: shut down\n");
}
