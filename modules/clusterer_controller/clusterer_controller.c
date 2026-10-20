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

static void cl_ctr_retx_enqueue(cl_ctr_cluster_t *cl, uint32_t seq, unsigned char type,
                            const unsigned char *pkt, int pkt_len,
                            const struct sockaddr *dest, socklen_t destlen);
static int mod_init(void);
static int cl_ctr_child_init(int rank);
static void mod_destroy(void);
const unsigned char CL_CTR_PACKET_MAGIC[CL_CTR_MAGIC_SZ]    = { CL_CTR_WIRE_MAGIC0, 0x00 };
const unsigned char CL_CTR_BOOTSTRAP_MAGIC[CL_CTR_MAGIC_SZ] = { CL_CTR_WIRE_MAGIC0, 0x01 };
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
int   query_time        = 5;
static char *password          = CL_CTR_DEFAULT_PASSWORD; /* default; falls back per cluster */
static char *on_config_mismatch_s = NULL;              /* raw modparam string   */
int   on_config_mismatch   = CL_CTR_CFGMISMATCH_REJECT; /* resolved; default reject */

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
int cc_mtu = 0;
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
int cc_mtu_now = 0;
/* Consecutive polls that disagreed with cc_mtu (see CL_CTR_MTU_DRIFT_STRIKES). */
int cc_mtu_drift_strikes = 0;
/* Consecutive polls that could not read the MTU at all.  Tracked separately
 * from the drift strikes because a failed read is not evidence of anything -
 * see cl_ctr_mtu_step(). */
int cc_mtu_read_fails = 0;

/**
 * cl_ctr_read_iface_mtu() - current MTU of the interface we run the plane on.
 *
 * Returns the kernel's value, or -1 if it cannot be read.  This is the ONLY
 * source of MTU truth in the module; there is no configured alternative to
 * fall back to, by design.
 */
int cl_ctr_read_iface_mtu(void)
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
int cl_ctr_mtu_step(int now_mtu, int joined_mtu, int *strikes, int *fails)
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
uint64_t cl_ctr_incarnation                      = 0;

/* clusterer integration - loaded at mod_init if clusterer use_controller=1 */
clusterer_ctrl_binds_t clctl;
int                    clctl_loaded  = 0;
int                    manage_shtags = 1;
int                    consumer_retries = CL_CTR_CONSUMER_RETRIES_DEFAULT;
int                    consumer_retry_ms = CL_CTR_CONSUMER_RETRY_MS_DEFAULT;
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
int                    master_stickiness = 1;
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

unsigned int ip_to_num(const char *ip)
{
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0)
	return 0;
    return ntohl(addr.s_addr);
}

void cl_ctr_prune_stale(cl_ctr_cluster_t *cl)
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
void cl_ctr_apply_master_from_list_locked(const char *master_ip, cl_ctr_cluster_t *cl)
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
cl_ctr_peer_t *cl_ctr_peer_by_ip_locked(cl_ctr_cluster_t *cl, const char *ip)
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
void cl_ctr_learn_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl)
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
void cl_ctr_upsert_peer_locked(const char *src_ip, cl_ctr_cluster_t *cl)
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
void cl_ctr_reserve_id_locked(cl_ctr_cluster_t *cl, const char *ip,
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
uint16_t cl_ctr_alloc_node_id_locked(cl_ctr_cluster_t *cl, const char *ip)
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
void cl_ctr_update_peer_bin_locked(const char *ip, uint16_t node_id,
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
int cl_ctr_random_bytes(unsigned char *buf, size_t len)
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

int cl_ctr_gen_ecdh_keypair(unsigned char *privkey, unsigned char *pubkey)
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
int cl_ctr_noise_read2(cl_ctr_symstate_t *s, const unsigned char e_priv[32],
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
int cl_ctr_derive_session_key(cl_ctr_cluster_t *cl)
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

const char *cl_ctr_cid_state_name(int st)
{
    switch (st) {
    case CL_CTR_CID_PROVISIONAL: return "provisional";
    case CL_CTR_CID_ESTABLISHED: return "established";
    case CL_CTR_CID_PINNED:      return "pinned";
    default:                     return "none";
    }
}

/* "8-4-4-4-12" lowercase into @out (37 bytes) */
void cl_ctr_cid_str(const unsigned char *cid, char *out)
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

int cl_ctr_cid_is_zero(const unsigned char *cid)
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
void cl_ctr_cid_adopt(cl_ctr_cluster_t *cl, const unsigned char *cid,
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
void cl_ctr_cid_found(cl_ctr_cluster_t *cl)
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
void cl_ctr_cid_tick(cl_ctr_cluster_t *cl)
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
int cl_ctr_decrypt_pkt(char *buf, ssize_t n, const char *sender_ip,
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
int cl_ctr_check_and_update_seq(const char *sender_ip, uint32_t pkt_seq,
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

int cl_ctr_setup_socket(cl_ctr_cluster_t *cl)
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
void cl_ctr_retx_flush(cl_ctr_cluster_t *cl)
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
void cl_ctr_handle_ack(const char *payload, int payload_len,
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
int cl_ctr_on_retx_tfd(int fd, void *param, int was_timeout)
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
void cl_ctr_send_ack(int sock, cl_ctr_cluster_t *cl, uint32_t acked_seq,
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
void cl_ctr_send_pkt_with_ip(int sock, unsigned char type, cl_ctr_cluster_t *cl,
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

/**
 * cl_ctr_send_list_pkt() - encrypt and multicast the active peer table.
 *
 * Wire: [magic 2B][cluster_id 2B][nonce 24B][XChaCha20-Poly1305([type 1B][seq 4B][count 2B][entries...])][tag 16B]
 */
void cl_ctr_send_list_pkt(int sock, unsigned char type, cl_ctr_cluster_t *cl,
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

/**
 * cl_ctr_send_join_req_pkt() - send CL_CTR_PKT_JOIN_REQ with BIN socket info.
 *
 * Payload: [ip NUL][bin_count 1B][sock1 NUL]...[sockN NUL]
 */
void cl_ctr_send_join_req_pkt(int sock, cl_ctr_cluster_t *cl)
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
void cl_ctr_send_node_assign(int sock, const char *ip, uint16_t node_id,
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
void cl_ctr_membership_digest(cl_ctr_cluster_t *cl, uint16_t *count, uint64_t *hash)
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
void cl_ctr_sockaddr_in(const char *ip, int port, struct sockaddr_in *out)
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
void cl_ctr_apply_alive_bitmap(cl_ctr_cluster_t *cl, const unsigned char *bm)
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
void cl_ctr_send_master_alive(int sock, cl_ctr_cluster_t *cl)
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
void cl_ctr_send_resync(int sock, cl_ctr_cluster_t *cl,
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
void cl_ctr_send_master_beacon(int sock, cl_ctr_cluster_t *cl)
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
void cl_ctr_send_key_grant(int sock, const char *target_ip, cl_ctr_cluster_t *cl,
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
void cl_ctr_send_key_handoff(int sock, const char *next_master_ip,
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
void cl_ctr_drop_peer_locked(const char *ip, cl_ctr_cluster_t *cl)
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
