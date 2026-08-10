/*
 * cachedb_perf - high-performance local memory cache
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fnmatch.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../statistics.h"
#include "../../mi/mi.h"
#include "../../mi/item.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../../timer.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../lib/csv.h"
#include "../../evi/evi_modules.h"
#include "../../bin_interface.h"
#include <sys/eventfd.h>
#include <poll.h>
#include "../clusterer/api.h"
#ifdef CLUSTERER_CTRL_SUPPORT
/* Optional at build time: the controller offers an alternative (encrypted
 * multicast) transport for pulls, but cachedb_perf must never require it.
 * Without this flag every pull and sync rides the clusterer's bin links. */
#include "../clusterer_controller/api.h"
#endif
#include "pull_api.h"

#include "cachedb_perf.h"
#include "pcache_mem.h"
#include "pcache_arena.h"
#include "pcache_htable.h"
#include "pcache_db.h"

str pcache_mod_name = str_init("perf");

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

pcache_col_t *pcache_collection = NULL;
pcache_url_t *pcache_url_list = NULL;
/* the collection behind the engine's default (groupless) connection -
 * what cache_store("perf", ...) writes to; the glob functions default
 * to it so both views always agree */
static pcache_col_t *pcache_default_col = NULL;
static int arena_selftest = 0;
static int htable_selftest = 0;
extern int pcache_arena_hugepage_mb;
static int expiry_sweep_period = 1;   /* seconds; 0 disables the sweep */
/* CP-09 growth: split buckets while entries/nbuckets exceeds this; 0 = off.
 * Default 2 keeps load factor low so the 84 ns bucket shape holds at scale -
 * the whole reason this module exists (cachedb_local cannot resize). */
static int growth_load_factor = 2;
static int growth_budget = 4096;      /* max splits per maintenance tick */

/* ---- CP-11 observability events ---- */
static str evi_expired_name  = str_init("E_CACHEDB_PERF_EXPIRED");
static str evi_nomem_name    = str_init("E_CACHEDB_PERF_NOMEM");
static str evi_grown_name    = str_init("E_CACHEDB_PERF_GROWN");
static str evi_degraded_name = str_init("E_CACHEDB_PERF_MEM_DEGRADED");
static event_id_t evi_expired_id  = EVI_ERROR;
static event_id_t evi_nomem_id    = EVI_ERROR;
static event_id_t evi_grown_id    = EVI_ERROR;
static event_id_t evi_degraded_id = EVI_ERROR;
/* event parameter names */
static str evp_collection   = str_init("collection");
static str evp_key          = str_init("key");
static str evp_size         = str_init("size");
static str evp_buckets      = str_init("buckets");
static str evp_prev_buckets = str_init("prev_buckets");
static str evp_splits       = str_init("splits");
static str evp_entries      = str_init("entries");
static str evp_tier         = str_init("tier");
static str evp_backing      = str_init("backing");
static str evp_requested_mb = str_init("requested_mb");
static str evp_overcommit   = str_init("overcommit_pages");
/* CSV of collections opted in to E_CACHEDB_PERF_EXPIRED (per-collection so a
 * high-churn collection reaping in bulk pays only if it asked to); "" = none */
static char *event_expired_collections = NULL;

/* ---- CP-19 DB persistence ---- */
static char *db_url = NULL;                    /* a db_* backend URL */
static char *db_table = (char *)"cachedb_perf";
/* 0 = off, 1 = load on startup, 2 = load on startup + save on shutdown */
static int db_mode = 0;
/* CSV of the collections that auto load/save with db_mode; "" = none */
static char *persist_collections = NULL;

/* ---- CP-19 Stage 2: cluster sync (save-then-broadcast, pull-from-DB) ---- */
static struct clusterer_binds clusterer_api;
static str pcache_sync_cap = str_init("cachedb-perf-sync");
static int sync_cluster_id = 0;        /* modparam; 0 = off */
static char *sync_shtag_str;           /* modparam "name/cluster_id"; failover sync */
static str  pc_shtag;                  /* parsed tag name                    */
static int  pc_shtag_cid;              /* parsed tag cluster                 */

/* ---- CP-15.5: cross-node pull ---------------------------------------- */
/* CP-15.5 cross-node pull, on the same capability as the sync packets */
#define PCACHE_PULL_REQ     2
#define PCACHE_PULL_RPL     3

#define PCACHE_PULL_SLOTS      64     /* concurrent in-flight pulls        */
/* Defaults for the pull_max_value / pull_max_key modparams below. Sized from
 * measurement rather than round numbers: the live cachedb_perf collections on
 * the billing gateways hold values of 1-20 bytes under keys of at most 33, and
 * sql_cacher's are ~70 bytes. 512/128 is roughly 25x and 4x that headroom.
 *
 * dns_cache is the deliberate exception - it serialises whole record sets and
 * runs to several KB with no real bound - which is exactly why these are
 * configurable instead of constants. A dns_cache deployment raises
 * pull_max_value and accepts a larger slot (hence fewer slots for the same
 * memory); everything above the cap already degrades through the existing
 * PCACHE_FOUND_OVERSIZE path, so the cost is "not pulled cross-node", never a
 * wrong answer. */
#define PCACHE_PULL_MAX_VAL_DEF  512
#define PCACHE_PULL_MAX_KEY_DEF  128
/* Hard ceilings for the runtime caps below. They stay compile-time because
 * three per-call scratch buffers are stack arrays and the negative-cache slot
 * embeds a key inline - a modparam able to grow those without bound would
 * trade a queue limit for a stack overflow. */
#define PCACHE_PULL_MAX_VAL    8192
#define PCACHE_PULL_MAX_KEY    256
#define PCACHE_NEG_SLOTS       256    /* direct-mapped negative cache      */
/* how long past its deadline a woken slot is left for its caller to come
 * back and finish() before the reaper takes it away regardless */
#define PCACHE_PULL_ABANDON_US (5 * 1000000)
/* a peer that answered within this many seconds is treated as answering;
 * beyond it we only know it HAS answered at some point, not that it still
 * would - which is why the raw counters are reported beside the verdict */
#define PCACHE_PEER_FRESH_S    300
#define CL_MAX_NODE_ID         256    /* the cluster stack's design cap    */
static char *pull_transport_str;       /* "bin" (default) | "clctr"          */
static int   pull_max_value  = PCACHE_PULL_MAX_VAL_DEF;
static int   pull_max_key    = PCACHE_PULL_MAX_KEY_DEF;
/* byte offsets into a slot, computed once from the caps above - the key and
 * value buffers are no longer fixed members, so slots are sized at init */
static int   pull_slot_sz;
static int   pull_timeout_ms = 50;     /* how long a miss waits for peers    */
/* Optional extra bound on how late an answer may be and still be stored.
 *
 * 0 (default) = no time bound: what makes a late answer valid is that the
 * VALUE is still valid, and the value carries its own expiry.  A peer reports
 * ttl_left in RELATIVE seconds and we add it to our own clock, so nothing
 * here needs the cluster's clocks to agree.  The practical ceiling is the
 * slot's own life, PCACHE_PULL_ABANDON_US.
 *
 * Set it non-zero only where the script DELETES keys from a replicated
 * collection: store-if-absent cannot tell "never had it" from "deleted a
 * moment ago", so a peer's copy could resurrect a key the script removed.
 * A deployment that only writes and lets TTLs expire cannot hit that. */
static int   pull_linger_ms = 0;
static char *replicate_collections;    /* CSV opt-in; nothing pulls by default */
static int   pull_ready;               /* transport up AND a collection opted in */

/* CP-15.8: the pull may ride the controller's encrypted multicast plane
 * instead of the clusterer's TCP mesh.  One query becomes one packet
 * regardless of cluster size, and it is encrypted - which the BIN links
 * are not.  Everything above the transport is identical; only how a
 * request leaves and a reply comes back changes. */
#ifdef CLUSTERER_CTRL_SUPPORT
static clctr_api_t clctr_api;
static str  pull_channel = str_init("cdbperf-pull");
#endif
/* stays 0 for the whole run when the controller is not compiled in */
static int  pull_via_clctr;

/* flat wire format for the controller plane, which carries bytes rather
 * than the BIN push/pop stream.  All integers network order.
 *   request: [u8 REQ][u32 id][u8 collen][col][u16 klen][key]
 *   reply:   [u8 RPL][u32 id][u8 found][u32 ttl][u16 klen][key][u16 vlen][val]
 * @found: 0 = not here, 1 = value follows, 2 = held but too big to send. */
#define PCACHE_CLCTR_REQ  1
#define PCACHE_CLCTR_RPL  2
/* fixed bytes of each framing, so the size checks and the budget the serve
 * path hands out cannot drift from what the writers actually emit */
#define PCACHE_CLCTR_REQ_HDR  8    /* type + id + collen + klen           */
#define PCACHE_CLCTR_RPL_HDR  14   /* type + id + found + ttl + klen+vlen */
#define PCACHE_FOUND_NO       0
#define PCACHE_FOUND_YES      1
#define PCACHE_FOUND_OVERSIZE 2

/* One in-flight pull.  The request is issued by whichever process took the
 * miss, but the replies land in whichever process the transport delivers
 * them to - so the rendezvous has to live in shm, keyed by request id.
 * (Today the requester polls this slot; the async work of CP-15.9 replaces
 * the poll with an eventfd it registers here, and nothing else changes.) */
struct pcache_pull_slot {
	unsigned int id;                 /* 0 = free                          */
	int          efd;                /* readable once an answer landed    */
	/* absolute us, like the negative cache: a pull that never gets a
	 * conclusive answer has to be reclaimed on time, and second-grained
	 * ticks would hold a SIP transaction up to a second past a timeout
	 * the operator set in milliseconds */
	utime_t      deadline;
	/* the reaper woke this slot; do not keep re-arming the eventfd on
	 * every tick while the consumer works its way back to finish() */
	int          reaped;
	unsigned int gen;                /* membership generation at dispatch */
	int          expect;             /* peers we asked                    */
	int          negative;           /* peers that answered "not here"    */
	/* which nodes have answered, so a repeated reply cannot be counted
	 * twice - two negatives from one node would otherwise reach @expect
	 * and manufacture a "nobody has it" that nobody said */
	unsigned char answered[(CL_MAX_NODE_ID + 7) / 8];
	int          done;               /* 1 = a value landed                */
	int          oversize;           /* a peer HAS it but could not send  */
	int          hinted;             /* asked one node, not the cluster   */
	int          partial;            /* more peers than the snapshot held */
	/* The waiter left without a value and handed this slot to the protocol
	 * rather than the pool: an answer may still be in flight, and the slot
	 * holds the only record of which collection and key it belongs to (the
	 * reply carries neither).  A late answer that lands here is stored by
	 * pcache_pull_do_reply() instead of being dropped.  Reclaimed by the
	 * reaper at deadline + PCACHE_PULL_ABANDON_US, or stolen sooner if the
	 * pool runs dry. */
	int          orphan;
	unsigned int expires;            /* ABSOLUTE, as the owner holds it   */
	unsigned int vlen;
	int          klen;
	char         col[64];
	int          collen;
	/* key[pull_max_key] then val[pull_max_value] follow this header; reach
	 * them with pull_slot_key()/pull_slot_val(). Kept as a trailing blob
	 * rather than two fixed arrays so the caps can be configured without
	 * every slot paying for the largest value anyone might ever store. */
	char         buf[];
};

#define pull_slot_key(sl)  ((sl)->buf)
#define pull_slot_val(sl)  ((sl)->buf + pull_max_key)
#define pull_slot_at(i)    ((struct pcache_pull_slot *)((char *)pull_slots \
                            + (size_t)(i) * pull_slot_sz))
static struct pcache_pull_slot *pull_slots;
static gen_lock_t *pull_lock;
static unsigned int *pull_next_id;     /* shm: ids must be unique per node  */

/* pull counters, deliberately separate from hits/misses so a pulled key
 * cannot flatter the local hit rate (R6) */
/* Pull counters.  In shm and bumped from several processes - the request
 * side runs in whichever worker took the miss, the reply and serve sides in
 * whichever one the transport picked - so the increments are atomic.  A
 * plain ++ would drop counts under exactly the load worth measuring.  This
 * is one shared line, which the module forbids on the hot path (CP-06); a
 * cross-node miss is not the hot path. */
static unsigned int *pull_stats;       /* PULL_ST_* counters */
/* Rate-limit state for the send-failure warning (pull_send_failed()).  In shm
 * rather than a plain static because a pull reply goes out from whichever
 * worker happened to receive the request: a per-process limiter would let all
 * ~30 SIP workers warn once per interval each. */
static struct pcache_send_warn {
	unsigned int last;        /* get_ticks() when we last warned */
	unsigned int suppressed;  /* failures folded into the next warning */
} *pull_send_warn;

/* Negative cache (R4).  A key that is genuinely nowhere costs a full
 * round of questions, and SIP retransmits ask again a few hundred
 * milliseconds later - so remember "nobody had it" just long enough to
 * absorb the retransmit, and no longer: the key may legitimately be
 * created on another node a second from now, and a negative that outlives
 * that turns a transient miss into a hard failure.
 *
 * Kept out of the cache proper, deliberately: a negative is not a value.
 * Putting it in the table would make perf_keys and perf_dump show keys
 * that do not exist and would count in the entry total.  Direct-mapped,
 * so a fresh negative may evict an older one - losing one only costs a
 * repeated question. */
struct pcache_neg_slot {
	unsigned int hash;               /* 0 = free                        */
	utime_t      deadline;           /* absolute us                     */
	int          klen, collen;
	char         key[PCACHE_PULL_MAX_KEY];
	char         col[64];
};
static struct pcache_neg_slot *neg_slots;
static gen_lock_t *neg_lock;
static int pull_negative_ms = 300;     /* modparam; 0 = no negative cache  */
static int pull_on_miss;               /* modparam; read repair on the get path */
#define PULL_ST_REQUESTED 0
#define PULL_ST_SERVED    1
#define PULL_ST_RECEIVED  2
#define PULL_ST_TIMEOUT   3
#define PULL_ST_STORED    4
#define PULL_ST_SUPPRESSED 5   /* asks a cached negative absorbed */
/* slots the reaper had to release because the caller never collected them -
 * distinct from a timeout, which the caller DID collect */
#define PULL_ST_ABANDONED 6
/* A pull datagram the transport refused to send.  Distinct from a TIMEOUT:
 * the request never left this node, so no peer was ever given the chance to
 * answer it. */
#define PULL_ST_SEND_FAIL 7
/* a waiter left without a value and the slot was kept for a late answer */
#define PULL_ST_ORPHANED  8
/* that late answer arrived and was stored - convergence the old code lost */
#define PULL_ST_LATE_STORED 9
/* an orphan's slot was reclaimed early because the pool ran dry */
#define PULL_ST_ORPHAN_EVICTED 10
/* a late answer arrived but a local write had already filled the key */
#define PULL_ST_LATE_SUPERSEDED 11
/* a late answer landed after pull_linger_ms and was refused as too stale */
#define PULL_ST_LATE_EXPIRED 12
/* an orphan reached the end of its life with no late answer - the ordinary
 * outcome of a timeout, and explicitly NOT an abandoned slot: its caller DID
 * collect it, which is the distinction PULL_ST_ABANDONED exists to make */
#define PULL_ST_ORPHAN_EXPIRED 13
#define PULL_ST_MAX       14
/* Two different readinesses, deliberately kept apart:
 *   cluster_ready - the clusterer is bound, the capability is registered and
 *                   membership is being tracked.  Everything cross-node needs
 *                   this and nothing more.
 *   sync_ready    - that, plus a DB to snapshot through.  Only perf_sync and
 *                   the failover hook need it, because only they use the DB.
 * Conflating them made a cache that only ever pulls demand a database it
 * never touches. */
static int cluster_ready = 0;
static int sync_ready = 0;             /* cluster_ready + a usable db_url */

/* Cluster membership view (CP-15.4).  The clusterer node list changes at
 * runtime (under clusterer_controller, on every join/leave/eviction), so
 * anything that fans work out to peers must snapshot the member set and
 * notice when it changed mid-flight.  The event callback below maintains
 * this shm view; `generation` is the load-bearing field - a future
 * cross-node pull snapshots it together with its responder set and
 * re-checks it on completion, because an absence conclusion drawn across
 * a membership change is unsafe.  Counters are monitoring-grade: plain
 * stores + atomic bumps, no lock (events are rare and single-field). */
struct pcache_cluster_view {
	unsigned int generation;     /* bumped on every UP/DOWN            */
	unsigned int node_ups;       /* lifetime UP events                 */
	unsigned int node_downs;     /* lifetime DOWN events               */
	unsigned int last_change;    /* ticks of the latest event, 0=never */
	int          last_node;      /* node id of the latest event        */
	int          last_was_up;    /* 1 = UP, 0 = DOWN                   */
};
static struct pcache_cluster_view *pc_view;

/* What each peer has actually done for us, as opposed to what the clusterer
 * says about it.  The two can disagree in the way that matters most: the
 * membership can read perfectly healthy while the transport carrying pulls
 * is dropping every packet, and a bare peer COUNT cannot show that.  Keyed
 * by node id (1..CL_MAX_NODE_ID); monitoring-grade, so atomic bumps and no
 * lock. */
struct pcache_peer_stat {
	unsigned int replies;        /* answers of any kind received from it */
	unsigned int values;         /* of those, ones that carried a value  */
	unsigned int served;         /* answers WE sent to it                */
	unsigned int last_reply;     /* ticks of its last answer, 0 = never  */
};
static struct pcache_peer_stat *peer_stats;   /* [CL_MAX_NODE_ID + 1] */

static inline void peer_note_reply(int node_id, int carried_value)
{
	if (!peer_stats || node_id <= 0 || node_id > CL_MAX_NODE_ID)
		return;
	__sync_fetch_and_add(&peer_stats[node_id].replies, 1);
	if (carried_value)
		__sync_fetch_and_add(&peer_stats[node_id].values, 1);
	peer_stats[node_id].last_reply = get_ticks();
}

static inline void peer_note_served(int node_id)
{
	if (!peer_stats || node_id <= 0 || node_id > CL_MAX_NODE_ID)
		return;
	__sync_fetch_and_add(&peer_stats[node_id].served, 1);
}

static void pcache_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev != CLUSTER_NODE_UP && ev != CLUSTER_NODE_DOWN)
		return;   /* sync-protocol events: we register startup_sync=0 */
	if (!pc_view)
		return;

	pc_view->last_node   = node_id;
	pc_view->last_was_up = (ev == CLUSTER_NODE_UP);
	pc_view->last_change = get_ticks();
	if (ev == CLUSTER_NODE_UP)
		__sync_fetch_and_add(&pc_view->node_ups, 1);
	else
		__sync_fetch_and_add(&pc_view->node_downs, 1);
	__sync_fetch_and_add(&pc_view->generation, 1);

	LM_INFO("cluster %d membership: node %d went %s (generation %u)\n",
		sync_cluster_id, node_id, ev == CLUSTER_NODE_UP ? "UP" : "DOWN",
		pc_view->generation);
}

/* Snapshot the live peer set (the clusterer list holds peers only, not
 * this node) plus the membership generation it was taken under.  A caller
 * that fans work out to these peers re-reads the generation afterwards:
 * a change means the set went stale mid-flight.  Returns the number of
 * ids written, or -1 when cluster sync is not active.
 *
 * @truncated, when given, says the cluster held more peers than fitted.
 * A caller that concludes something from the whole set answering - the
 * pull deciding a key is absent - must not draw that conclusion from a
 * partial set, because the peers it never counted are exactly the ones
 * that might have had it. */
static int pcache_cluster_members(int *ids, int max, unsigned int *gen,
		int *truncated)
{
	clusterer_node_t *list, *n;
	int cnt = 0;

	if (truncated)
		*truncated = 0;
	if (!cluster_ready || !pc_view)
		return -1;
	if (gen)
		*gen = pc_view->generation;
	list = clusterer_api.get_nodes(sync_cluster_id);
	for (n = list; n; n = n->next) {
		if (cnt >= max) {
			if (truncated)
				*truncated = 1;
			break;
		}
		ids[cnt++] = n->node_id;
	}
	if (list)
		clusterer_api.free_nodes(list);
	return cnt;
}
#define PCACHE_SYNC_RELOAD  1
#define PCACHE_SYNC_VERSION 1
/* raised on a node that reloaded because a peer issued perf_sync */
static str evi_synced_name = str_init("E_CACHEDB_PERF_SYNCED");
static event_id_t evi_synced_id = EVI_ERROR;
static str evp_source_node = str_init("source_node");
static void pcache_raise_synced(str *coll, int src_node);
/* huge pages requested but the granted tier is sub-optimal; raised once from
 * the first maintenance tick, since EVI has no subscribers yet at mod_init.
 * The one-shot gate is in shm with an atomic test-and-set, so exactly one
 * process raises it however many run the timer */
static int mem_degraded = 0;
static int *mem_degraded_gate = NULL;

static int pcache_parse_collections(unsigned int type, void *val);
static int pcache_store_urls(unsigned int type, void *val);
static int w_perf_del(struct sip_msg *msg, str *glob, str *col_s);
static int w_perf_mget(struct sip_msg *msg, str *glob, pv_spec_t *keys_pv,
		pv_spec_t *vals_pv, str *col_s, int *limit);
static int w_perf_mget_json(struct sip_msg *msg, str *glob, pv_spec_t *dst_pv,
		str *col_s, int *limit);
static int w_perf_sync(struct sip_msg *msg, str *col_s);
static int fixup_check_wvar(void **param);

/* introspection MI (CP-18) - defined just above the mi_cmds table; these
 * forward decls let that table sit before the glob/collection helpers */
static pcache_col_t *col_by_name(const str *name);
static mi_response_t *mi_perf_cluster_probe_0(const mi_params_t *params,
		struct mi_handler *async);
static mi_response_t *mi_perf_cluster_probe_1(const mi_params_t *params,
		struct mi_handler *async);
int load_pcache_pull(pcache_pull_api_t *api);
static int pcache_pull_start(pcache_col_t *col, const str *key,
		int hint_node, int *fd, unsigned int *id_out);
static int pcache_pull_key(pcache_col_t *col, const str *key, char *out,
		unsigned int outlen, unsigned int *vlen, unsigned int *expires);
static int pcache_pull_enabled(pcache_col_t *col);
static char *glob_dup(const str *glob);
static int perf_del_run(pcache_col_t *col, str *glob);
static inline unsigned int ttl_to_abs(int expires);

#define PERF_ROUTES (REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|\
	LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE)

static const cmd_export_t cmds[] = {
	{"load_pcache_pull", (cmd_function)load_pcache_pull, {{0,0,0}}, 0},
	{"perf_del", (cmd_function)w_perf_del, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		PERF_ROUTES},
	{"perf_mget", (cmd_function)w_perf_mget, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,fixup_check_wvar,0},
		{CMD_PARAM_VAR,fixup_check_wvar,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		PERF_ROUTES},
	{"perf_mget_json", (cmd_function)w_perf_mget_json, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,fixup_check_wvar,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		PERF_ROUTES},
	{"perf_sync", (cmd_function)w_perf_sync, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		PERF_ROUTES},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[] = {
	{ "cache_collections", STR_PARAM|USE_FUNC_PARAM,
		(void *)pcache_parse_collections },
	{ "cachedb_url",       STR_PARAM|USE_FUNC_PARAM,
		(void *)pcache_store_urls },
	{ "arena_selftest",    INT_PARAM, &arena_selftest },
	{ "htable_selftest",   INT_PARAM, &htable_selftest },
	{ "arena_hugepage_mb", INT_PARAM, &pcache_arena_hugepage_mb },
	{ "expiry_sweep_period", INT_PARAM, &expiry_sweep_period },
	{ "growth_load_factor",  INT_PARAM, &growth_load_factor },
	{ "growth_budget",       INT_PARAM, &growth_budget },
	{ "event_expired_collections", STR_PARAM, &event_expired_collections },
	{ "db_url",              STR_PARAM, &db_url },
	{ "db_table",            STR_PARAM, &db_table },
	{ "db_mode",             INT_PARAM, &db_mode },
	{ "persist_collections", STR_PARAM, &persist_collections },
	{ "sync_cluster_id",     INT_PARAM, &sync_cluster_id },
	{ "sync_shtag",          STR_PARAM, &sync_shtag_str },
	{ "pull_transport",      STR_PARAM, &pull_transport_str },
	{ "pull_timeout_ms",     INT_PARAM, &pull_timeout_ms },
	{ "pull_linger_ms",      INT_PARAM, &pull_linger_ms },
	{ "pull_negative_ms",    INT_PARAM, &pull_negative_ms },
	{ "pull_on_miss",        INT_PARAM, &pull_on_miss },
	{ "pull_max_value",      INT_PARAM, &pull_max_value },
	{ "pull_max_key",        INT_PARAM, &pull_max_key },
	{ "replicate_collections", STR_PARAM, &replicate_collections },
	{0,0,0}
};

/*
 * CP-06 statistics: everything is STAT_IS_FUNC - sums of the per-process
 * shards computed at read time.  No shared counter is ever touched on the
 * hot path (DESIGN 2.5 hard rule).
 */
enum pcache_stat_field {
	PSF_HITS, PSF_MISSES, PSF_STORES, PSF_REMOVES, PSF_ENTRIES,
	PSF_RETRIES, PSF_FALLBACKS, PSF_EXPIRED, PSF_DESTROYED
};

static unsigned long pcache_stat_field(enum pcache_stat_field which)
{
	pcache_col_t *col;
	pcache_ht_totals_t t;
	unsigned long sum = 0;

	for (col = pcache_collection; col; col = col->next) {
		if (!col->htable)
			continue;
		pcache_ht_totals(col->htable, &t);
		switch (which) {
		case PSF_HITS:      sum += t.hits; break;
		case PSF_MISSES:    sum += t.misses; break;
		case PSF_STORES:    sum += t.stores; break;
		case PSF_REMOVES:   sum += t.removes; break;
		case PSF_EXPIRED:   sum += t.expired; break;
		case PSF_DESTROYED: sum += t.destroyed; break;
		case PSF_ENTRIES:   sum += t.entries; break;
		case PSF_RETRIES:   sum += t.retries; break;
		case PSF_FALLBACKS: sum += t.fallbacks; break;
		}
	}
	return sum;
}

#define PSTATF(_fn, _which) \
	static unsigned long _fn(void *ctx) \
	{ return pcache_stat_field(_which); }

PSTATF(smf_hits, PSF_HITS)
PSTATF(smf_misses, PSF_MISSES)
PSTATF(smf_stores, PSF_STORES)
PSTATF(smf_removes, PSF_REMOVES)
PSTATF(smf_expired, PSF_EXPIRED)
PSTATF(smf_destroyed, PSF_DESTROYED)
PSTATF(smf_entries, PSF_ENTRIES)
PSTATF(smf_retries, PSF_RETRIES)
PSTATF(smf_fallbacks, PSF_FALLBACKS)

/*
 * Cross-node pull statistics.
 *
 * These mirror what perf_stats already reports, but as module statistics so
 * Prometheus scrapes them - without that, the only evidence a dashboard has
 * that read repair is working is the entry count rising, which shows the
 * RESULT and not the mechanism: a node whose every pull times out looks
 * exactly like one that simply has no misses.
 *
 * pull_stats[] is shm and only exists once the pull layer came up, so every
 * accessor tolerates it being NULL (pull disabled, or a config that never
 * reached that far).
 */
static unsigned long pull_stat(int which)
{
	return pull_stats ? (unsigned long)pull_stats[which] : 0;
}

#define PULLSTATF(_fn, _which) \
	static unsigned long _fn(void *ctx) { return pull_stat(_which); }

/* Complain about a pull datagram that never left, at most once every
 * PCACHE_PULL_SEND_WARN_IVL seconds.
 *
 * This used to be LM_DBG, which made it unreachable on every deployed node:
 * log_level 3 is INFO and L_DBG is 4.  That is the wrong level for it - a send
 * that fails is invisible at the far end, so the requester simply times out,
 * and this line is the only direct evidence of why.  It is the actual cause
 * behind a class of "cross-node pull is slow / does not converge" reports.
 *
 * It cannot be an unconditional LM_WARN either: a partitioned or overloaded
 * peer fails every send, and an unbounded warn is its own incident.  So warn
 * on the first failure, then at most once per interval, carrying the count it
 * stands for.  The exact total is always available as pulls_send_failed.
 *
 * Two workers can pass the interval check at once and both warn.  That is
 * deliberate - it costs an occasional duplicate line and saves taking a lock
 * on a failure path. */
#define PCACHE_PULL_SEND_WARN_IVL 30

static void pull_send_failed(const char *what, int dst_node)
{
	unsigned int now = get_ticks(), held;
	char tgt[32];

	if (pull_stats)
		__sync_fetch_and_add(&pull_stats[PULL_ST_SEND_FAIL], 1);
	if (!pull_send_warn)
		return;

	if (pull_send_warn->last != 0 &&
	    now - pull_send_warn->last < PCACHE_PULL_SEND_WARN_IVL) {
		__sync_fetch_and_add(&pull_send_warn->suppressed, 1);
		return;
	}
	pull_send_warn->last = now;
	held = __sync_lock_test_and_set(&pull_send_warn->suppressed, 0);

	if (dst_node > 0)
		snprintf(tgt, sizeof tgt, "node %d", dst_node);
	else
		snprintf(tgt, sizeof tgt, "the cluster");

	if (held)
		LM_WARN("cross-node pull: %s [%s], and %u more in the last %ds - "
			"whoever asked is timing out; see the pulls_send_failed "
			"statistic for the running total\n",
			what, tgt, held, PCACHE_PULL_SEND_WARN_IVL);
	else
		LM_WARN("cross-node pull: %s [%s] - whoever asked is timing out\n",
			what, tgt);
}

PULLSTATF(smf_pulls_requested,  PULL_ST_REQUESTED)
PULLSTATF(smf_pulls_served,     PULL_ST_SERVED)
PULLSTATF(smf_pulls_received,   PULL_ST_RECEIVED)
PULLSTATF(smf_pulls_timeout,    PULL_ST_TIMEOUT)
PULLSTATF(smf_pulls_stored,     PULL_ST_STORED)
PULLSTATF(smf_pulls_suppressed, PULL_ST_SUPPRESSED)
PULLSTATF(smf_pulls_abandoned,  PULL_ST_ABANDONED)
PULLSTATF(smf_pulls_send_failed, PULL_ST_SEND_FAIL)
PULLSTATF(smf_pulls_orphaned,   PULL_ST_ORPHANED)
PULLSTATF(smf_pulls_late_stored, PULL_ST_LATE_STORED)
PULLSTATF(smf_pulls_orphan_evicted, PULL_ST_ORPHAN_EVICTED)
PULLSTATF(smf_pulls_late_superseded, PULL_ST_LATE_SUPERSEDED)
PULLSTATF(smf_pulls_late_expired, PULL_ST_LATE_EXPIRED)
PULLSTATF(smf_pulls_orphan_expired, PULL_ST_ORPHAN_EXPIRED)

/* A GAUGE, unlike every other pull stat: it should read 0 whenever nothing is
 * being asked.  Anything parked here means slots are taken and not released,
 * which ends as "all pull slots busy" and silent loss of read repair - so it
 * is worth alerting on, where the counters are only worth graphing. */
static unsigned long smf_pulls_in_flight(void *ctx)
{
	unsigned long busy = 0;
	int k;

	if (!pull_slots || !pull_lock)
		return 0;
	lock_get(pull_lock);
	for (k = 0; k < PCACHE_PULL_SLOTS; k++)
		/* an orphan is not a pull in flight - nobody is waiting on it.
		 * This gauge is documented as the one that should sit at 0, so
		 * counting orphans would fire the leak alarm on the ordinary
		 * outcome of a timeout. */
		if (pull_slot_at(k)->id && !pull_slot_at(k)->orphan)
			busy++;
	lock_release(pull_lock);
	return busy;
}

/* Per-collection convergence, registered dynamically in mod_init (one pair per
 * declared collection) because the module-wide names above cannot say WHICH
 * collection is converging - and with a fetch-only collection like rtpdebug in
 * the mix, the aggregate is actively misleading.  @ctx is the collection. */
/*
 * "<collection>_<stat>" in shm, for a dynamically registered statistic.
 *
 * NOT build_stat_name(): that joins with a HYPHEN, which is fine for the
 * per-process pkmem statistics because those are STAT_HIDDEN and only their
 * group name is ever exported - but these are meant to be read individually,
 * and the prometheus module concatenates a statistic name verbatim with no
 * sanitising.  A hyphen is not legal in a Prometheus metric name, so
 * "default-pulled_from_cluster" would have produced a metric that breaks the
 * scrape rather than one that merely looks odd.
 */
static char *pcache_stat_name(pcache_col_t *col, const char *what)
{
	int n = col->col_name.len + 1 + strlen(what) + 1;
	char *s = shm_malloc(n);

	if (!s)
		return NULL;
	snprintf(s, n, "%.*s_%s", col->col_name.len, col->col_name.s, what);
	return s;
}

static unsigned long smf_col_pulled_in(void *ctx)
{
	return ctx ? ((pcache_col_t *)ctx)->pulled_in : 0;
}

static unsigned long smf_col_served_out(void *ctx)
{
	return ctx ? ((pcache_col_t *)ctx)->served_out : 0;
}

static unsigned long smf_arena_bytes(void *ctx)
{
	unsigned int c;
	unsigned long b;

	pcache_arena_stats(&c, &b);
	return b;
}

static unsigned long smf_arena_chunks(void *ctx)
{
	unsigned int c;
	unsigned long b;

	pcache_arena_stats(&c, &b);
	return c;
}

static unsigned long smf_mem_tier_probe(void *ctx)
{
	/* what this host is CAPABLE of - not necessarily what is in use,
	 * see smf_mem_tier_active() for that */
	return pcache_mem.tier;
}

static unsigned long smf_mem_tier_active(void *ctx)
{
	/* the tier ACTUALLY backing the dedicated arena_hugepage_mb
	 * reservation right now; reads as PCACHE_MEM_NO_ARENA (99) whenever
	 * arena_hugepage_mb is unset/0 or its reservation failed - which is
	 * also exactly when every cachedb_perf allocation is really going
	 * through shm_malloc(), so the true page backing is the CORE
	 * allocator's and is NOT measured here.  It used to read 4 (plain 4K),
	 * which was misread live as "the cache is on small pages" while it sat
	 * on HG_MALLOC's 2M hugepages.  See smf_hugepage_arena_active(). */
	return pcache_arena_tier();
}

static unsigned long smf_hugepage_arena_active(void *ctx)
{
	int active;
	unsigned long total, used, free;

	pcache_arena_hugepage_capacity(&active, &total, &used, &free);
	return active;
}

static unsigned long smf_hugepage_arena_total_bytes(void *ctx)
{
	int active;
	unsigned long total, used, free;

	pcache_arena_hugepage_capacity(&active, &total, &used, &free);
	return total;
}

static unsigned long smf_hugepage_arena_used_bytes(void *ctx)
{
	int active;
	unsigned long total, used, free;

	pcache_arena_hugepage_capacity(&active, &total, &used, &free);
	return used;
}

static unsigned long smf_hugepage_arena_free_bytes(void *ctx)
{
	int active;
	unsigned long total, used, free;

	pcache_arena_hugepage_capacity(&active, &total, &used, &free);
	return free;
}

static const stat_export_t mod_stats[] = {
	{"hits",            STAT_IS_FUNC, (stat_var **)smf_hits},
	{"misses",          STAT_IS_FUNC, (stat_var **)smf_misses},
	{"stores",          STAT_IS_FUNC, (stat_var **)smf_stores},
	{"removes",         STAT_IS_FUNC, (stat_var **)smf_removes},
	{"expired",         STAT_IS_FUNC, (stat_var **)smf_expired},
	{"destroyed",       STAT_IS_FUNC, (stat_var **)smf_destroyed},
	{"entries",         STAT_IS_FUNC, (stat_var **)smf_entries},
	{"seqlock_retries", STAT_IS_FUNC, (stat_var **)smf_retries},
	{"lock_fallbacks",  STAT_IS_FUNC, (stat_var **)smf_fallbacks},
	{"arena_bytes",     STAT_IS_FUNC, (stat_var **)smf_arena_bytes},
	{"arena_chunks",    STAT_IS_FUNC, (stat_var **)smf_arena_chunks},
	/* memory_tier renamed to memory_tier_probe (2026-08-07) - the old
	 * name was mistaken for "what's in use" live during a real
	 * diagnosis session; not shipped/stable API yet (module unmerged),
	 * so a rename is safe. See smf_mem_tier_probe()'s comment. */
	{"memory_tier_probe",  STAT_IS_FUNC, (stat_var **)smf_mem_tier_probe},
	{"memory_tier_active", STAT_IS_FUNC, (stat_var **)smf_mem_tier_active},
	{"hugepage_arena_active",      STAT_IS_FUNC, (stat_var **)smf_hugepage_arena_active},
	{"hugepage_arena_total_bytes", STAT_IS_FUNC, (stat_var **)smf_hugepage_arena_total_bytes},
	{"hugepage_arena_used_bytes",  STAT_IS_FUNC, (stat_var **)smf_hugepage_arena_used_bytes},
	{"hugepage_arena_free_bytes",  STAT_IS_FUNC, (stat_var **)smf_hugepage_arena_free_bytes},
	/* cross-node pull (CP-15).  Module-wide; the per-collection split is
	 * registered dynamically in mod_init - see smf_col_pulled_in(). */
	{"pulls_requested",  STAT_IS_FUNC, (stat_var **)smf_pulls_requested},
	{"pulls_served",     STAT_IS_FUNC, (stat_var **)smf_pulls_served},
	{"pulls_received",   STAT_IS_FUNC, (stat_var **)smf_pulls_received},
	{"pulls_timed_out",  STAT_IS_FUNC, (stat_var **)smf_pulls_timeout},
	{"pulls_stored",     STAT_IS_FUNC, (stat_var **)smf_pulls_stored},
	{"pulls_suppressed", STAT_IS_FUNC, (stat_var **)smf_pulls_suppressed},
	{"pulls_abandoned",  STAT_IS_FUNC, (stat_var **)smf_pulls_abandoned},
	{"pulls_send_failed", STAT_IS_FUNC, (stat_var **)smf_pulls_send_failed},
	{"pulls_orphaned",   STAT_IS_FUNC, (stat_var **)smf_pulls_orphaned},
	{"pulls_late_stored", STAT_IS_FUNC, (stat_var **)smf_pulls_late_stored},
	{"pulls_orphan_evicted", STAT_IS_FUNC,
		(stat_var **)smf_pulls_orphan_evicted},
	{"pulls_late_superseded", STAT_IS_FUNC,
		(stat_var **)smf_pulls_late_superseded},
	{"pulls_late_expired", STAT_IS_FUNC,
		(stat_var **)smf_pulls_late_expired},
	{"pulls_orphan_expired", STAT_IS_FUNC,
		(stat_var **)smf_pulls_orphan_expired},
	{"pulls_in_flight",  STAT_IS_FUNC, (stat_var **)smf_pulls_in_flight},
	{0,0,0}
};

/* the perf_stats MI (5.2): per-collection detail the flat stats cannot carry */
static int mi_stats_fill(mi_item_t *cobj, pcache_col_t *col)
{
	pcache_htable_t *ht = col->htable;
	pcache_ht_totals_t t;
	unsigned long reads;
	const char *note;
	double rate;
	char buf[32];
	int n;

	pcache_ht_totals(ht, &t);
	if (add_mi_string(cobj, MI_SSTR("name"),
	        col->col_name.s, col->col_name.len) < 0 ||
	    add_mi_number(cobj, MI_SSTR("buckets"), ht->nbuckets) < 0 ||
	    add_mi_number(cobj, MI_SSTR("entries"), t.entries) < 0 ||
	    add_mi_number(cobj, MI_SSTR("overflow"), ht->ovf_count) < 0 ||
	    add_mi_number(cobj, MI_SSTR("hits"), t.hits) < 0 ||
	    add_mi_number(cobj, MI_SSTR("misses"), t.misses) < 0 ||
	    add_mi_number(cobj, MI_SSTR("stores"), t.stores) < 0 ||
	    add_mi_number(cobj, MI_SSTR("removes"), t.removes) < 0 ||
	    add_mi_number(cobj, MI_SSTR("expired"), t.expired) < 0 ||
	    add_mi_number(cobj, MI_SSTR("destroyed"), t.destroyed) < 0 ||
	    add_mi_number(cobj, MI_SSTR("seqlock_retries"), t.retries) < 0 ||
	    add_mi_number(cobj, MI_SSTR("lock_fallbacks"), t.fallbacks) < 0)
		return -1;

	reads = t.hits + t.misses;
	rate = reads ? 100.0 * t.hits / reads : 0.0;
	n = snprintf(buf, sizeof buf, "%.1f", rate);
	if (add_mi_string(cobj, MI_SSTR("hit_rate_pct"), buf, n) < 0)
		return -1;
	/* The counters are cumulative since startup (or the last
	 * perf_stats_reset), so this is a lifetime average: right after a
	 * restart it is dragged down by every sequential request whose dialog
	 * predates the cache, and it recovers only as those age out.  Judge a
	 * running system on the trend between two polls, not on one reading. */
	if (!reads)
		note = "no lookups yet";
	else if (!t.stores)
		/* Every read has been a miss, but nothing has ever been stored
		 * either - there is no state to have been "lost" or "expired",
		 * this collection has simply never been written to (e.g. it
		 * loaded 0 entries from persistence at startup). A low rate
		 * here points at nothing reaching this collection at all, not
		 * at eviction/TTL tuning. */
		note = "no state has ever been stored in this collection - a miss "
		       "here is not loss or expiry, check whether writes reach "
		       "this collection and whether persistence loaded any rows";
	else if (rate >= 80.0)
		note = "healthy: the large majority of lookups hit";
	else if (rate >= 40.0)
		note = "fair: normal while the cache refills after a restart - "
		       "if it does not climb, state is expiring before it is used";
	else
		note = "low: cached state is being lost or is expiring before it "
		       "is used - expected only shortly after a restart";
	if (add_mi_string(cobj, MI_SSTR("hit_rate_note"), note, strlen(note)) < 0)
		return -1;

	/* Cluster sync is on-demand, so report WHEN this node last pushed or
	 * pulled rather than implying the caches match.  -1 = never.  Note the
	 * clusterer's own "Ok" for the cachedb-perf-sync capability only means
	 * it is registered and enabled - it says nothing about convergence. */
	if (sync_cluster_id > 0) {
		if (add_mi_number(cobj, MI_SSTR("pulled_from_cluster"),
		        col->pulled_in) < 0 ||
		    add_mi_number(cobj, MI_SSTR("served_to_cluster"),
		        col->served_out) < 0)
			return -1;
		if (add_mi_number(cobj, MI_SSTR("last_sync_out"),
		        col->last_sync_out ?
		            (int)(get_ticks() - col->last_sync_out) : -1) < 0 ||
		    add_mi_number(cobj, MI_SSTR("last_sync_in"),
		        col->last_sync_in ?
		            (int)(get_ticks() - col->last_sync_in) : -1) < 0 ||
		    add_mi_number(cobj, MI_SSTR("last_sync_source"),
		        col->last_sync_src) < 0)
			return -1;
	}

	n = snprintf(buf, sizeof buf, "%.3f",
		(double)t.entries / ht->nbuckets);
	if (add_mi_string(cobj, MI_SSTR("load_factor"), buf, n) < 0)
		return -1;
	reads = t.hits + t.misses;
	n = snprintf(buf, sizeof buf, "%.3f",
		reads ? 1000.0 * t.retries / reads : 0.0);
	return add_mi_string(cobj, MI_SSTR("retries_per_1k_reads"), buf, n);
}

static mi_response_t *mi_perf_stats(str *col_s)
{
	mi_response_t *resp;
	mi_item_t *obj, *arr, *cobj, *aobj, *hobj;
	pcache_col_t *col;
	const char *tier_probe, *tier_active;
	unsigned long bytes, hp_total, hp_used, hp_free;
	unsigned int nchunks, matched = 0;
	int hp_active;

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;

	arr = add_mi_array(obj, MI_SSTR("collections"));
	if (!arr)
		goto err;
	for (col = pcache_collection; col; col = col->next) {
		if (col_s && (col->col_name.len != col_s->len ||
		        memcmp(col->col_name.s, col_s->s, col_s->len)))
			continue;
		if (!col->htable)
			continue;
		cobj = add_mi_object(arr, NULL, 0);
		if (!cobj || mi_stats_fill(cobj, col) < 0)
			goto err;
		matched++;
	}
	if (col_s && !matched) {
		free_mi_response(resp);
		return init_mi_error(404, MI_SSTR("no such collection"));
	}

	/* "arena": total cachedb_perf usage regardless of which backing
	 * actually served it (dedicated reservation OR the shm_malloc
	 * fallback) - NOT specific to the dedicated arena_hugepage_mb
	 * reservation, see "hugepage_reservation" below for that. */
	aobj = add_mi_object(obj, MI_SSTR("arena"));
	if (!aobj)
		goto err;
	pcache_arena_stats(&nchunks, &bytes);
	if (add_mi_number(aobj, MI_SSTR("chunks"), nchunks) < 0 ||
	    add_mi_number(aobj, MI_SSTR("bytes"), bytes) < 0)
		goto err;

	/* _probe = what this host is CAPABLE of (startup capability check,
	 * see pcache_mem_probe()) - NOT proof anything is actually reserved.
	 * _active = the tier ACTUALLY backing the dedicated reservation
	 * right now; reads PCACHE_MEM_4K/"4K" whenever arena_hugepage_mb is
	 * unset/0 or its reservation failed, which is also exactly when
	 * every cachedb_perf allocation is really going through plain
	 * shm_malloc() - counted in core's own shmem: stats, not here. */
	tier_probe = pcache_mem_tier_str(pcache_mem.tier);
	tier_active = pcache_mem_tier_str(pcache_arena_tier());
	if (add_mi_number(obj, MI_SSTR("memory_tier_probe"), pcache_mem.tier) < 0 ||
	    add_mi_string(obj, MI_SSTR("memory_backing_probe"),
	        (char *)tier_probe, strlen(tier_probe)) < 0 ||
	    add_mi_number(obj, MI_SSTR("memory_tier_active"), pcache_arena_tier()) < 0 ||
	    add_mi_string(obj, MI_SSTR("memory_backing_active"),
	        (char *)tier_active, strlen(tier_active)) < 0)
		goto err;

	/* "hugepage_reservation": the DEDICATED arena_hugepage_mb reservation
	 * specifically - deliberately its OWN object, never folded into
	 * "arena" above or into core's shmem: stats, so a human or dashboard
	 * can never double-count or misattribute. "active" MUST be checked
	 * before trusting the byte counts - all three read 0 whenever no
	 * dedicated reservation exists, which is NOT the same thing as "a
	 * reservation exists and is currently empty". */
	hobj = add_mi_object(obj, MI_SSTR("hugepage_reservation"));
	if (!hobj)
		goto err;
	pcache_arena_hugepage_capacity(&hp_active, &hp_total, &hp_used, &hp_free);
	if (add_mi_number(hobj, MI_SSTR("active"), hp_active) < 0 ||
	    add_mi_number(hobj, MI_SSTR("total_bytes"), hp_total) < 0 ||
	    add_mi_number(hobj, MI_SSTR("used_bytes"), hp_used) < 0 ||
	    add_mi_number(hobj, MI_SSTR("free_bytes"), hp_free) < 0)
		goto err;

	/* Cluster membership, when sync is active.  peers_up counts the OTHER
	 * nodes the clusterer can currently reach; the generation ticks on
	 * every membership change, so two equal reads bracket a quiet period. */
	if (cluster_ready && pc_view) {
		mi_item_t *clobj = add_mi_object(obj, MI_SSTR("cluster"));
		int ids[CL_MAX_NODE_ID], nup;
		unsigned int gen = 0;

		if (!clobj)
			goto err;
		nup = pcache_cluster_members(ids, CL_MAX_NODE_ID, &gen, NULL);
		if (add_mi_number(clobj, MI_SSTR("cluster_id"), sync_cluster_id) < 0 ||
		    /* which of the peers below is us - the list holds peers only */
		    add_mi_number(clobj, MI_SSTR("my_node_id"),
		        clusterer_api.get_my_id ? clusterer_api.get_my_id() : 0) < 0 ||
		    add_mi_number(clobj, MI_SSTR("peers_up"), nup < 0 ? 0 : nup) < 0 ||
		    add_mi_number(clobj, MI_SSTR("membership_generation"), gen) < 0 ||
		    add_mi_number(clobj, MI_SSTR("node_ups"), pc_view->node_ups) < 0 ||
		    add_mi_number(clobj, MI_SSTR("node_downs"),
		        pc_view->node_downs) < 0 ||
		    add_mi_number(clobj, MI_SSTR("last_change_ago"),
		        pc_view->last_change ?
		            (int)(get_ticks() - pc_view->last_change) : -1) < 0)
			goto err;
		if (pull_ready && pull_stats &&
		    (add_mi_number(clobj, MI_SSTR("pulls_requested"),
		        pull_stats[PULL_ST_REQUESTED]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_received"),
		        pull_stats[PULL_ST_RECEIVED]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_served"),
		        pull_stats[PULL_ST_SERVED]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_timed_out"),
		        pull_stats[PULL_ST_TIMEOUT]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_stored"),
		        pull_stats[PULL_ST_STORED]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_suppressed"),
		        pull_stats[PULL_ST_SUPPRESSED]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_send_failed"),
		        pull_stats[PULL_ST_SEND_FAIL]) < 0 ||
		     add_mi_number(clobj, MI_SSTR("pulls_abandoned"),
		        pull_stats[PULL_ST_ABANDONED]) < 0))
			goto err;
		/* in-flight requests: a gauge, not a counter.  It should sit at 0
		 * when nothing is being asked; anything else parked there means
		 * slots are being taken and not released, which ends as "all pull
		 * slots busy" and silent loss of read repair. */
		if (pull_ready && pull_slots) {
			int busy = 0, k;

			lock_get(pull_lock);
			for (k = 0; k < PCACHE_PULL_SLOTS; k++)
				if (pull_slot_at(k)->id)
					busy++;
			lock_release(pull_lock);
			if (add_mi_number(clobj, MI_SSTR("pulls_in_flight"), busy) < 0 ||
			    add_mi_number(clobj, MI_SSTR("pull_slots"),
			        PCACHE_PULL_SLOTS) < 0)
				goto err;
		}

		/* Who the peers are, and whether they are actually answering US.
		 * A peer count alone cannot tell a healthy cluster apart from one
		 * whose membership is fine while the transport carrying pulls is
		 * black-holing every packet - the two look identical until you
		 * see that no peer has ever replied.  So each peer is listed with
		 * both views side by side: `membership` is what the clusterer
		 * believes, `replies`/`last_reply_ago` are what this node has
		 * actually received from it. */
		{
			mi_item_t *parr = add_mi_array(clobj, MI_SSTR("topology"));
			clusterer_node_t *list, *n;
			unsigned int now = get_ticks();
			int me = clusterer_api.get_my_id ? clusterer_api.get_my_id() : 0;
			mi_item_t *self;

			if (!parr)
				goto err;

			/* this node first - the clusterer list holds peers only, so a
			 * topology built from it alone silently omits the one node the
			 * reader is talking to */
			self = add_mi_object(parr, NULL, 0);
			if (!self ||
			    add_mi_number(self, MI_SSTR("node_id"), me) < 0 ||
			    add_mi_string(self, MI_SSTR("role"), MI_SSTR("self")) < 0 ||
			    add_mi_string(self, MI_SSTR("membership"),
			        MI_SSTR("up")) < 0)
				goto err;
			/* Which address this node actually uses on the cluster plane,
			 * and which of the three resolution paths produced it.  Node
			 * ids are assigned by the controller and do not follow the
			 * hosts' addresses in any readable order, so without this a
			 * reader cannot tell which box they are looking at.  It is
			 * also the fastest way to spot the failure that matters:
			 * a node resolving its own IP onto the wrong interface. */
#ifdef CLUSTERER_CTRL_SUPPORT
			if (pull_via_clctr && clctr_api.get_my_ip) {
				const char *mip = NULL, *mif = NULL, *msrc = NULL;

				if (clctr_api.get_my_ip(&mip, &mif, &msrc) == 0 && mip) {
					if (add_mi_string(self, MI_SSTR("ip"),
					        (char *)mip, strlen(mip)) < 0 ||
					    (mif && add_mi_string(self, MI_SSTR("interface"),
					        (char *)mif, strlen(mif)) < 0) ||
					    (msrc && add_mi_string(self, MI_SSTR("ip_source"),
					        (char *)msrc, strlen(msrc)) < 0))
						goto err;
				}
			}
#endif

			list = cluster_ready ?
				clusterer_api.get_nodes(sync_cluster_id) : NULL;
			for (n = list; n; n = n->next) {
				mi_item_t *p = add_mi_object(parr, NULL, 0);
				struct pcache_peer_stat *ps = peer_stats && n->node_id > 0 &&
					n->node_id <= CL_MAX_NODE_ID ?
					&peer_stats[n->node_id] : NULL;
				const char *verdict;
				int ago;

				if (!p)
					goto err;
				if (add_mi_number(p, MI_SSTR("node_id"), n->node_id) < 0 ||
				    add_mi_string(p, MI_SSTR("role"), MI_SSTR("peer")) < 0 ||
				    /* what the clusterer believes about it */
				    add_mi_string(p, MI_SSTR("membership"),
				        MI_SSTR("up")) < 0)
					goto err;
				if (n->description.s && n->description.len &&
				    add_mi_string(p, MI_SSTR("description"),
				        n->description.s, n->description.len) < 0)
					goto err;
				if (n->sip_addr.s && n->sip_addr.len &&
				    add_mi_string(p, MI_SSTR("sip_addr"),
				        n->sip_addr.s, n->sip_addr.len) < 0)
					goto err;
				/* the peer's address on the cluster plane - see the note on
				 * the self entry above; node_id alone does not identify a
				 * host to a human reading these stats */
				{
					struct ip_addr pip;
					char *pips;

					su2ip_addr(&pip, &n->addr);
					pips = ip_addr2a(&pip);
					if (pips && *pips &&
					    add_mi_string(p, MI_SSTR("ip"), pips,
					        strlen(pips)) < 0)
						goto err;
				}

				if (!ps)
					continue;
				/* ...and what it has actually done for us.  These two can
				 * disagree in the way that matters: a membership can read
				 * perfectly healthy while the transport carrying pulls
				 * drops every packet, and only this half shows it. */
				ago = ps->last_reply ? (int)(now - ps->last_reply) : -1;
				verdict = !ps->replies ? "never-answered"
				        : (ago <= PCACHE_PEER_FRESH_S ? "answering"
				                                      : "quiet");
				if (add_mi_string(p, MI_SSTR("pull_health"),
				        verdict, strlen(verdict)) < 0 ||
				    add_mi_number(p, MI_SSTR("replies"), ps->replies) < 0 ||
				    add_mi_number(p, MI_SSTR("replies_with_value"),
				        ps->values) < 0 ||
				    add_mi_number(p, MI_SSTR("answers_we_sent_it"),
				        ps->served) < 0 ||
				    add_mi_number(p, MI_SSTR("last_reply_ago"), ago) < 0)
					goto err;
			}
			if (list)
				clusterer_api.free_nodes(list);
		}
		if (pc_view->last_change) {
			char lbuf[32];
			int ln = snprintf(lbuf, sizeof lbuf, "%s:%d",
				pc_view->last_was_up ? "up" : "down", pc_view->last_node);
			if (add_mi_string(clobj, MI_SSTR("last_event"), lbuf, ln) < 0)
				goto err;
		}
	}

	return resp;
err:
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("Internal error"));
}

static mi_response_t *mi_perf_stats_1(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	return mi_perf_stats(NULL);
}

static mi_response_t *mi_perf_stats_2(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	str c;

	if (get_mi_string_param(params, "collection", &c.s, &c.len) < 0)
		return init_mi_param_error();
	return mi_perf_stats(&c);
}

/*
 * perf_stats_reset - re-baseline the cumulative counters.
 *
 * hits/misses/stores/removes/expired/destroyed/retries are running totals
 * since startup, so the rates derived from them are lifetime averages: a
 * burst of misses right after a restart keeps dragging the hit rate down
 * long after the cache has recovered.  Resetting gives a clean interval to
 * measure over without restarting OpenSIPS.
 *
 * The counters themselves are not rewound - the hot paths own their per
 * process cache lines and must never be written from another process.  Only
 * a baseline is recorded, and pcache_ht_totals() reports the difference.
 * Live gauges (entries, buckets, overflow, load factor, arena) are derived
 * from current state, not from the counters, so a reset does not disturb them.
 */
static mi_response_t *mi_perf_stats_reset(str *col_s)
{
	mi_response_t *resp;
	mi_item_t *obj;
	pcache_col_t *col;
	unsigned int matched = 0;

	for (col = pcache_collection; col; col = col->next) {
		if (col_s && (col->col_name.len != col_s->len ||
		        memcmp(col->col_name.s, col_s->s, col_s->len)))
			continue;
		if (!col->htable)
			continue;
		pcache_ht_stats_reset(col->htable);
		matched++;
	}
	if (col_s && !matched)
		return init_mi_error(404, MI_SSTR("no such collection"));

	resp = init_mi_result_object(&obj);
	if (!resp)
		return init_mi_error(500, MI_SSTR("Internal error"));
	if (add_mi_number(obj, MI_SSTR("collections_reset"), matched) < 0) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("Internal error"));
	}
	return resp;
}

static mi_response_t *mi_perf_stats_reset_1(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	return mi_perf_stats_reset(NULL);
}

static mi_response_t *mi_perf_stats_reset_2(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	str c;

	if (get_mi_string_param(params, "collection", &c.s, &c.len) < 0)
		return init_mi_param_error();
	return mi_perf_stats_reset(&c);
}

/*
 * Introspection MI (CP-18, DESIGN 5.2).  Every command is perf_-prefixed to
 * match the script functions and to stay clear of the core's bare get/set.
 * The walkers are lock-free (seqlock reads), so unlike cachedb_local's scan
 * they never stall writers; keys/dump are bounded and scan is the cursored
 * answer for anything large.
 */
#define PCACHE_MI_DEF_LIMIT 1000

struct mi_walk_ctx {
	const char *pat;         /* fnmatch pattern, NULL = match all */
	mi_item_t *arr;
	unsigned int limit;      /* 0 = unbounded (scan bounds by buckets) */
	unsigned int now;
	int with_values;         /* dump vs keys */
	unsigned int n;
	int err;
};

static int mi_walk_cb(const str *key, const str *val, unsigned int exp, void *p)
{
	struct mi_walk_ctx *w = p;
	mi_item_t *o;
	int ttl;

	if (exp && exp <= w->now)
		return 0;                          /* expired-as-absent (3.5) */
	if (w->pat && fnmatch(w->pat, key->s, 0))
		return 0;

	o = add_mi_object(w->arr, NULL, 0);
	if (!o)
		goto oom;
	if (add_mi_string(o, MI_SSTR("key"), (char *)key->s, key->len) < 0)
		goto oom;
	ttl = exp ? (int)(exp - w->now) : -1;   /* -1 = never expires */
	if (add_mi_number(o, MI_SSTR("ttl"), ttl) < 0)
		goto oom;
	if (w->with_values &&
	        add_mi_string(o, MI_SSTR("value"), (char *)val->s, val->len) < 0)
		goto oom;

	w->n++;
	if (w->limit && w->n >= w->limit)
		return -1;                          /* stop: limit reached */
	return 0;
oom:
	w->err = 1;
	return -1;
}

/* backs perf_keys (with_values = 0) and perf_dump (with_values = 1) */
static mi_response_t *do_perf_keys(str *glob, str *col_s, int limit,
		int with_values)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj, *arr;
	struct mi_walk_ctx w;
	char *pat = NULL;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));
	if (glob && glob->len) {
		pat = glob_dup(glob);
		if (!pat)
			return init_mi_error(500, MI_SSTR("out of memory"));
	}

	resp = init_mi_result_object(&obj);
	if (!resp) {
		if (pat)
			pkg_free(pat);
		return NULL;
	}
	arr = add_mi_array(obj, MI_SSTR("keys"));
	if (!arr)
		goto err;

	memset(&w, 0, sizeof w);
	w.pat = pat;
	w.arr = arr;
	w.limit = limit > 0 ? (unsigned int)limit : PCACHE_MI_DEF_LIMIT;
	w.now = get_ticks();
	w.with_values = with_values;
	pcache_ht_iter(col->htable, mi_walk_cb, &w);
	if (pat) {
		pkg_free(pat);
		pat = NULL;
	}
	if (w.err)
		goto err;

	if (add_mi_number(obj, MI_SSTR("returned"), w.n) < 0)
		goto err;
	/* tell the operator the result was cut so they narrow it or use scan */
	if (w.n >= w.limit && add_mi_string(obj, MI_SSTR("note"),
	        MI_SSTR("limit reached - truncated; narrow the glob or use perf_scan")) < 0)
		goto err;
	return resp;
err:
	if (pat)
		pkg_free(pat);
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("internal error"));
}

/* perf_scan <cursor> [glob] [count] - cursored, on the default collection */
static mi_response_t *do_perf_scan(int cursor_in, str *glob, int count)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj, *arr;
	struct mi_walk_ctx w;
	char *pat = NULL;
	unsigned int cur;

	if (cursor_in < 0)
		return init_mi_param_error();
	col = col_by_name(NULL);            /* the groupless default collection */
	if (!col)
		return init_mi_error(404, MI_SSTR("no default collection"));
	if (glob && glob->len) {
		pat = glob_dup(glob);
		if (!pat)
			return init_mi_error(500, MI_SSTR("out of memory"));
	}

	resp = init_mi_result_object(&obj);
	if (!resp) {
		if (pat)
			pkg_free(pat);
		return NULL;
	}
	arr = add_mi_array(obj, MI_SSTR("keys"));
	if (!arr)
		goto err;

	memset(&w, 0, sizeof w);
	w.pat = pat;
	w.arr = arr;
	w.limit = 0;                        /* bucket-bounded: no per-entry stop */
	w.now = get_ticks();
	w.with_values = 0;                  /* SCAN returns names + ttl */
	cur = (unsigned int)cursor_in;
	pcache_ht_scan(col->htable, &cur, count > 0 ? (unsigned int)count : 0,
		mi_walk_cb, &w);
	if (pat) {
		pkg_free(pat);
		pat = NULL;
	}
	if (w.err)
		goto err;

	/* cursor 0 = iteration complete; feed any other value back verbatim */
	if (add_mi_number(obj, MI_SSTR("cursor"), cur) < 0 ||
	    add_mi_number(obj, MI_SSTR("returned"), w.n) < 0)
		goto err;
	return resp;
err:
	if (pat)
		pkg_free(pat);
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("internal error"));
}

/* perf_get <key> [collection] - value + TTL + size for one key */
/* perf_pull <key> [collection] - ask the cluster for a key this node does
 * not have.  The MI face exists to exercise and observe the protocol on
 * its own, before a SIP path uses it: it reports where the answer came
 * from, which is what makes a failing pull diagnosable. */
static mi_response_t *do_perf_pull(str *key, str *col_s)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	char buf[PCACHE_PULL_MAX_VAL];
	unsigned int vlen = 0, exp = 0;
	int rc;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));
	if (!pull_ready)
		return init_mi_error(500,
			MI_SSTR("cross-node pull not active (replicate_collections)"));
	if (!col->replicate)
		return init_mi_error(500,
			MI_SSTR("collection is not in replicate_collections"));

	/* a local hit needs no cluster at all - say so plainly */
	if (pcache_ht_probe(col->htable, key, &vlen, &exp, NULL) == 0) {
		resp = init_mi_result_object(&obj);
		if (!resp)
			return NULL;
		if (add_mi_string(obj, MI_SSTR("source"), MI_SSTR("local")) < 0 ||
		    add_mi_number(obj, MI_SSTR("size"), vlen) < 0 ||
		    add_mi_number(obj, MI_SSTR("ttl"),
		        exp ? (int)(exp - get_ticks()) : -1) < 0)
			goto err;
		return resp;
	}

	rc = pcache_pull_key(col, key, buf, sizeof buf, &vlen, &exp);

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_string(obj, MI_SSTR("source"),
	        rc == 1 ? "cluster" : (rc == 0 ? "absent" : "no-answer"),
	        rc == 1 ? 7 : (rc == 0 ? 6 : 9)) < 0)
		goto err;
	if (rc == 1) {
		if (add_mi_string(obj, MI_SSTR("value"), buf, vlen) < 0 ||
		    add_mi_number(obj, MI_SSTR("size"), vlen) < 0 ||
		    add_mi_number(obj, MI_SSTR("ttl"),
		        exp ? (int)(exp - get_ticks()) : -1) < 0)
			goto err;
	}
	return resp;
err:
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("internal error"));
}

/* perf_probe <key> [collection] - is the key here, and what does it look
 * like?  Deliberately never returns the value: this is the existence test
 * a cross-node lookup would run on a peer, so it must cost what that costs
 * (no allocation, no copy, the payload never touched). */
static mi_response_t *do_perf_probe(str *key, str *col_s)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	unsigned int vlen = 0, exp = 0;
	int rc;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));

	rc = pcache_ht_probe(col->htable, key, &vlen, &exp, NULL);
	if (rc == -2)
		return init_mi_error(404, MI_SSTR("key not found"));
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("internal error"));

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_string(obj, MI_SSTR("key"), key->s, key->len) < 0 ||
	    add_mi_number(obj, MI_SSTR("size"), vlen) < 0 ||
	    add_mi_number(obj, MI_SSTR("ttl"),
	        exp ? (int)(exp - get_ticks()) : -1) < 0) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("internal error"));
	}
	return resp;
}

static mi_response_t *do_perf_get(str *key, str *col_s)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	str val;
	unsigned int exp = 0, now;
	int rc, ttl;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));

	rc = pcache_ht_fetch_ex(col->htable, key, &val, &exp);
	if (rc == -2)
		return init_mi_error(404, MI_SSTR("key not found"));
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("internal error"));

	now = get_ticks();
	ttl = exp ? (int)(exp - now) : -1;

	resp = init_mi_result_object(&obj);
	if (!resp) {
		pkg_free(val.s);
		return NULL;
	}
	if (add_mi_string(obj, MI_SSTR("key"), key->s, key->len) < 0 ||
	    add_mi_string(obj, MI_SSTR("value"), val.s, val.len) < 0 ||
	    add_mi_number(obj, MI_SSTR("size"), val.len) < 0 ||
	    add_mi_number(obj, MI_SSTR("ttl"), ttl) < 0) {
		pkg_free(val.s);
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("internal error"));
	}
	pkg_free(val.s);
	return resp;
}

/* perf_set <key> <value> [ttl] [collection] - single key write */
static mi_response_t *do_perf_set(str *key, str *value, int ttl, str *col_s)
{
	pcache_col_t *col;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));
	if (pcache_ht_store(col->htable, key, value, ttl_to_abs(ttl)) < 0)
		return init_mi_error(500, MI_SSTR("store failed"));
	return init_mi_result_ok();
}

/* perf_del <glob> [collection] - the MI face of the perf_del() script fn */
static mi_response_t *do_perf_del_mi(str *glob, str *col_s)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	int removed;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));
	removed = perf_del_run(col, glob);
	if (removed < 0)
		return init_mi_error(500, MI_SSTR("out of memory - deletion partial"));

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_number(obj, MI_SSTR("deleted"), removed) < 0) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("internal error"));
	}
	return resp;
}

/* re-arm the TTL of every live key matching a glob (perf_ttl): collect the
 * matches lock-free, then touch each - like perf_del, not an atomic snapshot */
struct touch_ctx {
	const char *pat;
	str *keys;
	unsigned int n, cap, now;
	int oom;
};

static int touch_collect_cb(const str *key, const str *val, unsigned int exp,
		void *p)
{
	struct touch_ctx *tc = p;
	str *grown;

	if (exp && exp <= tc->now)          /* skip expired: never revive them */
		return 0;
	if (fnmatch(tc->pat, key->s, 0))
		return 0;
	if (tc->n == tc->cap) {
		tc->cap = tc->cap ? 2 * tc->cap : 64;
		grown = pkg_realloc(tc->keys, tc->cap * sizeof *tc->keys);
		if (!grown) {
			tc->oom = 1;
			return -1;
		}
		tc->keys = grown;
	}
	if (pkg_str_dup(&tc->keys[tc->n], key) < 0) {
		tc->oom = 1;
		return -1;
	}
	tc->n++;
	return 0;
}

static int perf_touch_run(pcache_col_t *col, str *glob, unsigned int expires)
{
	struct touch_ctx tc;
	char *pat;
	unsigned int i, touched = 0;

	pat = glob_dup(glob);
	if (!pat)
		return -1;
	memset(&tc, 0, sizeof tc);
	tc.pat = pat;
	tc.now = get_ticks();
	pcache_ht_iter(col->htable, touch_collect_cb, &tc);

	for (i = 0; i < tc.n; i++) {
		if (pcache_ht_touch(col->htable, &tc.keys[i], expires) == 1)
			touched++;
		pkg_free(tc.keys[i].s);
	}
	if (tc.keys)
		pkg_free(tc.keys);
	pkg_free(pat);
	if (tc.oom) {
		LM_ERR("out of pkg memory mid-walk - re-arm is partial\n");
		return -1;
	}
	return (int)touched;
}

/* perf_ttl <glob> <ttl> [collection] - re-arm the TTL of matching keys */
static mi_response_t *do_perf_ttl(str *glob, int ttl, str *col_s)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	int touched;

	col = col_by_name(col_s);
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));
	touched = perf_touch_run(col, glob, ttl_to_abs(ttl));
	if (touched < 0)
		return init_mi_error(500, MI_SSTR("out of memory - update partial"));

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_number(obj, MI_SSTR("updated"), touched) < 0) {
		free_mi_response(resp);
		return init_mi_error(500, MI_SSTR("internal error"));
	}
	return resp;
}

/* perf_save / perf_load [collection] - persist to / restore from the DB
 * backend; with no collection, all declared collections */
static mi_response_t *do_perf_persist(str *col_s, int save)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	int total = 0, ncol = 0, rc;

	if (!pcache_db_enabled())
		return init_mi_error(500,
			MI_SSTR("no DB backend configured (set db_url)"));

	if (col_s) {
		col = col_by_name(col_s);
		if (!col)
			return init_mi_error(404, MI_SSTR("no such collection"));
		rc = save ? pcache_db_save(col) : pcache_db_load(col);
		if (rc < 0)
			return init_mi_error(500, MI_SSTR("DB operation failed"));
		total = rc;
		ncol = 1;
	} else {
		for (col = pcache_collection; col; col = col->next) {
			if (!col->htable)
				continue;
			rc = save ? pcache_db_save(col) : pcache_db_load(col);
			if (rc < 0)
				return init_mi_error(500, MI_SSTR("DB operation failed"));
			total += rc;
			ncol++;
		}
	}

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_number(obj, MI_SSTR("collections"), ncol) < 0)
		goto err;
	if (save) {
		if (add_mi_number(obj, MI_SSTR("saved"), total) < 0)
			goto err;
	} else {
		if (add_mi_number(obj, MI_SSTR("loaded"), total) < 0)
			goto err;
	}
	return resp;
err:
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("internal error"));
}

/*
 * CP-19 Stage 2: cluster sync.  The DB is the shared source of truth; a sync
 * is save-then-broadcast (the issuing node writes its collection to the DB,
 * then signals peers to reload it) - never per-operation replication, and no
 * locking.  perf_sync OVERWRITES a peer's copy from the DB, so it is meant
 * for single-writer / read-replica topologies; a node that also takes local
 * writes would lose the unsaved ones.  With no clusterer (or cluster_id 0) it
 * degrades to a DB save only.
 */

/* a peer signalled "reload collection X": pull it from the DB and announce */
/* =====================================================================
 * CP-15.5: pull a key from the cluster on a local miss (read repair)
 *
 * A node that misses asks the cluster for that one key and uses the
 * answer.  Pull rather than eager push because the request is issued at
 * the moment of need, so it cannot race the traffic the way a broadcast
 * on write does - and because misses are the only thing that pays.
 *
 * Every peer answers, positively or negatively (R5): with a handful of
 * nodes the extra packets are trivial and definitive absence is worth
 * far more than saving them, because "nobody has it" is then a fact
 * rather than a timeout.  The probe of CP-15.2 is what makes answering
 * cheap - a negative costs the bucket's tag word and nothing else.
 * ===================================================================== */

static unsigned int neg_hash(pcache_col_t *col, const str *key)
{
	unsigned int h = core_hash((str *)key, &col->col_name, 0);

	return h ? h : 1;                    /* 0 marks a free slot */
}

/* Did we recently establish that nobody has this key? */
static int pcache_neg_check(pcache_col_t *col, const str *key)
{
	struct pcache_neg_slot *sl;
	unsigned int h;
	int hit = 0;

	if (!neg_slots || pull_negative_ms <= 0)
		return 0;
	h = neg_hash(col, key);
	sl = &neg_slots[h % PCACHE_NEG_SLOTS];

	lock_get(neg_lock);
	if (sl->hash == h && sl->klen == key->len &&
	        !memcmp(sl->key, key->s, key->len) &&
	        sl->collen == col->col_name.len &&
	        !memcmp(sl->col, col->col_name.s, sl->collen)) {
		if (sl->deadline > get_uticks())
			hit = 1;
		else
			sl->hash = 0;                /* lapsed - ask again */
	}
	lock_release(neg_lock);
	return hit;
}

static void pcache_neg_add(pcache_col_t *col, const str *key)
{
	struct pcache_neg_slot *sl;
	unsigned int h;

	if (!neg_slots || pull_negative_ms <= 0 ||
	        key->len > pull_max_key || col->col_name.len > 63)
		return;
	h = neg_hash(col, key);
	sl = &neg_slots[h % PCACHE_NEG_SLOTS];

	lock_get(neg_lock);
	sl->hash = h;
	sl->deadline = get_uticks() + (utime_t)pull_negative_ms * 1000;
	sl->klen = key->len;
	memcpy(sl->key, key->s, key->len);
	sl->collen = col->col_name.len;
	memcpy(sl->col, col->col_name.s, sl->collen);
	lock_release(neg_lock);
}

/* A local write makes the key exist here, so whatever we concluded about
 * the cluster no longer describes it. */
static void pcache_neg_clear(pcache_col_t *col, const str *key)
{
	struct pcache_neg_slot *sl;
	unsigned int h;

	if (!neg_slots || pull_negative_ms <= 0)
		return;
	h = neg_hash(col, key);
	sl = &neg_slots[h % PCACHE_NEG_SLOTS];
	if (sl->hash != h)
		return;                          /* cheap check before the lock */

	lock_get(neg_lock);
	if (sl->hash == h && sl->klen == key->len &&
	        !memcmp(sl->key, key->s, key->len))
		sl->hash = 0;
	lock_release(neg_lock);
}

/* Is this collection opted in?  Nothing pulls unless an operator said so:
 * a pull only makes sense where keys are globally meaningful, which the
 * module cannot know and must not assume (R2). */
static int pcache_pull_enabled(pcache_col_t *col)
{
	return pull_ready && col && col->replicate;
}

static struct pcache_pull_slot *pull_slot_get(unsigned int id)
{
	int i;

	for (i = 0; i < PCACHE_PULL_SLOTS; i++)
		if (pull_slot_at(i)->id == id)
			return pull_slot_at(i);
	return NULL;
}

/* Send one reply, over the transport the request came in on.
 *
 * @via_clctr says how it arrived, and is deliberately NOT this node's own
 * configuration: the two can differ while a cluster is being reconfigured,
 * and answering a BIN request over the multicast plane (or the reverse)
 * means the requester waits out its timeout for an answer that was sent,
 * which is indistinguishable from packet loss. */
static void pcache_pull_send_rpl(int dst_node, unsigned int id, const str *key,
		int found, int ttl, const str *val, int via_clctr)
{
#ifdef CLUSTERER_CTRL_SUPPORT
	if (via_clctr) {
		char buf[CLCTR_MAX_PAYLOAD];
		str pl;
		uint32_t id_be = htonl(id), ttl_be = htonl((uint32_t)ttl);
		uint16_t kl = htons((uint16_t)key->len);
		int vlen = (found == PCACHE_FOUND_YES) ? val->len : 0;
		uint16_t vl = htons((uint16_t)vlen);
		int n = 0;

		/* Never trust the caller to have sized this: the key is echoed
		 * straight back from the request, so a peer sending an oversized
		 * one would otherwise write past the buffer.  The serve path
		 * rejects those already - this is the second lock on the door. */
		if (PCACHE_CLCTR_RPL_HDR + key->len + vlen > (int)sizeof buf) {
			LM_ERR("pull reply for a %d byte key with %d bytes of value "
				"does not fit %d - dropping it\n", key->len, vlen,
				(int)sizeof buf);
			return;
		}

		buf[n++] = PCACHE_CLCTR_RPL;
		memcpy(buf + n, &id_be, 4);  n += 4;
		buf[n++] = (char)found;
		memcpy(buf + n, &ttl_be, 4); n += 4;
		memcpy(buf + n, &kl, 2);     n += 2;
		memcpy(buf + n, key->s, key->len); n += key->len;
		memcpy(buf + n, &vl, 2);     n += 2;
		if (found == PCACHE_FOUND_YES) {
			memcpy(buf + n, val->s, val->len);
			n += val->len;
		}
		pl.s = buf;
		pl.len = n;
		if (clctr_api.send_ucast(sync_cluster_id, dst_node, &pull_channel,
		        &pl, 0) < 0)
			pull_send_failed("a reply did not get through", dst_node);
		else if (found == PCACHE_FOUND_YES)
			__sync_fetch_and_add(&pull_stats[PULL_ST_SERVED], 1);
		return;
	}
#endif

	{
		bin_packet_t out;
		str empty = {NULL, 0};

		if (bin_init(&out, &pcache_sync_cap, PCACHE_PULL_RPL,
		        PCACHE_SYNC_VERSION, 0) < 0)
			return;
		if (bin_push_int(&out, (int)id) < 0 ||
		    bin_push_str(&out, (str *)key) < 0 ||
		    bin_push_int(&out, found) < 0 ||
		    bin_push_int(&out, ttl) < 0 ||
		    bin_push_str(&out, found == PCACHE_FOUND_YES ? (str *)val
		                                                 : &empty) < 0) {
			bin_free_packet(&out);
			return;
		}
		if (clusterer_api.send_to(&out, sync_cluster_id, dst_node) !=
		        CLUSTERER_SEND_SUCCESS)
			pull_send_failed("a reply did not get through", dst_node);
		else if (found == PCACHE_FOUND_YES)
			__sync_fetch_and_add(&pull_stats[PULL_ST_SERVED], 1);
		bin_free_packet(&out);
	}
}

/* Answer a peer's request for one key.  Transport-neutral: both the BIN
 * and the controller-plane receivers decode their own framing and land
 * here, so the two can never disagree about what is served. */
static void pcache_pull_do_serve(int src_node, unsigned int id, str *coll,
		str *key, int via_clctr)
{
	pcache_col_t *col;
	str val = {NULL, 0};
	unsigned int exp = 0;
	int found = PCACHE_FOUND_NO, ttl_left = 0, budget;

	/* The key arrives from a peer and is echoed back in the reply, so it
	 * is sized before anything else touches it.  A requester never asks
	 * for more than pull_max_key; anything longer is a peer that
	 * is broken, of another version, or hostile, and answering it at all
	 * would mean copying it into a fixed reply buffer. */
	if (key->len <= 0 || key->len > pull_max_key ||
	        coll->len <= 0 || coll->len > 63) {
		LM_ERR("pull request from node %d has a %d byte key in a %d byte "
			"collection - out of range, ignored\n", src_node, key->len,
			coll->len);
		return;
	}

	col = col_by_name(coll);
	if (!col || !col->htable || !col->replicate)
		goto reply;

	{
		int is_counter = 0;

		/* Classify before reading: a native counter counts what happened
		 * on THIS node, so handing it to a peer would import our tally as
		 * if it were theirs - and the read path formats it as a decimal
		 * string, which would silently arrive as a plain value and stop
		 * being a counter at all.  Refuse to serve one; the requester
		 * treats it as "not here", which is the truth from its side. */
		if (pcache_ht_probe(col->htable, key, NULL, NULL, &is_counter) == 0
		        && is_counter) {
			LM_DBG("pull: <%.*s> is a counter - not portable, not served\n",
				key->len, key->s);
			goto reply;
		}
	}

	if (pcache_ht_fetch_ex(col->htable, key, &val, &exp) != 0)
		goto reply;

	/* Hand over the ORIGINAL lifetime, never a fresh TTL: a copy that
	 * outlives the owner's entry would serve state the owner already
	 * dropped (R6).  0 = never expires. */
	if (exp) {
		unsigned int now = get_ticks();

		if (exp <= now) {              /* raced the sweep - treat as absent */
			pkg_free(val.s);
			val.s = NULL;
			goto reply;
		}
		ttl_left = (int)(exp - now);
	}

	/* The controller plane is one datagram, so a large value cannot ride
	 * it.  Say "I have it but cannot send it" rather than "not here":
	 * the requester must not conclude the key is absent from a node that
	 * demonstrably holds it. */
#ifdef CLUSTERER_CTRL_SUPPORT
	budget = via_clctr
		? CLCTR_MAX_PAYLOAD - (int)(PCACHE_CLCTR_RPL_HDR + key->len)
		: pull_max_value;
#else
	budget = pull_max_value;
#endif
	if (val.len > budget) {
		LM_DBG("pull: <%.*s> is %d bytes, over this transport's %d - "
			"reporting held-but-unsendable\n", key->len, key->s, val.len,
			budget);
		found = PCACHE_FOUND_OVERSIZE;
	} else {
		found = PCACHE_FOUND_YES;
		/* counted here, not in pcache_pull_send_rpl(): that helper is
		 * transport framing and has no collection in scope.  Only a real
		 * value counts - a "not here"/oversize answer is not a serve. */
		if (col)
			__sync_fetch_and_add(&col->served_out, 1);
	}

reply:
	peer_note_served(src_node);
	pcache_pull_send_rpl(src_node, id, key, found, ttl_left, &val, via_clctr);
	if (val.s)
		pkg_free(val.s);
}

/* BIN framing -> the shared serve path */
static void pcache_pull_serve(bin_packet_t *in)
{
	str coll, key;
	unsigned int id;

	if (bin_pop_int(in, (int *)&id) < 0 || bin_pop_str(in, &coll) < 0 ||
	        bin_pop_str(in, &key) < 0) {
		LM_ERR("malformed pull request from node %d\n", in->src_id);
		return;
	}
	/* arrived over BIN, so it is answered over BIN - even on a node whose
	 * own pull_transport is the controller plane */
	pcache_pull_do_serve(in->src_id, id, &coll, &key, 0);
}

/* A peer answered.  Fill the waiting slot; first positive answer wins and
 * later ones are dropped (several nodes may hold the key once pulls have
 * converged).  Transport-neutral, like the serve path. */
static void pcache_pull_do_reply(int src_node, unsigned int id, str *key,
		int found, int ttl_left, str *val)
{
	struct pcache_pull_slot *sl;
	/* copied out under the lock, used once it is released */
	char         late_key[PCACHE_PULL_MAX_KEY], late_col[64];
	char         late_val[PCACHE_PULL_MAX_VAL];
	unsigned int late_len = 0, late_exp = 0;
	int          late_kl = 0, late_cl = 0, store_late = 0, late_after_linger = 0;

	lock_get(pull_lock);
	sl = pull_slot_get(id);
	/* the echoed key must match the slot's, or this is an answer to a
	 * request that has already been recycled */
	if (!sl || sl->klen != key->len || memcmp(pull_slot_key(sl), key->s, key->len)) {
		lock_release(pull_lock);
		LM_DBG("late or unmatched pull reply (id %u) from node %d\n",
			id, src_node);
		return;
	}

	/* record who answered before any dedupe or early return, so the peer
	 * view reflects what actually arrived on the wire */
	peer_note_reply(src_node, found == PCACHE_FOUND_YES);

	/* Count each node once, whatever the transport does.  An id outside
	 * the range the bitmap covers cannot be tracked, and counting it
	 * undeduped is exactly the defect the bitmap exists to prevent - two
	 * answers from one node reaching @expect and manufacturing an absence
	 * nobody stated.  The controller assigns 1..CL_MAX_NODE_ID, but a
	 * stock clusterer takes whatever the database says, so this is
	 * reachable without the controller.  Drop such a reply rather than
	 * let it vote. */
	if (src_node <= 0 || src_node > CL_MAX_NODE_ID) {
		lock_release(pull_lock);
		LM_ERR("pull reply from node id %d, outside 1..%d - cannot be "
			"tracked, ignored\n", src_node, CL_MAX_NODE_ID);
		return;
	}
	{
		int byte = (src_node - 1) / 8, bit = 1 << ((src_node - 1) % 8);

		if (sl->answered[byte] & bit) {
			lock_release(pull_lock);
			LM_DBG("duplicate pull reply from node %d - ignored\n", src_node);
			return;
		}
		sl->answered[byte] |= bit;
	}

	if (found == PCACHE_FOUND_NO) {
		sl->negative++;
	} else if (found == PCACHE_FOUND_OVERSIZE) {
		/* someone HAS it - so the key is not absent, whatever the rest of
		 * the cluster says.  Not a negative, and not a value either. */
		sl->oversize = 1;
	} else if (!sl->done && val->len <= pull_max_value) {
		memcpy(pull_slot_val(sl), val->s, val->len);
		sl->vlen = val->len;
		/* back to an absolute deadline on our own clock */
		sl->expires = ttl_left ? get_ticks() + (unsigned int)ttl_left : 0;
		sl->done = 1;
		__sync_fetch_and_add(&pull_stats[PULL_ST_RECEIVED], 1);
	}
	/* Nobody is waiting on an orphan - its caller timed out and left.  We
	 * are the last chance this value has to reach the cache, so copy what
	 * we need out of the slot, hand the slot back, and store after the
	 * lock is dropped.  Storing here under pull_lock would nest it outside
	 * the bucket locks; see the note in pcache_pull_finish(). */
	if (sl->orphan && sl->done) {
		late_len = sl->vlen;
		late_exp = sl->expires;
		late_kl  = sl->klen;
		late_cl  = sl->collen;
		memcpy(late_key, pull_slot_key(sl), late_kl);
		memcpy(late_col, sl->col, late_cl);
		memcpy(late_val, pull_slot_val(sl), late_len);
		/* No in-flight TTL correction, deliberately.  The peer computes
		 * ttl_left immediately before sending (see the serve path: it reads
		 * get_ticks() and hands the value straight to send_rpl), so a peer
		 * that was busy for seconds still reports a CURRENT remaining TTL.
		 * The only unaccounted time is the transit back to us.  Charging the
		 * requester's elapsed time here would subtract the peer's own delay
		 * from a figure that never included it - expiring late answers early
		 * for precisely the reason they were late. */
		late_after_linger = pull_linger_ms > 0 &&
			get_uticks() > sl->deadline + (utime_t)pull_linger_ms * 1000;
		sl->id     = 0;              /* back to the pool, job finished */
		sl->orphan = 0;
		store_late = 1;
	} else if (sl->efd >= 0 &&
	        (sl->done || sl->oversize || sl->negative >= sl->expect)) {
		/* Wake whoever is waiting on this slot.  The reply almost never
		 * lands in the process that asked, so this is the only way back
		 * to it: the fd was created before the fork, which is what lets
		 * a sibling write to it at all. */
		uint64_t one = 1;

		if (write(sl->efd, &one, sizeof one) != sizeof one)
			LM_DBG("could not signal the pull waiter\n");
	}
	lock_release(pull_lock);

	if (store_late) {
		pcache_col_t *lcol;
		str lk, lv, cn;

		lk.s = late_key;  lk.len = late_kl;
		lv.s = late_val;  lv.len = late_len;
		cn.s = late_col;  cn.len = late_cl;
		lcol = col_by_name(&cn);
		if (!lcol || !lcol->htable) {
			LM_DBG("late pull answer for a collection that went away\n");
		} else if (late_after_linger) {
			__sync_fetch_and_add(&pull_stats[PULL_ST_LATE_EXPIRED], 1);
			LM_DBG("pull answer for <%.*s> arrived %d ms past the linger "
				"window - not stored\n", lk.len, lk.s, pull_linger_ms);
		} else if (late_exp && late_exp <= get_ticks()) {
			LM_DBG("late pull answer for <%.*s> had already expired\n",
				lk.len, lk.s);
		} else if (pcache_ht_probe(lcol->htable, &lk, NULL, NULL, NULL) == 0) {
			/* Something live is already here.  This is read REPAIR: fill what
			 * is missing, never overwrite what is present.  Seconds may have
			 * passed since the request went out, and a local write in that
			 * window is by definition fresher than a peer's copy of what we
			 * asked for.  probe() is allocation-free and returns exactly 0
			 * for a present, live key - NOT `!= -2`, which would read a pkg
			 * failure (-1) as "present" and silently stop repairing under the
			 * very memory pressure that matters, while miscounting it here. */
			__sync_fetch_and_add(&pull_stats[PULL_ST_LATE_SUPERSEDED], 1);
			LM_DBG("late pull answer for <%.*s> superseded by a local "
				"write - not stored\n", lk.len, lk.s);
		} else if (pcache_ht_store(lcol->htable, &lk, &lv, late_exp) < 0) {
			LM_ERR("could not store the late pulled value for <%.*s>\n",
				lk.len, lk.s);
		} else {
			__sync_fetch_and_add(&pull_stats[PULL_ST_STORED], 1);
			__sync_fetch_and_add(&pull_stats[PULL_ST_LATE_STORED], 1);
			__sync_fetch_and_add(&lcol->pulled_in, 1);
			pcache_neg_clear(lcol, &lk);
			LM_DBG("stored a pull answer that arrived after its caller "
				"gave up: <%.*s>\n", lk.len, lk.s);
		}
	}
}

/* Reclaim pulls that never got a conclusive answer.
 *
 * pcache_pull_do_reply() only arms the eventfd once the outcome is settled
 * - a value, an oversize holder, or every asked peer having said no.  When
 * fewer than @expect peers answer (a reply is lost, a peer dies mid-flight,
 * a node is asked that never responds) that never becomes true, so on the
 * ASYNCHRONOUS path nothing wakes the caller: its resume never runs,
 * pcache_pull_finish() is never reached, and since that is the only place a
 * slot is released the slot is held for ever.  Enough of those and every
 * slot is busy and the node stops pulling entirely.
 *
 * The blocking entry point never had this problem - it polls for at most
 * pull_timeout_ms and then calls finish() regardless - which is exactly why
 * the concurrent soak, which drives that path, reported no leak.
 *
 * Two stages, deliberately:
 *   1. past its deadline, arm the eventfd once.  The caller then resumes
 *      normally and finish() draws the ordinary "no answer" conclusion and
 *      counts the timeout, so nothing about the outcome is special-cased
 *      here.
 *   2. still busy well past that, give up on the caller ever coming back
 *      (its transaction may already be gone) and release the slot.  Safe
 *      because releasing means clearing @id: a late finish() then simply
 *      fails to find the slot and reports "already reaped", and ids are
 *      monotonic so it cannot match a slot that has since been reused.
 */
static void pcache_pull_reap(utime_t ticks, void *param)
{
	utime_t now = get_uticks();
	uint64_t one = 1;
	int i, woke = 0, dropped = 0, expired = 0;

	if (!pull_slots || !pull_lock)
		return;

	lock_get(pull_lock);
	for (i = 0; i < PCACHE_PULL_SLOTS; i++) {
		struct pcache_pull_slot *sl = pull_slot_at(i);

		if (!sl->id || now <= sl->deadline)
			continue;

		if (!sl->reaped) {
			sl->reaped = 1;
			/* An orphan's caller already finished and left - there is
			 * nobody on the eventfd, and arming it would leave a count
			 * for whoever inherits this slot to drain. */
			if (sl->orphan)
				continue;
			if (sl->efd >= 0 &&
			        write(sl->efd, &one, sizeof one) != sizeof one)
				LM_DBG("could not wake the pull waiter on reap\n");
			woke++;
		} else if (now > sl->deadline + PCACHE_PULL_ABANDON_US) {
			/* An orphan reaching here is the ordinary end of a timeout
			 * whose answer never came.  Only a slot whose caller never
			 * came back is genuinely abandoned - that distinction is the
			 * whole point of PULL_ST_ABANDONED and its warning. */
			if (sl->orphan)
				expired++;
			else
				dropped++;
			sl->id     = 0;
			sl->orphan = 0;
		}
	}
	lock_release(pull_lock);

	if (woke)
		LM_DBG("reaped %d pull(s) past their deadline\n", woke);
	if (expired)
		__sync_fetch_and_add(&pull_stats[PULL_ST_ORPHAN_EXPIRED], expired);
	if (dropped) {
		__sync_fetch_and_add(&pull_stats[PULL_ST_ABANDONED], dropped);
		LM_WARN("released %d pull slot(s) whose caller never collected "
			"them - a suspended lookup was torn down before it could "
			"resume\n", dropped);
	}
}

/* BIN framing -> the shared reply path */
static void pcache_pull_reply(bin_packet_t *in)
{
	str key, val;
	unsigned int id;
	int found = 0, ttl_left = 0;

	if (bin_pop_int(in, (int *)&id) < 0 || bin_pop_str(in, &key) < 0 ||
	        bin_pop_int(in, &found) < 0 || bin_pop_int(in, &ttl_left) < 0 ||
	        bin_pop_str(in, &val) < 0) {
		LM_ERR("malformed pull reply from node %d\n", in->src_id);
		return;
	}
	pcache_pull_do_reply(in->src_id, id, &key, found, ttl_left, &val);
}

#ifdef CLUSTERER_CTRL_SUPPORT
/* Controller-plane framing -> the shared paths.  Runs in the controller's
 * receiving process; the cache is in shm, so serving from here is fine. */
static void pcache_clctr_recv(int cluster_id, int src_node_id, str *channel,
		str *payload)
{
	const char *p = payload->s;
	int left = payload->len;
	uint32_t id_be, ttl_be;
	uint16_t l16;
	str coll, key, val;
	unsigned char type;
	int found;

	if (left < 6)
		goto bad;
	type = (unsigned char)*p++; left--;
	memcpy(&id_be, p, 4); p += 4; left -= 4;

	if (type == PCACHE_CLCTR_REQ) {
		if (left < 1)
			goto bad;
		coll.len = (unsigned char)*p++; left--;
		if (left < coll.len + 2)
			goto bad;
		coll.s = (char *)p; p += coll.len; left -= coll.len;
		memcpy(&l16, p, 2); p += 2; left -= 2;
		key.len = ntohs(l16);
		if (left < key.len)
			goto bad;
		key.s = (char *)p;
		pcache_pull_do_serve(src_node_id, ntohl(id_be), &coll, &key, 1);
		return;
	}
	if (type == PCACHE_CLCTR_RPL) {
		if (left < 7)
			goto bad;
		found = (unsigned char)*p++; left--;
		memcpy(&ttl_be, p, 4); p += 4; left -= 4;
		memcpy(&l16, p, 2); p += 2; left -= 2;
		key.len = ntohs(l16);
		if (left < key.len + 2)
			goto bad;
		key.s = (char *)p; p += key.len; left -= key.len;
		memcpy(&l16, p, 2); p += 2; left -= 2;
		val.len = ntohs(l16);
		if (left < val.len)
			goto bad;
		val.s = (char *)p;
		pcache_pull_do_reply(src_node_id, ntohl(id_be), &key, found,
			(int)ntohl(ttl_be), &val);
		return;
	}
bad:
	LM_ERR("malformed pull message from node %d on <%.*s>\n", src_node_id,
		channel->len, channel->s);
}
#endif

/* ---- asynchronous face -------------------------------------------------
 *
 * Same protocol, without owning a process while the cluster thinks.  The
 * caller starts a pull, gets back a file descriptor, hands it to whatever
 * reactor it lives under, and collects the answer when that fd fires.
 *
 * The fd is the slot's, created before the fork; the reply handler writes
 * to it from whichever process received the answer.  Nothing else about
 * the protocol changes - the blocking entry point below is this same
 * machinery with a poll loop where the reactor would be.
 * ---------------------------------------------------------------------- */

/* Begin a pull.  @fd receives the descriptor to wait on, @id the handle to
 * finish with.
 * @return  1 = started, wait on @fd,
 *          0 = answered without asking anyone (a cached negative),
 *         -1 = cannot pull (not enabled, no peers, no free slot). */
/* @hint_node: ask this one node instead of everybody, when membership
 * confirms it exists and is not us.  A hint is never authoritative - the
 * node may have restarted, expired the entry, or had its id reissued to
 * somebody else - so an unhelpful answer must leave the caller able to
 * ask the rest, which is why a hinted request that comes back empty is
 * reported as "no answer" rather than as absence. */
static int pcache_pull_start(pcache_col_t *col, const str *key, int hint_node,
		int *fd, unsigned int *id_out)
{
	struct pcache_pull_slot *sl = NULL;
	bin_packet_t packet;
	int ids[CL_MAX_NODE_ID], nmembers, i, truncated = 0;
	unsigned int gen = 0, id;

	if (!pcache_pull_enabled(col) || key->len > pull_max_key ||
	        col->col_name.len > 63)
		return -1;
	if (pcache_neg_check(col, key)) {
		__sync_fetch_and_add(&pull_stats[PULL_ST_SUPPRESSED], 1);
		return 0;
	}
	nmembers = pcache_cluster_members(ids, CL_MAX_NODE_ID, &gen, &truncated);
	if (nmembers <= 0)
		return -1;

	/* Validate the hint before trusting it: a node id that is not a
	 * current peer is stale, reissued, or simply wrong, and asking it
	 * would waste the request. */
	if (hint_node > 0) {
		int k, live = 0;

		for (k = 0; k < nmembers; k++)
			if (ids[k] == hint_node) {
				live = 1;
				break;
			}
		if (!live) {
			LM_DBG("hint points at node %d, which is not a current peer - "
				"asking everybody instead\n", hint_node);
			hint_node = 0;
		}
	}

	lock_get(pull_lock);
	for (i = 0; i < PCACHE_PULL_SLOTS; i++)
		if (!pull_slot_at(i)->id) {
			sl = pull_slot_at(i);
			break;
		}
	if (!sl) {
		/* Nothing free.  An orphan is only holding its slot on the chance
		 * that a late answer still arrives, which is worth strictly less
		 * than the request in front of us - take the one whose deadline
		 * passed longest ago.  A live pull is never stolen. */
		struct pcache_pull_slot *victim = NULL;
		int v;

		for (v = 0; v < PCACHE_PULL_SLOTS; v++) {
			struct pcache_pull_slot *c = pull_slot_at(v);

			if (c->id && c->orphan &&
			    (!victim || c->deadline < victim->deadline))
				victim = c;
		}
		if (victim) {
			sl = victim;
			__sync_fetch_and_add(&pull_stats[PULL_ST_ORPHAN_EVICTED], 1);
		}
	}
	if (!sl) {
		lock_release(pull_lock);
		LM_WARN("all %d pull slots busy - dropping the request\n",
			PCACHE_PULL_SLOTS);
		return -1;
	}
	id = ++(*pull_next_id);
	if (!id)
		id = ++(*pull_next_id);
	{
		int efd = sl->efd;             /* survives the memset below */
		uint64_t drain;

		memset(sl, 0, sizeof *sl);
		sl->efd = efd;
		/* a previous user may have left the counter armed if it timed
		 * out just as an answer arrived - start from a known state */
		while (read(efd, &drain, sizeof drain) == (ssize_t)sizeof drain)
			;
	}
	sl->id       = id;
	sl->gen      = gen;
	sl->hinted   = hint_node;
	/* A broadcast goes to every peer, but only the ones that fitted the
	 * snapshot were counted - so on a truncated set the negatives can
	 * reach @expect while peers nobody tallied still hold the key. */
	sl->partial  = hint_node > 0 ? 0 : truncated;
	/* one node was asked, so one answer settles it */
	sl->expect   = hint_node > 0 ? 1 : nmembers;
	sl->deadline = get_uticks() + (utime_t)pull_timeout_ms * 1000;
	memcpy(pull_slot_key(sl), key->s, key->len);
	sl->klen = key->len;
	memcpy(sl->col, col->col_name.s, col->col_name.len);
	sl->collen = col->col_name.len;
	lock_release(pull_lock);

	__sync_fetch_and_add(&pull_stats[PULL_ST_REQUESTED], 1);
#ifdef CLUSTERER_CTRL_SUPPORT
	if (pull_via_clctr) {
		char buf[CLCTR_MAX_PAYLOAD];
		str pl;
		uint32_t id_be = htonl(id);
		uint16_t kl = htons((uint16_t)key->len);
		int n = 0;

		/* the entry checks above bound both lengths, so this can only
		 * fire if those ever change - which is exactly when it should */
		if (PCACHE_CLCTR_REQ_HDR + col->col_name.len + key->len >
		        (int)sizeof buf) {
			LM_ERR("pull request for a %d byte key does not fit %d\n",
				key->len, (int)sizeof buf);
			goto fail;
		}
		buf[n++] = PCACHE_CLCTR_REQ;
		memcpy(buf + n, &id_be, 4); n += 4;
		buf[n++] = (char)col->col_name.len;
		memcpy(buf + n, col->col_name.s, col->col_name.len);
		n += col->col_name.len;
		memcpy(buf + n, &kl, 2); n += 2;
		memcpy(buf + n, key->s, key->len); n += key->len;
		pl.s = buf;
		pl.len = n;
		/* one packet, whatever the cluster size - and encrypted, which
		 * the BIN links are not */
		if (hint_node > 0
		        ? clctr_api.send_ucast(sync_cluster_id, hint_node,
		              &pull_channel, &pl, 0) < 0
		        : clctr_api.send_mcast(sync_cluster_id, &pull_channel,
		              &pl, 0) < 0)
			pull_send_failed("a request could not be sent", hint_node);
	} else
#endif
	{
		if (bin_init(&packet, &pcache_sync_cap, PCACHE_PULL_REQ,
		        PCACHE_SYNC_VERSION, 0) < 0)
			goto fail;
		if (bin_push_int(&packet, (int)id) < 0 ||
		    bin_push_str(&packet, &col->col_name) < 0 ||
		    bin_push_str(&packet, (str *)key) < 0) {
			bin_free_packet(&packet);
			goto fail;
		}
		if ((hint_node > 0
		        ? clusterer_api.send_to(&packet, sync_cluster_id, hint_node)
		        : clusterer_api.send_all(&packet, sync_cluster_id)) !=
		        CLUSTERER_SEND_SUCCESS)
			pull_send_failed("a request reached no or only some nodes",
				hint_node);
		bin_free_packet(&packet);
	}

	*fd = sl->efd;
	*id_out = id;
	return 1;

fail:
	lock_get(pull_lock);
	sl->id = 0;
	lock_release(pull_lock);
	return -1;
}

/* Collect a started pull.  Safe to call on a timeout as well - it releases
 * the slot either way, so a caller that gives up leaks nothing.
 * @return 1 = value in @out, 0 = definitively absent, -1 = no answer. */
static int pcache_pull_finish(pcache_col_t *col, const str *key,
		unsigned int id, char *out, unsigned int outlen, unsigned int *vlen,
		unsigned int *expires)
{
	struct pcache_pull_slot *sl;
	unsigned int exp = 0;
	uint64_t drain;
	int rc = -1;

	lock_get(pull_lock);
	sl = pull_slot_get(id);
	if (!sl) {
		lock_release(pull_lock);
		return -1;                      /* already reaped */
	}
	while (read(sl->efd, &drain, sizeof drain) == (ssize_t)sizeof drain)
		;
	if (sl->done && sl->vlen <= outlen) {
		memcpy(out, pull_slot_val(sl), sl->vlen);
		*vlen = sl->vlen;
		exp = sl->expires;
		if (expires)
			*expires = exp;
		rc = 1;
	} else if (sl->oversize) {
		/* a peer holds it but could not send it over this transport.  The
		 * key exists, so this is "no answer", never absence - and nothing
		 * about it is worth remembering as a negative. */
		rc = -1;
	} else if (sl->negative >= sl->expect) {
		/* One node was asked and it does not have it.  That is not the
		 * cluster's answer, so it must not become one: report no answer
		 * and let the caller ask properly.  Same for a set we could only
		 * partly account for - silence from peers we never counted is
		 * not evidence of absence. */
		rc = (sl->hinted || sl->partial) ? -1 : 0;
	} else {
		__sync_fetch_and_add(&pull_stats[PULL_ST_TIMEOUT], 1);
	}
	if (rc == 0 && pc_view && pc_view->generation != sl->gen) {
		LM_DBG("membership changed during the pull - not concluding "
			"absence\n");
		rc = -1;
	}
	/* Hand the slot to the protocol rather than the pool when we leave
	 * empty-handed: the answer may simply be late, and this slot holds the
	 * only copy of the collection and key it belongs to.  rc == 1 is already
	 * stored below; an oversize holder and a settled absence are final
	 * answers - none of those wants a late reply. */
	if (rc == 1 || sl->oversize || sl->negative >= sl->expect) {
		sl->id = 0;                  /* the slot is reusable from here */
	} else {
		sl->orphan = 1;
		__sync_fetch_and_add(&pull_stats[PULL_ST_ORPHANED], 1);
	}
	lock_release(pull_lock);

	/* Everything below runs OUTSIDE the pull lock, on the copy taken above.
	 * Storing under it would serialise every node-wide pull behind one
	 * table write - and worse, it would nest the pull lock outside the
	 * bucket locks, so any future caller that pulls while holding a bucket
	 * would deadlock.  Nothing here needs the slot. */
	if (rc == 1) {
		str v;

		v.s = out;
		v.len = *vlen;
		if (exp && exp <= get_ticks()) {
			LM_DBG("pulled <%.*s> had already expired in flight - not "
				"stored\n", key->len, key->s);
		} else if (pcache_ht_store(col->htable, key, &v, exp) < 0) {
			LM_ERR("could not store the pulled value for <%.*s>\n",
				key->len, key->s);
		} else {
			__sync_fetch_and_add(&pull_stats[PULL_ST_STORED], 1);
			/* per-collection twin of PULL_ST_STORED: this is the number
			 * that actually answers "is this collection converging?" */
			__sync_fetch_and_add(&col->pulled_in, 1);
			pcache_neg_clear(col, key);
		}
	} else if (rc == 0) {
		pcache_neg_add(col, key);
	}
	return rc;
}

/* Ask the cluster for one key and wait for the answer.
 *
 * A thin wrapper over the asynchronous pair above, with a poll where a
 * reactor would be - so the two paths cannot drift apart, and everything
 * that exercises this also exercises the machinery a suspended lookup
 * will use.  Blocking is why pull_on_miss is off by default.
 *
 * @return 1 = value found (copied into @out), 0 = definitively absent,
 *        -1 = no answer in time, or not usable. */
static int pcache_pull_key(pcache_col_t *col, const str *key, char *out,
		unsigned int outlen, unsigned int *vlen, unsigned int *expires)
{
	struct pollfd pfd;
	unsigned int id = 0;
	int fd = -1, rc, left = pull_timeout_ms;

	rc = pcache_pull_start(col, key, 0, &fd, &id);
	if (rc <= 0)
		return rc == 0 ? 0 : -1;        /* cached negative, or cannot ask */

	pfd.fd = fd;
	pfd.events = POLLIN;
	while (left > 0) {
		int n = poll(&pfd, 1, left);

		if (n > 0)
			break;                      /* an answer landed */
		if (n < 0 && errno == EINTR) {
			left -= 1;                  /* a signal, not an answer */
			continue;
		}
		break;                          /* timeout, or poll failed */
	}

	return pcache_pull_finish(col, key, id, out, outlen, vlen, expires);
}

/* Ask every peer for a key that cannot exist, purely to see who answers.
 *
 * The passive per-peer counters cannot separate "this peer ignores us" from
 * "we have never had reason to ask it" - both read as zero replies.  This
 * settles it by generating the traffic itself, over the configured
 * transport and through the same serve path a real pull uses, so a peer
 * that answers here is genuinely reachable for pulls.
 *
 * CAVEAT, measured: the request inherits the transport's send semantics.
 * Over `bin` that is a TCP write through the clusterer, and a peer that is
 * up but not READING (wedged, stopped, swapping) can block it well past
 * pull_timeout_ms - the timeout here bounds the wait for an ANSWER, not
 * the send.  Observed blocking until the peer was resumed.  Over `clctr`
 * the send is a datagram and cannot block, so this is dependable exactly
 * where it is most wanted.  Run it on a bin cluster knowing it may stall
 * against the kind of peer you are probing for.
 *
 * @seen must have room for CL_MAX_NODE_ID + 1 flags; on return each live
 * peer's slot is 1 if it answered.  Returns the number that did, or -1 if
 * the pull could not even be started.
 */
static int pcache_cluster_probe(pcache_col_t *col, unsigned char *seen,
		int *asked)
{
	struct pollfd pfd;
	struct pcache_pull_slot *sl;
	unsigned int id = 0;
	int fd = -1, rc, left = pull_timeout_ms, i, answered = 0;
	/* no caller can store this: perf_set rejects an empty key, and the
	 * marker byte cannot appear in a th key or any script key */
	static str probe_key = str_init("\x01""cachedb-perf-probe");

	if (asked)
		*asked = 0;
	/* a cached negative for the probe key would answer without asking
	 * anyone, which is the one thing this must not do */
	pcache_neg_clear(col, &probe_key);

	rc = pcache_pull_start(col, &probe_key, 0, &fd, &id);
	if (rc <= 0)
		return -1;

	pfd.fd = fd;
	pfd.events = POLLIN;
	while (left > 0) {
		int n = poll(&pfd, 1, left);

		if (n > 0)
			break;
		if (n < 0 && errno == EINTR) {
			left -= 1;
			continue;
		}
		break;
	}

	/* read the bitmap the reply handler filled in, then release the slot
	 * exactly as finish() would - the answers are the result here, so the
	 * value path is not used at all */
	lock_get(pull_lock);
	sl = pull_slot_get(id);
	if (sl) {
		if (asked)
			*asked = sl->expect;
		for (i = 1; i <= CL_MAX_NODE_ID; i++) {
			int byte = (i - 1) / 8, bit = 1 << ((i - 1) % 8);

			if (sl->answered[byte] & bit) {
				seen[i] = 1;
				answered++;
			}
		}
		sl->id = 0;
	}
	lock_release(pull_lock);

	/* the probe key is absent everywhere by construction; do not let that
	 * conclusion linger and suppress the next probe */
	pcache_neg_clear(col, &probe_key);
	return answered;
}

/* perf_cluster_probe [collection] - who is actually reachable for a pull */
static mi_response_t *do_perf_cluster_probe(str *col_s)
{
	mi_response_t *resp;
	mi_item_t *obj, *arr;
	pcache_col_t *col;
	clusterer_node_t *list, *n;
	unsigned char seen[CL_MAX_NODE_ID + 1];
	int answered, asked = 0;
	/* MI_SSTR expands to two arguments, so it cannot go in a ternary */
	const char *tname = pull_via_clctr ? "clctr" : "bin";

	col = col_s ? col_by_name(col_s) : pcache_default_col;
	if (!col)
		return init_mi_error(404, MI_SSTR("no such collection"));
	if (!pcache_pull_enabled(col))
		return init_mi_error(400, MI_SSTR("cross-node pull is not active "
			"for this collection (replicate_collections)"));

	memset(seen, 0, sizeof seen);
	answered = pcache_cluster_probe(col, seen, &asked);
	if (answered < 0)
		return init_mi_error(500, MI_SSTR("could not start the probe - no "
			"peers, or no free pull slot"));

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_number(obj, MI_SSTR("asked"), asked) < 0 ||
	    add_mi_number(obj, MI_SSTR("answered"), answered) < 0 ||
	    add_mi_number(obj, MI_SSTR("timeout_ms"), pull_timeout_ms) < 0 ||
	    add_mi_string(obj, MI_SSTR("transport"), tname, strlen(tname)) < 0)
		goto err;

	arr = add_mi_array(obj, MI_SSTR("peers"));
	if (!arr)
		goto err;
	list = clusterer_api.get_nodes(sync_cluster_id);
	for (n = list; n; n = n->next) {
		mi_item_t *p = add_mi_object(arr, NULL, 0);
		int up = n->node_id > 0 && n->node_id <= CL_MAX_NODE_ID &&
			seen[n->node_id];

		if (!p) {
			clusterer_api.free_nodes(list);
			goto err;
		}
		if (add_mi_number(p, MI_SSTR("node_id"), n->node_id) < 0 ||
		    add_mi_string(p, MI_SSTR("answered_probe"),
		        up ? "yes" : "no", up ? 3 : 2) < 0) {
			clusterer_api.free_nodes(list);
			goto err;
		}
	}
	if (list)
		clusterer_api.free_nodes(list);
	return resp;
err:
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("Internal error"));
}

static mi_response_t *mi_perf_cluster_probe_0(const mi_params_t *params,
		struct mi_handler *async)
{
	return do_perf_cluster_probe(NULL);
}

static mi_response_t *mi_perf_cluster_probe_1(const mi_params_t *params,
		struct mi_handler *async)
{
	str col;

	if (get_mi_string_param(params, "collection", &col.s, &col.len) < 0)
		return init_mi_param_error();
	return do_perf_cluster_probe(&col);
}

static void pcache_sync_recv(bin_packet_t *packet)
{
	pcache_col_t *col;
	str coll;

	if (packet->type == PCACHE_PULL_REQ) {
		pcache_pull_serve(packet);
		return;
	}
	if (packet->type == PCACHE_PULL_RPL) {
		pcache_pull_reply(packet);
		return;
	}
	if (packet->type != PCACHE_SYNC_RELOAD) {
		LM_WARN("unknown sync packet type %d from node %d\n",
			packet->type, packet->src_id);
		return;
	}
	if (bin_pop_str(packet, &coll) < 0) {
		LM_ERR("malformed sync packet from node %d\n", packet->src_id);
		return;
	}
	col = col_by_name(&coll);
	if (!col || !col->htable) {
		LM_WARN("sync for unknown collection <%.*s> from node %d\n",
			coll.len, coll.s, packet->src_id);
		return;
	}
	LM_INFO("cluster sync: reloading <%.*s> from DB (issued by node %d)\n",
		coll.len, coll.s, packet->src_id);
	if (pcache_db_load(col) >= 0) {
		col->last_sync_in = get_ticks();
		col->last_sync_src = packet->src_id;
		pcache_raise_synced(&col->col_name, packet->src_id);
	}
}

/* broadcast "reload collection X" to the cluster (best-effort - the DB
 * already holds the truth; a peer that misses it re-syncs later) */
static void pcache_sync_broadcast(str *coll)
{
	bin_packet_t packet;

	if (!sync_ready)
		return;
	if (bin_init(&packet, &pcache_sync_cap, PCACHE_SYNC_RELOAD,
	        PCACHE_SYNC_VERSION, 0) < 0) {
		LM_ERR("failed to init the sync packet\n");
		return;
	}
	if (bin_push_str(&packet, coll) < 0) {
		bin_free_packet(&packet);
		return;
	}
	if (clusterer_api.send_all(&packet, sync_cluster_id) != CLUSTERER_SEND_SUCCESS)
		LM_DBG("sync broadcast for <%.*s> reached no/partial nodes\n",
			coll->len, coll->s);
	bin_free_packet(&packet);
}

/* save a collection to the DB then signal peers to reload it */
static int perf_sync_one(pcache_col_t *col, int *bcast)
{
	int rc = pcache_db_save(col);

	if (rc < 0)
		return -1;
	col->last_sync_out = get_ticks();
	pcache_sync_broadcast(&col->col_name);
	if (sync_ready)
		(*bcast)++;
	return rc;
}

/* Sharing-tag failover hook (CP-15.12).  A BACKUP->ACTIVE flip hands this
 * node traffic for state its cache never saw - a mass-miss event.  The two
 * directions of the hook keep that a snapshot-sized problem:
 *   ACTIVE - warm the persist collections from the DB snapshot BEFORE the
 *            storm.  On a crash failover the snapshot is the only source
 *            there is; wall-clock TTLs skip whatever already expired.
 *   BACKUP - graceful demotion: save our (freshest) state and broadcast,
 *            so the new active reloads it via the normal sync path.  This
 *            also repairs the flip-ordering race: the new active's warm
 *            load may run before our save lands, but the broadcast makes
 *            it reload again afterwards.
 * The tag schedules bulk syncs and NOTHING ELSE - lookups are never gated
 * on shtag state (a backup node can still legitimately receive traffic).
 * Runs in whichever process the clusterer delivers the state change to;
 * the DB ops use their own short-lived, fork-safe connections. */
static void pcache_shtag_cb(str *tag_name, int state, int c_id, void *param)
{
	pcache_col_t *col;
	int n = 0, entries = 0, bcast = 0, rc;

	if (state == SHTAG_STATE_ACTIVE) {
		/* same scope as a no-argument perf_load/perf_sync: every declared
		 * collection - the persist flag only governs startup/shutdown */
		for (col = pcache_collection; col; col = col->next) {
			if (!col->htable)
				continue;
			rc = pcache_db_load(col);
			if (rc >= 0) {
				n++;
				entries += rc;
			}
		}
		LM_INFO("sharing tag <%.*s/%d> ACTIVE: warmed %d collection(s), "
			"%d entries, from the DB snapshot\n",
			tag_name->len, tag_name->s, c_id, n, entries);
	} else if (state == SHTAG_STATE_BACKUP) {
		for (col = pcache_collection; col; col = col->next) {
			if (!col->htable)
				continue;
			if (perf_sync_one(col, &bcast) >= 0)
				n++;
		}
		LM_INFO("sharing tag <%.*s/%d> BACKUP: saved %d collection(s)%s\n",
			tag_name->len, tag_name->s, c_id, n,
			bcast ? ", peers signalled to reload" : "");
	}
}

/* perf_sync [collection] - save-then-broadcast; all declared if none named */
static mi_response_t *do_perf_sync(str *col_s)
{
	pcache_col_t *col;
	mi_response_t *resp;
	mi_item_t *obj;
	int saved = 0, ncol = 0, bcast = 0, rc;

	if (!pcache_db_enabled())
		return init_mi_error(500,
			MI_SSTR("no DB backend configured (set db_url)"));

	if (col_s) {
		col = col_by_name(col_s);
		if (!col)
			return init_mi_error(404, MI_SSTR("no such collection"));
		rc = perf_sync_one(col, &bcast);
		if (rc < 0)
			return init_mi_error(500, MI_SSTR("save failed"));
		saved = rc;
		ncol = 1;
	} else {
		for (col = pcache_collection; col; col = col->next) {
			if (!col->htable)
				continue;
			rc = perf_sync_one(col, &bcast);
			if (rc < 0)
				return init_mi_error(500, MI_SSTR("save failed"));
			saved += rc;
			ncol++;
		}
	}

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_number(obj, MI_SSTR("collections"), ncol) < 0 ||
	    add_mi_number(obj, MI_SSTR("saved"), saved) < 0 ||
	    add_mi_number(obj, MI_SSTR("broadcast"), bcast) < 0)
		goto err;
	if (!sync_ready && add_mi_string(obj, MI_SSTR("note"),
	        MI_SSTR("cluster sync inactive (no clusterer / cluster_id 0) - "
	            "saved to the DB only")) < 0)
		goto err;
	return resp;
err:
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("internal error"));
}

static int w_perf_sync(struct sip_msg *msg, str *col_s)
{
	pcache_col_t *col;
	int bcast = 0;

	if (!pcache_db_enabled()) {
		LM_ERR("perf_sync needs a DB backend (db_url)\n");
		return -1;
	}
	if (col_s) {
		col = col_by_name(col_s);
		if (!col || perf_sync_one(col, &bcast) < 0)
			return -1;
	} else {
		for (col = pcache_collection; col; col = col->next)
			if (col->htable && perf_sync_one(col, &bcast) < 0)
				return -1;
	}
	return 1;
}

/* thin per-arity recipe wrappers: extract params, then defer to the workers */
#define MI_S(nm, dst) \
	do { if (get_mi_string_param(params, nm, &(dst).s, &(dst).len) < 0) \
		return init_mi_param_error(); } while (0)
#define MI_I(nm, dst) \
	do { if (get_mi_int_param(params, nm, &(dst)) < 0) \
		return init_mi_param_error(); } while (0)

static mi_response_t *mi_perf_keys_1(const mi_params_t *params, struct mi_handler *a)
{ str g; MI_S("glob", g); return do_perf_keys(&g, NULL, 0, 0); }
static mi_response_t *mi_perf_keys_2(const mi_params_t *params, struct mi_handler *a)
{ str g, c; MI_S("glob", g); MI_S("collection", c); return do_perf_keys(&g, &c, 0, 0); }
static mi_response_t *mi_perf_keys_3(const mi_params_t *params, struct mi_handler *a)
{ str g, c; int l; MI_S("glob", g); MI_S("collection", c); MI_I("limit", l);
  return do_perf_keys(&g, &c, l, 0); }
static mi_response_t *mi_perf_keys_gl(const mi_params_t *params, struct mi_handler *a)
{ str g; int l; MI_S("glob", g); MI_I("limit", l); return do_perf_keys(&g, NULL, l, 0); }

static mi_response_t *mi_perf_dump_1(const mi_params_t *params, struct mi_handler *a)
{ str g; MI_S("glob", g); return do_perf_keys(&g, NULL, 0, 1); }
static mi_response_t *mi_perf_dump_2(const mi_params_t *params, struct mi_handler *a)
{ str g, c; MI_S("glob", g); MI_S("collection", c); return do_perf_keys(&g, &c, 0, 1); }
static mi_response_t *mi_perf_dump_3(const mi_params_t *params, struct mi_handler *a)
{ str g, c; int l; MI_S("glob", g); MI_S("collection", c); MI_I("limit", l);
  return do_perf_keys(&g, &c, l, 1); }
static mi_response_t *mi_perf_dump_gl(const mi_params_t *params, struct mi_handler *a)
{ str g; int l; MI_S("glob", g); MI_I("limit", l); return do_perf_keys(&g, NULL, l, 1); }

static mi_response_t *mi_perf_scan_1(const mi_params_t *params, struct mi_handler *a)
{ int cu; MI_I("cursor", cu); return do_perf_scan(cu, NULL, 0); }
static mi_response_t *mi_perf_scan_2(const mi_params_t *params, struct mi_handler *a)
{ int cu; str g; MI_I("cursor", cu); MI_S("glob", g); return do_perf_scan(cu, &g, 0); }
static mi_response_t *mi_perf_scan_3(const mi_params_t *params, struct mi_handler *a)
{ int cu, co; str g; MI_I("cursor", cu); MI_S("glob", g); MI_I("count", co);
  return do_perf_scan(cu, &g, co); }
static mi_response_t *mi_perf_scan_cc(const mi_params_t *params, struct mi_handler *a)
{ int cu, co; MI_I("cursor", cu); MI_I("count", co); return do_perf_scan(cu, NULL, co); }

static mi_response_t *mi_perf_pull_1(const mi_params_t *params, struct mi_handler *a)
{ str k; MI_S("key", k); return do_perf_pull(&k, NULL); }
static mi_response_t *mi_perf_pull_2(const mi_params_t *params, struct mi_handler *a)
{ str k, c; MI_S("key", k); MI_S("collection", c); return do_perf_pull(&k, &c); }

static mi_response_t *mi_perf_probe_1(const mi_params_t *params, struct mi_handler *a)
{ str k; MI_S("key", k); return do_perf_probe(&k, NULL); }
static mi_response_t *mi_perf_probe_2(const mi_params_t *params, struct mi_handler *a)
{ str k, c; MI_S("key", k); MI_S("collection", c); return do_perf_probe(&k, &c); }

static mi_response_t *mi_perf_get_1(const mi_params_t *params, struct mi_handler *a)
{ str k; MI_S("key", k); return do_perf_get(&k, NULL); }
static mi_response_t *mi_perf_get_2(const mi_params_t *params, struct mi_handler *a)
{ str k, c; MI_S("key", k); MI_S("collection", c); return do_perf_get(&k, &c); }

static mi_response_t *mi_perf_set_2(const mi_params_t *params, struct mi_handler *a)
{ str k, v; MI_S("key", k); MI_S("value", v); return do_perf_set(&k, &v, 0, NULL); }
static mi_response_t *mi_perf_set_3(const mi_params_t *params, struct mi_handler *a)
{ str k, v; int t; MI_S("key", k); MI_S("value", v); MI_I("ttl", t);
  return do_perf_set(&k, &v, t, NULL); }
static mi_response_t *mi_perf_set_4(const mi_params_t *params, struct mi_handler *a)
{ str k, v, c; int t; MI_S("key", k); MI_S("value", v); MI_I("ttl", t);
  MI_S("collection", c); return do_perf_set(&k, &v, t, &c); }
static mi_response_t *mi_perf_set_kvc(const mi_params_t *params, struct mi_handler *a)
{ str k, v, c; MI_S("key", k); MI_S("value", v); MI_S("collection", c);
  return do_perf_set(&k, &v, 0, &c); }

static mi_response_t *mi_perf_del_1(const mi_params_t *params, struct mi_handler *a)
{ str g; MI_S("glob", g); return do_perf_del_mi(&g, NULL); }
static mi_response_t *mi_perf_del_2(const mi_params_t *params, struct mi_handler *a)
{ str g, c; MI_S("glob", g); MI_S("collection", c); return do_perf_del_mi(&g, &c); }

static mi_response_t *mi_perf_ttl_2(const mi_params_t *params, struct mi_handler *a)
{ str g; int t; MI_S("glob", g); MI_I("ttl", t); return do_perf_ttl(&g, t, NULL); }
static mi_response_t *mi_perf_ttl_3(const mi_params_t *params, struct mi_handler *a)
{ str g, c; int t; MI_S("glob", g); MI_I("ttl", t); MI_S("collection", c);
  return do_perf_ttl(&g, t, &c); }

static mi_response_t *mi_perf_save_0(const mi_params_t *params, struct mi_handler *a)
{ return do_perf_persist(NULL, 1); }
static mi_response_t *mi_perf_save_1(const mi_params_t *params, struct mi_handler *a)
{ str c; MI_S("collection", c); return do_perf_persist(&c, 1); }
static mi_response_t *mi_perf_load_0(const mi_params_t *params, struct mi_handler *a)
{ return do_perf_persist(NULL, 0); }
static mi_response_t *mi_perf_load_1(const mi_params_t *params, struct mi_handler *a)
{ str c; MI_S("collection", c); return do_perf_persist(&c, 0); }
static mi_response_t *mi_perf_sync_0(const mi_params_t *params, struct mi_handler *a)
{ return do_perf_sync(NULL); }
static mi_response_t *mi_perf_sync_1(const mi_params_t *params, struct mi_handler *a)
{ str c; MI_S("collection", c); return do_perf_sync(&c); }

#undef MI_S
#undef MI_I

static const mi_export_t mi_cmds[] = {
	{ "perf_stats", "per-collection stats (entries, buckets, load factor, "
		"overflow, seqlock retries, memory tier)", 0, 0, {
		{mi_perf_stats_1, {0}},
		{mi_perf_stats_2, {"collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_stats_reset", "re-baseline the cumulative counters so the rates "
		"cover a fresh interval; live gauges are unaffected", 0, 0, {
		{mi_perf_stats_reset_1, {0}},
		{mi_perf_stats_reset_2, {"collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_keys", "names of keys matching a glob, bounded (KEYS-like)", 0, 0, {
		{mi_perf_keys_1, {"glob", 0}},
		{mi_perf_keys_2, {"glob", "collection", 0}},
		{mi_perf_keys_gl, {"glob", "limit", 0}},
		{mi_perf_keys_3, {"glob", "collection", "limit", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_scan", "cursor-based incremental iteration (Redis SCAN); pass "
		"cursor 0 to start, iteration ends when it returns 0", 0, 0, {
		{mi_perf_scan_1, {"cursor", 0}},
		{mi_perf_scan_2, {"cursor", "glob", 0}},
		{mi_perf_scan_cc, {"cursor", "count", 0}},
		{mi_perf_scan_3, {"cursor", "glob", "count", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_dump", "keys AND values matching a glob, bounded (opt-in values)",
		0, 0, {
		{mi_perf_dump_1, {"glob", 0}},
		{mi_perf_dump_2, {"glob", "collection", 0}},
		{mi_perf_dump_gl, {"glob", "limit", 0}},
		{mi_perf_dump_3, {"glob", "collection", "limit", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_pull", "fetch one key from the cluster on a local miss", 0, 0, {
		{mi_perf_pull_1, {"key", 0}},
		{mi_perf_pull_2, {"key", "collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_cluster_probe", "ask every peer for a key that cannot exist, to "
		"see which ones actually answer a pull", 0, 0, {
		{mi_perf_cluster_probe_0, {0}},
		{mi_perf_cluster_probe_1, {"collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_probe", "one key: is it here, its TTL and size - no value", 0, 0, {
		{mi_perf_probe_1, {"key", 0}},
		{mi_perf_probe_2, {"key", "collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_get", "one key: value, TTL and size", 0, 0, {
		{mi_perf_get_1, {"key", 0}},
		{mi_perf_get_2, {"key", "collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_set", "write one key (optional ttl seconds, 0 = never)", 0, 0, {
		{mi_perf_set_2, {"key", "value", 0}},
		{mi_perf_set_3, {"key", "value", "ttl", 0}},
		{mi_perf_set_kvc, {"key", "value", "collection", 0}},
		{mi_perf_set_4, {"key", "value", "ttl", "collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_del", "delete keys matching a glob (the perf_del() script fn)",
		0, 0, {
		{mi_perf_del_1, {"glob", 0}},
		{mi_perf_del_2, {"glob", "collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_ttl", "re-arm the TTL of every key matching a glob (ttl seconds, "
		"0 = never); returns the count updated", 0, 0, {
		{mi_perf_ttl_2, {"glob", "ttl", 0}},
		{mi_perf_ttl_3, {"glob", "ttl", "collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_save", "snapshot a collection to the DB backend (all declared "
		"collections if none is named)", 0, 0, {
		{mi_perf_save_0, {0}},
		{mi_perf_save_1, {"collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_load", "load a collection from the DB backend (all declared "
		"collections if none is named)", 0, 0, {
		{mi_perf_load_0, {0}},
		{mi_perf_load_1, {"collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "perf_sync", "save a collection to the DB and signal the cluster to "
		"reload it (all declared collections if none is named)", 0, 0, {
		{mi_perf_sync_0, {0}},
		{mi_perf_sync_1, {"collection", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{EMPTY_MI_EXPORT}
};

/* soft clusterer dependency: when sync_cluster_id is set, have clusterer
 * init first (so register_capability runs and "cachedb-perf-sync" shows in
 * clusterer_list_caps) - but SILENT, so a missing clusterer does not abort;
 * perf_sync then degrades to a DB save (mod_init handles it) */
static module_dependency_t *get_deps_sync_cluster(const param_export_t *param)
{
	if (*(int *)param->param_pointer <= 0)
		return NULL;
	return alloc_module_dep(MOD_TYPE_DEFAULT, "clusterer", DEP_SILENT);
}

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "sync_cluster_id", get_deps_sync_cluster },
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports = {
	"cachedb_perf",             /* module name */
	MOD_TYPE_CACHEDB,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	mod_stats,                  /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) mod_destroy, /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};


/*
 * connection management
 *
 * The collection is taken from the URL's "database" part (perf:///name)
 * or, as a convenience, from the "host" part (perf://name) - a host has
 * no meaning for a local cache.  No collection in the URL means the
 * default one.  Matching is exact and an unknown name is a hard error.
 */
/* Connections this module created, so a con arriving through the exported
 * pull API can be recognised before anything is read out of it.
 *
 * The API is bound by name through find_export, which offers no type safety
 * whatever: any module that loads cachedb_perf can call these entry points
 * and pass a cachedb_con belonging to some other backend.  Reading ->data as
 * a pcache_con at that point is a type confusion - the field where this
 * module keeps its collection pointer is, in a redis or local connection,
 * whatever that module put there.  So the pointer is checked against this
 * list instead, which never dereferences the stranger.
 *
 * Per-process (pkg), like the connections themselves, and short - one entry
 * per URL this process opened. */
struct pcache_con_reg {
	pcache_con            *con;
	struct pcache_con_reg *next;
};
static struct pcache_con_reg *pcache_con_reg_head;

static void pcache_con_register(pcache_con *c)
{
	struct pcache_con_reg *r = pkg_malloc(sizeof(*r));

	if (!r) {
		LM_ERR("out of pkg memory registering a connection\n");
		return;
	}
	r->con = c;
	r->next = pcache_con_reg_head;
	pcache_con_reg_head = r;
}

static void pcache_con_unregister(pcache_con *c)
{
	struct pcache_con_reg **p = &pcache_con_reg_head;

	while (*p) {
		if ((*p)->con == c) {
			struct pcache_con_reg *dead = *p;

			*p = dead->next;
			pkg_free(dead);
			return;
		}
		p = &(*p)->next;
	}
}

/* The collection behind a connection, or NULL when the connection is not
 * ours.  Every exported entry point goes through this. */
static pcache_col_t *pcache_col_of(cachedb_con *con)
{
	struct pcache_con_reg *r;

	if (!con || !con->data)
		return NULL;
	for (r = pcache_con_reg_head; r; r = r->next)
		if (r->con == (pcache_con *)con->data)
			return r->con->col;

	LM_ERR("a connection that this module did not open was passed to its "
		"pull API - refusing it.  The caller is holding a handle to a "
		"different cachedb backend; only a perf:// connection can be "
		"pulled through\n");
	return NULL;
}

static pcache_con *pcache_new_connection(struct cachedb_id *id)
{
	pcache_con *con;
	pcache_col_t *col;
	const char *sel = NULL;
	int len;

	if (!id) {
		LM_ERR("null cachedb_id\n");
		return NULL;
	}

	if (id->database && id->database[0]) {
		sel = id->database;
		if (id->host && id->host[0] && strcmp(id->host, id->database))
			LM_WARN("URL <%s>: ignoring host part <%s>, "
				"using collection <%s>\n",
				id->initial_url, id->host, sel);
	} else if (id->host && id->host[0]) {
		sel = id->host;
	}

	if (!sel)
		sel = PCACHE_DEFAULT_COLLECTION;

	len = strlen(sel);
	for (col = pcache_collection; col; col = col->next)
		if (col->col_name.len == len &&
		        !memcmp(col->col_name.s, sel, len))
			break;

	if (!col) {
		LM_ERR("collection <%s> is not defined in 'cache_collections'\n",
			sel);
		return NULL;
	}

	con = pkg_malloc(sizeof *con);
	if (!con) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}
	memset(con, 0, sizeof *con);
	con->id = id;
	con->ref = 1;
	con->col = col;

	LM_DBG("URL <%s> bound to collection <%.*s>\n",
		id->initial_url, col->col_name.len, col->col_name.s);

	pcache_con_register(con);
	return con;
}

static cachedb_con *pcache_init(str *url)
{
	return cachedb_do_init(url, (void *)pcache_new_connection);
}

static void pcache_free_connection(cachedb_pool_con *con)
{
	pcache_con_unregister((pcache_con *)con);

	pkg_free(con);
}

static void pcache_destroy(cachedb_con *con)
{
	cachedb_do_close(con, pcache_free_connection);
}


/*
 * CP-11 event raising.  Every raise is gated by evi_probe_event(), so with
 * no subscribers the cost is one shared read and nothing else - none of
 * these sit on the lock-free get/set hot path (expiry/growth run in the
 * maintenance timer, NOMEM only on a dropped write, degraded once at boot).
 */
static void pcache_on_expired(const str *key, void *ctx)
{
	str *coll = ctx;
	evi_params_p list;

	/* the timer already probed before opting this sweep into events */
	list = evi_get_params();
	if (!list)
		return;
	if (evi_param_add_str(list, &evp_collection, coll) ||
	    evi_param_add_str(list, &evp_key, key)) {
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(evi_expired_id, list))
		LM_ERR("failed to raise %.*s\n", evi_expired_name.len,
			evi_expired_name.s);
}

static void pcache_raise_nomem(str *coll, str *key, int size)
{
	evi_params_p list;

	if (evi_nomem_id == EVI_ERROR || !evi_probe_event(evi_nomem_id))
		return;
	list = evi_get_params();
	if (!list)
		return;
	if (evi_param_add_str(list, &evp_collection, coll) ||
	    evi_param_add_str(list, &evp_key, key) ||
	    evi_param_add_int(list, &evp_size, &size)) {
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(evi_nomem_id, list))
		LM_ERR("failed to raise %.*s\n", evi_nomem_name.len,
			evi_nomem_name.s);
}

static void pcache_raise_grown(str *coll, int prev_b, int new_b, int splits,
		int entries)
{
	evi_params_p list;

	if (evi_grown_id == EVI_ERROR || !evi_probe_event(evi_grown_id))
		return;
	list = evi_get_params();
	if (!list)
		return;
	if (evi_param_add_str(list, &evp_collection, coll) ||
	    evi_param_add_int(list, &evp_prev_buckets, &prev_b) ||
	    evi_param_add_int(list, &evp_buckets, &new_b) ||
	    evi_param_add_int(list, &evp_splits, &splits) ||
	    evi_param_add_int(list, &evp_entries, &entries)) {
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(evi_grown_id, list))
		LM_ERR("failed to raise %.*s\n", evi_grown_name.len,
			evi_grown_name.s);
}

static void pcache_raise_degraded(void)
{
	evi_params_p list;
	str backing;
	int req = pcache_arena_hugepage_mb;
	int tier = pcache_arena_tier();
	int oc = pcache_mem.huge_overcommit;

	if (evi_degraded_id == EVI_ERROR || !evi_probe_event(evi_degraded_id))
		return;
	list = evi_get_params();
	if (!list)
		return;
	backing.s = (char *)pcache_mem_tier_str(tier);
	backing.len = strlen(backing.s);
	if (evi_param_add_int(list, &evp_requested_mb, &req) ||
	    evi_param_add_int(list, &evp_tier, &tier) ||
	    evi_param_add_str(list, &evp_backing, &backing) ||
	    evi_param_add_int(list, &evp_overcommit, &oc)) {
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(evi_degraded_id, list))
		LM_ERR("failed to raise %.*s\n", evi_degraded_name.len,
			evi_degraded_name.s);
}

static void pcache_raise_synced(str *coll, int src_node)
{
	evi_params_p list;

	if (evi_synced_id == EVI_ERROR || !evi_probe_event(evi_synced_id))
		return;
	list = evi_get_params();
	if (!list)
		return;
	if (evi_param_add_str(list, &evp_collection, coll) ||
	    evi_param_add_int(list, &evp_source_node, &src_node)) {
		evi_free_params(list);
		return;
	}
	if (evi_raise_event(evi_synced_id, list))
		LM_ERR("failed to raise %.*s\n", evi_synced_name.len,
			evi_synced_name.s);
}

/*
 * the cachedb vtable (CP-04) - thin adapters over the table core.  TTL to
 * absolute-ticks conversion happens here; internals only see absolutes.
 */
static pcache_htable_t *con_ht(cachedb_con *con)
{
	pcache_con *c = con ? (pcache_con *)con->data : NULL;

	if (!c || !c->col || !c->col->htable) {
		LM_ERR("no connection state\n");
		return NULL;
	}
	return c->col->htable;
}

static inline unsigned int ttl_to_abs(int expires)
{
	return expires > 0 ? get_ticks() + (unsigned int)expires : 0;
}

/* Read repair on the normal get path: a miss here asks the cluster, and a
 * value that comes back is returned as if it had been local all along -
 * so a consumer gets cross-node lookups without knowing they exist.
 *
 * Off by default, and it must stay that way until the lookup can suspend
 * the transaction instead of the worker: this blocks for as long as the
 * pull takes, which on a SIP path means a worker not serving anything
 * else.  A LAN pull is a couple of milliseconds and the negative cache
 * absorbs retransmits, but "usually fast" is not the same as "safe under
 * load", which is why the startup warning says so out loud. */
static int pcache_htable_fetch(cachedb_con *con, str *attr, str *val)
{
	pcache_col_t *col = con ? ((pcache_con *)con->data)->col : NULL;
	unsigned int vlen = 0;
	int rc;

	if (!col || !col->htable)
		return -1;
	rc = pcache_ht_fetch(col->htable, attr, val);
	if (rc != -2 || !pull_on_miss || !pcache_pull_enabled(col))
		return rc;

	/* the pull buffer lives in this branch, not in the frame of every
	 * local hit: this is the vtable read, and a cross-node miss is the
	 * rare path */
	{
		char buf[PCACHE_PULL_MAX_VAL];

		if (pcache_pull_key(col, attr, buf, sizeof buf, &vlen, NULL) != 1)
			return -2;                /* absent, or nobody answered */

		/* hand back a copy the caller owns, exactly as a local hit would */
		val->s = pkg_malloc(vlen ? vlen : 1);
		if (!val->s) {
			LM_ERR("no more pkg memory for a %u byte pulled value\n", vlen);
			return -1;
		}
		memcpy(val->s, buf, vlen);
	}
	val->len = vlen;
	return 0;
}

/* CACHEDB_CAP_GET_BUF: the allocation-free read.  Note this deliberately
 * does NOT touch pcache_htable_fetch() above - the vtable get() keeps its
 * own documented behaviour, byte for byte. */
static int pcache_htable_fetch_buf(cachedb_con *con, str *attr, char *buf,
		unsigned int buflen, unsigned int *vlen, unsigned int *needed)
{
	pcache_htable_t *ht = con_ht(con);

	if (vlen)
		*vlen = 0;
	if (needed)
		*needed = 0;
	return ht ? pcache_ht_fetch_buf(ht, attr, buf, buflen, vlen, needed) : -1;
}

static int pcache_htable_fetch_counter(cachedb_con *con, str *attr, int *val)
{
	pcache_htable_t *ht = con_ht(con);
	long long ll;
	str v;
	int rc;

	if (!ht)
		return -1;
	rc = pcache_ht_fetch(ht, attr, &v);
	if (rc != 0)
		return rc;                    /* -2 absent / -1 error */
	rc = pcache_str2ll(v.s, v.len, &ll);
	pkg_free(v.s);
	if (rc < 0) {
		LM_ERR("value of <%.*s> is not a counter\n", attr->len, attr->s);
		return -1;
	}
	if (val)
		*val = (int)ll;
	return 0;
}

static int pcache_htable_insert(cachedb_con *con, str *attr, str *val,
		int expires)
{
	pcache_col_t *col = con ? ((pcache_con *)con->data)->col : NULL;
	int rc;

	if (!col || !col->htable)
		return -1;
	rc = pcache_ht_store(col->htable, attr, val, ttl_to_abs(expires));
	if (rc == -2) {                       /* arena full - write dropped */
		pcache_raise_nomem(&col->col_name, attr, val ? val->len : 0);
		return -1;
	}
	/* the key exists here now, so any conclusion we drew about the
	 * cluster not having it no longer describes it */
	if (rc >= 0)
		pcache_neg_clear(col, attr);
	return rc;
}

static int pcache_htable_remove(cachedb_con *con, str *attr)
{
	pcache_htable_t *ht = con_ht(con);

	if (!ht)
		return -1;
	return pcache_ht_remove(ht, attr) < 0 ? -1 : 0;
}

static int pcache_htable_add(cachedb_con *con, str *attr, int val,
		int expires, int *new_val)
{
	pcache_htable_t *ht = con_ht(con);
	long long nv;

	if (!ht)
		return -1;
	if (pcache_ht_add(ht, attr, val, ttl_to_abs(expires), &nv) < 0)
		return -1;
	if (new_val)
		*new_val = (int)nv;
	return 0;
}

static int pcache_htable_sub(cachedb_con *con, str *attr, int val,
		int expires, int *new_val)
{
	pcache_htable_t *ht = con_ht(con);
	long long nv;

	if (!ht)
		return -1;
	if (pcache_ht_add(ht, attr, -(long long)val, ttl_to_abs(expires),
	        &nv) < 0)
		return -1;
	if (new_val)
		*new_val = (int)nv;
	return 0;
}

struct iter_ctx {
	int (*kv)(const str *key, const str *value);
	unsigned int now;
};

static int iter_adapt_cb(const str *key, const str *val, unsigned int exp,
		void *p)
{
	struct iter_ctx *ic = p;

	if (exp && exp <= ic->now)
		return 0;                     /* expired-as-absent */
	return ic->kv(key, val);
}

static int pcache_htable_iter_keys(cachedb_con *con,
		int (*kv_func)(const str *key, const str *value))
{
	pcache_con *c = con ? (pcache_con *)con->data : NULL;
	struct iter_ctx ic;

	if (!c || !c->col || !c->col->htable) {
		LM_ERR("no connection state\n");
		return -1;
	}
	ic.kv = kv_func;
	ic.now = get_ticks();
	return pcache_ht_iter(c->col->htable, iter_adapt_cb, &ic);
}


/*
 * glob operations (CP-07): perf_del / perf_mget / perf_mget_json, all on
 * the pcache_ht_iter() walker.  Redis SCAN-class guarantee: entries
 * mutating concurrently may be seen once, twice or not at all.
 */

static pcache_col_t *col_by_name(const str *name)
{
	pcache_col_t *col;
	str def = str_init(PCACHE_DEFAULT_COLLECTION);

	if (!name || !name->s || !name->len) {
		/* no collection argument = wherever cache_store("perf", ...)
		 * goes, i.e. the default connection's collection */
		if (pcache_default_col)
			return pcache_default_col;
		name = &def;
	}
	for (col = pcache_collection; col; col = col->next)
		if (col->col_name.len == name->len &&
		        !memcmp(col->col_name.s, name->s, name->len))
			return col;
	LM_ERR("collection <%.*s> is not defined\n", name->len, name->s);
	return NULL;
}

static int fixup_check_wvar(void **param)
{
	if (((pv_spec_t *)*param)->setf == NULL) {
		LM_ERR("output parameter must be a writable variable\n");
		return -1;
	}
	return 0;
}

static char *glob_dup(const str *glob)
{
	char *pat = pkg_malloc(glob->len + 1);

	if (!pat) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}
	memcpy(pat, glob->s, glob->len);
	pat[glob->len] = 0;
	return pat;
}

struct del_ctx {
	const char *pat;
	str *keys;
	unsigned int n, cap;
	int oom;
};

static int del_collect_cb(const str *key, const str *val, unsigned int exp,
		void *p)
{
	struct del_ctx *dc = p;
	str *grown;

	if (fnmatch(dc->pat, key->s, 0))
		return 0;
	if (dc->n == dc->cap) {
		dc->cap = dc->cap ? 2 * dc->cap : 64;
		grown = pkg_realloc(dc->keys, dc->cap * sizeof *dc->keys);
		if (!grown) {
			dc->oom = 1;
			return -1;
		}
		dc->keys = grown;
	}
	if (pkg_str_dup(&dc->keys[dc->n], key) < 0) {
		dc->oom = 1;
		return -1;
	}
	dc->n++;
	return 0;
}

/* glob-delete core, shared by the script perf_del() and the MI perf_del:
 * collect matches lock-free, then remove one by one - a glob delete is not
 * an atomic snapshot (and cannot usefully be).  Returns the number removed
 * (>= 0), or -1 on OOM (the removal is then partial). */
static int perf_del_run(pcache_col_t *col, str *glob)
{
	struct del_ctx dc;
	char *pat;
	unsigned int i, removed = 0;

	pat = glob_dup(glob);
	if (!pat)
		return -1;

	memset(&dc, 0, sizeof dc);
	dc.pat = pat;
	pcache_ht_iter(col->htable, del_collect_cb, &dc);

	for (i = 0; i < dc.n; i++) {
		if (pcache_ht_remove(col->htable, &dc.keys[i]) == 1)
			removed++;
		pkg_free(dc.keys[i].s);
	}
	if (dc.keys)
		pkg_free(dc.keys);

	LM_DBG("glob <%s>: removed %u of %u matches\n", pat, removed, dc.n);
	pkg_free(pat);
	if (dc.oom) {
		LM_ERR("out of pkg memory mid-walk - removal is partial\n");
		return -1;
	}
	return (int)removed;
}

static int w_perf_del(struct sip_msg *msg, str *glob, str *col_s)
{
	pcache_col_t *col = col_by_name(col_s);
	int removed;

	if (!col)
		return -1;
	removed = perf_del_run(col, glob);
	return removed > 0 ? removed : -1;   /* 0 matches / OOM -> script-false */
}

/* growing pkg buffer for the JSON form */
struct jbuf {
	char *s;
	unsigned int len, cap;
};

static int jb_put(struct jbuf *jb, const char *p, unsigned int n)
{
	char *grown;

	while (jb->len + n > jb->cap) {
		jb->cap = jb->cap ? 2 * jb->cap : 4096;
		grown = pkg_realloc(jb->s, jb->cap);
		if (!grown)
			return -1;
		jb->s = grown;
	}
	memcpy(jb->s + jb->len, p, n);
	jb->len += n;
	return 0;
}

/* length-based JSON string emission: escapes quote, backslash and
 * control bytes (values may be binary - embedded NULs survive); bytes
 * >= 0x80 pass through, so strict-JSON consumers need UTF-8 values */
static int jb_put_jstr(struct jbuf *jb, const str *s)
{
	static const char hexd[] = "0123456789abcdef";
	char esc[6] = "\\u00";
	unsigned int i, from = 0;
	unsigned char c;
	int r = jb_put(jb, "\"", 1);

	for (i = 0; i < (unsigned int)s->len && r == 0; i++) {
		c = (unsigned char)s->s[i];
		if (c != '"' && c != '\\' && c >= 0x20)
			continue;
		r = jb_put(jb, s->s + from, i - from);
		if (r == 0) {
			if (c == '"')
				r = jb_put(jb, "\\\"", 2);
			else if (c == '\\')
				r = jb_put(jb, "\\\\", 2);
			else {
				esc[4] = hexd[c >> 4];
				esc[5] = hexd[c & 0xF];
				r = jb_put(jb, esc, 6);
			}
		}
		from = i + 1;
	}
	if (r == 0)
		r = jb_put(jb, s->s + from, s->len - from);
	if (r == 0)
		r = jb_put(jb, "\"", 1);
	return r;
}

struct mget_ctx {
	const char *pat;
	struct sip_msg *msg;
	pv_spec_t *keys_pv, *vals_pv;    /* AVP mode */
	struct jbuf *jb;                 /* JSON mode */
	unsigned int limit, n, now;
	int err;
};

static int mget_cb(const str *key, const str *val, unsigned int exp, void *p)
{
	struct mget_ctx *mc = p;
	pv_value_t pval;

	if (exp && exp <= mc->now)
		return 0;                     /* expired-as-absent */
	if (fnmatch(mc->pat, key->s, 0))
		return 0;

	if (mc->jb) {
		if ((mc->n && jb_put(mc->jb, ",", 1) < 0) ||
		        jb_put_jstr(mc->jb, key) < 0 ||
		        jb_put(mc->jb, ":", 1) < 0 ||
		        jb_put_jstr(mc->jb, val) < 0) {
			mc->err = 1;
			return -1;
		}
	} else {
		memset(&pval, 0, sizeof pval);
		pval.flags = PV_VAL_STR;
		pval.rs.s = (char *)key->s;
		pval.rs.len = key->len;
		if (pv_set_value(mc->msg, mc->keys_pv, 0, &pval) < 0) {
			mc->err = 1;
			return -1;
		}
		pval.rs.s = (char *)val->s;
		pval.rs.len = val->len;
		if (pv_set_value(mc->msg, mc->vals_pv, 0, &pval) < 0) {
			mc->err = 1;
			return -1;
		}
	}

	mc->n++;
	if (mc->limit && mc->n >= mc->limit)
		return -1;                    /* stop: limit reached */
	return 0;
}

#define PERF_MGET_DEF_LIMIT 1000

static int perf_mget_run(struct sip_msg *msg, str *glob, pv_spec_t *keys_pv,
		pv_spec_t *vals_pv, struct jbuf *jb, str *col_s, int *limit)
{
	pcache_col_t *col = col_by_name(col_s);
	struct mget_ctx mc;
	char *pat;

	if (!col)
		return -1;
	pat = glob_dup(glob);
	if (!pat)
		return -1;

	memset(&mc, 0, sizeof mc);
	mc.pat = pat;
	mc.msg = msg;
	mc.keys_pv = keys_pv;
	mc.vals_pv = vals_pv;
	mc.jb = jb;
	mc.limit = limit ? (unsigned int)*limit : PERF_MGET_DEF_LIMIT;
	mc.now = get_ticks();

	pcache_ht_iter(col->htable, mget_cb, &mc);
	pkg_free(pat);

	return mc.err ? -1 : (int)mc.n;
}

static int w_perf_mget(struct sip_msg *msg, str *glob, pv_spec_t *keys_pv,
		pv_spec_t *vals_pv, str *col_s, int *limit)
{
	int n = perf_mget_run(msg, glob, keys_pv, vals_pv, NULL, col_s, limit);

	return n > 0 ? n : -1;
}

static int w_perf_mget_json(struct sip_msg *msg, str *glob, pv_spec_t *dst_pv,
		str *col_s, int *limit)
{
	struct jbuf jb;
	pv_value_t pval;
	int n;

	memset(&jb, 0, sizeof jb);
	if (jb_put(&jb, "{", 1) < 0)
		return -1;

	n = perf_mget_run(msg, glob, NULL, NULL, &jb, col_s, limit);
	if (n < 0 || jb_put(&jb, "}", 1) < 0) {
		if (jb.s)
			pkg_free(jb.s);
		return -1;
	}

	memset(&pval, 0, sizeof pval);
	pval.flags = PV_VAL_STR;
	pval.rs.s = jb.s;
	pval.rs.len = jb.len;
	if (pv_set_value(msg, dst_pv, 0, &pval) < 0) {
		pkg_free(jb.s);
		return -1;
	}
	pkg_free(jb.s);

	/* the variable holds "{}" on zero matches; script-false either way */
	return n > 0 ? n : -1;
}


/* CP-05 + CP-09: the maintenance timer.  Runs in a single timer process
 * (so it is the SOLE splitter, which the growth code relies on).  First
 * reclaims expired records (CP-05, hint-routed - an idle collection costs a
 * 16-hints-per-line scan), then grows any collection whose load factor has
 * climbed past growth_load_factor (CP-09), bounded per tick. */
static void pcache_expire_timer(unsigned int ticks, void *param)
{
	pcache_col_t *col;
	pcache_ht_totals_t t;
	unsigned int now = get_ticks(), freed, split, prev_b, new_b;

	/* one-shot: huge pages were requested but the granted tier is
	 * sub-optimal.  Deferred here from mod_init because EVI has no
	 * subscribers that early; the shm gate's atomic test-and-set makes it
	 * fire exactly once even if more than one process runs the timer. */
	if (mem_degraded && mem_degraded_gate &&
	        __sync_bool_compare_and_swap(mem_degraded_gate, 0, 1))
		pcache_raise_degraded();

	for (col = pcache_collection; col; col = col->next) {
		if (!col->htable)
			continue;

		/* only pay for the per-key expiry callback where a collection
		 * opted in AND someone is listening */
		if (col->raise_expired && evi_probe_event(evi_expired_id))
			freed = pcache_ht_sweep(col->htable, now,
				pcache_on_expired, &col->col_name);
		else
			freed = pcache_ht_sweep(col->htable, now, NULL, NULL);
		if (freed)
			LM_DBG("collection <%.*s>: reclaimed %u expired records\n",
				col->col_name.len, col->col_name.s, freed);

		if (growth_load_factor > 0) {
			prev_b = pcache_ht_nbuckets(col->htable);
			split = pcache_ht_grow(col->htable,
				growth_load_factor, growth_budget);
			if (split) {
				new_b = pcache_ht_nbuckets(col->htable);
				LM_DBG("collection <%.*s>: grew by %u splits "
					"(%u->%u buckets)\n", col->col_name.len,
					col->col_name.s, split, prev_b, new_b);
				pcache_ht_totals(col->htable, &t);
				pcache_raise_grown(&col->col_name, prev_b, new_b,
					split, t.entries);
			}
		}
	}
}

/* set a per-collection flag for every declared collection named in a CSV
 * modparam (event_expired_collections, persist_collections) */
enum col_flag { COL_FLAG_EXPIRED, COL_FLAG_PERSIST, COL_FLAG_REPLICATE };
static void mark_collections(char *csv_s, const char *what, enum col_flag f)
{
	csv_record *cr, *c;
	pcache_col_t *col;
	str csv;

	if (!csv_s || !*csv_s)
		return;
	csv.s = csv_s;
	csv.len = strlen(csv_s);
	cr = parse_csv_record(&csv);
	for (c = cr; c; c = c->next) {
		int found = 0;
		for (col = pcache_collection; col; col = col->next)
			if (col->col_name.len == c->s.len &&
			        !memcmp(col->col_name.s, c->s.s, c->s.len)) {
				if (f == COL_FLAG_EXPIRED)
					col->raise_expired = 1;
				else if (f == COL_FLAG_REPLICATE)
					col->replicate = 1;
				else
					col->persist = 1;
				found = 1;
			}
		if (!found)
			LM_WARN("%s: <%.*s> is not a declared collection\n",
				what, c->s.len, c->s.s);
	}
	free_csv_record(cr);
}

/* ---- consumer-facing pull API (pull_api.h) ---------------------------- */

static int pcache_api_pull_start(cachedb_con *con, str *key, int *fd,
		unsigned int *handle)
{
	pcache_col_t *col = pcache_col_of(con);

	if (!col || !key || !fd || !handle)
		return -1;
	return pcache_pull_start(col, key, 0, fd, handle);
}

static int pcache_api_pull_start_at(cachedb_con *con, str *key, int node_id,
		int *fd, unsigned int *handle)
{
	pcache_col_t *col = pcache_col_of(con);

	if (!col || !key || !fd || !handle)
		return -1;
	return pcache_pull_start(col, key, node_id, fd, handle);
}

static int pcache_api_my_node_id(cachedb_con *con)
{
	if (!cluster_ready || !clusterer_api.get_my_id)
		return 0;
	return clusterer_api.get_my_id();
}

static int pcache_api_pull_finish(cachedb_con *con, str *key,
		unsigned int handle, str *val)
{
	pcache_col_t *col = pcache_col_of(con);
	char buf[PCACHE_PULL_MAX_VAL];
	unsigned int vlen = 0;
	int rc;

	if (val) {
		val->s = NULL;
		val->len = 0;
	}
	if (!col || !key)
		return -1;

	rc = pcache_pull_finish(col, key, handle, buf, sizeof buf, &vlen, NULL);
	if (rc != 1 || !val)
		return rc;

	/* hand back memory the caller owns, exactly as a get would - the value
	 * is in the local table too, so a plain get would find it as well */
	val->s = pkg_malloc(vlen ? vlen : 1);
	if (!val->s) {
		LM_ERR("no more pkg memory for a %u byte pulled value\n", vlen);
		return -1;
	}
	memcpy(val->s, buf, vlen);
	val->len = vlen;
	return 1;
}

int load_pcache_pull(pcache_pull_api_t *api)
{
	if (!api)
		return -1;
	if (!pull_ready) {
		LM_WARN("a module asked for the cross-node pull API, but pulling "
			"is not configured (replicate_collections)\n");
		return -1;
	}
	api->start      = pcache_api_pull_start;
	api->finish     = pcache_api_pull_finish;
	api->start_at   = pcache_api_pull_start_at;
	api->my_node_id = pcache_api_my_node_id;
	return 0;
}

static int mod_init(void)
{
	cachedb_engine cde;
	cachedb_con *con;
	str default_url = str_init("perf://");
	str def_name = str_init(PCACHE_DEFAULT_COLLECTION);
	pcache_url_t *it, *next;
	pcache_col_t *col;
	int i;

	/* which of the four memory backings (DESIGN 2.6.1) does this host
	 * support?  Probed by trying, pre-fork; the arena CONSUMES the
	 * result only if arena_hugepage_mb>0 (CP-02/CP-20) - with it unset
	 * (the default), this is a capability check only and every
	 * cachedb_perf allocation actually goes through plain shm_malloc(),
	 * fully counted in core's own shmem: stats, not a separate
	 * reservation. The two NOTICEs below are deliberately worded to
	 * never be mistaken for each other - a probe result is not a
	 * report of what is actually in use. */
	pcache_mem_probe();

	if (pcache_mem.tier == PCACHE_MEM_HUGETLB)
		LM_NOTICE("memory backing CAPABILITY PROBE: this host supports "
			"tier 1/4 - %s (pool: %d static + %d overcommit pages)\n",
			pcache_mem_tier_str(pcache_mem.tier),
			pcache_mem.huge_static, pcache_mem.huge_overcommit);
	else
		LM_NOTICE("memory backing CAPABILITY PROBE: this host supports "
			"tier %d/4 - %s\n",
			pcache_mem.tier, pcache_mem_tier_str(pcache_mem.tier));

	if (pcache_arena_hugepage_mb > 0)
		LM_NOTICE("memory backing IN USE: a separate %d MB reservation, "
			"OUTSIDE OpenSIPS shared memory (arena_hugepage_mb)\n",
			pcache_arena_hugepage_mb);
	else
		LM_NOTICE("memory backing IN USE: OpenSIPS shared memory "
			"(shm_malloc) - NOT a separate reservation; counted in core's "
			"own shmem: stats, not a cachedb_perf-specific total. Set "
			"arena_hugepage_mb to reserve a dedicated arena instead.\n");

	switch (pcache_mem.tier) {
	case PCACHE_MEM_HUGETLB:
		break;
	case PCACHE_MEM_4K:
		LM_WARN("no 2M pages available: on a large cache, pointer-chase "
			"reads run up to 1.42x slower because the TLB cannot cover "
			"the arena with 4K pages; enable with "
			"'sysctl -w vm.nr_overcommit_hugepages=256' (a ceiling of "
			"256 x 2M = 512 MB - overcommit pages are taken from free "
			"memory only when faulted and returned on exit, so nothing "
			"is held while unused)\n");
		break;
	default:
		LM_WARN("running on THP - most of the TLB win, but hugetlb "
			"(tier 1) still measures ~1.2x faster on pointer-chase "
			"reads (125 vs 156 ns); enable with "
			"'sysctl -w vm.nr_overcommit_hugepages=256' (overcommit "
			"pages are taken from free memory only when faulted and "
			"returned on exit, so nothing is held while unused)\n");
	}

	/* the slab arena (DESIGN 3.3) - shm globals, pre-fork */
	if (pcache_arena_init() < 0) {
		LM_ERR("failed to init the arena\n");
		return -1;
	}

	/* CP-11: huge pages were asked for but the arena settled on a lesser
	 * tier - flagged now, raised from the first timer tick (EVI has no
	 * subscribers this early) via a shm one-shot gate */
	mem_degraded = (pcache_arena_hugepage_mb > 0 &&
		pcache_arena_tier() != PCACHE_MEM_HUGETLB);
	if (mem_degraded) {
		mem_degraded_gate = shm_malloc(sizeof *mem_degraded_gate);
		if (!mem_degraded_gate) {
			LM_ERR("no more shm memory\n");
			return -1;
		}
		*mem_degraded_gate = 0;
	}

	if (arena_selftest && pcache_arena_selftest() < 0) {
		LM_ERR("arena selftest failed\n");
		return -1;
	}

	if (htable_selftest && pcache_htable_selftest() < 0) {
		LM_ERR("htable selftest failed\n");
		return -1;
	}

	memset(&cde, 0, sizeof cde);
	cde.name = pcache_mod_name;

	cde.cdb_func.init = pcache_init;
	cde.cdb_func.destroy = pcache_destroy;
	cde.cdb_func.get = pcache_htable_fetch;
	cde.cdb_func.get_buf = pcache_htable_fetch_buf;
	cde.cdb_func.get_counter = pcache_htable_fetch_counter;
	cde.cdb_func.set = pcache_htable_insert;
	cde.cdb_func.remove = pcache_htable_remove;
	cde.cdb_func.add = pcache_htable_add;
	cde.cdb_func.sub = pcache_htable_sub;
	cde.cdb_func.iter_keys = pcache_htable_iter_keys;

	cde.cdb_func.capability = CACHEDB_CAP_BINARY_VALUE | CACHEDB_CAP_GET_BUF;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to register the 'perf' cachedb engine\n");
		return -1;
	}

	/* CP-11: publish the observability events.  A failed publish just
	 * leaves the id EVI_ERROR and the raise is skipped - never fatal. */
	evi_expired_id  = evi_publish_event(evi_expired_name);
	evi_nomem_id    = evi_publish_event(evi_nomem_name);
	evi_grown_id    = evi_publish_event(evi_grown_name);
	evi_degraded_id = evi_publish_event(evi_degraded_name);
	evi_synced_id   = evi_publish_event(evi_synced_name);
	if (evi_expired_id == EVI_ERROR || evi_nomem_id == EVI_ERROR ||
	    evi_grown_id == EVI_ERROR || evi_degraded_id == EVI_ERROR ||
	    evi_synced_id == EVI_ERROR)
		LM_ERR("could not publish one or more cachedb_perf events\n");

	/* CP-19 Stage 2: cluster sync is a soft, opt-in feature.  It needs a DB
	 * (peers pull from it) and the clusterer module; if either is missing,
	 * perf_sync degrades to a DB save with no peer signal - never fatal. */
	if (sync_cluster_id > 0) {
		if (load_clusterer_api(&clusterer_api) != 0) {
			LM_WARN("clusterer module not available - the cluster features "
				"are disabled; load clusterer before cachedb_perf\n");
		} else if ((pc_view = shm_malloc(sizeof *pc_view)) == NULL) {
			LM_WARN("no shm for the cluster membership view - the cluster "
				"features are disabled\n");
		} else if (memset(pc_view, 0, sizeof *pc_view),
		        clusterer_api.register_capability(&pcache_sync_cap,
		        pcache_sync_recv, pcache_cluster_event, sync_cluster_id,
		        0, NODE_CMP_ANY) < 0) {
			LM_WARN("could not register the cluster capability - the "
				"cluster features are disabled\n");
		} else {
			cluster_ready = 1;
			/* the DB is what perf_sync snapshots through; a cache that
			 * only pulls has no use for one */
			if (db_url && *db_url) {
				sync_ready = 1;
				LM_INFO("cluster sync active on cluster_id %d (cap <%.*s>)\n",
					sync_cluster_id, pcache_sync_cap.len, pcache_sync_cap.s);
			} else {
				LM_INFO("cluster membership active on cluster_id %d; "
					"perf_sync needs db_url and stays disabled\n",
					sync_cluster_id);
			}
		}
	}

	/* CP-15.12: arm the failover sync on a sharing tag.  Independent of
	 * sync_cluster_id (a deployment may want only the failover hook), so
	 * bind the clusterer API here if the sync block did not. */
	if (sync_shtag_str && *sync_shtag_str) {
		char *slash = strchr(sync_shtag_str, '/');

		pc_shtag.s = sync_shtag_str;
		pc_shtag.len = slash ? (int)(slash - sync_shtag_str)
		                     : (int)strlen(sync_shtag_str);
		pc_shtag_cid = slash ? atoi(slash + 1) : sync_cluster_id;

		if (!pc_shtag.len || pc_shtag_cid <= 0) {
			LM_WARN("bad sync_shtag '%s' (expected \"name/cluster_id\") - "
				"failover sync disabled\n", sync_shtag_str);
		} else if (!(db_url && *db_url)) {
			LM_WARN("sync_shtag is set but db_url is not - the failover "
				"sync needs the DB snapshot; disabled\n");
		} else if (!cluster_ready && load_clusterer_api(&clusterer_api) != 0) {
			LM_WARN("clusterer module not available - failover sync "
				"disabled\n");
		} else if (clusterer_api.shtag_register_callback(&pc_shtag,
		        pc_shtag_cid, NULL, pcache_shtag_cb) < 0) {
			LM_WARN("cannot register on sharing tag <%.*s/%d> - failover "
				"sync disabled\n", pc_shtag.len, pc_shtag.s, pc_shtag_cid);
		} else {
			LM_INFO("failover sync armed on sharing tag <%.*s/%d>\n",
				pc_shtag.len, pc_shtag.s, pc_shtag_cid);
		}
	}

	/* CP-15.5: cross-node pull.  Opt-in per collection, and inert without
	 * it: a key is only worth asking the cluster about if it means the
	 * same thing on every node, which only the operator knows. */
	if (replicate_collections && *replicate_collections) {
		int use_clctr = pull_transport_str &&
			!strcasecmp(pull_transport_str, "clctr");

		if (pull_transport_str && strcasecmp(pull_transport_str, "bin") &&
		        !use_clctr) {
			LM_ERR("bad pull_transport '%s' - expected 'bin' or 'clctr'\n",
				pull_transport_str);
			return -1;
		}
		if (use_clctr) {
			/* The controller is optional at build time AND at run time.
			 * An explicit clctr choice this deployment cannot honour
			 * degrades to the bin transport - or to no pull at all if
			 * the clusterer is missing too, which the cluster_ready
			 * check below already handles.  Loudly, but the cache
			 * itself is never held hostage by its cluster plane. */
#ifdef CLUSTERER_CTRL_SUPPORT
			if (load_clctr_api(&clctr_api) < 0) {
				LM_WARN("pull_transport 'clctr' but clusterer_controller "
					"is not loaded - falling back to 'bin'\n");
			} else if (clctr_api.register_channel(&pull_channel,
			        pcache_clctr_recv) < 0) {
				LM_WARN("cannot register the pull channel with "
					"clusterer_controller - falling back to 'bin'\n");
			} else {
				pull_via_clctr = 1;
			}
#else
			LM_WARN("pull_transport 'clctr' but this build carries no "
				"clusterer_controller support - falling back to 'bin'\n");
#endif
		}
		if (!cluster_ready) {
			LM_WARN("replicate_collections is set but the cluster is not "
				"available (needs sync_cluster_id + clusterer) - cross-node "
				"pull disabled\n");
		} else if (pull_timeout_ms <= 0 || pull_timeout_ms > 5000) {
			LM_ERR("pull_timeout_ms must be within 1..5000\n");
			return -1;
		} else {
			if (pull_max_value < 1 || pull_max_value > PCACHE_PULL_MAX_VAL) {
				LM_WARN("pull_max_value %d out of range 1..%d - clamping\n",
					pull_max_value, PCACHE_PULL_MAX_VAL);
				pull_max_value = pull_max_value < 1
					? PCACHE_PULL_MAX_VAL_DEF : PCACHE_PULL_MAX_VAL;
			}
			if (pull_max_key < 1 || pull_max_key > PCACHE_PULL_MAX_KEY) {
				LM_WARN("pull_max_key %d out of range 1..%d - clamping\n",
					pull_max_key, PCACHE_PULL_MAX_KEY);
				pull_max_key = pull_max_key < 1
					? PCACHE_PULL_MAX_KEY_DEF : PCACHE_PULL_MAX_KEY;
			}
			pull_slot_sz = (int)sizeof(struct pcache_pull_slot)
				+ pull_max_key + pull_max_value;
			LM_INFO("cross-node pull: %d slots x %d bytes "
				"(key %d, value %d) = %d KB of shm\n",
				PCACHE_PULL_SLOTS, pull_slot_sz, pull_max_key,
				pull_max_value,
				(PCACHE_PULL_SLOTS * pull_slot_sz + 1023) / 1024);
			pull_slots = shm_malloc((size_t)PCACHE_PULL_SLOTS * pull_slot_sz);
			pull_next_id = shm_malloc(sizeof *pull_next_id);
			pull_stats = shm_malloc(PULL_ST_MAX * sizeof *pull_stats);
			pull_send_warn = shm_malloc(sizeof *pull_send_warn);
			peer_stats = shm_malloc((CL_MAX_NODE_ID + 1) * sizeof *peer_stats);
			pull_lock = lock_alloc();
			if (!pull_slots || !pull_next_id || !pull_stats || !peer_stats ||
			        !pull_send_warn ||
			        !pull_lock || !lock_init(pull_lock)) {
				LM_ERR("no shm for the cross-node pull state\n");
				return -1;
			}
			memset(pull_slots, 0, (size_t)PCACHE_PULL_SLOTS * pull_slot_sz);
			memset(peer_stats, 0,
				(CL_MAX_NODE_ID + 1) * sizeof *peer_stats);
			/* One eventfd per slot, created HERE - before the fork - so
			 * that every worker inherits every fd.  This is the whole
			 * reason the pool is fixed and preallocated: a reply arrives
			 * in whichever process the transport chose, and it has to be
			 * able to wake the process that asked.  An fd created after
			 * the fork exists only in its own process and could not. */
			for (i = 0; i < PCACHE_PULL_SLOTS; i++) {
				pull_slot_at(i)->efd = eventfd(0, EFD_NONBLOCK);
				if (pull_slot_at(i)->efd < 0) {
					LM_ERR("cannot create the pull wakeup fds: %s\n",
						strerror(errno));
					return -1;
				}
			}
			*pull_next_id = 0;
			memset(pull_stats, 0, PULL_ST_MAX * sizeof *pull_stats);
			memset(pull_send_warn, 0, sizeof *pull_send_warn);
			if (pull_negative_ms < 0 || pull_negative_ms > 2000) {
				LM_ERR("pull_negative_ms must be within 0..2000 (0 = off) "
					"- a negative that outlives a retransmit turns a "
					"transient miss into a hard failure\n");
				return -1;
			}
			if (pull_negative_ms > 0) {
				neg_slots = shm_malloc(PCACHE_NEG_SLOTS * sizeof *neg_slots);
				neg_lock = lock_alloc();
				if (!neg_slots || !neg_lock || !lock_init(neg_lock)) {
					LM_ERR("no shm for the negative cache\n");
					return -1;
				}
				memset(neg_slots, 0, PCACHE_NEG_SLOTS * sizeof *neg_slots);
			}
			mark_collections(replicate_collections, "replicate_collections",
				COL_FLAG_REPLICATE);
			/* Reclaim slots whose answer never became conclusive.  A
			 * microsecond timer rather than the second-grained expiry
			 * sweep: pull_timeout_ms is set in milliseconds and a
			 * suspended lookup should not wait whole seconds past it.
			 * Checked at half the timeout so a slot is reclaimed within
			 * ~1.5x of it, and never tied to expiry_sweep_period, which
			 * an operator is allowed to switch off entirely. */
			{
				unsigned int iv = (unsigned int)pull_timeout_ms * 1000 / 2;

				if (iv < 10000)
					iv = 10000;          /* no tighter than 10 ms */
				if (register_utimer("cachedb-perf-pull-reap",
				        pcache_pull_reap, NULL, iv,
				        TIMER_FLAG_DELAY_ON_DELAY) < 0) {
					LM_ERR("failed to register the pull reaper - a pull "
						"that never gets a conclusive answer would hold "
						"its slot for ever\n");
					return -1;
				}
			}
			pull_ready = 1;
			/* One pair of stats per collection, named <collection>-<stat>
			 * via build_stat_name() (the same convention call_center uses
			 * for its per-flow stats).  Registered here rather than in the
			 * static table because the collection list is only known after
			 * cache_collections has been parsed.  A failure is not fatal:
			 * losing a statistic must never stop the module serving
			 * traffic, so it warns and carries on. */
			{
				pcache_col_t *sc;

				for (sc = pcache_collection; sc; sc = sc->next) {
					char *nm;

					if (!sc->replicate)
						continue;   /* cannot be pulled, so always 0 */
					nm = pcache_stat_name(sc, "pulled_from_cluster");
					if (!nm || register_stat2("cachedb_perf", nm,
					        (stat_var **)smf_col_pulled_in,
					        STAT_SHM_NAME|STAT_IS_FUNC, (void *)sc, 0) != 0)
						LM_WARN("could not register the pulled_from_cluster "
							"statistic for collection <%.*s>\n",
							sc->col_name.len, sc->col_name.s);
					nm = pcache_stat_name(sc, "served_to_cluster");
					if (!nm || register_stat2("cachedb_perf", nm,
					        (stat_var **)smf_col_served_out,
					        STAT_SHM_NAME|STAT_IS_FUNC, (void *)sc, 0) != 0)
						LM_WARN("could not register the served_to_cluster "
							"statistic for collection <%.*s>\n",
							sc->col_name.len, sc->col_name.s);
				}
			}
			LM_INFO("cross-node pull active over %s, %d ms timeout, "
				"%d ms negative cache, collections: %s\n",
				pull_via_clctr ? "clusterer_controller multicast" : "bin",
				pull_timeout_ms, pull_negative_ms, replicate_collections);
			if (pull_on_miss)
				LM_WARN("pull_on_miss is enabled: a cache miss now BLOCKS "
					"the calling process for up to %d ms while the cluster "
					"is asked.  That is fine for a maintenance or test "
					"path; on a SIP path it costs a worker, so keep it off "
					"until the lookup can be suspended instead\n",
					pull_timeout_ms);
		}
	}

	/* make sure the default collection exists */
	for (col = pcache_collection; col; col = col->next)
		if (col->col_name.len == def_name.len &&
		        !memcmp(col->col_name.s, def_name.s, def_name.len))
			break;

	if (!col) {
		col = shm_malloc(sizeof *col);
		if (!col) {
			LM_ERR("no more shm memory\n");
			return -1;
		}
		memset(col, 0, sizeof *col);

		if (shm_str_dup(&col->col_name, &def_name) < 0) {
			LM_ERR("no more shm memory\n");
			shm_free(col);
			return -1;
		}
		col->size_log2 = PCACHE_SIZE_DEFAULT;

		col->next = pcache_collection;
		pcache_collection = col;
	}

	/* one table per collection, pre-fork */
	for (col = pcache_collection; col; col = col->next) {
		col->htable = pcache_htable_new(col->size_log2);
		if (!col->htable) {
			LM_ERR("failed to create the table for collection <%.*s>\n",
				col->col_name.len, col->col_name.s);
			return -1;
		}
		LM_DBG("collection <%.*s>: 2^%u buckets\n",
			col->col_name.len, col->col_name.s, col->size_log2);
	}

	/* CP-11 / CP-19: per-collection opt-ins */
	mark_collections(event_expired_collections, "event_expired_collections",
		COL_FLAG_EXPIRED);
	mark_collections(persist_collections, "persist_collections",
		COL_FLAG_PERSIST);

	/* CP-19: bind the DB backend and load the persisted collections before
	 * the workers fork (so every worker starts with a warm cache) */
	if (db_url && *db_url) {
		str url = { db_url, strlen(db_url) };
		str tbl = { db_table, strlen(db_table) };

		if (pcache_db_init(&url, &tbl) < 0)
			return -1;
		if (db_mode >= 1)
			for (col = pcache_collection; col; col = col->next)
				if (col->persist && col->htable)
					pcache_db_load(col);
	} else if (db_mode) {
		LM_WARN("db_mode is set but db_url is not - persistence disabled\n");
	}

	/* one script connection per configured URL, or a default one */
	if (pcache_url_list) {
		for (it = pcache_url_list; it; it = next) {
			next = it->next;

			con = pcache_init(&it->url);
			if (!con) {
				LM_ERR("failed to init connection for URL <%.*s>\n",
					it->url.len, it->url.s);
				return -1;
			}

			if (cachedb_put_connection(&pcache_mod_name, con) < 0) {
				LM_ERR("failed to register connection for URL <%.*s>\n",
					it->url.len, it->url.s);
				return -1;
			}

			/* a groupless URL becomes the engine's default connection;
			 * remember its collection for the glob functions */
			if (!((pcache_con *)con->data)->id->group_name)
				pcache_default_col = ((pcache_con *)con->data)->col;

			pkg_free(it);
		}
		pcache_url_list = NULL;
	} else {
		con = pcache_init(&default_url);
		if (!con) {
			LM_ERR("failed to init the default connection\n");
			return -1;
		}

		if (cachedb_put_connection(&pcache_mod_name, con) < 0) {
			LM_ERR("failed to register the default connection\n");
			return -1;
		}

		pcache_default_col = ((pcache_con *)con->data)->col;
	}

	if (expiry_sweep_period > 0) {
		if (register_timer("cachedb-perf-expire", pcache_expire_timer,
		        NULL, expiry_sweep_period, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
			LM_ERR("failed to register the expiry sweep timer\n");
			return -1;
		}
	} else {
		LM_WARN("expiry sweep disabled: expired records stay invisible "
			"but their memory is never reclaimed\n");
	}

	return 0;
}

static int child_init(int rank)
{
	/* drop any allocator state inherited over fork - two processes must
	 * never share a bump pointer (pcache_arena.h) */
	pcache_arena_child_init();
	return 0;
}

static void mod_destroy(void)
{
	pcache_col_t *col, *next;

	/* CP-19: persist the marked collections on a graceful shutdown */
	if (db_mode >= 2 && pcache_db_enabled())
		for (col = pcache_collection; col; col = col->next)
			if (col->persist && col->htable)
				pcache_db_save(col);

	for (col = pcache_collection; col; col = next) {
		next = col->next;
		if (col->col_name.s)
			shm_free(col->col_name.s);
		shm_free(col);
	}
	pcache_collection = NULL;

	if (mem_degraded_gate) {
		shm_free(mem_degraded_gate);
		mem_degraded_gate = NULL;
	}

	if (pull_slots) {
		int i;

		for (i = 0; i < PCACHE_PULL_SLOTS; i++)
			if (pull_slot_at(i)->efd >= 0)
				close(pull_slot_at(i)->efd);
		shm_free(pull_slots);
		pull_slots = NULL;
	}
	if (pull_lock) {
		lock_destroy(pull_lock);
		lock_dealloc(pull_lock);
		pull_lock = NULL;
	}
	if (neg_slots) {
		shm_free(neg_slots);
		neg_slots = NULL;
	}
	if (neg_lock) {
		lock_destroy(neg_lock);
		lock_dealloc(neg_lock);
		neg_lock = NULL;
	}
	if (pull_next_id) {
		shm_free(pull_next_id);
		pull_next_id = NULL;
	}
	if (pull_stats) {
		shm_free(pull_stats);
		pull_stats = NULL;
	}
	if (pull_send_warn) {
		shm_free(pull_send_warn);
		pull_send_warn = NULL;
	}
	if (peer_stats) {
		shm_free(peer_stats);
		peer_stats = NULL;
	}

	pcache_arena_destroy();
}


/*
 * "name1=S;name2" - S is the log2 of the initial bucket count, clamped
 * to [PCACHE_SIZE_MIN, PCACHE_SIZE_MAX], PCACHE_SIZE_DEFAULT if absent
 */
static int pcache_parse_collections(unsigned int type, void *val)
{
	str collection_list, name;
	unsigned int size_log2;
	pcache_col_t *new_col, *dup;
	csv_record *cols, *col, *kv = NULL;

	if (!val) {
		LM_ERR("null 'cache_collections' value\n");
		return -1;
	}

	init_str(&collection_list, (char *)val);
	cols = __parse_csv_record(&collection_list, 0, ';');
	if (!cols) {
		LM_ERR("failed to parse 'cache_collections'\n");
		return -1;
	}

	for (col = cols; col; col = col->next) {
		kv = __parse_csv_record(&col->s, 0, '=');
		if (!kv)
			goto error;
		name = kv->s;

		if (ZSTR(name)) {
			LM_DBG("skipping empty collection name\n");
			free_csv_record(kv);
			kv = NULL;
			continue;
		}

		if (name.len >= 2 && name.s[name.len-2] == '/'
		        && name.s[name.len-1] == 'r') {
			LM_ERR("collection <%.*s>: replication ('/r') is not "
				"supported, cachedb_perf is a single-node cache\n",
				name.len, name.s);
			goto error;
		}

		if (kv->next) {
			if (str2int(&kv->next->s, &size_log2) < 0) {
				LM_ERR("collection <%.*s>: invalid size <%.*s>, "
					"expected a power-of-2 exponent\n",
					name.len, name.s,
					kv->next->s.len, kv->next->s.s);
				goto error;
			}

			if (size_log2 < PCACHE_SIZE_MIN) {
				LM_WARN("collection <%.*s>: size %u below minimum, "
					"clamping to %u\n", name.len, name.s,
					size_log2, PCACHE_SIZE_MIN);
				size_log2 = PCACHE_SIZE_MIN;
			} else if (size_log2 > PCACHE_SIZE_MAX) {
				LM_WARN("collection <%.*s>: size %u above maximum, "
					"clamping to %u\n", name.len, name.s,
					size_log2, PCACHE_SIZE_MAX);
				size_log2 = PCACHE_SIZE_MAX;
			}
		} else {
			size_log2 = PCACHE_SIZE_DEFAULT;
		}

		for (dup = pcache_collection; dup; dup = dup->next) {
			if (!str_strcmp(&name, &dup->col_name)) {
				LM_ERR("collection <%.*s> defined more than once\n",
					name.len, name.s);
				goto error;
			}
		}

		new_col = shm_malloc(sizeof *new_col);
		if (!new_col) {
			LM_ERR("no more shm memory\n");
			goto error;
		}
		memset(new_col, 0, sizeof *new_col);

		if (shm_str_dup(&new_col->col_name, &name) < 0) {
			LM_ERR("no more shm memory\n");
			shm_free(new_col);
			goto error;
		}
		new_col->size_log2 = size_log2;

		add_last(new_col, pcache_collection);

		LM_DBG("collection <%.*s>, initial size 2^%u buckets\n",
			name.len, name.s, size_log2);

		free_csv_record(kv);
		kv = NULL;
	}

	free_csv_record(cols);
	return 0;

error:
	LM_ERR("failed to parse 'cache_collections'\n");
	if (kv)
		free_csv_record(kv);
	free_csv_record(cols);
	return -1;
}


/* URLs are stored until mod_init, when all collections are known */
static int pcache_store_urls(unsigned int type, void *val)
{
	pcache_url_t *new_url;

	new_url = pkg_malloc(sizeof *new_url);
	if (!new_url) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	init_str(&new_url->url, (char *)val);
	new_url->next = pcache_url_list;
	pcache_url_list = new_url;

	return 0;
}
