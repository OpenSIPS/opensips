/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 *
 */

/*
 * cachedb_nats.c -- OpenSIPS cachedb engine backed by NATS JetStream KV
 *
 * Module architecture:
 *
 * This module implements the OpenSIPS cachedb API on top of NATS JetStream
 * Key-Value stores.  It provides:
 *
 *   - Standard cachedb operations (get/set/remove/add/sub/get_counter)
 *     mapped to KV put/get/delete/create/purge operations.
 *   - The cachedb query/update/map_get/map_set/map_remove extensions
 *     (non-key query/update filters need the cachedb_nats_fts module).
 *   - Native script functions: nats_kv_* KV primitives and
 *     nats_kv_history() for key version history.  (Synchronous NATS
 *     request/reply from script is owned by the nats_consumer module.)
 *   - A self-healing KV watcher process (cachedb_nats_watch.c) that
 *     keeps the JSON search index in sync with live KV mutations and
 *     raises E_NATS_KV_CHANGE EVI events.
 *
 * Connection management:
 *   mod_init() registers with the shared NATS connection pool (modules-contrib/nats/).
 *   child_init() obtains per-process connections, creates the KV bucket
 *   if needed, and (rank 1 only, with cachedb_nats_fts loaded) builds
 *   the initial search index.  The KV watcher and the reaper run in
 *   their own dedicated processes (see nats_reaper_watcher_procs).
 *
 * Rank filtering:
 *   NATS initializes in SIP workers (UDP and TCP, rank >= 1), module
 *   processes (PROC_MODULE) and the timer process; the attendant and
 *   TCP-main processes skip it (modules-contrib/nats/nats_rank.c).
 *
 *   The admission rule is centralized in modules-contrib/nats/nats_pool_should_init().
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  /* getpid() — nats_cdb_parent_pid capture in mod_init */

#include "../../sr_module.h"
#include "../../globals.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../cachedb/cachedb.h"
#include "../../mod_fix.h"
#include "../../mi/mi.h"

#include "cachedb_nats.h"
#include "cachedb_nats_dbase.h"
#include "cachedb_nats_json.h"
#include "../cachedb_nats_fts/cachedb_nats_fts_api.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_native.h"
#include "cachedb_nats_stats.h"
#include "cachedb_nats_expiry.h"
#include "cachedb_nats_reg.h"      /* registration MI + reap-pass gauges */
#include "cachedb_nats_kvobs.h"    /* generic stream/KV introspection MI */
#include "cachedb_nats_url.h"      /* cachedb_url -> server list */
#include "../nats/nats_bind_mod.h"
#include "../nats/nats_auth.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_url_scheme.h"
#include "../nats/nats_redact.h"

#include "../../evi/evi.h"

/* module lifecycle */
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

/* script function wrappers (implementations in cachedb_nats_native.c) */
static int w_nats_kv_history_wrap(struct sip_msg *msg, str *key,
                                  pv_spec_t *result);
static int w_nats_kv_get_wrap(struct sip_msg *msg, str *bucket, str *key,
                              pv_spec_t *value_var, pv_spec_t *rev_var);
static int w_nats_kv_put_wrap(struct sip_msg *msg, str *bucket, str *key,
                              str *value);
static int w_nats_kv_update_wrap(struct sip_msg *msg, str *bucket, str *key,
                                 str *value, int *expected_rev);
static int w_nats_kv_delete_wrap(struct sip_msg *msg, str *bucket, str *key);
static int w_nats_kv_revision_wrap(struct sip_msg *msg, str *bucket, str *key,
                                   pv_spec_t *rev_var);

/* MI command handler */
static mi_response_t *mi_nats_kv_status(const mi_params_t *params,
                                         struct mi_handler *async_hdl);

/* cachedb engine name -- must match the URL scheme prefix */
static str cache_mod_name = str_init("nats");
static struct cachedb_url *nats_cdb_urls = NULL;

/* module parameters -- non-static, accessed from cachedb_nats_dbase.c */
char *kv_bucket = "opensips";
int kv_replicas = 3;
/* history default 1: keep no old revisions.  Raise only for
 * nats_kv_history() consumers. */
int kv_history = 1;
int kv_ttl = 0;
/* Strict security mode: FAIL init instead of
 * warning.  Both default 0 -- the warn-only default is dev/lab
 * ergonomics (the usual lab broker is plaintext, no auth) and generic
 * non-PII cachedb use, not compatibility; a usrloc production profile
 * sets both to 1 (see the admin docs). */
int require_secure_url = 0;
int require_usrloc_safe_bucket = 0;
/* Multi-instance index coordination knobs.
 *
 * index_resync_on_reconnect (default 1):
 *   On a NATS reconnect (epoch change), should the watcher rebuild
 *   the in-memory JSON index in full?  The watcher subscribes with
 *   UpdatesOnly, so writes made by sibling instances WHILE this
 *   process was disconnected are never delivered live -- without a
 *   rebuild the index silently diverges after any outage during which
 *   writes occurred.  The default is therefore ON so the index always
 *   converges on reconnect.  The rebuild costs O(N) round-trips against
 *   the bucket (a 50k-AoR deployment stalls the watcher for ~5-10 s),
 *   so operators with large indexes or hot-reconnect topologies may set
 *   this to 0 and rely instead on index_resync_interval_secs (the
 *   periodic timer) plus the query-time stale-entry self-heal in
 *   nats_cache_query, accepting a brief window of staleness.
 *
 * index_resync_interval_secs (default 0 = off):
 *   Optional periodic full rebuild on a timer.  Belt-and-braces
 *   for deployments that want a hard upper bound on how stale any
 *   process-local index entry can ever be, beyond what reconnects
 *   and lazy self-heal already guarantee.
 */
int index_resync_on_reconnect = 1;

int index_resync_interval_secs = 0;

/* NATS server URL(s) -- overrides cachedb_url host when set.  TLS
 * configuration is sourced from the tls_mgm "nats" client domain at
 * connect time (apply_tls_from_mgm in modules-contrib/nats); no per-module TLS
 * modparams. */
static char *nats_url = NULL;

/* JSON full-text search parameters */
/* Default uses '_' rather than ':' because NATS-KV rejects ':' in
 * subject tokens (validate_kv_key in cachedb_nats_dbase.c), and any
 * key whose underlying form starts with the prefix would therefore be
 * unstorable. '_' is unambiguously safe across all allowed key
 * characters; operators may override via modparam if their bucket
 * convention requires a different separator. */
char *fts_json_prefix = "json_";

/* strlen(fts_json_prefix), stamped once in init_check_params --
 * the prefix is a config constant, yet the usrloc read/write/serialize
 * paths, the watch loop, the reg scan and the reaper each re-measured
 * it per operation/event/pass. */
int fts_json_prefix_len;

/* Compare-and-swap retry count for atomic counter increments
 * (nats_cache_add) and JSON field updates (nats_cache_update).
 * Each retry costs one round-trip to the NATS server.  Default 10
 * is a balance between giving up too early under modest contention
 * (the previous hard-coded 3 dropped silent counter increments
 * with as few as 3 concurrent writers) and burning latency on
 * pathological hotspots.  Operator can raise for very contended
 * counters; minimum bound is 1. */
int   nats_cas_retries = 10;

/* Max tolerated inter-node clock skew S, in seconds.  Used as
 * the grace margin everywhere absolute `expires`/`row_exp` is compared with
 * node-local now: the write-side expiry hygiene, the read filter,
 * and the reaper all require `+S` slack so a node whose clock leads by S
 * never deletes/omits another node's still-live binding.  MUST be >= the
 * deployment's real maximum node skew. */
int   nats_reap_grace = 5;

/* Reaper scan period, seconds.  The reaper is the
 * SINGLE expiry mechanism: a periodic CAS-prune is what guarantees an
 * expired binding is physically reclaimed.  Must be > 0; a non-positive
 * value HARD-FAILS mod_init rather than silently leaving expiries
 * unreclaimed.  Default 30s. */
int   nats_reap_interval = 30;

/* Physical retention of a row past its logical expiry
 * (expires + nats_reap_grace), in seconds.  0 = reclaim ASAP; e.g. 30 keeps an expired registration
 * readable in the bucket for ~30 s (forensics / churn damping).  Added to
 * every physical-reclamation cutoff (TTL computation, reaper due-gate +
 * projection, write hygiene) and NEVER to the read filter -- an expired
 * contact is not served, lingering or not.  Range 0..86400. */
int   nats_expired_linger = 0;

/* Max serialized KV value (one AoR row holds all its contacts), in
 * bytes.  All contacts of an AoR share one message; NATS caps message size
 * (max_payload, default 1 MiB; a stream's max_msg_size may be lower).  An
 * oversize row is detected before the CAS write and the offending contact's
 * save fails cleanly — never a silent truncation / corruption.  Default 1 MiB
 * (the NATS max_payload default); set to the deployment's real per-message cap
 * (and <= the stream's max_msg_size).  <= 0 disables the guard. */
int   nats_max_value_size = 1048576;

/* Optional FTS/search-index module binds: loading
 * cachedb_nats_fts IS the enable switch (replaces the former
 * enable_search_index modparam).  All hooks NULL / cdbn_fts_on == 0
 * when the module is absent — PK-only operation. */
cdbn_fts_api_t cdbn_fts;
int cdbn_fts_on = 0;

/* The KV watcher always runs as a dedicated OpenSIPS child process
 * (proc_export_t, forked when at least one
 * kv_watch pattern is configured).  The former in-worker pthread mode
 * (dedicated_watcher_proc=0) was removed: a pthread inside the rank-1
 * SIP worker called nats_pool_get_kv() concurrently with the worker's
 * main thread, but the pool's cached KV/JS handles are managed
 * process-single-threaded — after a reconnect one thread could destroy
 * a cached handle while the other was still using it (use-after-free
 * under broker flap, in what used to be the default mode).  The
 * dedicated process runs exactly one thread against the pool and has
 * none of these races. */

/* modules-contrib/nats connection-pool tuning.  These three modparams previously
 * appeared in the admin XML but were never actually exported -- the
 * values were hardcoded at the nats_pool_register() call site.  They
 * now match the documented behaviour.
 *
 * Registrations merge: every NATS module passes its values to
 * nats_pool_register(), and for each reconnect parameter the larger
 * explicit value wins, whatever the module load order.  See
 * modules-contrib/nats/README.md "How the modules share a connection".
 *
 * Defaults match the previously-hardcoded values so a deployment
 * that doesn't touch the modparams sees exactly the same behaviour
 * as before this commit. */
int   nats_cdb_reconnect_wait_ms = 2000;
int   nats_cdb_max_reconnect     = 60;

/* KV watcher patterns -- built via repeated modparam("kv_watch", "pattern")
 * calls.  When empty (no kv_watch configured), the watcher watches all keys.
 * When one or more patterns are set, nats_dl.kvStore_WatchMulti() is used.
 * Definition lives in cachedb_nats_watch.h so the dedicated-process
 * watcher (when running as a dedicated process) can read it from cachedb_nats_watch.c. */
struct kv_watch_entry *kv_watch_list = NULL;
int kv_watch_count = 0;

/* The startup checks of rank 1 -- the bucket checks and the search index
 * build -- in SHM: done, or deferred to the reaper process because NATS
 * was unavailable at startup (see nats_cdb_deferred_boot_checks()). */
#define CDBN_BOOT_PENDING   0
#define CDBN_BOOT_DONE      1
#define CDBN_BOOT_DEFERRED  2
static int *cdbn_boot_state;

static int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&nats_cdb_urls, (char *)val);
}

static int set_watch_pattern(unsigned int type, void *val)
{
	struct kv_watch_entry *e;
	char *pattern = (char *)val;

	if (!pattern || !*pattern) {
		LM_ERR("empty kv_watch pattern\n");
		return -1;
	}

	e = pkg_malloc(sizeof(*e));
	if (!e) {
		LM_ERR("no more pkg memory for kv_watch entry\n");
		return -1;
	}
	e->pattern = pattern;
	e->next = kv_watch_list;
	kv_watch_list = e;
	kv_watch_count++;
	return 0;
}

/* the nats module API (nats_bind_mod.h), bound in mod_init */
struct nats_binds nats_api;
/* settings of the shared connection, forwarded to the nats module */
NATS_ALIAS_SETTER(creds_file)
NATS_ALIAS_SETTER(drain_timeout_ms)
NATS_ALIAS_SETTER(kv_op_timeout_ms)
NATS_ALIAS_SETTER(nkey)
NATS_ALIAS_SETTER(nkey_seed_file)
NATS_ALIAS_SETTER(no_randomize)
NATS_ALIAS_SETTER(password)
NATS_ALIAS_SETTER(reconnect_buf_size)
NATS_ALIAS_SETTER(token)
NATS_ALIAS_SETTER(user)

static const param_export_t params[] = {
	{"cachedb_url",    STR_PARAM|USE_FUNC_PARAM, (void *)&set_connection},
	{"nats_url",       STR_PARAM,                 &nats_url},
	{"kv_bucket",      STR_PARAM,                 &kv_bucket},
	{"kv_replicas",    INT_PARAM,                 &kv_replicas},
	{"kv_history",     INT_PARAM,                 &kv_history},
	{"kv_ttl",         INT_PARAM,                 &kv_ttl},
	{"require_secure_url",  INT_PARAM,            &require_secure_url},
	{"require_usrloc_safe_bucket", INT_PARAM,     &require_usrloc_safe_bucket},
	{"index_resync_on_reconnect",   INT_PARAM,    &index_resync_on_reconnect},
	{"index_resync_interval_secs",  INT_PARAM,    &index_resync_interval_secs},
	/* Shared modules-contrib/nats shutdown drain timeout, ms (ONE pool value; see
	 * nats_pool_drain_timeout_decide for the merge contract). */
	{"drain_timeout_ms",            INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_drain_timeout_ms},
	/* Server order of the shared connection (ONE pool value; see
	 * nats_pool_no_randomize_decide for the merge contract). */
	{"no_randomize",                INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_no_randomize},
	/* Reconnect buffer of the shared connection (ONE pool value; see
	 * nats_pool_reconnect_buf_size_decide for the merge contract). */
	{"reconnect_buf_size",          INT_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_reconnect_buf_size},
	/* Credentials of the shared connection (ONE pool value each; see
	 * modules-contrib/nats/nats_auth.h), so no secret has to be inside a URL. */
	{"user",                 STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_user},
	{"password",             STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_password},
	{"token",                STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_token},
	{"creds_file",           STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_creds_file},
	{"nkey",                 STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_nkey},
	{"nkey_seed_file",       STR_PARAM|USE_FUNC_PARAM,
	      (void *)nats_alias_nkey_seed_file},
	{"kv_op_timeout_ms",            INT_PARAM|USE_FUNC_PARAM,    (void *)nats_alias_kv_op_timeout_ms},
	{"fts_json_prefix", STR_PARAM,               &fts_json_prefix},
	{"cas_retries",             INT_PARAM,         &nats_cas_retries},
	{"reap_grace",              INT_PARAM,         &nats_reap_grace},
	{"reap_interval",           INT_PARAM,         &nats_reap_interval},
	{"expired_linger",          INT_PARAM,         &nats_expired_linger},
	{"max_value_size",          INT_PARAM,         &nats_max_value_size},
	{"kv_watch",        STR_PARAM|USE_FUNC_PARAM, (void *)&set_watch_pattern},
	{"reconnect_wait_ms",   INT_PARAM,             &nats_cdb_reconnect_wait_ms},
	{"max_reconnect",       INT_PARAM,             &nats_cdb_max_reconnect},
	{0, 0, 0}
};

static const cmd_export_t cmds[] = {
	/* Synchronous NATS request/reply from script is provided ONLY by
	 * the nats_consumer module (headers + async support); this module's
	 * duplicate request/reply export was removed. */
	{"nats_kv_history", (cmd_function)w_nats_kv_history_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_VAR, 0, 0},   /* result pvar */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_get", (cmd_function)w_nats_kv_get_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_VAR, 0, 0},   /* value pvar (output) */
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},  /* revision pvar (output, optional) */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_put", (cmd_function)w_nats_kv_put_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_STR, 0, 0},   /* value */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_update", (cmd_function)w_nats_kv_update_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_STR, 0, 0},   /* value */
		{CMD_PARAM_INT, 0, 0},   /* expected revision */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_delete", (cmd_function)w_nats_kv_delete_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{0, 0, 0}},
	ALL_ROUTES},
	{"nats_kv_revision", (cmd_function)w_nats_kv_revision_wrap, {
		{CMD_PARAM_STR, 0, 0},   /* bucket */
		{CMD_PARAM_STR, 0, 0},   /* key */
		{CMD_PARAM_VAR, 0, 0},   /* revision pvar (output) */
		{0, 0, 0}},
	ALL_ROUTES},
	{0, 0, {{0, 0, 0}}, 0}
};

static const mi_export_t mi_cmds[] = {
	{"nats_kv_status", 0, 0, 0, {
		{mi_nats_kv_status, {0}},
		{EMPTY_MI_RECIPE}},
		{0}        /* aliases — required by mi_export_t struct */
	},
	{"nats_cdb_stats", 0, 0, 0, {
		{mi_nats_cdb_stats, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	/* registration observability — usrloc's own MI is empty by
	 * design in full-sharing-cachedb mode; the KV bucket is the truth. */
	{"nats_reg_summary", 0, 0, 0, {
		{mi_nats_reg_summary, {0}},
		{mi_nats_reg_summary, {"domains", 0}},
		{mi_nats_reg_summary, {"domains", "format", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_reg_list", 0, 0, 0, {
		{mi_nats_reg_list, {0}},
		{mi_nats_reg_list, {"filter", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_reg_show", 0, 0, 0, {
		{mi_nats_reg_show, {"aor", 0}},
		{mi_nats_reg_show, {"aor", "format", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	/* generic stream/KV introspection (read-only; buckets are
	 * bound, never created). */
	{"nats_stream_list", 0, 0, 0, {
		{mi_nats_stream_list, {0}},
		{mi_nats_stream_list, {"filter", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_stream_info", 0, 0, 0, {
		{mi_nats_stream_info, {"stream", 0}},
		{mi_nats_stream_info, {"stream", "format", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{"nats_kv_keys", 0, 0, 0, {
		{mi_nats_kv_keys, {0}},
		{mi_nats_kv_keys, {"filter", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{EMPTY_MI_EXPORT}
};

/* tls_mgm is required only when the operator wants TLS (URL begins
 * with tls://).  DEP_SILENT lets plaintext-only deployments load
 * cachedb_nats without tls_mgm; the tls:// path checks at connect
 * time and errors with operator-friendly guidance if tls_mgm is
 * missing or the "nats" domain isn't defined. */
static const dep_export_t deps = {
	{
		{ MOD_TYPE_DEFAULT, "nats", DEP_ABORT },
		{MOD_TYPE_DEFAULT, "tls_mgm", DEP_SILENT},
		{MOD_TYPE_NULL, NULL, 0},
	},
	{
		{NULL, NULL},
	},
};

/* Dedicated module processes.  exports.procs takes exactly one array,
 * chosen at runtime in mod_init (the core's start_module_procs() walks
 * exports.procs only after init_modules returns, so the late binding
 * is safe):
 *
 * "NATS Reaper" -- ALWAYS forked (the reaper is the single
 *   expiry mechanism): its O(bucket) pass (kvStore_Keys + per-key Get
 *   + CAS prune) must not run in the shared core timer process, where
 *   at scale one pass stalls usrloc/tm/dialog timers system-wide.
 *   The same process hosts the periodic FTS index resync when enabled.
 *
 * "NATS Watcher" -- the ONLY watcher mode, forked when at least one
 *   kv_watch pattern is set.  Single instance ("no" = 1): one watcher
 *   is enough; multiplying watchers does not parallelise the per-event
 *   cost and would just multiply broker delivery cost. */
static const proc_export_t nats_reaper_procs[] = {
	{ "NATS Reaper", 0, 0, nats_cdb_reaper_proc_main, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};
static const proc_export_t nats_reaper_watcher_procs[] = {
	{ "NATS Reaper",  0, 0, nats_cdb_reaper_proc_main, 1, 0 },
	{ "NATS Watcher", 0, 0, nats_watcher_proc_main, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

/** module exports */
struct module_exports exports = {
	"cachedb_nats",             /* module name */
	MOD_TYPE_CACHEDB,           /* class of this module */
	MODULE_VERSION,
	RTLD_NOW | RTLD_GLOBAL,     /* dlopen flags: GLOBAL so the optional
	                             * cachedb_nats_fts module (loaded after
	                             * us) resolves the shared JSON walkers
	                             * this module defines */
	0,                          /* load function */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

/**
 * mod_init() -- Module initialization (pre-fork).
 *
 * Registers this module with the shared NATS connection pool and the
 * OpenSIPS cachedb engine subsystem.  The NATS URL is resolved from
 * either the explicit nats_url parameter, the cachedb_url host portion,
 * or a localhost default.  TLS options are applied if tls_ca is set.
 *
 * Also populates the cachedb_engine function table with all supported
 * operations (get, set, remove, add, sub, get_counter, raw_query,
 * query, update, map_get, map_set, map_remove).
 *
 * @return  0 on success, -1 on error (aborts module loading).
 */
/* Is the effective connection URL insecure for a PII store?  Returns 1
 * when the WARN must fire: not TLS (tls://, tls+srv://), OR no
 * credentials -- neither "user[:pass]@" in the URL's authority nor the
 * credential modparams.  One rule, in modules-contrib/nats/nats_auth.h
 * (nats_url_insecure_for), tested by test/test_insecure_url_warn.c. */
static int nats_url_insecure(const char *url)
{
	return nats_url_insecure_for(url, nats_pool_auth_configured());
}

/* ── mod_init phases ─────────────────────────────────────────
 * The 150-line init is four independent phases; each returns 0/-1 and
 * fails the boot loudly.  Order matters: params before pool (fail
 * closed before any network state), pool before engine (the engine
 * callbacks assume a registered pool config), services last (timers /
 * procs / events reference everything above). */

/* Phase 1: validate operator parameters -- fail closed at boot. */
static int init_check_params(void)
{
	/* cache the prefix length (config constant; consumed on
	 * every usrloc read/write, watch event and reap pass). */
	fts_json_prefix_len = fts_json_prefix ? (int)strlen(fts_json_prefix) : 0;

	/* Kv_ttl becomes the KV bucket's
	 * MaxAge (nats_pool.c: kvCfg.TTL).  Stream MaxAge takes precedence over
	 * per-message TTL and would SILENTLY EXPIRE PERMANENT CONTACTS
	 * (expires==0) -- data loss in a registration store.  Refuse to start
	 * (fail closed) before any bucket is created/bound. */
	if (cdbn_kv_ttl_guard(kv_ttl) != 0) {
		LM_ERR("cachedb_nats: kv_ttl=%d invalid -- a non-zero kv_ttl sets the "
		       "KV bucket MaxAge, which overrides per-message TTL and would "
		       "EXPIRE PERMANENT CONTACTS (expires==0). Set kv_ttl=0.\n",
		       kv_ttl);
		return -1;
	}

	/* validate the new operator params -- fail loudly at boot,
	 * never misbehave silently at runtime. */
	if (cdbn_linger_guard(nats_expired_linger) != 0) {
		LM_ERR("cachedb_nats: expired_linger=%d out of range (0..86400); "
		       "large retention wants a different tool than this module\n",
		       nats_expired_linger);
		return -1;
	}
	return 0;
}

/* Phase 2: TLS bind + connection-URL resolution + pool registration. */
static int init_pool(void)
{
	/* Bind tls_mgm if loaded; hand the bind table to modules-contrib/nats so the
	 * pool's connect path can look up the "nats" client domain.  No
	 * effect on plaintext (nats://) URLs; tls:// URLs error at
	 * connect time if tls_mgm isn't bound or the "nats" domain
	 * isn't defined. */
	nats_pool_bind_tls("cachedb_nats");

	/*
	 * Register with the NATS connection pool.
	 *
	 * modules-contrib/nats is a shared .so, so all NATS modules share ONE pool; each
	 * module registers its config (URLs / reconnect) and the pool merges
	 * them.  cachedb_nats still needs its own nats_url and TLS params so a
	 * cachedb-only deployment can connect without another NATS module.
	 *
	 * If nats_url is set, use it directly. Otherwise, derive the server
	 * list from the cachedb_url (cdbn_url_to_servers).
	 */
	{
		const char *url_to_use = NULL;
		static char url_buf[1024];
		int is_default = 0;

		if (nats_url && *nats_url) {
			/* explicit nats_url param takes precedence */
			url_to_use = nats_url;
		} else if (nats_cdb_urls && nats_cdb_urls->url.s &&
				nats_cdb_urls->url.len) {
			/* nats:group://[user:pass@]h1:p1,h2:p2/[?tls_domain=nats]
			 * -> nats://[cred@]h1:p1,nats://[cred@]h2:p2 (tls:// with
			 * tls_domain) -- see cachedb_nats_url.c */
			int rc = cdbn_url_to_servers(nats_cdb_urls->url.s,
				nats_cdb_urls->url.len, url_buf, sizeof(url_buf));

			if (rc == CDBN_URL_TLS_DOMAIN) {
				LM_ERR("cachedb_url: tls_domain must be \"%s\", the "
					"tls_mgm client domain all NATS modules take "
					"their TLS settings from\n", CDBN_TLS_DOMAIN);
				return -1;
			}
			if (rc < 0) {
				LM_ERR("cachedb_url: cannot derive the NATS servers "
					"(expected nats:group://[user:pass@]host:port"
					"[,host:port...]/[?tls_domain=%s]); set nats_url "
					"or fix cachedb_url\n", CDBN_TLS_DOMAIN);
				return -1;
			}
			url_to_use = url_buf;
		} else {
			LM_WARN("no nats_url or cachedb_url -- using "
				"nats://localhost:4222 unless another NATS module "
				"configures servers\n");
			url_to_use = "nats://localhost:4222";
			is_default = 1;
		}

		/* The registration bucket is a PII / LI-relevant
		 * store (subscriber IP, UA, call-id, path) and NATS KV has no
		 * per-key ACL.  Transport + auth are mandatory: warn loudly when
		 * the connection URL is plaintext and/or carries no credentials. */
		if (nats_url_insecure(url_to_use)) {
			/* the URL may carry nats://user:pass@host credentials —
			 * never log it raw */
			char _redacted_url[512];
			nats_redact_url(url_to_use, _redacted_url,
				sizeof(_redacted_url));
			if (require_secure_url) {
				LM_ERR("cachedb_nats: connection URL '%s' is INSECURE "
					"for a PII/lawful-intercept store and "
					"require_secure_url=1 -- refusing to start. Use "
					"tls:// with an authenticated account.\n", _redacted_url);
				return -1;
			}
			LM_WARN("cachedb_nats: connection URL '%s' is INSECURE for a "
				"PII/lawful-intercept store (subscriber IP, user-agent, "
				"call-id, path) — use tls:// with an authenticated account "
				"and one bucket per trust domain.\n",
				_redacted_url);
		}

		/* TLS comes from the tls_mgm "nats" client domain at connect
		 * time (apply_tls_from_mgm in modules-contrib/nats).  Operator switches to
		 * TLS with tls:// in nats_url, or ?tls_domain=nats in
		 * cachedb_url, and defines the tls_mgm domain. */

		if ((is_default ? nats_pool_register_default :
				nats_pool_register)(url_to_use,
				"cachedb_nats",
				nats_cdb_reconnect_wait_ms,
				nats_cdb_max_reconnect) < 0) {
			LM_ERR("NATS pool registration failed\n");
			return -1;
		}
	}

	return 0;
}

/* Phase 3: cachedb engine + stats registration. */
static int init_engine(void)
{
	cachedb_engine cde;

	/* populate cachedb engine */
	memset(&cde, 0, sizeof(cachedb_engine));

	cde.name = cache_mod_name;

	cde.cdb_func.init = nats_cachedb_init;
	cde.cdb_func.destroy = nats_cachedb_destroy;
	cde.cdb_func.get = nats_cache_get;
	cde.cdb_func.set = nats_cache_set;
	cde.cdb_func.remove = nats_cache_remove;
	/* non-NULL "unsupported" stub: usrloc
	 * full-sharing never calls _remove; register it so a wrong-mode caller
	 * fails loudly (-1 + LM_ERR) instead of a NULL function-pointer crash. */
	cde.cdb_func._remove = nats_cache_remove_unsupported;
	cde.cdb_func.add = nats_cache_add;
	cde.cdb_func.sub = nats_cache_sub;
	cde.cdb_func.get_counter = nats_cache_get_counter;
	cde.cdb_func.raw_query = nats_cache_raw_query_impl;
	cde.cdb_func.query = nats_cache_query;
	cde.cdb_func.update = nats_cache_update;
	cde.cdb_func.map_get = nats_cache_map_get;
	cde.cdb_func.map_set = nats_cache_map_set;
	cde.cdb_func.map_remove = nats_cache_map_remove;

	cde.cdb_func.capability = 0;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to register cachedb_nats engine\n");
		return -1;
	}

	if (nats_cdb_stats_init() < 0) {
		LM_ERR("failed to initialize cdb stats\n");
		return -1;
	}

	return 0;
}

/* Phase 4: optional FTS bind, dedicated procs (reaper always; +watcher
 * when kv_watch is set) hosting the reap/resync passes,
 * E_NATS_KV_CHANGE registration. */
static int init_services(void)
{
	/* Bind the optional FTS/search-index module.  The
	 * module owns the SHM index + intern table (allocated in ITS
	 * mod_init, pre-fork); we only take its API here.  Without it,
	 * update accepts PK-only filters, query answers other filters with
	 * a bucket scan, and the watcher serves E_NATS_KV_CHANGE alone. */
	{
		cdbn_fts_bind_f bind_f =
			(cdbn_fts_bind_f)find_export("cdbn_fts_bind", 0);
		if (bind_f && bind_f(&cdbn_fts) == 0) {
			cdbn_fts_on = 1;
			LM_INFO("cachedb_nats: FTS module bound; non-PK "
				"query filters ENABLED\n");
		} else {
			LM_INFO("cachedb_nats: cachedb_nats_fts not loaded; "
				"update accepts PK-only filters, query scans the "
				"bucket for others\n");
		}
	}

	/* Periodic index resync: optional belt-and-braces rebuild for
	 * deployments that want a hard upper bound on index staleness.
	 * Only meaningful with the FTS module bound. Hosted by the
	 * dedicated reaper process (attached below), NOT the shared core
	 * timer process -- a full-bucket rebuild there stalls every other
	 * module's timers. */
	if (cdbn_fts_on && index_resync_interval_secs > 0)
		LM_INFO("cachedb_nats: periodic index resync every %d s "
			"(in the reaper process)\n", index_resync_interval_secs);

	/* Reaper host: the reaper is the
	 * SINGLE expiry mechanism, so a non-positive interval is
	 * refused.  Index-independent (it enumerates the bucket itself), so it
	 * runs whether or not cachedb_nats_fts is loaded. */
	if (cdbn_reap_interval_guard(nats_reap_interval) < 0) {
		LM_ERR("reap_interval=%d disables the reaper, the only "
			"expiry mechanism -- expired bindings would never be "
			"reclaimed; set reap_interval > 0\n",
			nats_reap_interval);
		return -1;
	}

	/* Attach the dedicated processes: the reaper process is
	 * unconditional (it hosts the O(bucket) reap + resync passes,
	 * keeping them out of the shared core timer process); the KV
	 * watcher joins it when at least one kv_watch pattern was
	 * configured.  This is the ONLY watcher mode: the process runs a
	 * single thread against the connection pool, so it has none of the
	 * pool races the removed in-worker pthread mode had.
	 * start_module_procs() (in main_loop) reads exports.procs AFTER
	 * init_modules returns, so this late assignment is safe and is the
	 * cleanest way to keep the proc selection runtime-conditional. */
	if (kv_watch_count > 0) {
		exports.procs = nats_reaper_watcher_procs;
		LM_INFO("cachedb_nats: dedicated KV watcher process "
			"ENABLED (%d kv_watch pattern(s))%s\n", kv_watch_count,
			cdbn_fts_on ? "" : " — E_NATS_KV_CHANGE only "
			"(FTS module not loaded)");
	} else {
		exports.procs = nats_reaper_procs;
		LM_INFO("cachedb_nats: no kv_watch pattern configured; "
			"KV watcher process NOT forked\n");
	}
	LM_INFO("cachedb_nats: reaper ENABLED, scan every %d s "
		"(grace %d s, dedicated process)\n",
		nats_reap_interval, nats_reap_grace);

	/* Register E_NATS_KV_CHANGE event in mod_init (pre-fork, runs once)
	 * so it exists before startup_route's subscribe_event() and before
	 * the dedicated watcher process forks. */
	{
		extern event_id_t evi_kv_change_id;
		str evi_name = str_init("E_NATS_KV_CHANGE");
		evi_kv_change_id = evi_publish_event(evi_name);
		if (evi_kv_change_id == EVI_ERROR)
			LM_WARN("cannot register E_NATS_KV_CHANGE event\n");
	}

	return 0;
}

static int mod_init(void)
{
	LM_NOTICE("initializing module cachedb_nats ...\n");

	if (nats_bind_api("cachedb_nats") < 0)
		return -1;

	/* Capture our pid while we are still the MAIN process, pre-fork: the
	 * dedicated watcher/reaper processes compare getppid() against this to
	 * detect real re-parenting. Must NOT be inferred as `getppid()==1`,
	 * because opensips main IS PID 1 under Docker — see
	 * nats_cdb_parent_gone() in cachedb_nats_watch.c. */
	nats_cdb_parent_pid = getpid();

	/* shared by rank 1 and the reaper process, so allocated pre-fork */
	cdbn_boot_state = shm_malloc(sizeof(*cdbn_boot_state));
	if (!cdbn_boot_state) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	*cdbn_boot_state = CDBN_BOOT_PENDING;

	if (init_check_params() < 0 || init_pool() < 0 ||
	    init_engine() < 0 || init_services() < 0)
		return -1;

	LM_INFO("cachedb_nats: bucket=%s replicas=%d history=%d ttl=%d\n",
		kv_bucket, kv_replicas, kv_history, kv_ttl);

	return 0;
}

/**
 * child_init() -- Per-child process initialization (post-fork).
 *
 * Ensures the KV bucket exists, initializes and builds the JSON search
 * index from existing KV data, starts the self-healing watcher thread
 * (on rank 1 only), and opens cachedb connections for each configured URL.
 *
 * Rank filtering is delegated to modules-contrib/nats/nats_pool_should_init();
 * see that function's documentation for the admission set.
 *
 * Watcher startup decision: only rank 1 (first SIP worker) starts the
 * KV watcher thread.  All other workers rely on the SHM-shared index
 * for the initial build; live updates from rank 1's watcher are
 * best-effort.
 *
 * @param rank  OpenSIPS process rank (1-based for SIP workers).
 * @return      0 on success, -1 on error (kills the child process).
 */
/* Open the cachedb connections of the configured URLs (child_init). */
static int cdbn_open_connections(void)
{
	struct cachedb_url *it;
	cachedb_con *con;

	/* open cachedb connections for each configured URL */
	for (it = nats_cdb_urls; it; it = it->next) {
		char _redacted[512];
		char _tmp[512];
		int _n = it->url.len < (int)sizeof(_tmp) - 1
			? it->url.len : (int)sizeof(_tmp) - 1;
		memcpy(_tmp, it->url.s, _n);
		_tmp[_n] = '\0';
		nats_redact_url(_tmp, _redacted, sizeof(_redacted));
		LM_DBG("opening cachedb_nats connection for [%s]\n", _redacted);
		con = nats_cachedb_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open cachedb_nats connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name, con) < 0) {
			LM_ERR("failed to insert cachedb_nats connection\n");
			return -1;
		}
	}

	cachedb_free_url(nats_cdb_urls);
	nats_cdb_urls = NULL;   /* freed: nothing may read it again */
	return 0;
}

/* Checks of the bound bucket, once (rank 1 at startup, or the reaper
 * process once NATS is up).  Returns -1 if require_usrloc_safe_bucket=1
 * must refuse the bucket. */
static int cdbn_bucket_checks(void)
{
	int64_t maxage_ns = 0;

	/* A PRE-EXISTING bucket may already carry a non-zero
	 * backing-stream MaxAge (older deployment / another tool).  The kv_ttl
	 * modparam guard (mod_init) only stops US from creating one; binding to an
	 * existing MaxAge!=0 bucket would SILENTLY expire permanent contacts
	 * (expires==0).  Detect it once and WARN loudly with the
	 * remediation -- the documented migration policy, never a silent expiry.
	 * WARN (not refuse) by default so a generic cachedb_nats TTL-cache user
	 * is not broken; require_usrloc_safe_bucket=1 makes it fail closed --
	 * a usrloc deployment must recreate the bucket with MaxAge=0. */
	if (nats_pool_bucket_maxage_ns(kv_bucket, &maxage_ns) == 0 &&
			cdbn_kv_legacy_bucket_maxage_warn(maxage_ns)) {
		if (require_usrloc_safe_bucket) {
			LM_ERR("cachedb_nats: bound bucket '%s' has a non-zero "
				"backing-stream MaxAge (%lld ns) and "
				"require_usrloc_safe_bucket=1 -- refusing to start "
				"(it would SILENTLY EXPIRE permanent contacts). "
				"Recreate the bucket with MaxAge=0 (kv_ttl=0) and "
				"migrate.\n",
				kv_bucket, (long long)maxage_ns);
			return -1;
		}
		LM_WARN("cachedb_nats: bound bucket '%s' has a non-zero backing-stream "
			"MaxAge (%lld ns) -- it will SILENTLY EXPIRE ALL keys including "
			"PERMANENT contacts (expires==0). If this bucket backs usrloc, "
			"recreate it with MaxAge=0 (kv_ttl=0) and migrate.\n",
			kv_bucket, (long long)maxage_ns);
	}
	/* Reaper-only expiry: a history-keeping bucket is fine
	 * for nats_kv_history() consumers; no per-message TTL exists to
	 * misbehave on it, so nothing to surface beyond the MaxAge
	 * check above. */
	return 0;
}

/*
 * Called by the reaper process on every pass of its loop: runs the startup
 * checks that rank 1 skipped because NATS was unavailable at startup, once
 * the connection is up.  Without it, a degraded start would never build
 * the search index when no watcher rebuilds it, and never check the
 * bucket.  The reaper is the single process that runs it (one instance).
 */
#ifdef UNIT_TESTS
/* mod_init's URL policy and bucket checks, for the unit tests */
int cn_ut_init_pool(void) { return init_pool(); }
int cn_ut_bucket_checks(void) { return cdbn_bucket_checks(); }
#endif

void nats_cdb_deferred_boot_checks(void)
{
	kvStore *kv;

	if (!cdbn_boot_state || *cdbn_boot_state != CDBN_BOOT_DEFERRED ||
			!nats_pool_is_connected())
		return;

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv)
		return;   /* next pass */

	LM_INFO("cachedb_nats: NATS is up; running the startup checks of "
		"bucket '%s' skipped at startup\n", kv_bucket);
	(void)cdbn_bucket_checks();   /* strict mode never starts degraded */

	/* The watcher rebuilds the index when it first connects, if it runs
	 * and index_resync_on_reconnect is on; otherwise build it here. */
	if (cdbn_fts_on && !(kv_watch_count > 0 && index_resync_on_reconnect) &&
			cdbn_fts.rebuild(kv, fts_json_prefix) < 0)
		LM_WARN("failed to build the search index; queries may return "
			"empty results until it is rebuilt\n");

	*cdbn_boot_state = CDBN_BOOT_DONE;
}

static int child_init(int rank)
{
	natsConnection *nc;
	kvStore *kv;

	if (!nats_pool_should_init(rank))
		return 0;

	/* No NATS server to talk to at startup (the broker is unreachable,
	 * or no usable server URL is configured): start degraded instead of
	 * keeping OpenSIPS from starting.  The cachedb operations fail until
	 * the connection is up, then get the KV handle themselves
	 * (nats_con_refresh_kv()).  A connection that cannot be set up with
	 * the configured servers is a configuration error, though: no waiting
	 * fixes it. */
	nc = nats_pool_get();
	if (!nc && nats_pool_has_servers()) {
		LM_ERR("cachedb_nats: cannot use the configured NATS servers "
			"(see the error above)\n");
		return -1;
	}
	if (!nc || !nats_pool_is_connected()) {
		if (require_usrloc_safe_bucket) {
			if (!nc)
				LM_ERR("cachedb_nats: no usable NATS server URL is "
					"configured and require_usrloc_safe_bucket=1 -- "
					"refusing to start without checking bucket "
					"'%s'\n", kv_bucket);
			else
				LM_ERR("cachedb_nats: NATS is unavailable at startup and "
					"require_usrloc_safe_bucket=1 -- refusing to start "
					"without checking bucket '%s'\n", kv_bucket);
			return -1;
		}
		if (rank == 1) {
			LM_WARN("cachedb_nats: NATS is unavailable at startup; "
				"starting degraded: cache operations fail until it "
				"connects; the checks of bucket '%s'%s run then\n",
				kv_bucket, cdbn_fts_on ? " and the search index build" : "");
			*cdbn_boot_state = CDBN_BOOT_DEFERRED;
		}
		return cdbn_open_connections();
	}

	/* ensure KV bucket exists via the shared pool */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get/create KV bucket '%s'\n", kv_bucket);
		return -1;
	}

	/* bucket checks, once (rank 1) */
	if (rank == 1 && cdbn_bucket_checks() < 0)
		return -1;

	/* The JSON search index is now SHM-backed and was allocated in
	 * mod_init pre-fork; every worker dereferences the same g_idx.
	 * Only rank 1 populates it from KV: the watcher (also rank-1)
	 * keeps it live thereafter, and every other worker sees those
	 * updates immediately through the shared SHM mapping.
	 *
	 * Skip both the initial build and the watcher if the index is
	 * disabled -- there's no SHM index to populate and nothing for
	 * the watcher to update. */
	if (cdbn_fts_on && rank == 1 &&
			cdbn_fts.build(kv, fts_json_prefix) < 0) {
		LM_WARN("failed to build initial search index; "
			"queries may return empty results until index is rebuilt\n");
	}
	if (rank == 1)
		*cdbn_boot_state = CDBN_BOOT_DONE;

	/* Live index updates come from the dedicated watcher process
	 * (exports.procs, attached in mod_init when kv_watch patterns
	 * exist).  The former rank-1 in-worker
	 * watcher pthread was removed: it shared the SIP worker's
	 * per-process connection pool from a second thread, racing the
	 * pool's single-threaded KV-handle cache (use-after-free under
	 * broker flap). */

	return cdbn_open_connections();
}

/**
 * destroy() -- Module cleanup on OpenSIPS shutdown.
 *
 * Stops the KV watcher thread, destroys the JSON search index, and
 * closes all cachedb connections.  Called once from the main process.
 */
static void destroy(void)
{
	LM_NOTICE("destroying module cachedb_nats ...\n");
	/* The KV watcher lives in its own forked child process; the
	 * OpenSIPS core delivers SIGTERM to every child including it,
	 * which terminates it cleanly — nothing to stop from here. */
	/* the SHM index + intern table are owned (and destroyed) by the
	 * optional cachedb_nats_fts module */
	cachedb_end_connections(&cache_mod_name);
	/* Drop our pool reference (pool tears down on the last module's
	 * unregister) -- after the watcher/index that used it are gone. */
	nats_pool_unregister();
	nats_cdb_stats_destroy();
}



/* ------------------------------------------------------------------ */
/*   Reaper host                                                      */
/* ------------------------------------------------------------------ */





/**
 * w_nats_kv_history_wrap() -- Script wrapper for nats_kv_history().
 *
 * Thin wrapper that delegates to w_nats_kv_history() in cachedb_nats_native.c.
 * Retrieves the version history for a KV key and stores the result as a
 * JSON array in the specified pseudo-variable.
 *
 * @param msg     Current SIP message context.
 * @param key     KV key to retrieve history for.
 * @param result  Pseudo-variable to store the JSON history array.
 * @return        1 on success, -1 on error (OpenSIPS script convention).
 */
static int w_nats_kv_history_wrap(struct sip_msg *msg, str *key,
                                  pv_spec_t *result)
{
	return w_nats_kv_history(msg, key, result);
}

static int w_nats_kv_get_wrap(struct sip_msg *msg, str *bucket, str *key,
                              pv_spec_t *value_var, pv_spec_t *rev_var)
{
	return w_nats_kv_get(msg, bucket, key, value_var, rev_var);
}

static int w_nats_kv_put_wrap(struct sip_msg *msg, str *bucket, str *key,
                              str *value)
{
	return w_nats_kv_put(msg, bucket, key, value);
}

static int w_nats_kv_update_wrap(struct sip_msg *msg, str *bucket, str *key,
                                 str *value, int *expected_rev)
{
	return w_nats_kv_update(msg, bucket, key, value, expected_rev);
}

static int w_nats_kv_delete_wrap(struct sip_msg *msg, str *bucket, str *key)
{
	return w_nats_kv_delete(msg, bucket, key);
}

static int w_nats_kv_revision_wrap(struct sip_msg *msg, str *bucket, str *key,
                                   pv_spec_t *rev_var)
{
	return w_nats_kv_revision(msg, bucket, key, rev_var);
}

/**
 * mi_nats_kv_status() -- MI handler for "nats_kv_status".
 *
 * Returns a JSON object with the KV bucket configuration (name, replicas,
 * history depth, TTL) and the current NATS connection state.
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
static mi_response_t *mi_nats_kv_status(const mi_params_t *params,
                                         struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if (add_mi_string(resp_obj, MI_SSTR("bucket"),
			kv_bucket, strlen(kv_bucket)) < 0)
		goto error;

	if (add_mi_number(resp_obj, MI_SSTR("replicas"), kv_replicas) < 0)
		goto error;

	if (add_mi_number(resp_obj, MI_SSTR("history"), kv_history) < 0)
		goto error;

	if (add_mi_number(resp_obj, MI_SSTR("ttl"), kv_ttl) < 0)
		goto error;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("connected"), "%s",
			nats_pool_is_connected() ? "yes" : "no") < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return NULL;
}
