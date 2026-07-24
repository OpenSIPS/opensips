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

#include "cachedb_perf.h"
#include "pcache_mem.h"
#include "pcache_arena.h"
#include "pcache_htable.h"

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

static int pcache_parse_collections(unsigned int type, void *val);
static int pcache_store_urls(unsigned int type, void *val);
static int w_perf_del(struct sip_msg *msg, str *glob, str *col_s);
static int w_perf_mget(struct sip_msg *msg, str *glob, pv_spec_t *keys_pv,
		pv_spec_t *vals_pv, str *col_s, int *limit);
static int w_perf_mget_json(struct sip_msg *msg, str *glob, pv_spec_t *dst_pv,
		str *col_s, int *limit);
static int fixup_check_wvar(void **param);

/* introspection MI (CP-18) - defined just above the mi_cmds table; these
 * forward decls let that table sit before the glob/collection helpers */
static pcache_col_t *col_by_name(const str *name);
static char *glob_dup(const str *glob);
static int perf_del_run(pcache_col_t *col, str *glob);
static inline unsigned int ttl_to_abs(int expires);

#define PERF_ROUTES (REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|\
	LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE)

static const cmd_export_t cmds[] = {
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
	{0,0,0}
};

/*
 * CP-06 statistics: everything is STAT_IS_FUNC - sums of the per-process
 * shards computed at read time.  No shared counter is ever touched on the
 * hot path (DESIGN 2.5 hard rule).
 */
enum pcache_stat_field {
	PSF_HITS, PSF_MISSES, PSF_STORES, PSF_REMOVES, PSF_ENTRIES,
	PSF_RETRIES, PSF_FALLBACKS
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
PSTATF(smf_entries, PSF_ENTRIES)
PSTATF(smf_retries, PSF_RETRIES)
PSTATF(smf_fallbacks, PSF_FALLBACKS)

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

static unsigned long smf_mem_tier(void *ctx)
{
	return pcache_mem.tier;
}

static const stat_export_t mod_stats[] = {
	{"hits",            STAT_IS_FUNC, (stat_var **)smf_hits},
	{"misses",          STAT_IS_FUNC, (stat_var **)smf_misses},
	{"stores",          STAT_IS_FUNC, (stat_var **)smf_stores},
	{"removes",         STAT_IS_FUNC, (stat_var **)smf_removes},
	{"entries",         STAT_IS_FUNC, (stat_var **)smf_entries},
	{"seqlock_retries", STAT_IS_FUNC, (stat_var **)smf_retries},
	{"lock_fallbacks",  STAT_IS_FUNC, (stat_var **)smf_fallbacks},
	{"arena_bytes",     STAT_IS_FUNC, (stat_var **)smf_arena_bytes},
	{"arena_chunks",    STAT_IS_FUNC, (stat_var **)smf_arena_chunks},
	{"memory_tier",     STAT_IS_FUNC, (stat_var **)smf_mem_tier},
	{0,0,0}
};

/* the perf_stats MI (5.2): per-collection detail the flat stats cannot carry */
static int mi_stats_fill(mi_item_t *cobj, pcache_col_t *col)
{
	pcache_htable_t *ht = col->htable;
	pcache_ht_totals_t t;
	unsigned long reads;
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
	    add_mi_number(cobj, MI_SSTR("seqlock_retries"), t.retries) < 0 ||
	    add_mi_number(cobj, MI_SSTR("lock_fallbacks"), t.fallbacks) < 0)
		return -1;

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
	mi_item_t *obj, *arr, *cobj, *aobj;
	pcache_col_t *col;
	const char *tier;
	unsigned long bytes;
	unsigned int nchunks, matched = 0;

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

	aobj = add_mi_object(obj, MI_SSTR("arena"));
	if (!aobj)
		goto err;
	pcache_arena_stats(&nchunks, &bytes);
	if (add_mi_number(aobj, MI_SSTR("chunks"), nchunks) < 0 ||
	    add_mi_number(aobj, MI_SSTR("bytes"), bytes) < 0)
		goto err;

	tier = pcache_mem_tier_str(pcache_mem.tier);
	if (add_mi_number(obj, MI_SSTR("memory_tier"), pcache_mem.tier) < 0 ||
	    add_mi_string(obj, MI_SSTR("memory_backing"),
	        (char *)tier, strlen(tier)) < 0)
		goto err;

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
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
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

	return con;
}

static cachedb_con *pcache_init(str *url)
{
	return cachedb_do_init(url, (void *)pcache_new_connection);
}

static void pcache_free_connection(cachedb_pool_con *con)
{
	pkg_free(con);
}

static void pcache_destroy(cachedb_con *con)
{
	cachedb_do_close(con, pcache_free_connection);
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

static int pcache_htable_fetch(cachedb_con *con, str *attr, str *val)
{
	pcache_htable_t *ht = con_ht(con);

	return ht ? pcache_ht_fetch(ht, attr, val) : -1;
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
	pcache_htable_t *ht = con_ht(con);

	return ht ? pcache_ht_store(ht, attr, val, ttl_to_abs(expires)) : -1;
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
	unsigned int now = get_ticks(), freed, split;

	for (col = pcache_collection; col; col = col->next) {
		if (!col->htable)
			continue;
		freed = pcache_ht_sweep(col->htable, now);
		if (freed)
			LM_DBG("collection <%.*s>: reclaimed %u expired records\n",
				col->col_name.len, col->col_name.s, freed);
		if (growth_load_factor > 0) {
			split = pcache_ht_grow(col->htable,
				growth_load_factor, growth_budget);
			if (split)
				LM_DBG("collection <%.*s>: grew by %u splits\n",
					col->col_name.len, col->col_name.s, split);
		}
	}
}

static int mod_init(void)
{
	cachedb_engine cde;
	cachedb_con *con;
	str default_url = str_init("perf://");
	str def_name = str_init(PCACHE_DEFAULT_COLLECTION);
	pcache_url_t *it, *next;
	pcache_col_t *col;

	/* which of the four memory backings (DESIGN 2.6.1) does this host
	 * support?  Probed by trying, pre-fork; the arena consumes the
	 * result once it exists (CP-02/CP-20) */
	pcache_mem_probe();

	if (pcache_mem.tier == PCACHE_MEM_HUGETLB)
		LM_NOTICE("memory backing: tier 1/4 - %s (pool: %d static + %d "
			"overcommit pages)\n",
			pcache_mem_tier_str(pcache_mem.tier),
			pcache_mem.huge_static, pcache_mem.huge_overcommit);
	else
		LM_NOTICE("memory backing: tier %d/4 - %s\n",
			pcache_mem.tier, pcache_mem_tier_str(pcache_mem.tier));

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
	cde.cdb_func.get_counter = pcache_htable_fetch_counter;
	cde.cdb_func.set = pcache_htable_insert;
	cde.cdb_func.remove = pcache_htable_remove;
	cde.cdb_func.add = pcache_htable_add;
	cde.cdb_func.sub = pcache_htable_sub;
	cde.cdb_func.iter_keys = pcache_htable_iter_keys;

	cde.cdb_func.capability = CACHEDB_CAP_BINARY_VALUE;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to register the 'perf' cachedb engine\n");
		return -1;
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

	for (col = pcache_collection; col; col = next) {
		next = col->next;
		if (col->col_name.s)
			shm_free(col->col_name.s);
		shm_free(col);
	}
	pcache_collection = NULL;

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
