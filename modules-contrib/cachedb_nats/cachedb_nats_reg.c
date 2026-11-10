/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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

/*
 * cachedb_nats_reg.c — registration observability: the operator's view
 * into the KV-stored registrations (see cachedb_nats_reg.h for the design
 * invariants).  The pure decision logic here is unit-locked by
 * test/test_reg_filter.c, test_reg_sort_page.c and test_reg_row_scan.c;
 * this TU adds the bucket scan + MI plumbing on top.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fnmatch.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../lib/osips_malloc.h"      /* osips_pkg_free                   */
#include "../../cachedb/cachedb_types.h"
#include "../../cachedb/cachedb_dict.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_dl.h"
#include "../nats/nats_pool.h"
#include "cachedb_nats_dbase.h"          /* kv_bucket / kv_replicas / ...    */
#include "cachedb_nats_json_internal.h"  /* walkers + cdbn_pk_target_key + dict  */
#include "cachedb_nats_fmt.h"
#include "cachedb_nats_emit.h"
#include "cachedb_nats_reg.h"
#include "cachedb_nats_reap_enum.h"

extern char *fts_json_prefix;            /* cachedb_nats.c                   */
extern int   fts_json_prefix_len;        /* cached at mod_init               */
extern int   nats_reap_grace;
/* kv_bucket / kv_replicas / kv_history / kv_ttl come from cachedb_nats_dbase.h */

/* ==================================================================== */
/* pure helpers — byte-identical to the carried copies in tests/        */
/* ==================================================================== */

int cdbn_reg_contact_state(int64_t expires, time_t now, int grace)
{
	if (expires == 0)
		return REG_C_PERMANENT;
	return (expires + (int64_t)grace > (int64_t)now)
		? REG_C_ACTIVE : REG_C_EXPIRED;
}

int cdbn_reg_domain_of(const char *aor, int len, const char **dom, int *dlen)
{
	int i;
	for (i = len - 1; i >= 0; i--) {
		if (aor[i] == '@') {
			*dom = aor + i + 1;
			*dlen = len - i - 1;
			return 0;
		}
	}
	*dom = NULL; *dlen = 0;
	return -1;
}

int cdbn_reg_ci_eq(const char *a, int alen, const char *b, int blen)
{
	int i;
	if (alen != blen)
		return 0;
	for (i = 0; i < alen; i++) {
		char ca = a[i], cb = b[i];
		if (ca >= 'A' && ca <= 'Z') ca += 32;
		if (cb >= 'A' && cb <= 'Z') cb += 32;
		if (ca != cb)
			return 0;
	}
	return 1;
}

int cdbn_reg_substr(const char *hay, int hlen, const char *nee, int nlen)
{
	int i;
	if (nlen <= 0 || nlen > hlen)
		return 0;
	for (i = 0; i + nlen <= hlen; i++)
		if (memcmp(hay + i, nee, nlen) == 0)
			return 1;
	return 0;
}

/* one key=value token; 0 ok, -1 reject */
static int reg_filter_kv(struct reg_filter *f, const char *k, int klen,
	const char *v, int vlen)
{
	char num[24];
	long n;
	char *end;

	if (vlen <= 0)
		return -1;
	/* an MI string may carry \u0000: the value is copied into C strings
	 * (globs, substrings, the number) that would silently stop at it */
	if (memchr(v, '\0', vlen))
		return -1;

#define KEQ(s) (klen == (int)sizeof(s)-1 && memcmp(k, s, klen) == 0)
#define CPY(dst) do { \
		if (vlen >= (int)sizeof(dst)) return -1; \
		memcpy(dst, v, vlen); dst[vlen] = '\0'; } while (0)

	if (KEQ("aor"))      { CPY(f->aor_glob); return 0; }
	if (KEQ("domain"))   { CPY(f->domain);   return 0; }
	if (KEQ("ua"))       { CPY(f->ua);       return 0; }
	if (KEQ("contact"))  { CPY(f->contact);  return 0; }
	if (KEQ("state")) {
		if (vlen == 6 && memcmp(v, "active", 6) == 0) f->state = REG_F_ACTIVE;
		else if (vlen == 7 && memcmp(v, "expired", 7) == 0) f->state = REG_F_EXPIRED;
		else if (vlen == 9 && memcmp(v, "permanent", 9) == 0) f->state = REG_F_PERMANENT;
		else if (vlen == 3 && memcmp(v, "all", 3) == 0) f->state = REG_F_ALL;
		else return -1;
		return 0;
	}
	if (KEQ("sort")) {
		if (vlen == 3 && memcmp(v, "aor", 3) == 0) f->sort = REG_SORT_AOR;
		else if (vlen == 6 && memcmp(v, "expiry", 6) == 0) f->sort = REG_SORT_EXPIRY;
		else if (vlen == 8 && memcmp(v, "contacts", 8) == 0) f->sort = REG_SORT_CONTACTS;
		else if (vlen == 8 && memcmp(v, "last_mod", 8) == 0) f->sort = REG_SORT_LAST_MOD;
		else return -1;
		return 0;
	}
	if (vlen >= (int)sizeof(num))
		return -1;
	memcpy(num, v, vlen); num[vlen] = '\0';
	n = strtol(num, &end, 10);
	if (*end != '\0')
		return -1;
	if (KEQ("expiring_within")) { if (n <= 0) return -1; f->expiring_within = n; return 0; }
	if (KEQ("min_contacts"))    { if (n < 0) return -1; f->min_contacts = n; return 0; }
	if (KEQ("desc"))            { if (n != 0 && n != 1) return -1; f->desc = (int)n; return 0; }
	if (KEQ("limit")) {
		if (n <= 0) return -1;
		f->limit = n > REG_LIMIT_CAP ? REG_LIMIT_CAP : n;
		return 0;
	}
	if (KEQ("offset"))          { if (n < 0) return -1; f->offset = n; return 0; }
	if (KEQ("header"))          { if (n != 0 && n != 1) return -1; f->header = (int)n; return 0; }
	return -1;
#undef KEQ
#undef CPY
}

/* string-valued format keys, shared shape with the kvobs parser */
static int reg_filter_fmt_kv(struct reg_filter *f, const char *k, int klen,
	const char *v, int vlen)
{
	if (klen == 6 && memcmp(k, "format", 6) == 0) {
		int fk = cdbn_fmt_kind_parse(v, vlen);
		if (fk < 0)
			return -1;
		f->format = fk;
		return 0;
	}
	if (klen == 3 && memcmp(k, "eol", 3) == 0) {
		if (vlen == 2 && memcmp(v, "lf", 2) == 0) f->eol_lf = 1;
		else if (vlen == 4 && memcmp(v, "crlf", 4) == 0) f->eol_lf = 0;
		else return -1;
		return 0;
	}
	return 1;                                  /* not a format key */
}

int cdbn_reg_filter_parse(const char *s, int len, struct reg_filter *f)
{
	const char *p = s, *end = s + len;

	memset(f, 0, sizeof(*f));
	f->state = REG_F_ACTIVE;
	f->limit = REG_LIMIT_DEFAULT;
	f->header = 1;

	while (p < end) {
		const char *tok = p, *eq, *te;
		while (p < end && *p != ';')
			p++;
		te = p;
		if (p < end)
			p++;
		while (tok < te && (*tok == ' ' || *tok == '\t')) tok++;
		while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) te--;
		if (tok == te)
			continue;
		for (eq = tok; eq < te && *eq != '='; eq++)
			;
		if (eq == te || eq == tok)
			return -1;
		{
			int r = reg_filter_fmt_kv(f, tok, (int)(eq - tok),
				eq + 1, (int)(te - eq - 1));
			if (r < 0)
				return -1;
			if (r == 0)
				continue;
		}
		if (reg_filter_kv(f, tok, (int)(eq - tok),
				eq + 1, (int)(te - eq - 1)) < 0)
			return -1;
	}
	return 0;
}

void cdbn_reg_page(long total, long limit, long offset, long *start, long *count)
{
	if (offset >= total) {
		*start = total; *count = 0;
		return;
	}
	*start = offset;
	*count = (offset + limit > total) ? total - offset : limit;
}

static int reg_aor_cmp(const struct reg_row_info *a, const struct reg_row_info *b)
{
	int n = a->aor_len < b->aor_len ? a->aor_len : b->aor_len;
	int c = memcmp(a->aor, b->aor, n);
	if (c)
		return c;
	return a->aor_len - b->aor_len;
}

int cdbn_reg_row_cmp(const struct reg_row_info *a, const struct reg_row_info *b,
	int sort, int desc)
{
	int c = 0;
	switch (sort) {
	case REG_SORT_EXPIRY:
		c = a->soonest_exp < b->soonest_exp ? -1 :
		    a->soonest_exp > b->soonest_exp ?  1 : 0;
		break;
	case REG_SORT_CONTACTS:
		c = a->n_contacts - b->n_contacts;
		break;
	case REG_SORT_LAST_MOD:
		c = a->last_mod < b->last_mod ? -1 :
		    a->last_mod > b->last_mod ?  1 : 0;
		break;
	}
	if (c == 0 && sort != REG_SORT_AOR)
		return reg_aor_cmp(a, b);          /* tie-break: AoR, ALWAYS ascending */
	if (sort == REG_SORT_AOR)
		c = reg_aor_cmp(a, b);
	return desc ? -c : c;
}

/* one contact object slice [cs,ce): classify + collect */
static void reg_scan_contact(const char *cs, const char *ce,
	time_t now, int grace,
	const char *ua_nee, int ua_len, const char *ct_nee, int ct_len,
	struct reg_row_info *o)
{
	const char *p = cdbn_skip_ws(cs, ce);
	int64_t expires = -1;
	int have_exp = 0;

	o->n_contacts++;
	if (p >= ce || *p != '{') {
		o->n_expired++;                 /* poison member: fail closed */
		return;
	}
	p++;
	while (p < ce) {
		const char *name, *vs;
		int nlen;
		p = cdbn_skip_ws(p, ce);
		if (p >= ce || *p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, ce, &name, &nlen);
		if (!p) { o->n_expired++; return; }
		p = cdbn_skip_ws(p, ce);
		if (p >= ce || *p != ':') { o->n_expired++; return; }
		p++;
		p = cdbn_skip_ws(p, ce);
		vs = p;
		if (nlen == 7 && memcmp(name, "expires", 7) == 0) {
			int64_t v;
			if (cdbn_contact_field_int64(cs, ce, "expires", 7, &v) == 0) {
				expires = v; have_exp = 1;
			}
		} else if (nlen == 8 && memcmp(name, "last_mod", 8) == 0) {
			int64_t v;
			if (cdbn_contact_field_int64(cs, ce, "last_mod", 8, &v) == 0 &&
			    v > o->last_mod)
				o->last_mod = v;
		} else if ((nlen == 2 && memcmp(name, "ua", 2) == 0) ||
		           (nlen == 7 && memcmp(name, "contact", 7) == 0)) {
			const char *sv; int svl;
			if (*vs == '"' && cdbn_parse_json_string(vs, ce, &sv, &svl)) {
				if (nlen == 2 && ua_len &&
				    cdbn_reg_substr(sv, svl, ua_nee, ua_len))
					o->ua_hit = 1;
				if (nlen == 7 && ct_len &&
				    cdbn_reg_substr(sv, svl, ct_nee, ct_len))
					o->ct_hit = 1;
			}
		}
		p = cdbn_skip_json_value(p, ce);
		if (!p) { o->n_expired++; return; }
	}
	if (!have_exp) {
		o->n_expired++;                 /* no usable expiry: fail closed */
		return;
	}
	if (expires == 0) {
		o->n_perm++;
		return;
	}
	if (expires + (int64_t)grace > (int64_t)now) {
		o->n_active++;
		if (expires < o->soonest_exp)
			o->soonest_exp = expires;
	} else {
		o->n_expired++;
	}
}

int cdbn_reg_row_scan(const char *json, int len, time_t now, int grace,
	const char *ua_nee, int ua_len, const char *ct_nee, int ct_len,
	struct reg_row_info *o)
{
	const char *p, *end = json + len;
	const char *c_vs = NULL, *c_ve = NULL;

	memset(o, 0, sizeof(*o));
	o->soonest_exp = REG_NO_EXPIRY;

	p = cdbn_skip_ws(json, end);
	if (p >= end || *p != '{')
		return -1;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen;
		p = cdbn_skip_ws(p, end);
		if (p >= end)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p)
			return -1;
		if (nlen == 3 && memcmp(name, "aor", 3) == 0 && *vs == '"') {
			cdbn_parse_json_string(vs, end, &o->aor, &o->aor_len);
		} else if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (*vs != '{')
				return -1;              /* poison contacts: not a row */
			c_vs = vs; c_ve = p;
		}
	}
	if (!c_vs)
		return -1;                      /* not a usrloc row */

	p = cdbn_skip_ws(c_vs, c_ve);
	p++;                                /* '{' */
	while (p < c_ve) {
		const char *name, *vs;
		int nlen;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve || *p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, c_ve, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, c_ve);
		vs = p;
		p = cdbn_skip_json_value(p, c_ve);
		if (!p)
			return -1;
		reg_scan_contact(vs, p, now, grace,
			ua_nee, ua_len, ct_nee, ct_len, o);
	}
	return 0;
}

/* ==================================================================== */
/* bucket scan + MI plumbing                                            */
/* ==================================================================== */

struct reg_scan_totals {
	long keys, rows, other, malformed;
	long contacts, active, expired, permanent;
	int64_t soonest;
	long ms;
};

/* cb returns 0 to continue, -1 to abort (OOM etc.) */
typedef int (*reg_row_cb)(const struct reg_row_info *ri, void *arg);

/* per-pass context threaded through nats_kv_enum_live_values() */
struct _reg_enum_pass {
	reg_row_cb cb;
	void *arg;
	struct reg_scan_totals *tot;
	time_t now;
	const char *ua_nee, *ct_nee;
	int ua_len, ct_len;
	int prefix_len;
};

/* Per-entry visitor: the same decision ladder the old Keys+Get loop
 * had, minus the per-key round trip.  The entry is owned by the
 * enumerator (destroyed after return). */
static int reg_enum_entry(kvEntry *e, void *arg)
{
	struct _reg_enum_pass *p = arg;
	const char *key = nats_dl.kvEntry_Key(e);
	const char *val;
	int vlen;
	struct reg_row_info ri;

	if (!key)
		return 0;
	if (p->prefix_len &&
	    strncmp(key, fts_json_prefix, p->prefix_len) != 0)
		return 0;
	p->tot->keys++;
	val = nats_dl.kvEntry_ValueString(e);
	vlen = nats_dl.kvEntry_ValueLen(e);
	if (!val || vlen <= 0)
		return 0;   /* defensive: IgnoreDeletes filters markers */
	if (cdbn_reg_row_scan(val, vlen, p->now, nats_reap_grace,
			p->ua_nee, p->ua_len, p->ct_nee, p->ct_len, &ri) != 0) {
		p->tot->other++;
		return 0;
	}
	p->tot->rows++;
	p->tot->contacts  += ri.n_contacts;
	p->tot->active    += ri.n_active;
	p->tot->expired   += ri.n_expired;
	p->tot->permanent += ri.n_perm;
	if (ri.soonest_exp < p->tot->soonest)
		p->tot->soonest = ri.soonest_exp;
	if (p->cb && p->cb(&ri, p->arg) < 0)
		return -1;
	return 0;
}

static int reg_scan_bucket(const struct reg_filter *f, reg_row_cb cb,
	void *arg, struct reg_scan_totals *tot)
{
	kvStore *kv;
	struct _reg_enum_pass p;
	struct timespec t0, t1;
	int rc;

	memset(tot, 0, sizeof(*tot));
	tot->soonest = REG_NO_EXPIRY;

	memset(&p, 0, sizeof(p));
	p.cb = cb;
	p.arg = arg;
	p.tot = tot;
	p.now = time(NULL);
	if (f && f->ua[0])      { p.ua_nee = f->ua; p.ua_len = (int)strlen(f->ua); }
	if (f && f->contact[0]) { p.ct_nee = f->contact; p.ct_len = (int)strlen(f->contact); }

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	p.prefix_len = (fts_json_prefix && *fts_json_prefix)
		? fts_json_prefix_len : 0;

	/* One value-carrying watch pass over the live keys -- the same
	 * enumeration the reaper uses.  The old kvStore_Keys() + per-key
	 * kvStore_Get() issued O(bucket) synchronous round trips, which
	 * is exactly what an operator must not pay for running
	 * nats_reg_summary mid-incident on a large deployment. */
	rc = nats_kv_enum_live_values(kv, NATS_KV_ENUM_NEXT_TIMEOUT_MS,
			reg_enum_entry, &p);

	clock_gettime(CLOCK_MONOTONIC, &t1);
	tot->ms = (t1.tv_sec - t0.tv_sec) * 1000
		+ (t1.tv_nsec - t0.tv_nsec) / 1000000;
	return rc < 0 ? -1 : 0;
}

#ifdef UNIT_TESTS
static int cn_ut_count_row(const struct reg_row_info *ri, void *arg)
{
	(void)ri;
	(*(int *)arg)++;
	return 0;
}

/* the registration scan, for the unit tests: rows handed to the row
 * callback, and the scan's contact total */
int cn_ut_reg_scan(int *rows, long *contacts)
{
	struct reg_scan_totals tot;
	int rc;

	*rows = 0;
	rc = reg_scan_bucket(NULL, cn_ut_count_row, rows, &tot);
	*contacts = (long)tot.contacts;
	return rc;
}
#endif

/* ---- nats_reg_summary --------------------------------------------- */

#define REG_MAX_DOMAINS 64

struct reg_dom_row {
	char d[192];
	int  dlen;
	long aors, contacts, active;
};

struct reg_summary_ctx {
	int want_domains;
	struct reg_dom_row dom[REG_MAX_DOMAINS];
	int n_dom;
	long dom_overflow_aors;
};

static int reg_summary_cb(const struct reg_row_info *ri, void *arg)
{
	struct reg_summary_ctx *c = arg;
	const char *d = NULL;
	int dlen = 0, i;

	if (!c->want_domains)
		return 0;
	if (ri->aor_len <= 0 ||
	    cdbn_reg_domain_of(ri->aor, ri->aor_len, &d, &dlen) != 0) {
		d = "(none)"; dlen = 6;
	}
	for (i = 0; i < c->n_dom; i++)
		if (cdbn_reg_ci_eq(c->dom[i].d, c->dom[i].dlen, d, dlen))
			break;
	if (i == c->n_dom) {
		if (c->n_dom >= REG_MAX_DOMAINS || dlen >= (int)sizeof(c->dom[0].d)) {
			c->dom_overflow_aors++;
			return 0;
		}
		memcpy(c->dom[i].d, d, dlen);
		c->dom[i].dlen = dlen;
		c->dom[i].aors = c->dom[i].contacts = c->dom[i].active = 0;
		c->n_dom++;
	}
	c->dom[i].aors++;
	c->dom[i].contacts += ri->n_contacts;
	c->dom[i].active   += ri->n_active;
	return 0;
}

/* the summary response envelope: bucket + totals + scan stats.  0/-1. */
static int reg_summary_meta(mi_item_t *obj,
	const struct reg_scan_totals *tot, time_t now)
{
	if (add_mi_string(obj, MI_SSTR("bucket"), kv_bucket,
			(int)strlen(kv_bucket)) < 0 ||
	    add_mi_number(obj, MI_SSTR("aors"), tot->rows) < 0 ||
	    add_mi_number(obj, MI_SSTR("contacts"), tot->contacts) < 0 ||
	    add_mi_number(obj, MI_SSTR("active_contacts"), tot->active) < 0 ||
	    add_mi_number(obj, MI_SSTR("expired_contacts"), tot->expired) < 0 ||
	    add_mi_number(obj, MI_SSTR("permanent_contacts"), tot->permanent) < 0)
		return -1;
	if (tot->soonest != REG_NO_EXPIRY) {
		if (add_mi_number(obj, MI_SSTR("soonest_expiry"),
				(double)tot->soonest) < 0 ||
		    add_mi_number(obj, MI_SSTR("soonest_expiry_in"),
				(double)(tot->soonest - now)) < 0)
			return -1;
	}
	if (add_mi_number(obj, MI_SSTR("scanned_keys"), tot->keys) < 0 ||
	    add_mi_number(obj, MI_SSTR("other_docs"), tot->other) < 0 ||
	    add_mi_number(obj, MI_SSTR("scan_ms"), tot->ms) < 0)
		return -1;
	return 0;
}

mi_response_t *mi_nats_reg_summary(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *obj;
	struct reg_scan_totals tot;
	struct reg_summary_ctx *ctx;
	int domains = 0, i;
	time_t now = time(NULL);
	int fk, f_eol, f_hdr;

	(void)async_hdl;
	if (try_get_mi_int_param(params, "domains", &domains) < 0)
		domains = 0;
	if (nats_mi_fmt_param(params, &fk, &f_eol, &f_hdr) < 0)
		return init_mi_error(400, MI_SSTR("bad format (json|csv|txt"
			"[;eol=lf|crlf][;header=0|1])"));

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return init_mi_error(500, MI_SSTR("out of memory"));
	memset(ctx, 0, sizeof(*ctx));
	ctx->want_domains = domains ? 1 : 0;

	if (reg_scan_bucket(NULL, reg_summary_cb, ctx, &tot) < 0) {
		free(ctx);
		return init_mi_error(503, MI_SSTR("NATS unavailable"));
	}

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto oom;
	if (reg_summary_meta(obj, &tot, now) < 0)
		goto oom;

	if (fk != FMT_JSON || ctx->want_domains) {
		/* ONE walk: table = totals record + per-domain records;
		 * json = just the domains array (totals live at top level, the
		 * `scope` cell and the empty expired/permanent trailers are
		 * table-structural) */
		static const char *COLS[] = {"scope", "domain", "aors", "contacts",
			"active", "expired", "permanent"};
		struct nats_emit em;
		int rc = 0;

		if (nats_emit_open(&em, obj, MI_SSTR("domains"),
				fk, f_eol, f_hdr, COLS, 7) < 0)
			goto oom;
		if (em.table) {
			rc |= nats_emit_rec(&em);
			rc |= nats_emit_lit(&em, "total", 5);
			rc |= nats_emit_absent(&em, MI_SSTR("domain"));
			rc |= nats_emit_i64(&em, MI_SSTR("aors"), tot.rows);
			rc |= nats_emit_i64(&em, MI_SSTR("contacts"), tot.contacts);
			rc |= nats_emit_i64(&em, MI_SSTR("active"), tot.active);
			rc |= nats_emit_i64(&em, MI_SSTR("expired"), tot.expired);
			rc |= nats_emit_i64(&em, MI_SSTR("permanent"), tot.permanent);
			rc |= nats_emit_end(&em);
		}
		if (ctx->want_domains) {
			for (i = 0; i < ctx->n_dom && rc == 0; i++) {
				rc |= nats_emit_rec(&em);
				rc |= nats_emit_lit(&em, "domain", 6);
				rc |= nats_emit_str(&em, MI_SSTR("domain"),
					ctx->dom[i].d, ctx->dom[i].dlen);
				rc |= nats_emit_i64(&em, MI_SSTR("aors"),
					ctx->dom[i].aors);
				rc |= nats_emit_i64(&em, MI_SSTR("contacts"),
					ctx->dom[i].contacts);
				rc |= nats_emit_i64(&em, MI_SSTR("active_contacts"),
					ctx->dom[i].active);
				rc |= nats_emit_absent(&em, MI_SSTR("expired"));
				rc |= nats_emit_absent(&em, MI_SSTR("permanent"));
				rc |= nats_emit_end(&em);
			}
		}
		if (rc < 0) {
			nats_emit_abort(&em);
			goto oom;
		}
		if (nats_emit_close(&em, obj) < 0)
			goto oom;
	}
	if (fk == FMT_JSON && ctx->want_domains && ctx->dom_overflow_aors &&
	    add_mi_number(obj, MI_SSTR("domains_overflow_aors"),
			ctx->dom_overflow_aors) < 0)
		goto oom;
	free(ctx);
	return resp;

oom:
	free(ctx);
	if (resp)
		free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("out of memory"));
}

/* ---- nats_reg_list ------------------------------------------------- */

#define REG_COLLECT_CAP 100000   /* runaway-bucket sanity bound */

struct reg_list_ctx {
	const struct reg_filter *f;
	time_t now;
	struct reg_row_info *rows;   /* aor points into aor_buf copies */
	long n, cap;
	int truncated;
	int oom;
};

static int reg_row_match(const struct reg_row_info *ri,
	const struct reg_filter *f, time_t now)
{
	(void)now;
	if (f->aor_glob[0]) {
		char abuf[512];
		if (ri->aor_len <= 0 || ri->aor_len >= (int)sizeof(abuf))
			return 0;
		memcpy(abuf, ri->aor, ri->aor_len);
		abuf[ri->aor_len] = '\0';
		if (fnmatch(f->aor_glob, abuf, 0) != 0)
			return 0;
	}
	if (f->domain[0]) {
		const char *d; int dlen;
		if (ri->aor_len <= 0 ||
		    cdbn_reg_domain_of(ri->aor, ri->aor_len, &d, &dlen) != 0)
			return 0;
		if (!cdbn_reg_ci_eq(d, dlen, f->domain, (int)strlen(f->domain)))
			return 0;
	}
	if (f->ua[0] && !ri->ua_hit)
		return 0;
	if (f->contact[0] && !ri->ct_hit)
		return 0;
	switch (f->state) {
	case REG_F_ACTIVE:    if (ri->n_active  <= 0) return 0; break;
	case REG_F_EXPIRED:   if (ri->n_expired <= 0) return 0; break;
	case REG_F_PERMANENT: if (ri->n_perm    <= 0) return 0; break;
	default: break;
	}
	if (f->expiring_within > 0 &&
	    (ri->soonest_exp == REG_NO_EXPIRY ||
	     ri->soonest_exp - (int64_t)time(NULL) > f->expiring_within))
		return 0;
	if (f->min_contacts > 0 && ri->n_contacts < f->min_contacts)
		return 0;
	return 1;
}

static int reg_list_cb(const struct reg_row_info *ri, void *arg)
{
	struct reg_list_ctx *c = arg;
	struct reg_row_info *slot;
	char *copy;

	if (!reg_row_match(ri, c->f, c->now))
		return 0;
	if (c->n >= REG_COLLECT_CAP) {
		c->truncated = 1;
		return 0;
	}
	if (c->n == c->cap) {
		long ncap = c->cap ? c->cap * 2 : 256;
		void *nr = realloc(c->rows, ncap * sizeof(*c->rows));
		if (!nr) { c->oom = 1; return -1; }
		c->rows = nr;
		c->cap = ncap;
	}
	copy = malloc(ri->aor_len > 0 ? ri->aor_len : 1);
	if (!copy) { c->oom = 1; return -1; }
	memcpy(copy, ri->aor, ri->aor_len > 0 ? ri->aor_len : 0);
	slot = &c->rows[c->n++];
	*slot = *ri;
	slot->aor = copy;
	return 0;
}

static int g_reg_sort, g_reg_desc;
static int reg_qcmp(const void *a, const void *b)
{
	return cdbn_reg_row_cmp((const struct reg_row_info *)a,
	                    (const struct reg_row_info *)b,
	                    g_reg_sort, g_reg_desc);
}

static void reg_list_ctx_free(struct reg_list_ctx *c)
{
	long i;
	for (i = 0; i < c->n; i++)
		free((char *)c->rows[i].aor);
	free(c->rows);
}

/* the list response envelope: match counts, page, scan stats.  0/-1. */
static int reg_list_meta(mi_item_t *obj, const struct reg_list_ctx *ctx,
	const struct reg_scan_totals *tot, long start, long count)
{
	if (add_mi_number(obj, MI_SSTR("matched"), ctx->n) < 0 ||
	    add_mi_number(obj, MI_SSTR("returned"), count) < 0 ||
	    add_mi_number(obj, MI_SSTR("offset"), start) < 0 ||
	    add_mi_number(obj, MI_SSTR("scanned_aors"), tot->rows) < 0 ||
	    add_mi_number(obj, MI_SSTR("scan_ms"), tot->ms) < 0)
		return -1;
	if (ctx->truncated &&
	    add_mi_bool(obj, MI_SSTR("truncated"), 1) < 0)
		return -1;
	return 0;
}

mi_response_t *mi_nats_reg_list(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *obj;
	str fstr = {NULL, 0};
	struct reg_filter f;
	struct reg_scan_totals tot;
	struct reg_list_ctx ctx;
	long start, count, i;
	time_t now = time(NULL);

	(void)async_hdl;
	if (try_get_mi_string_param(params, "filter", &fstr.s, &fstr.len) < 0)
		fstr.s = NULL;

	if (cdbn_reg_filter_parse(fstr.s ? fstr.s : "", fstr.s ? fstr.len : 0,
			&f) < 0)
		return init_mi_error(400, MI_SSTR("bad filter (keys: aor domain ua "
			"contact state expiring_within min_contacts sort desc limit "
			"offset; ';'-separated key=value)"));

	memset(&ctx, 0, sizeof(ctx));
	ctx.f = &f;
	ctx.now = now;

	if (reg_scan_bucket(&f, reg_list_cb, &ctx, &tot) < 0) {
		int oom = ctx.oom;
		reg_list_ctx_free(&ctx);
		if (oom)
			return init_mi_error(500, MI_SSTR("out of memory"));
		return init_mi_error(503, MI_SSTR("NATS unavailable"));
	}

	g_reg_sort = f.sort;
	g_reg_desc = f.desc;
	if (ctx.n > 1)
		qsort(ctx.rows, ctx.n, sizeof(*ctx.rows), reg_qcmp);

	cdbn_reg_page(ctx.n, f.limit, f.offset, &start, &count);

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto oom;
	if (reg_list_meta(obj, &ctx, &tot, start, count) < 0)
		goto oom;

	{
		/* ONE walk; json rows land in the `aors` array, table
		 * rows in the format/data blob */
		static const char *COLS[] = {"aor", "contacts", "active", "expired",
			"permanent", "expires_next", "expires_in", "last_mod"};
		struct nats_emit em;
		int rc = 0;

		if (nats_emit_open(&em, obj, MI_SSTR("aors"),
				f.format, f.eol_lf, f.header, COLS, 8) < 0)
			goto oom;
		for (i = start; i < start + count && rc == 0; i++) {
			struct reg_row_info *r = &ctx.rows[i];

			rc |= nats_emit_rec(&em);
			rc |= nats_emit_str(&em, MI_SSTR("aor"),
				r->aor, r->aor_len);
			rc |= nats_emit_i64(&em, MI_SSTR("contacts"), r->n_contacts);
			rc |= nats_emit_i64(&em, MI_SSTR("active"), r->n_active);
			rc |= nats_emit_i64(&em, MI_SSTR("expired"), r->n_expired);
			rc |= nats_emit_i64(&em, MI_SSTR("permanent"), r->n_perm);
			if (r->soonest_exp != REG_NO_EXPIRY) {
				rc |= nats_emit_i64(&em, MI_SSTR("expires_next"),
					r->soonest_exp);
				rc |= nats_emit_i64(&em, MI_SSTR("expires_in"),
					r->soonest_exp - now);
			} else {
				rc |= nats_emit_absent(&em, MI_SSTR("expires_next"));
				rc |= nats_emit_absent(&em, MI_SSTR("expires_in"));
			}
			if (r->last_mod)
				rc |= nats_emit_i64(&em, MI_SSTR("last_mod"),
					r->last_mod);
			else
				rc |= nats_emit_absent(&em, MI_SSTR("last_mod"));
			rc |= nats_emit_end(&em);
		}
		if (rc < 0) {
			nats_emit_abort(&em);
			goto oom;
		}
		if (nats_emit_close(&em, obj) < 0)
			goto oom;
	}
	reg_list_ctx_free(&ctx);
	return resp;

oom:
	reg_list_ctx_free(&ctx);
	if (resp)
		free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("out of memory"));
}

/* ---- nats_reg_show -------------------------------------------------- */

static int add_mi_cdb_val(mi_item_t *to, const str *name, const cdb_val_t *v)
{
	switch (v->type) {
	case CDB_STR:
		return add_mi_string(to, name->s, name->len,
			v->val.st.s, v->val.st.len);
	case CDB_INT32:
		return add_mi_number(to, name->s, name->len, v->val.i32);
	case CDB_INT64:
		return add_mi_number(to, name->s, name->len, (double)v->val.i64);
	case CDB_NULL:
		return add_mi_null(to, name->s, name->len);
	default:
		return 0;                    /* nested dicts handled by caller */
	}
}

/* the "expires" int of a contact dict; like the json scan, the LAST
 * occurrence wins.  0 found, -1 absent/non-int (caller fails closed). */
static int contact_dict_exp(const cdb_dict_t *ct, int64_t *exp)
{
	struct list_head *_;
	cdb_pair_t *fld;
	int have = -1;

	list_for_each (_, ct) {
		fld = list_entry(_, cdb_pair_t, list);
		if (fld->key.name.len != 7 ||
		    memcmp(fld->key.name.s, "expires", 7) != 0)
			continue;
		if (fld->val.type == CDB_INT32) {
			*exp = fld->val.val.i32; have = 0;
		} else if (fld->val.type == CDB_INT64) {
			*exp = fld->val.val.i64; have = 0;
		}
	}
	return have;
}

static const char *reg_state_str(int64_t exp, time_t now, int grace)
{
	int st = cdbn_reg_contact_state(exp, now, grace);
	return st == REG_C_PERMANENT ? "permanent" :
	       st == REG_C_ACTIVE ? "active" : "expired";
}

/* emit one named field of a contact dict into the table (string ->
 * fmt_str, ints -> fmt_int, absent/null/nested -> empty field). */
static void show_fmt_field(struct fmt_table *t, const cdb_dict_t *ct,
	const char *name, int nlen)
{
	struct list_head *_;
	cdb_pair_t *fld;

	list_for_each (_, ct) {
		fld = list_entry(_, cdb_pair_t, list);
		if (fld->key.name.len != nlen ||
		    memcmp(fld->key.name.s, name, nlen) != 0)
			continue;
		switch (fld->val.type) {
		case CDB_STR:
			fmt_str(t, fld->val.val.st.s, fld->val.val.st.len);
			return;
		case CDB_INT32:
			fmt_int(t, fld->val.val.i32);
			return;
		case CDB_INT64:
			fmt_int(t, fld->val.val.i64);
			return;
		default:
			break;
		}
		break;
	}
	fmt_empty(t);
}

/* the show response envelope: aor, key, KV entry meta, row meta.  0/-1. */
static int reg_show_meta(mi_item_t *obj, const str *aor, const char *key,
	kvEntry *e, int64_t row_exp, int64_t schema)
{
	if (add_mi_string(obj, MI_SSTR("aor"), aor->s, aor->len) < 0 ||
	    add_mi_string(obj, MI_SSTR("key"), (char *)key,
			(int)strlen(key)) < 0 ||
	    add_mi_number(obj, MI_SSTR("revision"),
			(double)nats_dl.kvEntry_Revision(e)) < 0 ||
	    add_mi_number(obj, MI_SSTR("created"),
			(double)(nats_dl.kvEntry_Created(e) / 1000000000LL)) < 0 ||
	    add_mi_number(obj, MI_SSTR("row_exp"), (double)row_exp) < 0 ||
	    add_mi_number(obj, MI_SSTR("schema_version"), (double)schema) < 0)
		return -1;
	return 0;
}

/* one fixed-16-column table record per contact */
static void show_contact_fmt(struct fmt_table *t, const str *aor,
	const cdb_pair_t *ct, time_t now)
{
	int64_t exp = -1;

	fmt_str(t, aor->s, aor->len);
	fmt_str(t, ct->key.name.s, ct->key.name.len);
	show_fmt_field(t, &ct->val.val.dict, "contact", 7);
	if (contact_dict_exp(&ct->val.val.dict, &exp) == 0) {
		const char *sn = reg_state_str(exp, now, nats_reap_grace);
		fmt_str(t, sn, (int)strlen(sn));
		fmt_int(t, exp);
		if (exp > 0)
			fmt_int(t, exp - now);
		else
			fmt_empty(t);
	} else {
		fmt_str(t, "expired", 7);            /* fail closed */
		fmt_empty(t);
		fmt_empty(t);
	}
	show_fmt_field(t, &ct->val.val.dict, "q", 1);
	show_fmt_field(t, &ct->val.val.dict, "cseq", 4);
	show_fmt_field(t, &ct->val.val.dict, "callid", 6);
	show_fmt_field(t, &ct->val.val.dict, "ua", 2);
	show_fmt_field(t, &ct->val.val.dict, "sock", 4);
	show_fmt_field(t, &ct->val.val.dict, "received", 8);
	show_fmt_field(t, &ct->val.val.dict, "path", 4);
	show_fmt_field(t, &ct->val.val.dict, "flags", 5);
	show_fmt_field(t, &ct->val.val.dict, "cflags", 6);
	show_fmt_field(t, &ct->val.val.dict, "last_mod", 8);
	fmt_end_record(t);
}

/* json: one object per contact -- id + every scalar field in STORED order,
 * then the computed state / expires_in.  0 ok, -1 OOM. */
static int show_contact_mi(mi_item_t *arr, const cdb_pair_t *ct, time_t now)
{
	mi_item_t *it;
	struct list_head *_;
	cdb_pair_t *fld;
	int64_t exp = -1;

	it = add_mi_object(arr, NULL, 0);
	if (!it)
		return -1;
	if (add_mi_string(it, MI_SSTR("id"),
			ct->key.name.s, ct->key.name.len) < 0)
		return -1;
	list_for_each (_, &ct->val.val.dict) {
		fld = list_entry(_, cdb_pair_t, list);
		if (fld->val.type == CDB_DICT)
			continue;
		if (add_mi_cdb_val(it, &fld->key.name, &fld->val) < 0)
			return -1;
	}
	if (contact_dict_exp(&ct->val.val.dict, &exp) == 0) {
		const char *sn = reg_state_str(exp, now, nats_reap_grace);
		if (add_mi_string(it, MI_SSTR("state"),
				(char *)sn, (int)strlen(sn)) < 0)
			return -1;
		if (exp > 0 &&
		    add_mi_number(it, MI_SSTR("expires_in"),
				(double)(exp - now)) < 0)
			return -1;
	} else if (add_mi_string(it, MI_SSTR("state"),
			MI_SSTR("expired")) < 0) {
		return -1;                           /* fail closed */
	}
	return 0;
}

mi_response_t *mi_nats_reg_show(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *obj, *arr;
	str aor = {NULL, 0};
	char keybuf[NATS_KEY_BUF_SIZE];
	char *key;
	int key_heap = 0;
	kvStore *kv;
	kvEntry *e = NULL;
	const char *val;
	int vlen;
	cdb_dict_t dict;
	struct list_head *_;
	cdb_pair_t *pair;
	int64_t row_exp = 0, schema = 0;
	time_t now = time(NULL);
	int fk, f_eol, f_hdr;
	struct fmt_table ftab;
	int fmt_active = 0;

	(void)async_hdl;
	if (get_mi_string_param(params, "aor", &aor.s, &aor.len) < 0)
		return init_mi_error(400, MI_SSTR("missing aor"));
	if (nats_mi_fmt_param(params, &fk, &f_eol, &f_hdr) < 0)
		return init_mi_error(400, MI_SSTR("bad format (json|csv|txt"
			"[;eol=lf|crlf][;header=0|1])"));

	key = cdbn_pk_target_key(aor.s, aor.len, keybuf, sizeof(keybuf), &key_heap);
	if (!key)
		return init_mi_error(400, MI_SSTR("unencodable aor"));

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		if (key_heap) pkg_free(key);
		return init_mi_error(503, MI_SSTR("NATS unavailable"));
	}
	if (nats_dl.kvStore_Get(&e, kv, key) != NATS_OK) {
		if (key_heap) pkg_free(key);
		return init_mi_error(404, MI_SSTR("no such registration"));
	}
	val = nats_dl.kvEntry_ValueString(e);
	vlen = nats_dl.kvEntry_ValueLen(e);
	if (!val || vlen <= 0) {
		nats_dl.kvEntry_Destroy(e);
		if (key_heap) pkg_free(key);
		return init_mi_error(404,
			MI_SSTR("expired (server delete marker present)"));
	}

	INIT_LIST_HEAD(&dict);
	if (cdbn_safe_json_to_dict(val, vlen, &dict) != 0) {
		nats_dl.kvEntry_Destroy(e);
		if (key_heap) pkg_free(key);
		return init_mi_error(500, MI_SSTR("stored value is not valid JSON"));
	}
	cdbn_row_patch_last_mod_int64(val, vlen, &dict);
	cdbn_contact_field_int64(val, val + vlen, "row_exp", 7, &row_exp);
	cdbn_contact_field_int64(val, val + vlen, "schema_version", 14, &schema);

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto oom;
	if (reg_show_meta(obj, &aor, key, e, row_exp, schema) < 0)
		goto oom;

	if (fk != FMT_JSON) {
		static const char *COLS[] = {"aor", "id", "contact", "state",
			"expires", "expires_in", "q", "cseq", "callid", "ua", "sock",
			"received", "path", "flags", "cflags", "last_mod"};
		fmt_init(&ftab, fk, f_eol, f_hdr, COLS, 16);
		fmt_active = 1;
		arr = NULL;
	} else {
		arr = add_mi_array(obj, MI_SSTR("contacts"));
		if (!arr)
			goto oom;
	}

	list_for_each (_, &dict) {
		struct list_head *__;
		cdb_pair_t *ct;

		pair = list_entry(_, cdb_pair_t, list);
		if (pair->key.name.len != 8 ||
		    memcmp(pair->key.name.s, "contacts", 8) != 0 ||
		    pair->val.type != CDB_DICT)
			continue;
		list_for_each (__, &pair->val.val.dict) {
			ct = list_entry(__, cdb_pair_t, list);
			if (ct->val.type != CDB_DICT)
				continue;
			if (fmt_active)
				show_contact_fmt(&ftab, &aor, ct, now);
			else if (show_contact_mi(arr, ct, now) < 0)
				goto oom;
		}
	}

	if (fmt_active) {
		int blen;
		char *blob = fmt_take(&ftab, &blen);
		fmt_active = 0;
		if (nats_emit_attach_blob(obj, fk, blob, blen) < 0)
			goto oom;
	}

	cdb_free_entries(&dict, osips_pkg_free);
	nats_dl.kvEntry_Destroy(e);
	if (key_heap) pkg_free(key);
	return resp;

oom:
	if (fmt_active)
		fmt_free(&ftab);
	cdb_free_entries(&dict, osips_pkg_free);
	nats_dl.kvEntry_Destroy(e);
	if (key_heap) pkg_free(key);
	if (resp)
		free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("out of memory"));
}
