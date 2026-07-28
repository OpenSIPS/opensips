/*
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define _XOPEN_SOURCE 700  /* See strptime(3) - same idiom as db/db_ut.c */
#define _DEFAULT_SOURCE    /* timegm(3) */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../md5utils.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../pvar.h"

#include "rest_cache.h"

char *rcc_cdb_url;
char *rcc_policy_str;
int   rcc_cache_ttl;
int   rcc_max_body = 65536;
enum rcc_policy rcc_policy = RCC_POLICY_STRICT;

int rcc_ctl_ttl = RCC_CTL_UNSET;

stat_var *rcc_st_hits;
stat_var *rcc_st_misses;
stat_var *rcc_st_stores;
stat_var *rcc_st_skipped;

/*
 * Hit rate over this process's lifetime, in whole percent.
 *
 * Read it with the same care as any cache metric: it is meaningless until there
 * have been lookups, and a low value right after a restart is a cold cache
 * rather than a regression.  Zero lookups reports 0, not a division by zero.
 */
unsigned long rcc_stat_hit_rate(void *unused)
{
	unsigned long h = get_stat_val(rcc_st_hits);
	unsigned long m = get_stat_val(rcc_st_misses);

	return (h + m) ? (100 * h) / (h + m) : 0;
}

static cachedb_funcs rcc_cdbf;
static cachedb_con  *rcc_cdbc;

/* the status codes RFC 9111 lists as cacheable by default */
static int rcc_cacheable_status(int code)
{
	switch (code) {
	case 200: case 203: case 204: case 300: case 301:
	case 308: case 404: case 405: case 410: case 414: case 501:
		return 1;
	default:
		return 0;
	}
}

void rcc_ctl_reset(void)
{
	rcc_ctl_ttl = RCC_CTL_UNSET;
}

int rcc_enabled(void)
{
	return rcc_cdbc != NULL && rcc_policy != RCC_POLICY_OFF;
}

int rcc_init(void)
{
	str url;

	if (!rcc_cdb_url)          /* the feature is off unless a backend is given */
		return 0;

	if (rcc_policy_str) {
		if (!strcasecmp(rcc_policy_str, "off"))
			rcc_policy = RCC_POLICY_OFF;
		else if (!strcasecmp(rcc_policy_str, "strict"))
			rcc_policy = RCC_POLICY_STRICT;
		else if (!strcasecmp(rcc_policy_str, "heuristic"))
			rcc_policy = RCC_POLICY_HEURISTIC;
		else if (!strcasecmp(rcc_policy_str, "force"))
			rcc_policy = RCC_POLICY_FORCE;
		else {
			LM_ERR("bad cache_policy '%s' - expected one of "
				"off, strict, heuristic, force\n", rcc_policy_str);
			return -1;
		}
	}

	/* heuristic and force both fall back to cache_ttl when the origin is
	 * silent (force, additionally, when it objects); without one they would
	 * quietly cache nothing at all, which looks identical to a broken cache */
	if ((rcc_policy == RCC_POLICY_HEURISTIC || rcc_policy == RCC_POLICY_FORCE)
	        && rcc_cache_ttl <= 0) {
		LM_ERR("cache_policy '%s' needs a positive cache_ttl to have any "
			"effect\n", rcc_policy_str);
		return -1;
	}

	if (rcc_max_body <= 0) {
		LM_ERR("cache_max_body must be positive\n");
		return -1;
	}
	if (rcc_max_body > 64 * 1024) {
		/* the encoded entry lives in a fixed RCC_MAX_VALUE (64K + 512)
		 * buffer; a larger cache_max_body would pass startup and then
		 * silently store nothing */
		LM_WARN("cache_max_body %d exceeds the 64K entry buffer - "
			"clamping to %d\n", rcc_max_body, 64 * 1024);
		rcc_max_body = 64 * 1024;
	}

	init_str(&url, rcc_cdb_url);
	if (cachedb_bind_mod(&url, &rcc_cdbf) < 0) {
		LM_ERR("cannot bind the cachedb backend for '%s'\n", rcc_cdb_url);
		return -1;
	}
	if (!rcc_cdbf.get || !rcc_cdbf.set) {
		LM_ERR("the '%s' backend lacks get/set - unusable as a response "
			"cache\n", rcc_cdb_url);
		return -1;
	}
	rcc_cdbc = rcc_cdbf.init(&url);
	if (!rcc_cdbc) {
		LM_ERR("cannot connect to the cachedb backend '%s'\n", rcc_cdb_url);
		return -1;
	}

	LM_INFO("response cache on '%s', policy %s, fallback ttl %ds, max body %d\n",
		rcc_cdb_url, rcc_policy_str ? rcc_policy_str : "strict",
		rcc_cache_ttl, rcc_max_body);
	return 0;
}

void rcc_destroy(void)
{
	if (rcc_cdbc && rcc_cdbf.destroy)
		rcc_cdbf.destroy(rcc_cdbc);
	rcc_cdbc = NULL;
}

/*
 * ---- response header capture -------------------------------------------
 * Called once per header line from header_func(), which otherwise keeps only
 * Content-Type.  Only the directives that decide cacheability are kept.
 */

static int rcc_hdr_is(const char *line, int len, const char *name, int nlen,
                      const char **val, int *vlen)
{
	const char *p;

	if (len <= nlen + 1 || strncasecmp(line, name, nlen) != 0
	        || line[nlen] != ':')
		return 0;

	p = line + nlen + 1;
	len -= nlen + 1;
	while (len > 0 && (*p == ' ' || *p == '\t')) { p++; len--; }
	while (len > 0 && (p[len-1] == '\r' || p[len-1] == '\n'
	                   || p[len-1] == ' ' || p[len-1] == '\t')) len--;

	*val = p;
	*vlen = len;
	return 1;
}

/* case-insensitive needle inside a bounded haystack */
static const char *rcc_memcasemem(const char *h, int hlen, const char *n)
{
	int nlen = strlen(n), i;

	for (i = 0; i + nlen <= hlen; i++)
		if (strncasecmp(h + i, n, nlen) == 0)
			return h + i;
	return NULL;
}

static long rcc_delta_after(const char *p, int left)
{
	while (left > 0 && (*p == ' ' || *p == '=')) { p++; left--; }
	if (left <= 0 || !isdigit((unsigned char)*p))
		return -1;
	return strtol(p, NULL, 10);
}

void rcc_parse_header(struct rcc_resp_hdrs *h, const char *line, int len)
{
	const char *v, *p;
	int vlen;

	if (rcc_hdr_is(line, len, "Cache-Control", 13, &v, &vlen)) {
		h->have_cc = 1;
		if (rcc_memcasemem(v, vlen, "no-store"))  h->cc_no_store = 1;
		if (rcc_memcasemem(v, vlen, "no-cache"))  h->cc_no_cache = 1;
		if (rcc_memcasemem(v, vlen, "private"))   h->cc_private  = 1;
		/* s-maxage wins over max-age; look for it first */
		if ((p = rcc_memcasemem(v, vlen, "s-maxage"))) {
			long d = rcc_delta_after(p + 8, vlen - (int)(p - v) - 8);
			if (d >= 0) { h->maxage = d; h->have_maxage = 1; }
		} else if ((p = rcc_memcasemem(v, vlen, "max-age"))) {
			long d = rcc_delta_after(p + 7, vlen - (int)(p - v) - 7);
			if (d >= 0) { h->maxage = d; h->have_maxage = 1; }
		}
		return;
	}
	if (rcc_hdr_is(line, len, "Expires", 7, &v, &vlen)) {
		char tmp[64];
		struct tm tm;

		if (vlen > 0 && vlen < (int)sizeof(tmp)) {
			memcpy(tmp, v, vlen);
			tmp[vlen] = '\0';
			memset(&tm, 0, sizeof tm);
			/* RFC 9110 preferred form; the obsolete forms are rare enough
			 * that failing to parse them simply means "no Expires" */
			if (strptime(tmp, "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
				h->expires = timegm(&tm);
				h->have_expires = 1;
			}
		}
		return;
	}
	if (rcc_hdr_is(line, len, "Age", 3, &v, &vlen)) {
		if (vlen > 0 && isdigit((unsigned char)*v))
			h->age = strtol(v, NULL, 10);
		return;
	}
	if (rcc_hdr_is(line, len, "Vary", 4, &v, &vlen)) {
		h->have_vary = 1;
		return;
	}
	if (rcc_hdr_is(line, len, "Set-Cookie", 10, &v, &vlen)) {
		h->have_setcookie = 1;
		return;
	}
}

/*
 * ---- cache key ----------------------------------------------------------
 * The pending rest_append_hf() headers MUST take part.  They are process-global
 * and consumed by the next request, so the same URL can legitimately be fetched
 * with different Authorization/Accept/tenant headers and return different
 * bodies; keying on the URL alone would serve one caller's response to another.
 *
 * The headers are lower-cased, trimmed and sorted so that appending the same two
 * headers in the other order still hits the same entry, and the whole thing is
 * hashed - a raw key would put bearer tokens somewhere perf_dump can print them.
 */
static int rcc_hdr_cmp(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

/* publish the provenance string into the caller's variable, if it asked for one */
void rcc_set_source(struct sip_msg *msg, void *source_pv, struct rcc_ctx *ctx)
{
	pv_value_t val;

	if (!source_pv)
		return;
	memset(&val, 0, sizeof val);
	val.flags = PV_VAL_STR;
	val.rs.s = (char *)(ctx->src ? ctx->src : RCC_SRC_MISS);
	val.rs.len = strlen(val.rs.s);
	if (pv_set_value(msg, (pv_spec_p)source_pv, 0, &val) != 0)
		LM_ERR("failed to set the cache source output variable\n");
}

int rcc_prepare(struct rcc_ctx *ctx, const char *method, const str *url,
                struct curl_slist *extra_hdrs)
{
	if (!rcc_enabled() || rcc_ctl_ttl == RCC_CTL_BYPASS) {
		ctx->enabled = 0;
		ctx->src = RCC_SRC_BYPASS;
		rcc_ctl_reset();
		return 0;
	}
	ctx->ctl_ttl = rcc_ctl_ttl;         /* capture before the global is cleared */
	rcc_ctl_reset();
	if (rcc_build_key(ctx, method, url, extra_hdrs) < 0) {
		ctx->enabled = 0;
		return 0;
	}
	ctx->enabled = 1;
	return 1;
}

int rcc_build_key(struct rcc_ctx *ctx, const char *method, const str *url,
                  struct curl_slist *extra_hdrs)
{
	struct curl_slist *it;
	char **hdrs = NULL, *low;
	int n = 0, i, rc = -1;
	str parts[4];
	str joined = {NULL, 0};

	for (it = extra_hdrs; it; it = it->next)
		n++;

	if (n) {
		hdrs = pkg_malloc(n * sizeof *hdrs);
		if (!hdrs) {
			LM_ERR("no more pkg memory for the cache key\n");
			return -1;
		}
		memset(hdrs, 0, n * sizeof *hdrs);
		for (it = extra_hdrs, i = 0; it; it = it->next, i++) {
			int l = it->data ? strlen(it->data) : 0;
			int j;

			low = pkg_malloc(l + 1);
			if (!low)
				goto out;
			/* only the header NAME is case-insensitive; lower-casing the
			 * value too would collapse tokens that differ only in case */
			for (j = 0; j < l; j++) {
				if (j && it->data[j-1] == ':') { /* value starts */
					memcpy(low + j, it->data + j, l - j);
					j = l;
					break;
				}
				low[j] = tolower((unsigned char)it->data[j]);
			}
			low[l] = '\0';
			hdrs[i] = low;
		}
		qsort(hdrs, n, sizeof *hdrs, rcc_hdr_cmp);

		for (i = 0; i < n; i++)
			joined.len += strlen(hdrs[i]) + 1;
		joined.s = pkg_malloc(joined.len);
		if (!joined.s)
			goto out;
		joined.len = 0;
		for (i = 0; i < n; i++) {
			int l = strlen(hdrs[i]);
			memcpy(joined.s + joined.len, hdrs[i], l);
			joined.len += l;
			joined.s[joined.len++] = '\n';
		}
	}

	/* The key covers the method, the URL and the appended headers, but NOT
	 * the request body.  That is safe only because rcc_decide() stores GET
	 * responses and nothing else: a POST key can never collide with a stored
	 * entry because no POST response is ever written.  If storing is ever
	 * extended to POST, the body MUST become part of the key - two POSTs to
	 * one URL differing only in body are different resources. */
	init_str(&parts[0], method);
	parts[1] = *url;
	parts[2] = joined;
	parts[3] = joined;              /* MD5StringArray takes a fixed count */

	MD5StringArray(ctx->keybuf, parts, joined.s ? 3 : 2);
	ctx->keybuf[32] = '\0';
	ctx->key.s = ctx->keybuf;
	ctx->key.len = 32;
	rc = 0;

out:
	if (joined.s)
		pkg_free(joined.s);
	if (hdrs) {
		for (i = 0; i < n; i++)
			if (hdrs[i])
				pkg_free(hdrs[i]);
		pkg_free(hdrs);
	}
	if (rc)
		LM_ERR("no more pkg memory for the cache key\n");
	return rc;
}

/*
 * ---- policy -------------------------------------------------------------
 * Decides whether this response may be stored and for how long, and records a
 * reason when it may not.  The reason is the whole point: a cache that stores
 * nothing because every response says no-store is otherwise indistinguishable
 * from one that is broken or switched off.
 */
static void rcc_deny(struct rcc_ctx *ctx, const char *why)
{
	ctx->store_ttl = 0;
	snprintf(ctx->srcbuf, sizeof ctx->srcbuf, "miss:%s", why);
	ctx->src = ctx->srcbuf;
	update_stat(rcc_st_skipped, 1);
}

void rcc_decide(struct rcc_ctx *ctx, const char *method, int code)
{
	struct rcc_resp_hdrs *h = &ctx->hdrs;
	int forced = (ctx->ctl_ttl > 0);
	long ttl = -1;

	ctx->store_ttl = 0;
	if (!ctx->src)
		ctx->src = RCC_SRC_MISS;
	/* reached only when the cache was consulted and did not serve the call,
	 * so exactly one miss is counted per lookup that went to the origin */
	update_stat(rcc_st_misses, 1);

	/* hard invariants - no policy and no per-call override reaches these */
	if (strcmp(method, "GET") != 0)      { rcc_deny(ctx, "method");  return; }
	if (!rcc_cacheable_status(code))     { rcc_deny(ctx, "status");  return; }
	if (h->have_vary)                    { rcc_deny(ctx, "vary");    return; }

	/* an explicit per-call ttl overrides both the policy and the origin */
	if (forced) {
		ctx->store_ttl = ctx->ctl_ttl;
		ctx->src = RCC_SRC_MISS;
		return;
	}

	if (h->have_setcookie && rcc_policy != RCC_POLICY_FORCE) {
		rcc_deny(ctx, "set-cookie"); return;
	}
	if (h->cc_no_store && rcc_policy != RCC_POLICY_FORCE) {
		rcc_deny(ctx, "no-store");  return;
	}
	if (h->cc_no_cache && rcc_policy != RCC_POLICY_FORCE) {
		rcc_deny(ctx, "no-cache");  return;
	}
	if (h->cc_private && rcc_policy != RCC_POLICY_FORCE) {
		rcc_deny(ctx, "private");   return;
	}

	/* what the origin permits, in precedence order */
	if (h->have_maxage)
		ttl = h->maxage - (h->age > 0 ? h->age : 0);
	else if (h->have_expires)
		ttl = (long)(h->expires - time(NULL));

	if (h->have_maxage || h->have_expires) {
		if (ttl <= 0) {
			/* the origin DID give a lifetime and it has already elapsed
			 * (past Expires, Age beyond max-age, max-age=0).  That is not
			 * silence: RFC 9111 permits heuristic freshness only where no
			 * explicit expiration exists, so heuristic must not resuscitate
			 * an explicitly stale response.  force still may - ignoring the
			 * origin is its contract. */
			if (rcc_policy != RCC_POLICY_FORCE) {
				rcc_deny(ctx, "expired");
				return;
			}
			ttl = rcc_cache_ttl;
		}
	} else {
		/* the origin said nothing at all */
		if (rcc_policy == RCC_POLICY_HEURISTIC || rcc_policy == RCC_POLICY_FORCE)
			ttl = rcc_cache_ttl;
		else {
			rcc_deny(ctx, "silent");
			return;
		}
	}

	if (ttl <= 0) { rcc_deny(ctx, "expired"); return; }

	ctx->store_ttl = (int)ttl;
	ctx->src = RCC_SRC_MISS;
}

/*
 * ---- value encoding -----------------------------------------------------
 *   [u16 code][u16 ctype_len][u64 expires_at][ctype][u32 body_len][body]
 * Length-prefixed and fixed-width up front, so a hit decodes by pointing into
 * the buffer rather than parsing it.
 *
 * expires_at is an absolute wall-clock second, and it is what actually
 * enforces freshness on a read.  The same lifetime is handed to the backend
 * as a TTL, but a backend is not obliged to act on it - cachedb_mongodb, for
 * one, accepts the expiry argument and ignores it - and a cache that silently
 * serves a response for ever is a worse failure than one that does not cache
 * at all.  Eight bytes buys correctness that does not depend on which backend
 * the deployment picked.
 */
#define RCC_HDR_SZ  (2 + 2 + 8 + 4)

static int rcc_encode(char *dst, int dstlen, const str *body, const str *ctype,
                      int code, int ttl)
{
	unsigned short c16, ct16;
	unsigned int b32;
	uint64_t exp;
	int need, ctl = ctype ? ctype->len : 0;

	need = RCC_HDR_SZ + ctl + body->len;
	if (need > dstlen)
		return -1;

	c16  = (unsigned short)code;
	ct16 = (unsigned short)ctl;
	b32  = (unsigned int)body->len;
	exp  = (uint64_t)time(NULL) + (uint64_t)ttl;

	memcpy(dst,      &c16,  2);
	memcpy(dst + 2,  &ct16, 2);
	memcpy(dst + 4,  &exp,  8);
	if (ctl)
		memcpy(dst + 12, ctype->s, ctl);
	memcpy(dst + 12 + ctl, &b32, 4);
	if (body->len)
		memcpy(dst + RCC_HDR_SZ + ctl, body->s, body->len);
	return need;
}

/* returns 0 on a usable entry, -1 on a malformed one, 1 on an expired one */
static int rcc_decode(char *src, int srclen, str *body, str *ctype, int *code)
{
	unsigned short c16, ct16;
	unsigned int b32;
	uint64_t exp;

	if (srclen < RCC_HDR_SZ)
		return -1;
	memcpy(&c16,  src,     2);
	memcpy(&ct16, src + 2, 2);
	memcpy(&exp,  src + 4, 8);
	if (RCC_HDR_SZ + (int)ct16 > srclen)
		return -1;
	memcpy(&b32, src + 12 + ct16, 4);
	if (RCC_HDR_SZ + (int)ct16 + (int)b32 > srclen)
		return -1;

	/* the backend was asked to expire this, but it may not have done so */
	if ((uint64_t)time(NULL) >= exp)
		return 1;

	*code = c16;
	if (ctype) {
		ctype->s   = ct16 ? src + 12 : NULL;
		ctype->len = ct16;
	}
	body->s   = b32 ? src + RCC_HDR_SZ + ct16 : NULL;
	body->len = b32;
	return 0;
}

/*
 * ---- lookup / store -----------------------------------------------------
 */
/*
 * On a hit, @body/@ctype point into a per-process scratch buffer owned by this
 * module and valid until this process's next rcc_lookup().  The caller must NOT
 * free them - it copies them straight into pvars, which take their own copy.
 *
 * Both backend paths land in the same buffer on purpose.  Returning pkg memory
 * from one path and a borrowed pointer from the other is how the first version
 * of this aborted with "freeing dangling pkg pointer": the get_buf path handed
 * back a pointer into static storage and the caller pkg_free()d it.  One
 * provenance, one rule.
 */
static char rcc_scratch[RCC_MAX_VALUE];

int rcc_lookup(struct rcc_ctx *ctx, str *body, str *ctype, int *code)
{
	str val = {NULL, 0};
	int rc, len = 0;

	if (!ctx->enabled)
		return 0;

#ifdef CACHEDB_HAVE_GET_BUF
	/* the core carries the allocation-free endpoint - use it when the backend
	 * in use actually implements it (a core may have it, redis:// may not) */
	if (rcc_cdbf.get_buf && CACHEDB_CAPABILITY(&rcc_cdbf, CACHEDB_CAP_GET_BUF)) {
		unsigned int vlen = 0;

		rc = rcc_cdbf.get_buf(rcc_cdbc, &ctx->key, rcc_scratch,
		                      sizeof rcc_scratch, &vlen, NULL);
		if (rc != 0 || !vlen)
			return 0;
		len = (int)vlen;
	} else
#endif
	{
		rc = rcc_cdbf.get(rcc_cdbc, &ctx->key, &val);
		if (rc < 0 || !val.s || !val.len)
			return 0;
		if (val.len > (int)sizeof rcc_scratch) {
			LM_ERR("cached entry for [%.*s] is %d bytes, larger than the "
				"scratch - ignoring\n", ctx->key.len, ctx->key.s, val.len);
			pkg_free(val.s);
			return 0;
		}
		/* copy out and release immediately, so both paths leave the value in
		 * the same place with the same lifetime */
		memcpy(rcc_scratch, val.s, val.len);
		len = val.len;
		pkg_free(val.s);
	}

	rc = rcc_decode(rcc_scratch, len, body, ctype, code);
	if (rc < 0) {
		LM_ERR("corrupt cache entry for [%.*s] - ignoring\n",
			ctx->key.len, ctx->key.s);
		return 0;
	}
	if (rc > 0) {
		/* the entry outlived its lifetime, so the backend is not enforcing
		 * the TTL we gave it.  Treat it as a miss and refetch. */
		LM_DBG("stale entry for [%.*s] - the backend did not expire it\n",
			ctx->key.len, ctx->key.s);
		return 0;
	}

	ctx->src = RCC_SRC_HIT;
	update_stat(rcc_st_hits, 1);
	return 1;
}

void rcc_store(struct rcc_ctx *ctx, const str *body, const str *ctype, int code)
{
	static char buf[RCC_MAX_VALUE];
	str val;
	int n;

	if (!ctx->enabled || ctx->store_ttl <= 0)
		return;

	if (body->len > rcc_max_body) {
		LM_DBG("response of %d bytes exceeds cache_max_body %d - not stored\n",
			body->len, rcc_max_body);
		snprintf(ctx->srcbuf, sizeof ctx->srcbuf, "miss:oversize");
		ctx->src = ctx->srcbuf;
		update_stat(rcc_st_skipped, 1);
		return;
	}

	n = rcc_encode(buf, sizeof buf, body, ctype, code, ctx->store_ttl);
	if (n < 0) {
		snprintf(ctx->srcbuf, sizeof ctx->srcbuf, "miss:oversize");
		ctx->src = ctx->srcbuf;
		update_stat(rcc_st_skipped, 1);
		return;
	}

	val.s = buf;
	val.len = n;
	if (rcc_cdbf.set(rcc_cdbc, &ctx->key, &val, ctx->store_ttl) < 0) {
		LM_ERR("failed to store the response for [%.*s]\n",
			ctx->key.len, ctx->key.s);
	} else {
		update_stat(rcc_st_stores, 1);
		LM_DBG("stored %d bytes for [%.*s], ttl %ds\n",
			n, ctx->key.len, ctx->key.s, ctx->store_ttl);
	}
}
