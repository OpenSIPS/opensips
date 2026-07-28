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

#ifndef _REST_CACHE_H_
#define _REST_CACHE_H_

#include "../../str.h"
#include "../../cachedb/cachedb.h"
#include "../../statistics.h"
#include <curl/curl.h>

/* what a lookup/store decided, reported to the script and the log */
#define RCC_SRC_BYPASS      "bypass"
#define RCC_SRC_HIT         "hit"
#define RCC_SRC_MISS        "miss"

/* module-wide policy: how far to go beyond what the origin explicitly allows */
enum rcc_policy {
	RCC_POLICY_OFF = 0,   /* never cache                                     */
	RCC_POLICY_STRICT,    /* only what the origin explicitly permits         */
	RCC_POLICY_HEURISTIC, /* also cache when the origin says nothing         */
	RCC_POLICY_FORCE,     /* also cache when the origin says not to          */
};

/* per-call override, set by rest_cache_ctl() for the NEXT request only, in the
 * same "pending state" style the module already uses for header_list */
#define RCC_CTL_UNSET   (-1)   /* no override: module policy applies */
#define RCC_CTL_BYPASS   (0)   /* skip the cache entirely for this call */

/* upper bound on one cached response: header + ctype + body */
#define RCC_MAX_VALUE   (64 * 1024 + 512)

/*
 * The caching directives worth keeping out of a response.  header_func() fills
 * this in as the headers stream past; everything else is still discarded.
 */
struct rcc_resp_hdrs {
	int   have_cc;          /* a Cache-Control header was seen              */
	int   cc_no_store;
	int   cc_no_cache;
	int   cc_private;
	int   have_maxage;      /* s-maxage or max-age was parsed               */
	long  maxage;
	int   have_expires;
	time_t expires;         /* absolute, from the Expires header            */
	long  age;              /* Age header, 0 if absent                      */
	int   have_vary;
	int   have_setcookie;
};

/* everything the cache needs to know about one in-flight request */
struct rcc_ctx {
	int          enabled;       /* cache consulted for this call at all     */
	int          ctl_ttl;       /* per-call rest_cache_ctl(), captured at    */
	                            /* dispatch: -1 none, 0 bypass, >0 force     */
	int          store_ttl;     /* >0 = store for this many seconds         */
	str          key;           /* MD5 hex of method+url+headers            */
	char         keybuf[33];
	const char  *src;           /* provenance string, see RCC_SRC_*         */
	char         srcbuf[32];    /* holds "miss:<reason>"                    */
	struct rcc_resp_hdrs hdrs;
};

extern char *rcc_cdb_url;
extern char *rcc_policy_str;
extern int   rcc_cache_ttl;
extern int   rcc_max_body;
extern enum rcc_policy rcc_policy;

/* module life cycle */
int  rcc_init(void);          /* parse policy, connect the backend          */
void rcc_destroy(void);
int  rcc_enabled(void);       /* a backend is configured and policy != off  */

/* per-call override (rest_cache_ctl), cleared with the header list */
extern int rcc_ctl_ttl;
void rcc_ctl_reset(void);

/*
 * Build the cache key for this request.  @extra_hdrs is the pending
 * rest_append_hf() list - it MUST take part, since the same URL can be fetched
 * with different Authorization/Accept headers and get different answers.
 */
int  rcc_build_key(struct rcc_ctx *ctx, const char *method, const str *url,
                   struct curl_slist *extra_hdrs);

/*
 * Prepare @ctx for a request: decide whether the cache applies, capture the
 * per-call rest_cache_ctl() override, and build the key.  Returns 1 if the
 * cache is engaged (ctx->enabled set), 0 if this call bypasses it entirely.
 * The global override is cleared here, so it never leaks to a later request -
 * which matters for async, whose store runs long after the next call started.
 */
int  rcc_prepare(struct rcc_ctx *ctx, const char *method, const str *url,
                 struct curl_slist *extra_hdrs);

/* returns 1 and fills body/ctype/code on a hit, 0 on a miss */
int  rcc_lookup(struct rcc_ctx *ctx, str *body, str *ctype, int *code);

/* decide from policy + origin headers whether to store, and for how long */
void rcc_decide(struct rcc_ctx *ctx, const char *method, int code);

/* store the response if rcc_decide() allowed it */
void rcc_store(struct rcc_ctx *ctx, const str *body, const str *ctype, int code);

/* statistics - the aggregate view of what source_pv reports per call */
extern stat_var *rcc_st_hits;
extern stat_var *rcc_st_misses;
extern stat_var *rcc_st_stores;
extern stat_var *rcc_st_skipped;
unsigned long rcc_stat_hit_rate(void *unused);

/* publish ctx->src into a script variable (no-op when source_pv is NULL) */
struct sip_msg;
void rcc_set_source(struct sip_msg *msg, void *source_pv, struct rcc_ctx *ctx);

/* one header line, as seen by header_func() */
void rcc_parse_header(struct rcc_resp_hdrs *h, const char *line, int len);

#endif /* _REST_CACHE_H_ */
