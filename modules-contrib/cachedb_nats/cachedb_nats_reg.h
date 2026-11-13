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
 * cachedb_nats_reg.h — registration observability.
 *
 * In usrloc full-sharing-cachedb mode the in-memory urecord is freed after
 * every flush, so usrloc's own MI (ul_dump & friends) is empty BY DESIGN and
 * the only truth about registrations is the KV bucket.  This TU gives
 * operators that view back:
 *
 *   nats_reg_summary [domains=1]   high level: totals + per-domain table
 *   nats_reg_list    [filter]      per-AoR rows with filter/sort/pagination
 *   nats_reg_show    aor=<aor>     every stored attribute of one AoR
 *
 * plus reaper-piggybacked gauges in nats_cdb_stats (the reaper already Gets
 * every key each pass — recording totals there costs nothing extra on the
 * broker and gives monitoring a registration time series every
 * nats_reap_interval seconds).
 *
 * Design invariants:
 * the bucket is the source of truth: MI scans on demand
 *             (kvStore_Keys + Get, the reaper's index-independent pattern);
 *             per-instance incremental gauges cannot represent a shared
 *             multi-writer bucket.
 * "active" == "would be served": expires==0 or expires+grace>now,
 *             identical to the read filter; linger NEVER affects it.
 */

#ifndef CACHEDB_NATS_REG_H
#define CACHEDB_NATS_REG_H

#include <stdint.h>
#include <time.h>

#include "../../mi/mi.h"

#define REG_NO_EXPIRY INT64_MAX

enum reg_cstate { REG_C_ACTIVE = 0, REG_C_EXPIRED = 1, REG_C_PERMANENT = 2 };
enum reg_sortkey { REG_SORT_AOR = 0, REG_SORT_EXPIRY = 1,
                   REG_SORT_CONTACTS = 2, REG_SORT_LAST_MOD = 3 };
enum reg_statef { REG_F_ACTIVE = 0, REG_F_EXPIRED = 1, REG_F_PERMANENT = 2,
                  REG_F_ALL = 3 };

#define REG_LIMIT_DEFAULT 50
#define REG_LIMIT_CAP     200   /* MI datagram size bound */

struct reg_filter {
	char aor_glob[256];
	char domain[192];
	char ua[128];
	char contact[192];
	int  state;                 /* enum reg_statef, default ACTIVE */
	long expiring_within;       /* 0 = off */
	long min_contacts;          /* 0 = off */
	int  sort;                  /* enum reg_sortkey, default AOR */
	int  desc;
	long limit;                 /* default 50, clamped to REG_LIMIT_CAP */
	long offset;
	int  format;                /* enum fmt_kind, default FMT_JSON */
	int  eol_lf;                /* 0=CRLF 1=LF */
	int  header;                /* header record on/off (default 1) */
};

/* One-pass summary of a stored usrloc row (slices point into the doc). */
struct reg_row_info {
	const char *aor; int aor_len;
	int n_contacts, n_active, n_expired, n_perm;
	int64_t soonest_exp;        /* min upcoming (active) expiry, or sentinel */
	int64_t last_mod;           /* max over contacts, 0 if absent */
	int ua_hit, ct_hit;         /* filter needles matched some contact */
};

/* ---- pure helpers (unit-locked in tests/test_reg_*.c) -------------
 *
 * All of these are pure functions on caller-provided memory: no
 * allocation, no logging, no locking, no broker I/O.  Callable from any
 * process context; in production they run in the MI process (the
 * handlers below) and cdbn_reg_row_scan additionally in the dedicated
 * reaper process (pass gauges) — cdbn_reg_page is also reused by the
 * stream/KV introspection handlers (cachedb_nats_kvobs.c). */

/**
 * Classify one contact's expiry per.
 *
 * @param expires  the contact's absolute expiry (0 = permanent).
 * @param now      node-local current time.
 * @param grace    visibility grace (nats_reap_grace).
 * @return REG_C_PERMANENT (expires==0), REG_C_ACTIVE
 *         (expires+grace>now), or REG_C_EXPIRED.
 */
int  cdbn_reg_contact_state(int64_t expires, time_t now, int grace);

/**
 * Extract the domain part of an AoR (the bytes after the LAST '@').
 *
 * @param aor   AoR bytes.
 * @param len   AoR length.
 * @param dom   [out] domain start — borrowed, points INTO @aor.
 * @param dlen  [out] domain length.
 * @return 0 found; -1 when there is no '@' (*dom NULL, *dlen 0).
 */
int  cdbn_reg_domain_of(const char *aor, int len, const char **dom, int *dlen);

/**
 * ASCII-case-insensitive equality of two byte ranges.
 *
 * @param a/alen  first range.   @param b/blen  second range.
 * @return 1 equal (same length, case-folded bytes match), else 0.
 */
int  cdbn_reg_ci_eq(const char *a, int alen, const char *b, int blen);

/**
 * Case-sensitive substring search (naive scan).
 *
 * @param hay/hlen  haystack.   @param nee/nlen  needle.
 * @return 1 when the needle occurs in the haystack; 0 otherwise
 *         (including an empty or over-long needle).
 */
int  cdbn_reg_substr(const char *hay, int hlen, const char *nee, int nlen);

/**
 * Parse the nats_reg_list filter string (';'-separated key=value:
 * aor domain ua contact state sort desc limit offset expiring_within
 * min_contacts header, plus the format/eol keys).
 *
 * @param s    filter bytes (empty input yields pure defaults).
 * @param len  filter length.
 * @param f    [out] caller-owned struct, fully reset first; string
 *             needles are COPIED into its fixed arrays (nothing
 *             borrowed from @s afterwards); limit clamped to
 *             REG_LIMIT_CAP.
 * @return 0 ok, -1 refused (unknown key, bad value, oversize token).
 */
int  cdbn_reg_filter_parse(const char *s, int len, struct reg_filter *f);

/**
 * Compute the page window over @total collected rows.
 *
 * @param total   row count.
 * @param limit   page size.
 * @param offset  requested start.
 * @param start   [out] first index to emit (== total when offset is
 *                past the end).
 * @param count   [out] rows to emit (0 when past the end).
 */
void cdbn_reg_page(long total, long limit, long offset, long *start, long *count);

/**
 * qsort-style comparator for reg_row_info under a sort key.
 * Non-AoR sorts tie-break on the AoR, ALWAYS ascending (the tie-break
 * ignores @desc); the primary key honours @desc.
 *
 * @param a/b   rows to compare.
 * @param sort  enum reg_sortkey.
 * @param desc  1 for descending primary order.
 * @return <0 / 0 / >0 in strcmp style.
 */
int  cdbn_reg_row_cmp(const struct reg_row_info *a, const struct reg_row_info *b,
	int sort, int desc);

/**
 * One-pass scan of a stored usrloc row: per-contact state counts,
 * soonest active expiry, max last_mod, and ua/contact substring hits.
 * Contacts with no parseable integer `expires` (or poison members)
 * count as expired — fail closed, mirroring the read filter.
 *
 * @param json    stored row bytes (need not be NUL-terminated).
 * @param len     row length.
 * @param now     node-local current time.
 * @param grace   visibility grace (nats_reap_grace).
 * @param ua_nee/ua_len  optional `ua` substring needle (NULL/0 = off).
 * @param ct_nee/ct_len  optional `contact` substring needle.
 * @param out     [out] filled summary.  out->aor is a BORROWED slice
 *                pointing INTO @json — valid only while @json lives;
 *                copy it before releasing the document.
 * @return 0 on a scanned usrloc row; -1 for malformed JSON or a
 *         document without a top-level "contacts" object.
 */
int  cdbn_reg_row_scan(const char *json, int len, time_t now, int grace,
	const char *ua_nee, int ua_len, const char *ct_nee, int ct_len,
	struct reg_row_info *out);

/* ---- MI handlers (registered in cachedb_nats.c) -------------------
 *
 * Common contract: run in the MI process handling the command (never
 * SIP workers); block for the duration of the bucket work — summary
 * and list do one O(bucket) value-carrying watch pass over the
 * per-process NATS pool connection (lazily opened on first use), show
 * does a single kvStore_Get.  Internal scratch is libc heap, released
 * before returning.  The returned mi_response_t (result or
 * init_mi_error) is owned and freed by the MI framework after sending.
 * @async_hdl is unused (synchronous handlers).  No locking taken. */

/**
 * nats_reg_summary [domains=1] [format=...] — bucket-wide totals (+
 * optional per-domain table, capped at 64 domains).
 *
 * @param params     MI params: optional int `domains`, string `format`.
 * @param async_hdl  unused.
 * @return MI result object; error responses: 400 bad format, 503 NATS
 *         unavailable, 500 OOM.
 */
mi_response_t *mi_nats_reg_summary(const mi_params_t *params,
	struct mi_handler *async_hdl);

/**
 * nats_reg_list [filter=...] — per-AoR rows with filter / sort /
 * pagination (collection capped at 100k rows; page at REG_LIMIT_CAP).
 *
 * @param params     MI params: optional string `filter`
 *                   (cdbn_reg_filter_parse grammar).
 * @param async_hdl  unused.
 * @return MI result object; error responses: 400 bad filter, 503 NATS
 *         unavailable, 500 OOM.
 */
mi_response_t *mi_nats_reg_list(const mi_params_t *params,
	struct mi_handler *async_hdl);

/**
 * nats_reg_show aor=<aor> [format=...] — every stored attribute of one
 * AoR (single Get; the row is parsed via cdbn_safe_json_to_dict with
 * the int64 last_mod patch applied).
 *
 * @param params     MI params: required string `aor`, optional `format`.
 * @param async_hdl  unused.
 * @return MI result object; error responses: 400 missing aor / bad
 *         format / unencodable aor, 404 no such registration or delete
 *         marker, 500 bad stored JSON or OOM, 503 NATS unavailable.
 */
mi_response_t *mi_nats_reg_show(const mi_params_t *params,
	struct mi_handler *async_hdl);

#endif /* CACHEDB_NATS_REG_H */
