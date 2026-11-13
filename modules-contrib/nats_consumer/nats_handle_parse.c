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
 * nats_handle_parse.c -- table-driven parser for the bind-parameter
 * config string.  Builds a freshly-allocated nats_handle_t in SHM.
 *
 * Grammar: pairs := pair ( ';' pair )*
 *          pair  := key '=' value
 *
 * Leading whitespace is trimmed from both key and value.  Trailing
 * whitespace is preserved on values (an explicit quoting scheme can be
 * added later if needed).
 *
 * Unknown keys are rejected as config errors (the forward-compat
 * ("k":"v",...) for forward-compat.  All other syntactic / semantic
 * errors are fatal.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <stddef.h>

#include "nats_handle_parse.h"

/* error strings (borrowed static) */
#define ERR_MISSING_ID      "missing id"
#define ERR_MISSING_STREAM  "missing stream"
#define ERR_MUT_EXCL        "durable and ephemeral are mutually exclusive"
#define ERR_NEED_DUR_EPH    "consumer requires either durable= or ephemeral=1"
#define ERR_BAD_DELIVER     "invalid deliver_policy"
#define ERR_BAD_ACK         "invalid ack_policy"
#define ERR_BAD_REPLAY      "invalid replay_policy"
#define ERR_NEED_SSEQ       "start_seq required with deliver_policy=by_start_seq"
#define ERR_NEED_STIME      "start_time required with deliver_policy=by_start_time"
#define ERR_BAD_DURATION    "invalid duration"
#define ERR_BAD_INT         "invalid integer"
#define ERR_BAD_UINT        "invalid unsigned integer"
#define ERR_BAD_BOOL        "invalid boolean"
#define ERR_BAD_TIME        "invalid RFC3339 timestamp"
#define ERR_DUP_KEY         "duplicate key"
#define ERR_BAD_PAIR        "malformed pair (missing =)"
#define ERR_OOM             "out of memory"
#define ERR_UNKNOWN_KEY     "unknown config key"
#define ERR_SAMPLE_RANGE    "sample_freq out of range 0..100"
#define ERR_RING_POW2       "ring_capacity must be power of two >= 2"
#define ERR_RING_TOO_BIG    "ring_capacity exceeds the maximum (65536)"
/* ~17.7 KB per ring slot -> 65536 slots is already ~1.2 GB of SHM. */
#define NATS_RING_CAPACITY_MAX  65536u
#define ERR_FETCH_BATCH     "fetch_batch out of range 1..4096"
#define ERR_FETCH_TMO       "fetch_timeout_ms out of range 1..60000"
#define ERR_NEG_COUNT       "value must not be negative"

/* ── helpers: trim / case-insensitive compare ─────────────────── */

static inline const char *ltrim(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

static int ieq(const char *a, int alen, const char *b)
{
	int blen = (int)strlen(b);
	int i;
	if (alen != blen) return 0;
	for (i = 0; i < alen; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static int str_dup_shm(str *dst, const char *src, int len)
{
	dst->s = (char *)shm_malloc(len > 0 ? len : 1);
	if (!dst->s) return -1;
	if (len > 0) memcpy(dst->s, src, len);
	dst->len = len;
	return 0;
}

/* ── scalar value parsers ─────────────────────────────────────── */

static int parse_bool(const char *s, int len, int *out)
{
	if (len == 1) {
		if (s[0] == '0') { *out = 0; return 0; }
		if (s[0] == '1') { *out = 1; return 0; }
	}
	if (ieq(s, len, "true") || ieq(s, len, "yes") || ieq(s, len, "on")) {
		*out = 1; return 0;
	}
	if (ieq(s, len, "false") || ieq(s, len, "no") || ieq(s, len, "off")) {
		*out = 0; return 0;
	}
	return -1;
}

static int parse_int(const char *s, int len, int *out)
{
	char buf[32];
	char *end;
	long v;
	if (len <= 0 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';
	errno = 0;
	v = strtol(buf, &end, 10);
	if (errno != 0 || *end != '\0') return -1;
	if (v < INT_MIN || v > INT_MAX) return -1;
	*out = (int)v;
	return 0;
}

static int parse_uint64(const char *s, int len, uint64_t *out)
{
	char buf[32];
	char *end, *q;
	unsigned long long v;
	if (len <= 0 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';
	/* strtoull silently wraps a negative ("-1" -> UINT64_MAX) with no errno.
	 * For an unsigned config field that is a typo/adversarial value, not a
	 * huge count -- reject a leading sign (after optional whitespace). */
	q = buf;
	while (*q == ' ' || *q == '\t') q++;
	if (*q == '-' || *q == '+') return -1;
	errno = 0;
	v = strtoull(buf, &end, 10);
	if (errno != 0 || *end != '\0') return -1;
	*out = (uint64_t)v;
	return 0;
}

static int parse_uint32(const char *s, int len, uint32_t *out)
{
	uint64_t v;
	if (parse_uint64(s, len, &v) < 0) return -1;
	if (v > 0xFFFFFFFFull) return -1;
	*out = (uint32_t)v;
	return 0;
}

/* Duration syntax: <int>(ms|s|m|h|d).
 * Returns milliseconds in *out. */
static int parse_duration_ms(const char *s, int len, int *out)
{
	int i = 0, digits = 0;
	long long v = 0;
	long long mult;

	while (i < len && isdigit((unsigned char)s[i])) {
		v = v * 10 + (s[i] - '0');
		if (v > (long long)INT_MAX) return -1;
		digits++;
		i++;
	}
	if (!digits) return -1;

	if (i == len) {
		/* no suffix -> treat as ms for consistency with spec */
		mult = 1;
	} else if (i + 2 == len && s[i] == 'm' && s[i+1] == 's') {
		mult = 1;
	} else if (i + 1 == len && s[i] == 's') {
		mult = 1000LL;
	} else if (i + 1 == len && s[i] == 'm') {
		mult = 60LL * 1000LL;
	} else if (i + 1 == len && s[i] == 'h') {
		mult = 60LL * 60LL * 1000LL;
	} else if (i + 1 == len && s[i] == 'd') {
		mult = 24LL * 60LL * 60LL * 1000LL;
	} else {
		return -1;
	}

	v *= mult;
	if (v > (long long)INT_MAX || v < 0) return -1;
	*out = (int)v;
	return 0;
}

/* Minimal RFC3339 -> unix_ns parser. Accepts "YYYY-MM-DDThh:mm:ssZ"
 * or "YYYY-MM-DDThh:mm:ss.fffZ" or ...+hh:mm. */
static int parse_rfc3339_ns(const char *s, int len, int64_t *out)
{
	char buf[64];
	struct tm tm;
	time_t tt;
	int frac_ns = 0;
	int tz_off_sec = 0;
	const char *p;
	int pos;

	if (len <= 0 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';

	memset(&tm, 0, sizeof(tm));
	/* require at least "YYYY-MM-DDThh:mm:ss" (19 chars) */
	if (len < 19) return -1;
	if (sscanf(buf, "%4d-%2d-%2dT%2d:%2d:%2d",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
		return -1;
	tm.tm_year -= 1900;
	tm.tm_mon  -= 1;

	pos = 19;
	p = buf + pos;
	if (*p == '.') {
		/* fractional seconds */
		int f = 0, scale = 100000000; /* nanos per 0.1 */
		p++; pos++;
		while (pos < len && isdigit((unsigned char)*p) && scale > 0) {
			f += (*p - '0') * scale;
			scale /= 10;
			p++; pos++;
		}
		/* skip any remaining digits (truncate) */
		while (pos < len && isdigit((unsigned char)*p)) { p++; pos++; }
		frac_ns = f;
	}
	if (pos == len) return -1;       /* must have Z or offset */
	if (*p == 'Z' || *p == 'z') {
		if (pos + 1 != len) return -1;
		tz_off_sec = 0;
	} else if (*p == '+' || *p == '-') {
		int sign = (*p == '+') ? 1 : -1;
		int hh, mm;
		if (pos + 6 != len) return -1;
		if (sscanf(p+1, "%2d:%2d", &hh, &mm) != 2) return -1;
		tz_off_sec = sign * (hh * 3600 + mm * 60);
	} else {
		return -1;
	}

	/* timegm treats tm as UTC -> seconds since epoch */
	tt = timegm(&tm);
	if (tt == (time_t)-1) return -1;
	tt -= tz_off_sec;

	*out = ((int64_t)tt) * 1000000000LL + (int64_t)frac_ns;
	return 0;
}

/* ── enums ────────────────────────────────────────────────────── */

static int parse_deliver_policy(const char *s, int len,
		nats_deliver_policy_e *out)
{
	if (ieq(s, len, "all"))               { *out = NATS_DELIVER_ALL; return 0; }
	if (ieq(s, len, "last"))              { *out = NATS_DELIVER_LAST; return 0; }
	if (ieq(s, len, "new"))               { *out = NATS_DELIVER_NEW; return 0; }
	if (ieq(s, len, "last_per_subject"))  { *out = NATS_DELIVER_LAST_PER_SUBJECT; return 0; }
	if (ieq(s, len, "by_start_seq"))      { *out = NATS_DELIVER_BY_START_SEQ; return 0; }
	if (ieq(s, len, "by_start_time"))     { *out = NATS_DELIVER_BY_START_TIME; return 0; }
	return -1;
}

static int parse_ack_policy(const char *s, int len, nats_ack_policy_e *out)
{
	if (ieq(s, len, "explicit")) { *out = NATS_ACK_EXPLICIT; return 0; }
	if (ieq(s, len, "none"))     { *out = NATS_ACK_NONE; return 0; }
	if (ieq(s, len, "all"))      { *out = NATS_ACK_ALL; return 0; }
	return -1;
}

static int parse_replay_policy(const char *s, int len,
		nats_replay_policy_e *out)
{
	if (ieq(s, len, "instant"))  { *out = NATS_REPLAY_INSTANT; return 0; }
	if (ieq(s, len, "original")) { *out = NATS_REPLAY_ORIGINAL; return 0; }
	return -1;
}

/* ── field flag bits (for duplicate + cross-field detection) ──── */

enum {
	F_ID             = 1<<0,
	F_STREAM         = 1<<1,
	F_DURABLE        = 1<<2,
	F_EPHEMERAL      = 1<<3,
	F_FILTER         = 1<<4,
	F_FILTERS        = 1<<5,
	F_DELIVER        = 1<<6,
	F_START_SEQ      = 1<<7,
	F_START_TIME     = 1<<8,
	F_REPLAY         = 1<<9,
	F_ACK_POLICY     = 1<<10,
	F_ACK_WAIT       = 1<<11,
	F_MAX_DELIVER    = 1<<12,
	F_BACKOFF        = 1<<13,
	F_MAX_ACK_PEND   = 1<<14,
	F_HEADERS_ONLY   = 1<<15,
	F_SAMPLE_FREQ    = 1<<16,
	F_RATE_LIMIT     = 1<<17,
	F_INACTIVE_THR   = 1<<18,
	F_JS_DOMAIN      = 1<<19,
	F_API_PREFIX     = 1<<20,
	F_RING_CAPACITY  = 1<<21,
	F_FETCH_BATCH    = 1<<22,
	F_FETCH_TMO_MS   = 1<<23,
};

/* ── main parser ──────────────────────────────────────────────── */

#define FAIL(_err) do { *err = (_err); goto fail; } while (0)

/* ── key table + per-pair dispatch ─────────────────────────
 *
 * One row per config key: dup-flag, value kind and (for scalars) the
 * target field offset + inclusive range.  Three keys with semantics a
 * kind can't express (durable/ephemeral type selection, ring_capacity
 * power-of-two) are dispatched by flag after the generic decode.  The
 * former 23-branch else-if ladder (CCN 96) is gone; adding a key is
 * now one table row.
 */

struct parse_st {
	uint32_t seen;
	int have_durable;
	int have_ephemeral;
};

enum kv_kind {
	K_STR,        /* str field, shm-duplicated */
	K_INT,        /* int field, range-checked */
	K_UINT32,     /* uint32_t field, range-checked */
	K_UINT64,     /* uint64_t field */
	K_BOOL,       /* int field via parse_bool */
	K_DUR_MS,     /* int field via parse_duration_ms */
	K_TIME_NS,    /* int64 field via parse_rfc3339_ns */
	K_DELIVER,
	K_REPLAY,
	K_ACK,
	K_CUSTOM      /* handled by flag in parse_one_pair */
};

typedef struct kv_ent {
	const char  *name;
	uint32_t     flag;
	enum kv_kind kind;
	size_t       off;          /* offsetof target in nats_handle_t */
	long         min, max;     /* inclusive range (K_INT/K_UINT32) */
	const char  *empty_err;    /* non-NULL: reject empty values */
	const char  *parse_err;    /* decode failure */
	const char  *range_err;    /* out-of-range failure */
} kv_ent_t;

#define HOFF(f) offsetof(nats_handle_t, f)

static const kv_ent_t kv_table[] = {
	{ "id",              F_ID,           K_STR,     HOFF(id),
	  0, 0, ERR_MISSING_ID, ERR_OOM, NULL },
	{ "stream",          F_STREAM,       K_STR,     HOFF(stream),
	  0, 0, ERR_MISSING_STREAM, ERR_OOM, NULL },
	{ "durable",         F_DURABLE,      K_STR,     HOFF(durable),
	  0, 0, ERR_NEED_DUR_EPH, ERR_OOM, NULL },
	{ "ephemeral",       F_EPHEMERAL,    K_CUSTOM,  0,
	  0, 0, NULL, ERR_BAD_BOOL, NULL },
	{ "filter",          F_FILTER,       K_STR,     HOFF(filter),
	  0, 0, NULL, ERR_OOM, NULL },
	{ "filters",         F_FILTERS,      K_STR,     HOFF(filters_csv),
	  0, 0, NULL, ERR_OOM, NULL },
	{ "deliver_policy",  F_DELIVER,      K_DELIVER, HOFF(deliver_policy),
	  0, 0, NULL, ERR_BAD_DELIVER, NULL },
	{ "start_seq",       F_START_SEQ,    K_UINT64,  HOFF(start_seq),
	  0, 0, NULL, ERR_BAD_UINT, NULL },
	{ "start_time",      F_START_TIME,   K_TIME_NS, HOFF(start_time_unix_ns),
	  0, 0, NULL, ERR_BAD_TIME, NULL },
	{ "replay_policy",   F_REPLAY,       K_REPLAY,  HOFF(replay_policy),
	  0, 0, NULL, ERR_BAD_REPLAY, NULL },
	{ "ack_policy",      F_ACK_POLICY,   K_ACK,     HOFF(ack_policy),
	  0, 0, NULL, ERR_BAD_ACK, NULL },
	{ "ack_wait",        F_ACK_WAIT,     K_DUR_MS,  HOFF(ack_wait_ms),
	  0, 0, NULL, ERR_BAD_DURATION, NULL },
	/* Negative counts are config errors now (they used to parse
	 * and silently behave as "unset"). */
	{ "max_deliver",     F_MAX_DELIVER,  K_INT,     HOFF(max_deliver),
	  0, INT_MAX, NULL, ERR_BAD_INT, ERR_NEG_COUNT },
	{ "backoff",         F_BACKOFF,      K_STR,     HOFF(backoff_csv),
	  0, 0, NULL, ERR_OOM, NULL },
	{ "max_ack_pending", F_MAX_ACK_PEND, K_INT,     HOFF(max_ack_pending),
	  0, INT_MAX, NULL, ERR_BAD_INT, ERR_NEG_COUNT },
	{ "headers_only",    F_HEADERS_ONLY, K_BOOL,    HOFF(headers_only),
	  0, 0, NULL, ERR_BAD_BOOL, NULL },
	{ "sample_freq",     F_SAMPLE_FREQ,  K_INT,     HOFF(sample_freq),
	  0, 100, NULL, ERR_BAD_INT, ERR_SAMPLE_RANGE },
	{ "rate_limit",      F_RATE_LIMIT,   K_INT,     HOFF(rate_limit_bps),
	  0, INT_MAX, NULL, ERR_BAD_INT, ERR_NEG_COUNT },
	{ "inactive_threshold", F_INACTIVE_THR, K_DUR_MS, HOFF(inactive_threshold_ms),
	  0, 0, NULL, ERR_BAD_DURATION, NULL },
	{ "js_domain",       F_JS_DOMAIN,    K_STR,     HOFF(js_domain),
	  0, 0, NULL, ERR_OOM, NULL },
	{ "api_prefix",      F_API_PREFIX,   K_STR,     HOFF(api_prefix),
	  0, 0, NULL, ERR_OOM, NULL },
	{ "ring_capacity",   F_RING_CAPACITY, K_CUSTOM, 0,
	  0, 0, NULL, ERR_BAD_UINT, NULL },
	{ "fetch_batch",     F_FETCH_BATCH,  K_UINT32,  HOFF(fetch_batch),
	  1, 4096, NULL, ERR_BAD_UINT, ERR_FETCH_BATCH },
	{ "fetch_timeout_ms", F_FETCH_TMO_MS, K_UINT32, HOFF(fetch_timeout_ms),
	  1, 60000, NULL, ERR_BAD_UINT, ERR_FETCH_TMO },
	{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL }
};

/* Decode a table-typed scalar into its target field; range-check the
 * integer kinds.  Returns 0 or -1 with *err set. */
static int decode_scalar(const kv_ent_t *e, void *fld,
		const char *val, int vallen, const char **err)
{
	switch (e->kind) {
	case K_STR:
		if (str_dup_shm((str *)fld, val, vallen) < 0)
			{ *err = ERR_OOM; return -1; }
		return 0;
	case K_INT: {
		int *ip = (int *)fld;
		if (parse_int(val, vallen, ip) < 0) break;
		if (*ip < (int)e->min || *ip > (int)e->max)
			{ *err = e->range_err; return -1; }
		return 0;
	}
	case K_UINT32: {
		uint32_t *up = (uint32_t *)fld;
		if (parse_uint32(val, vallen, up) < 0) break;
		if (*up < (uint32_t)e->min || *up > (uint32_t)e->max)
			{ *err = e->range_err; return -1; }
		return 0;
	}
	case K_UINT64:
		if (parse_uint64(val, vallen, (uint64_t *)fld) < 0) break;
		return 0;
	case K_BOOL:
		if (parse_bool(val, vallen, (int *)fld) < 0) break;
		return 0;
	case K_DUR_MS:
		if (parse_duration_ms(val, vallen, (int *)fld) < 0) break;
		return 0;
	case K_TIME_NS:
		if (parse_rfc3339_ns(val, vallen, (int64_t *)fld) < 0) break;
		return 0;
	case K_DELIVER:
		if (parse_deliver_policy(val, vallen,
				(nats_deliver_policy_e *)fld) < 0) break;
		return 0;
	case K_REPLAY:
		if (parse_replay_policy(val, vallen,
				(nats_replay_policy_e *)fld) < 0) break;
		return 0;
	case K_ACK:
		if (parse_ack_policy(val, vallen,
				(nats_ack_policy_e *)fld) < 0) break;
		return 0;
	case K_CUSTOM:
		break; /* handled by parse_custom() */
	}
	*err = e->parse_err;
	return -1;
}

/* The two keys a kind can't express: ephemeral (type selection into the
 * parse state, no handle field) and ring_capacity (power-of-two + SHM
 * cap rules). */
static int parse_custom(nats_handle_t *h, struct parse_st *st,
		const kv_ent_t *e, const char *val, int vallen, const char **err)
{
	if (e->flag == F_EPHEMERAL) {
		int b;
		if (parse_bool(val, vallen, &b) < 0)
			{ *err = ERR_BAD_BOOL; return -1; }
		st->have_ephemeral = b;
		return 0;
	}

	/* F_RING_CAPACITY */
	if (parse_uint32(val, vallen, &h->ring_capacity) < 0)
		{ *err = ERR_BAD_UINT; return -1; }
	/* Reject 0/1 and non-power-of-2 now so the registry can trust the
	 * value at bind time without re-validating. */
	if (h->ring_capacity < 2 ||
	    (h->ring_capacity & (h->ring_capacity - 1)) != 0)
		{ *err = ERR_RING_POW2; return -1; }
	/* Cap the capacity: each slot is ~17.7 KB of SHM, so an unbounded
	 * power-of-two (up to 2^31) would let one MI bind request tens of
	 * GB.  65536 slots is ~1.2 GB. */
	if (h->ring_capacity > NATS_RING_CAPACITY_MAX)
		{ *err = ERR_RING_TOO_BIG; return -1; }
	return 0;
}

/* Decode one key=value pair through the table.  Returns 0 on success,
 * -1 with *err set on failure. */
static int parse_one_pair(nats_handle_t *h, struct parse_st *st,
		const char *key, int keylen,
		const char *val, int vallen, const char **err)
{
	const kv_ent_t *e;
	void *fld;

	for (e = kv_table; e->name; e++)
		if (ieq(key, keylen, e->name))
			break;
	if (!e->name) {
		/* Unknown key: a config error.  (The forward-compat
		 * extra_json stash was deleted with the persistence layer
		 * -- nothing consumes extras any more, so
		 * silently accepting typos would only hide
		 * misconfiguration.) */
		*err = ERR_UNKNOWN_KEY;
		return -1;
	}

	if (st->seen & e->flag) { *err = ERR_DUP_KEY; return -1; }
	st->seen |= e->flag;

	if (e->empty_err && vallen == 0) { *err = e->empty_err; return -1; }

	if (e->kind == K_CUSTOM)
		return parse_custom(h, st, e, val, vallen, err);

	fld = (unsigned char *)h + e->off;
	if (decode_scalar(e, fld, val, vallen, err) < 0)
		return -1;
	if (e->flag == F_DURABLE)
		st->have_durable = 1;
	return 0;
}

/* Cross-field rules, applied once all pairs are decoded. */
static int handle_validate(nats_handle_t *h, const struct parse_st *st,
		const char **err)
{
	if (!(st->seen & F_ID) || h->id.len == 0)
		{ *err = ERR_MISSING_ID; return -1; }
	if (!(st->seen & F_STREAM) || h->stream.len == 0)
		{ *err = ERR_MISSING_STREAM; return -1; }

	if (st->have_durable && st->have_ephemeral)
		{ *err = ERR_MUT_EXCL; return -1; }
	if (!st->have_durable && !st->have_ephemeral)
		{ *err = ERR_NEED_DUR_EPH; return -1; }
	h->type = st->have_durable ? NATS_CONSUMER_DURABLE
	                           : NATS_CONSUMER_EPHEMERAL;

	if (h->deliver_policy == NATS_DELIVER_BY_START_SEQ &&
			!(st->seen & F_START_SEQ))
		{ *err = ERR_NEED_SSEQ; return -1; }
	if (h->deliver_policy == NATS_DELIVER_BY_START_TIME &&
			!(st->seen & F_START_TIME))
		{ *err = ERR_NEED_STIME; return -1; }
	return 0;
}

nats_handle_t *nats_handle_parse(const str *config_str, const char **err)
{
	nats_handle_t *h;
	const char *p, *end, *pair_end, *eq;
	const char *key, *val;
	int keylen, vallen;
	struct parse_st st = { 0, 0, 0 };
	static const char *dummy_err = NULL;

	if (!err) err = &dummy_err;
	*err = NULL;

	if (!config_str || !config_str->s || config_str->len <= 0) {
		*err = ERR_MISSING_ID;
		return NULL;
	}

	h = (nats_handle_t *)shm_malloc(sizeof(*h));
	if (!h) { *err = ERR_OOM; return NULL; }
	memset(h, 0, sizeof(*h));

	/* defaults */
	h->type           = NATS_CONSUMER_EPHEMERAL; /* overridden below */
	h->deliver_policy = NATS_DELIVER_ALL;
	h->replay_policy  = NATS_REPLAY_INSTANT;
	h->ack_policy     = NATS_ACK_EXPLICIT;

	p = config_str->s;
	end = p + config_str->len;

	while (p < end) {
		/* skip leading ws + semicolons */
		while (p < end && (*p == ' ' || *p == '\t' || *p == ';'))
			p++;
		if (p >= end) break;

		pair_end = memchr(p, ';', end - p);
		if (!pair_end) pair_end = end;

		key = ltrim(p, pair_end);
		eq = memchr(key, '=', pair_end - key);
		if (!eq) FAIL(ERR_BAD_PAIR);

		/* trim trailing ws from key */
		keylen = (int)(eq - key);
		while (keylen > 0 && (key[keylen-1] == ' ' || key[keylen-1] == '\t'))
			keylen--;
		if (keylen == 0) FAIL(ERR_BAD_PAIR);

		val = eq + 1;
		val = ltrim(val, pair_end);
		vallen = (int)(pair_end - val);
		/* trim trailing ws from value too */
		while (vallen > 0 && (val[vallen-1] == ' ' || val[vallen-1] == '\t'))
			vallen--;

		p = pair_end;

		if (parse_one_pair(h, &st, key, keylen, val, vallen, err) < 0)
			goto fail;
	}

	if (handle_validate(h, &st, err) < 0)
		goto fail;

	return h;

fail:
	nats_handle_free(h);
	return NULL;
}
