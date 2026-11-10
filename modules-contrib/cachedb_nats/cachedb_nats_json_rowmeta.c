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
 */

/*
 * cachedb_nats_json_rowmeta.c — usrloc row-metadata denormalization for the
 * NATS-backed location service.  This TU owns the
 * cachedb_nats-private, usrloc-row-shaped transforms that run over the MERGED
 * document on the update() path — recomputing the `row_exp` / `schema_version`
 * top-level peers from the merged contact set.  It is kept separate from the
 * generic single-pass merge (cachedb_nats_json.c) and the cdb-dict serializer
 * (cachedb_nats_json_ser.c) so that usrloc-specific row semantics never leak
 * into the paths shared by other cachedb_nats consumers.  Built on the shared
 * iterative JSON walkers (cdbn_skip_ws/cdbn_parse_json_string/cdbn_skip_json_value) and the
 * json_sink_t serializer declared in cachedb_nats_json_internal.h.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../mem/mem.h"
#include "../../lib/osips_malloc.h"
#include "../../cachedb/cachedb_dict.h"
#include "cachedb_nats_json_internal.h"

/* ------------------------------------------------------------------ */
/*   Reject-at-write NUL hygiene                                       */
/* ------------------------------------------------------------------ */

/* An OpenSIPS str is length-based, so a 0x00 byte is reachable in a
 * contact field (ua/attr/...).  Such a value cannot round-trip: the reader is
 * cJSON_Parse + str.len = strlen(valuestring), so an interior NUL truncates
 * the value (silent corruption).  Returns 1 if @s carries a raw 0x00 OR the
 * 6-byte JSON escape "\u0000" (which cJSON decodes to 0x00); else 0.  Fail
 * closed: a value embedding the literal escape is conservatively refused (a
 * real SIP UA/attr never carries it). */
static int field_has_nul(const char *s, int len)
{
	int i;

	if (!s || len <= 0)
		return 0;
	for (i = 0; i < len; i++) {
		if (s[i] == '\0')
			return 1;                       /* raw 0x00 byte */
		/* escaped JSON NUL: '\' 'u' '0' '0' '0' '0' (decodes to 0x00) */
		if (s[i] == '\\' && i + 5 < len &&
		    s[i+1] == 'u' &&
		    s[i+2] == '0' && s[i+3] == '0' &&
		    s[i+4] == '0' && s[i+5] == '0')
			return 1;
	}
	return 0;
}

/* Recurse the incoming update dict (usrloc nests each contact's fields under
 * contacts.<id>, so a NUL can sit at any depth); return 1 if any CDB_STR field
 * value carries an embedded NUL.  Run before any merge / kvStore op so the save
 * can be refused with no partial row. */
int cdbn_dict_has_nul_field(const cdb_dict_t *dict)
{
	struct list_head *pos;
	cdb_pair_t *pair;

	if (!dict)
		return 0;
	list_for_each(pos, dict) {
		pair = list_entry(pos, cdb_pair_t, list);
		if (pair->unset)
			continue;
		switch (pair->val.type) {
		case CDB_STR:
			if (field_has_nul(pair->val.val.st.s,
					pair->val.val.st.len))
				return 1;
			break;
		case CDB_DICT:
			if (cdbn_dict_has_nul_field(&pair->val.val.dict))
				return 1;
			break;
		default:
			break;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*   Row_exp / schema_version denormalization                          */
/* ------------------------------------------------------------------ */

/* Parse a bare JSON integer (optional leading '-', then digits) in [p,end).
 * On success sets *out and returns the position just past the number; returns
 * NULL if there is no integer at p, or it would overflow int64.  Leading
 * whitespace must already be skipped.  Fractions/exponents are rejected — a
 * usrloc `expires` is always an integer epoch; anything else is "not a number"
 * and the caller treats the contact as having no usable expiry. */
static const char *json_parse_int64(const char *p, const char *end,
	int64_t *out)
{
	int neg = 0;
	uint64_t mag = 0;

	if (p >= end)
		return NULL;
	if (*p == '-') { neg = 1; p++; }
	if (p >= end || *p < '0' || *p > '9')
		return NULL;
	for (; p < end && *p >= '0' && *p <= '9'; p++) {
		uint64_t d = (uint64_t)(*p - '0');
		/* int64 range: |min| = 2^63, max = 2^63 - 1. */
		uint64_t lim = neg ? 9223372036854775808ULL
				   : 9223372036854775807ULL;
		if (mag > (lim - d) / 10)
			return NULL;          /* would overflow int64 */
		mag = mag * 10 + d;
	}
	/* 2^63 is INT64_MIN itself: negating (int64_t)2^63 would overflow */
	if (neg)
		*out = mag > (uint64_t)INT64_MAX ? INT64_MIN : -(int64_t)mag;
	else
		*out = (int64_t)mag;
	return p;
}

/* row_exp denormalization: the earliest time the row
 * needs reaper attention.  0 is the "permanent / never auto-expire" sentinel
 * — if ANY contact is permanent (expires==0) the whole row is permanent.  An
 * empty/NULL set yields 0.  Otherwise the minimum (earliest) expiry.  int64
 * throughout: no int32 clamp, so post-2038 epochs survive.  Only 0 is the
 * sentinel; a negative (already-past) expiry is a real candidate value. */
static int64_t row_exp_min(const int64_t *exp, int n)
{
	int64_t m = 0;
	int i, seen = 0;

	if (!exp || n <= 0)
		return 0;
	for (i = 0; i < n; i++) {
		if (exp[i] == 0)
			return 0;             /* permanent contact => permanent row */
		if (!seen || exp[i] < m) {
			m = exp[i];
			seen = 1;
		}
	}
	return seen ? m : 0;
}

/* Find the integer-valued field @fname (length @flen) within one contact-object
 * slice [vstart,vend).  Sets *out and returns 0 on success; returns -1 if the
 * slice is not an object, or the field is absent / not an integer.  Shared by
 * the row_exp `expires` scan (write side) and the int64 `last_mod` post-patch
 * (read side). */
int cdbn_contact_field_int64(const char *vstart, const char *vend,
	const char *fname, int flen, int64_t *out)
{
	const char *p = cdbn_skip_ws(vstart, vend);

	if (p >= vend || *p != '{')
		return -1;
	p++;
	while (p < vend) {
		const char *name, *vs;
		int nlen;

		p = cdbn_skip_ws(p, vend);
		if (p >= vend)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }

		p = cdbn_parse_json_string(p, vend, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, vend);
		if (p >= vend || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, vend);
		vs = p;
		if (nlen == flen && memcmp(name, fname, flen) == 0) {
			int64_t v;
			if (json_parse_int64(vs, vend, &v)) {
				*out = v;
				return 0;
			}
			/* present but not an integer — keep scanning (no dup key
			 * expected, but be tolerant); fall through to skip. */
		}
		p = cdbn_skip_json_value(p, vend);
		if (!p)
			return -1;
	}
	return -1;
}

/* row_exp's per-contact `expires` accessor (write side).  A contact with no
 * usable expiry contributes nothing to row_exp; fail-closed read handling of a
 * poison/absent expiry happens on the read path. */
int cdbn_contact_expires(const char *vstart, const char *vend, int64_t *out)
{
	return cdbn_contact_field_int64(vstart, vend, "expires", 7, out);
}

/* Collect every contact's integer `expires` from a "contacts" object slice
 * [vstart,vend) into a fresh pkg array (caller pkg_frees *out_arr).
 * Returns 0 on success (possibly 0 entries), -1 on malformed input. */
static int row_collect_expiries(const char *vstart, const char *vend,
	int64_t **out_arr, int *out_n)
{
	const char *p = cdbn_skip_ws(vstart, vend);
	int64_t *arr = NULL;
	int n = 0, cap = 0;

	*out_arr = NULL;
	*out_n = 0;
	if (p >= vend || *p != '{')
		return -1;
	p++;
	while (p < vend) {
		const char *name, *cvs;
		int nlen;
		int64_t e;

		p = cdbn_skip_ws(p, vend);
		if (p >= vend) { pkg_free(arr); return -1; }
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }

		p = cdbn_parse_json_string(p, vend, &name, &nlen); /* contact subkey */
		if (!p) { pkg_free(arr); return -1; }
		p = cdbn_skip_ws(p, vend);
		if (p >= vend || *p != ':') { pkg_free(arr); return -1; }
		p++;
		p = cdbn_skip_ws(p, vend);
		cvs = p;
		p = cdbn_skip_json_value(p, vend);
		if (!p) { pkg_free(arr); return -1; }

		if (cdbn_contact_expires(cvs, p, &e) == 0) {
			if (n == cap) {
				int ncap = cap ? cap * 2 : 8;
				int64_t *na = pkg_realloc(arr, ncap * sizeof(*na));
				if (!na) { pkg_free(arr); return -1; }
				arr = na;
				cap = ncap;
			}
			arr[n++] = e;
		}
	}
	*out_arr = arr;
	*out_n = n;
	return 0;
}

/* Recompute the cachedb_nats-private `row_exp` / `schema_version` top-level
 * peers over the merged contact set.
 *
 * Returns a fresh pkg_malloc'd document (caller pkg_frees):
 *   - usrloc row (has a top-level "contacts" object): every top-level field is
 *     copied through except any stale "row_exp"/"schema_version", which are
 *     re-emitted fresh (row_exp from min(expires), schema_version=1).
 *   - non-usrloc document (no top-level "contacts"): returned byte-for-byte
 *     unchanged, so other cachedb_nats consumers are never disturbed.
 * Returns NULL on malformed input or OOM. */
/* pass-1 helper: remember the span of the top-level "contacts"
 * object (last occurrence wins, matching the old scan). */
struct find_contacts_ctx {
	const char *vs, *ve;
};

static int find_contacts_cb(const char *name, int nlen,
	const char *vstart, const char *vend, void *ud)
{
	struct find_contacts_ctx *c = ud;

	if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
		c->vs = vstart;
		c->ve = vend;
	}
	return 0;
}

/* pass-2 helper: copy every top-level field through except the
 * private metadata peers (freshly recomputed by the caller). */
struct copy_minus_meta_ctx {
	json_sink_t *s;
	int          first;
};

static int copy_minus_meta_cb(const char *name, int nlen,
	const char *vstart, const char *vend, void *ud)
{
	struct copy_minus_meta_ctx *c = ud;

	if ((nlen == 7 && memcmp(name, "row_exp", 7) == 0) ||
	    (nlen == 14 && memcmp(name, "schema_version", 14) == 0))
		return 0;            /* drop stale private peer */
	if (!c->first && cdbn_sink_putc(c->s, ',') < 0)
		return -1;
	c->first = 0;
	if (cdbn_sink_emit_raw_string(c->s, name, nlen) < 0)
		return -1;
	if (cdbn_sink_putc(c->s, ':') < 0)
		return -1;
	if (cdbn_sink_write(c->s, vstart, (int)(vend - vstart)) < 0)
		return -1;
	return 0;
}

char *cdbn_row_finalize_metadata(const char *json, int len, int *out_len,
	int64_t *out_row_exp, int *out_n_contacts, int *out_all_same)
{
	const char *c_vs = NULL, *c_ve = NULL;
	int64_t *exps = NULL;
	int n_exp = 0, first = 1;
	int64_t row_exp;
	json_sink_t s;

	/* Default the eligibility out-params to "ineligible" (no TTL) so every
	 * early/error return leaves the caller with a safe value. */
	if (out_row_exp)     *out_row_exp = 0;
	if (out_n_contacts)  *out_n_contacts = 0;
	if (out_all_same)    *out_all_same = 0;

	if (!json || len <= 0)
		return NULL;

	/* Pass 1: locate the top-level "contacts" object. */
	{
		struct find_contacts_ctx fc = { NULL, NULL };
		if (cdbn_json_foreach_top_field(json, len,
				find_contacts_cb, &fc) < 0)
			return NULL;
		c_vs = fc.vs;
		c_ve = fc.ve;
	}

	/* Non-usrloc document: return verbatim, never re-shape it. */
	if (!c_vs) {
		char *copy = pkg_malloc(len + 1);
		if (!copy)
			return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (out_len)
			*out_len = len;
		return copy;
	}

	if (row_collect_expiries(c_vs, c_ve, &exps, &n_exp) < 0)
		return NULL;
	row_exp = row_exp_min(exps, n_exp);

	/*: per-message-TTL eligibility inputs.  A row gets a TTL only when
	 * it is a single contact OR all contacts share one expiry (else a min-expiry
	 * TTL would expire siblings early).  all_same is computed over the same
	 * expiry array used for row_exp. */
	if (out_row_exp || out_n_contacts || out_all_same) {
		int i, all_same = 1;
		for (i = 1; i < n_exp; i++)
			if (exps[i] != exps[0]) { all_same = 0; break; }
		if (out_row_exp)    *out_row_exp = row_exp;
		if (out_n_contacts) *out_n_contacts = n_exp;
		if (out_all_same)   *out_all_same = (n_exp <= 1) ? 1 : all_same;
	}
	pkg_free(exps);

	/* Pass 2: copy through every top-level field except the private peers,
	 * then append freshly computed row_exp + schema_version. */
	if (cdbn_sink_init(&s, len + 64) < 0)
		return NULL;
	if (cdbn_sink_putc(&s, '{') < 0)
		goto fail;
	{
		struct copy_minus_meta_ctx cm = { &s, 1 };
		if (cdbn_json_foreach_top_field(json, len,
				copy_minus_meta_cb, &cm) < 0)
			goto fail;
		first = cm.first;
	}
	if (!first && cdbn_sink_putc(&s, ',') < 0)
		goto fail;
	if (cdbn_sink_write(&s, "\"row_exp\":", 10) < 0)
		goto fail;
	if (cdbn_sink_emit_int(&s, row_exp) < 0)
		goto fail;
	if (cdbn_sink_write(&s, ",\"schema_version\":1", 19) < 0)
		goto fail;
	if (cdbn_sink_putc(&s, '}') < 0)
		goto fail;
	return cdbn_sink_take(&s, out_len);

fail:
	pkg_free(s.buf);
	return NULL;
}

/* ------------------------------------------------------------------ */
/*   Int64 last_mod read seam                                         */
/* ------------------------------------------------------------------ */

/* Locate the raw JSON slice of the contact whose id == [id,id_len] within the
 * "contacts" object slice [c_vs,c_ve).  Contact ids are base64(matchkey), so
 * they are JSON-escape-free and a byte compare against the raw (un-decoded) key
 * is exact.  Returns 0 + [*out_vs,*out_ve) on success, -1 if not found. */
static int raw_find_contact(const char *c_vs, const char *c_ve,
	const char *id, int id_len, const char **out_vs, const char **out_ve)
{
	const char *p = cdbn_skip_ws(c_vs, c_ve);

	if (p >= c_ve || *p != '{')
		return -1;
	p++;
	while (p < c_ve) {
		const char *name, *vs;
		int nlen;

		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve)
			return -1;
		if (*p == '}')
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
		if (nlen == id_len && memcmp(name, id, id_len) == 0) {
			*out_vs = vs;
			*out_ve = p;
			return 0;
		}
	}
	return -1;
}

/*: the shared cdb_json_to_dict clamps every
 * JSON number to CDB_INT32 (cJSON valueint -> INT_MAX), silently narrowing a
 * `last_mod` (a usrloc CDB_INT64, read as i64) that exceeds INT32_MAX.  Re-parse
 * `last_mod` as int64 from the raw row JSON and overwrite each contact's
 * `last_mod` pair in @row_dict to CDB_INT64 with the true value.  Only last_mod
 * is widened — `expires` stays int32-bounded at the usrloc boundary.
 * A no-op for a document without a top-level "contacts" object (non-usrloc row)
 * and for any contact whose last_mod is absent / non-integer (left untouched). */
void cdbn_row_patch_last_mod_int64(const char *json, int len, cdb_dict_t *row_dict)
{
	const char *c_vs = NULL, *c_ve = NULL;
	struct list_head *pos;
	cdb_pair_t *pair;

	if (!json || len <= 0 || !row_dict)
		return;

	/* locate the raw top-level "contacts" object slice */
	{
		struct find_contacts_ctx fc = { NULL, NULL };
		if (cdbn_json_foreach_top_field(json, len,
				find_contacts_cb, &fc) < 0)
			return;
		c_vs = fc.vs;
		c_ve = fc.ve;
	}
	if (!c_vs)
		return;            /* not a usrloc row */

	/* walk the parsed "contacts" dict; patch each contact's last_mod */
	list_for_each(pos, row_dict) {
		struct list_head *cpos;

		pair = list_entry(pos, cdb_pair_t, list);
		if (pair->val.type != CDB_DICT)
			continue;
		if (pair->key.name.len != 8 ||
		    memcmp(pair->key.name.s, "contacts", 8) != 0)
			continue;

		list_for_each(cpos, &pair->val.val.dict) {
			cdb_pair_t *cpair = list_entry(cpos, cdb_pair_t, list);
			const char *rc_vs, *rc_ve;
			struct list_head *fpos;
			int64_t lm;

			if (cpair->val.type != CDB_DICT)
				continue;
			if (raw_find_contact(c_vs, c_ve, cpair->key.name.s,
					cpair->key.name.len, &rc_vs, &rc_ve) != 0)
				continue;
			if (cdbn_contact_field_int64(rc_vs, rc_ve, "last_mod", 8, &lm) != 0)
				continue;   /* absent / non-integer: leave the pair as-is */

			list_for_each(fpos, &cpair->val.val.dict) {
				cdb_pair_t *fp = list_entry(fpos, cdb_pair_t, list);
				if (fp->key.name.len == 8 &&
				    memcmp(fp->key.name.s, "last_mod", 8) == 0) {
					fp->val.type = CDB_INT64;
					fp->val.val.i64 = lm;
					if (lm > (int64_t)INT32_MAX)  /* observe the preserved int64 from the production READ (not `nats kv`) — the int32-clamp case */
						LM_DBG("preserved post-2038 last_mod=%lld\n", (long long)lm);
					break;
				}
			}
		}
		break;             /* only one top-level "contacts" */
	}
}

/* ------------------------------------------------------------------ */
/*   Fail-closed poison classification                                 */
/* ------------------------------------------------------------------ */

/* Classify a stored KV value on read:
 *   NATS_VAL_EMPTY  — zero-length / all-whitespace: a server-side delete
 *                     marker; treat the AoR as absent (no error).
 *   NATS_VAL_OBJECT — first non-whitespace byte is '{': parse it.
 *   NATS_VAL_POISON — non-empty and not a JSON object (null / string / number
 *                     / array / garbage): a hard integrity error.  The current
 *                     `data[0]=='{'` gate masks this as an empty AoR — a silent
 *                     deregistration a stale node / co-writer / attacker could
 *                     plant — so alarms + counts instead. */
int cdbn_value_classify(const char *data, int len)
{
	const char *p, *end;

	if (!data || len <= 0)
		return NATS_VAL_EMPTY;
	p = data;
	end = data + len;
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	if (p >= end)
		return NATS_VAL_EMPTY;        /* all whitespace == delete marker */
	return (*p == '{') ? NATS_VAL_OBJECT : NATS_VAL_POISON;
}

/* ------------------------------------------------------------------ */
/*   Strip cachedb_nats-private top-level peers */
/* ------------------------------------------------------------------ */

/* True for the cachedb_nats-private top-level peers usrloc must never see. */
static int is_private_top_key(const char *name, int len)
{
	return (len == 7  && memcmp(name, "row_exp", 7) == 0) ||
	       (len == 14 && memcmp(name, "schema_version", 14) == 0);
}

/* Free one removed pair completely (it is no longer in any dict, so
 * cdb_free_rows will not reach it).  row_exp/schema_version are normally
 * CDB_INT32, but a crafted-yet-valid object could carry them as a string or a
 * nested dict (the poison check only gates the top-level value type), so free by type. */
static void free_one_pair(cdb_pair_t *p)
{
	switch (p->val.type) {
	case CDB_DICT:
		cdb_free_entries(&p->val.val.dict, osips_pkg_free);
		break;
	case CDB_STR:
		if (p->val.val.st.s)
			osips_pkg_free(p->val.val.st.s);
		break;
	default:
		break;
	}
	pkg_free(p);
}

/*: the cdb_row_t handed to usrloc must be
 * exactly {contacts, aorhash}.  Strip the cachedb_nats-private top-level peers
 * (row_exp, schema_version) at row assembly — they are top-level peers, not
 * members of any contact subdict, so this is a top-level walk.  Safe against
 * removal mid-iteration (list_for_each_safe). */
void cdbn_row_strip_private_keys(cdb_dict_t *row_dict)
{
	struct list_head *pos, *tmp;

	if (!row_dict)
		return;
	list_for_each_safe(pos, tmp, row_dict) {
		cdb_pair_t *pair = list_entry(pos, cdb_pair_t, list);
		if (is_private_top_key(pair->key.name.s, pair->key.name.len)) {
			list_del(&pair->list);
			free_one_pair(pair);
		}
	}
}

/* ------------------------------------------------------------------ */
/*   Skew-safe write-side expiry hygiene                               */
/* ------------------------------------------------------------------ */

/* Upper bound on touched-expired subkeys dropped in one update.  An update that
 * sets more than this many already-expired contacts (pathological) leaves the
 * excess for the reaper — never a correctness loss, only deferred. */
#define NATS_MAX_DROP_IDS 256

/* A contact is already-expired when its absolute `expires` plus
 * the skew grace S has passed node-local `now`.  expires==0 is permanent. */
static int contact_is_expired(int64_t expires, time_t now, int grace)
{
	return expires != 0 && (expires + (int64_t)grace) <= (int64_t)now;
}

/* Extract a set-contact pair's own `expires` (CDB_INT32/INT64) from its value
 * dict.  Returns 0 + *out, or -1 if absent / not an integer. */
static int pair_contact_expires(const cdb_pair_t *p, int64_t *out)
{
	struct list_head *pos;

	if (p->val.type != CDB_DICT)
		return -1;
	list_for_each(pos, &p->val.val.dict) {
		cdb_pair_t *f = list_entry(pos, cdb_pair_t, list);
		if (f->key.name.len != 7 || memcmp(f->key.name.s, "expires", 7) != 0)
			continue;
		if (f->val.type == CDB_INT32) { *out = f->val.val.i32; return 0; }
		if (f->val.type == CDB_INT64) { *out = f->val.val.i64; return 0; }
		return -1;
	}
	return -1;
}

/* incremental row_exp / TTL-eligibility accumulator -- replaces the
 * pkg expiry array when collection happens inside the emit walk.  Semantics
 * mirror row_exp_min + the all_same scan: any expires==0 makes the row
 * permanent; all_same compares every collected value (zeros included). */
struct row_exp_acc {
	int64_t min, first;
	int     n, seen_zero, seen_min, mismatch;
};

static void row_exp_acc_add(struct row_exp_acc *a, int64_t e)
{
	if (a->n == 0)
		a->first = e;
	else if (e != a->first)
		a->mismatch = 1;
	if (e == 0)
		a->seen_zero = 1;
	else if (!a->seen_min || e < a->min) {
		a->min = e;
		a->seen_min = 1;
	}
	a->n++;
}

/* Collect-only arm of the fold: fold every contact's integer
 * `expires` in [cvs,cve) into @acc without emitting -- used when the
 * drop set is empty so the caller can copy the slice in ONE write. */
static int acc_collect_expiries(const char *cvs, const char *cve,
	struct row_exp_acc *acc)
{
	const char *p = cdbn_skip_ws(cvs, cve);

	if (p >= cve || *p != '{')
		return -1;
	p++;
	while (p < cve) {
		const char *name, *vs;
		int nlen;
		int64_t e;

		p = cdbn_skip_ws(p, cve);
		if (p >= cve)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, cve, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, cve);
		if (p >= cve || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, cve);
		vs = p;
		p = cdbn_skip_json_value(p, cve);
		if (!p)
			return -1;
		if (cdbn_contact_expires(vs, p, &e) == 0)
			row_exp_acc_add(acc, e);
	}
	return 0;
}

/* Rewrite a "contacts" object slice [cvs,cve), dropping any subkey in @ids.
 * When @acc is non-NULL, every SURVIVING contact's integer `expires` is
 * folded into it (the single-walk row_exp collection). */
static int emit_contacts_minus(json_sink_t *s, const char *cvs, const char *cve,
	const char **ids, const int *id_lens, int n_ids, struct row_exp_acc *acc)
{
	const char *p = cdbn_skip_ws(cvs, cve), *end = cve;
	int first = 1;

	if (p >= end || *p != '{') return -1;
	if (cdbn_sink_putc(s, '{') < 0) return -1;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen, i, drop = 0;

		p = cdbn_skip_ws(p, end);
		if (p >= end) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p) return -1;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':') return -1;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p) return -1;
		for (i = 0; i < n_ids; i++)
			if (nlen == id_lens[i] && memcmp(name, ids[i], nlen) == 0) { drop = 1; break; }
		if (drop) continue;
		if (acc) {
			int64_t e;
			if (cdbn_contact_expires(vs, p, &e) == 0)
				row_exp_acc_add(acc, e);
		}
		if (!first && cdbn_sink_putc(s, ',') < 0) return -1;
		first = 0;
		if (cdbn_sink_emit_raw_string(s, name, nlen) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (cdbn_sink_write(s, vs, (int)(p - vs)) < 0) return -1;
	}
	if (cdbn_sink_putc(s, '}') < 0) return -1;
	return 0;
}

/* Shared top-level rebuild walk.  Copies @json through, rewriting
 * every top-level "contacts" object minus the @ids subkeys.  When @usrloc
 * is set (the fold: document known to carry a "contacts" object), stale
 * "row_exp"/"schema_version" peers are skipped and fresh ones are appended
 * from @acc; @acc also receives every surviving contact's expires (reset
 * per "contacts" occurrence -- last one wins, like the reference's
 * find_contacts_cb).  With @usrloc unset (the standalone hygiene pass) the
 * peers pass through untouched and nothing is appended.
 * Returns a fresh pkg doc (caller pkg_frees), NULL on error/OOM. */
static char *row_emit_rebuild(const char *json, int len,
	const char **ids, const int *id_lens, int n_ids,
	int usrloc, struct row_exp_acc *acc, int *out_len)
{
	const char *p, *end;
	json_sink_t s;
	int first = 1;

	if (!json || len <= 0) return NULL;
	end = json + len;
	p = cdbn_skip_ws(json, end);
	if (p >= end || *p != '{') return NULL;
	if (cdbn_sink_init(&s, len + (usrloc ? 64 : 16)) < 0) return NULL;
	if (cdbn_sink_putc(&s, '{') < 0) goto fail;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen;

		p = cdbn_skip_ws(p, end);
		if (p >= end) goto fail;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p) goto fail;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':') goto fail;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p) goto fail;
		if (usrloc &&
		    ((nlen == 7 && memcmp(name, "row_exp", 7) == 0) ||
		     (nlen == 14 && memcmp(name, "schema_version", 14) == 0)))
			continue;         /* stale private peer: re-emitted below */
		if (!first && cdbn_sink_putc(&s, ',') < 0) goto fail;
		first = 0;
		if (cdbn_sink_emit_raw_string(&s, name, nlen) < 0) goto fail;
		if (cdbn_sink_putc(&s, ':') < 0) goto fail;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (acc)
				memset(acc, 0, sizeof(*acc));
			if (n_ids == 0 && acc) {
				/* nothing to drop: collect expiries, then copy the
				 * slice in ONE write (per-contact re-emission
				 * measurably loses to a bulk copy). */
				if (acc_collect_expiries(vs, p, acc) < 0)
					goto fail;
				if (cdbn_sink_write(&s, vs, (int)(p - vs)) < 0)
					goto fail;
			} else if (emit_contacts_minus(&s, vs, p, ids, id_lens,
					n_ids, acc) < 0)
				goto fail;
		} else {
			if (cdbn_sink_write(&s, vs, (int)(p - vs)) < 0) goto fail;
		}
	}
	if (usrloc) {
		int64_t row_exp = acc->seen_zero ? 0 :
			(acc->seen_min ? acc->min : 0);

		if (!first && cdbn_sink_putc(&s, ',') < 0) goto fail;
		if (cdbn_sink_write(&s, "\"row_exp\":", 10) < 0) goto fail;
		if (cdbn_sink_emit_int(&s, row_exp) < 0) goto fail;
		if (cdbn_sink_write(&s, ",\"schema_version\":1", 19) < 0) goto fail;
	}
	if (cdbn_sink_putc(&s, '}') < 0) goto fail;
	return cdbn_sink_take(&s, out_len);
fail:
	pkg_free(s.buf);
	return NULL;
}

/* Build the drop-id set: the contacts THIS update set whose own
 * `expires` is already past now + grace.  Shared by the two-pass reference
 * and the fold; capped at NATS_MAX_DROP_IDS (excess defers to the
 * reaper).  Returns the id count. */
static int build_drop_ids(const cdb_dict_t *pairs, time_t now, int grace,
	const char **ids, int *id_lens)
{
	int n = 0;
	struct list_head *pos;

	if (!pairs)
		return 0;
	list_for_each(pos, pairs) {
		cdb_pair_t *p = list_entry(pos, cdb_pair_t, list);
		int64_t exp;

		if (p->unset) continue;
		if (p->key.name.len != 8 || memcmp(p->key.name.s, "contacts", 8) != 0)
			continue;
		if (p->subkey.len <= 0 || !p->subkey.s) continue;
		if (pair_contact_expires(p, &exp) != 0) continue;
		if (!contact_is_expired(exp, now, grace)) continue;
		if (n < NATS_MAX_DROP_IDS) {
			ids[n] = p->subkey.s;
			id_lens[n] = p->subkey.len;
			n++;
		}
	}
	return n;
}

char *cdbn_row_drop_expired_own(const char *json, int len, const cdb_dict_t *pairs,
	time_t now, int grace, int *out_len)
{
	const char *ids[NATS_MAX_DROP_IDS];
	int id_lens[NATS_MAX_DROP_IDS];
	int n;

	if (!json || len <= 0) return NULL;
	n = build_drop_ids(pairs, now, grace, ids, id_lens);
	if (n == 0) {
		char *copy = pkg_malloc(len + 1);
		if (!copy) return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (out_len) *out_len = len;
		return copy;
	}
	return row_emit_rebuild(json, len, ids, id_lens, n, 0, NULL, out_len);
}

/* cdbn_row_drop_expired_own + cdbn_row_finalize_metadata as ONE
 * emit walk / ONE allocation (contract + byte-equivalence proof:
 * test/test_row_fold_equiv.c; header contract in the internal header).
 * The cheap pass-1 field scan only answers "is this a usrloc row?" so the
 * non-usrloc verbatim/rebuild behaviour matches the reference pair exactly. */
char *cdbn_row_hygiene_finalize(const char *json, int len,
	const cdb_dict_t *pairs, time_t now, int grace, int *out_len,
	int64_t *out_row_exp, int *out_n_contacts, int *out_all_same)
{
	const char *ids[NATS_MAX_DROP_IDS];
	int id_lens[NATS_MAX_DROP_IDS];
	int n_ids, have_contacts;
	struct row_exp_acc acc;
	char *out;

	if (out_row_exp)     *out_row_exp = 0;
	if (out_n_contacts)  *out_n_contacts = 0;
	if (out_all_same)    *out_all_same = 0;

	if (!json || len <= 0)
		return NULL;

	n_ids = build_drop_ids(pairs, now, grace, ids, id_lens);

	/* Pass 1 (no allocation): usrloc row or not?  Decides verbatim-vs-
	 * rebuild identically to the reference pair. */
	{
		struct find_contacts_ctx fc = { NULL, NULL };
		if (cdbn_json_foreach_top_field(json, len,
				find_contacts_cb, &fc) < 0)
			return NULL;
		have_contacts = (fc.vs != NULL);
	}

	if (!have_contacts && n_ids == 0) {
		/* non-usrloc, nothing due: both reference passes copy through
		 * byte-for-byte. */
		char *copy = pkg_malloc(len + 1);
		if (!copy)
			return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (out_len)
			*out_len = len;
		return copy;
	}

	memset(&acc, 0, sizeof(acc));
	out = row_emit_rebuild(json, len, ids, id_lens, n_ids,
		have_contacts, have_contacts ? &acc : NULL, out_len);
	if (out && have_contacts) {
		if (out_row_exp)
			*out_row_exp = acc.seen_zero ? 0 :
				(acc.seen_min ? acc.min : 0);
		if (out_n_contacts) *out_n_contacts = acc.n;
		if (out_all_same)   *out_all_same = (acc.n <= 1) ? 1 : !acc.mismatch;
	}
	return out;
}

/* ------------------------------------------------------------------ */
/*   Same-subkey cseq merge ordering                                   */
/* ------------------------------------------------------------------ */

/* On a same-contact-subkey collision in the merge, does the NEW value
 * supersede the existing OLD one?  Higher `cseq` wins; a tie on cseq is broken
 * by higher `last_mod` (absent == 0); an exact duplicate is NOT superseding
 * (the stale write is discarded).  Engages ONLY when BOTH values carry a cseq
 * (usrloc contacts) — otherwise returns 1 (last-writer-wins), preserving the
 * generic merge's behavior for every non-usrloc cachedb_nats consumer and any
 * non-object value.  Without this, a delayed/retransmitted REGISTER with an
 * older cseq would roll the binding backward versus the SQL backend. */
int cdbn_cseq_new_wins(const char *new_json, int new_len,
	const char *old_json, int old_len)
{
	int64_t nc, oc, nlm = 0, olm = 0;

	if (cdbn_contact_field_int64(new_json, new_json + new_len, "cseq", 4, &nc) != 0)
		return 1;
	if (cdbn_contact_field_int64(old_json, old_json + old_len, "cseq", 4, &oc) != 0)
		return 1;
	if (nc != oc)
		return nc > oc;
	(void)cdbn_contact_field_int64(new_json, new_json + new_len, "last_mod", 8, &nlm);
	(void)cdbn_contact_field_int64(old_json, old_json + old_len, "last_mod", 8, &olm);
	return nlm > olm;
}

/* ------------------------------------------------------------------ */
/*   Value-size / payload bound                                        */
/* ------------------------------------------------------------------ */

/* Is a serialized KV value within the payload bound?  @max <= 0 means
 * the guard is disabled (unbounded).  Checked on the FINAL merged row just
 * before the CAS write, so an over-limit save fails cleanly with the previous
 * revision untouched — never a silent truncation or a broker-side size error. */
int cdbn_value_size_ok(int len, int max)
{
	if (max <= 0)
		return 1;
	return len <= max;
}

/* ------------------------------------------------------------------ */
/*   Read-side expiry filter                                          */
/* ------------------------------------------------------------------ */

/* Read an integer field @name from a parsed contact dict.  Returns 0 + *out
 * (CDB_INT32/INT64), or -1 if absent / present-but-not-an-integer. */
static int dict_int_field(const cdb_dict_t *d, const char *name, int len,
	int64_t *out)
{
	struct list_head *pos;

	list_for_each(pos, d) {
		cdb_pair_t *p = list_entry(pos, cdb_pair_t, list);
		if (p->key.name.len != len ||
		    memcmp(p->key.name.s, name, len) != 0)
			continue;
		if (p->val.type == CDB_INT32) { *out = p->val.val.i32; return 0; }
		if (p->val.type == CDB_INT64) { *out = p->val.val.i64; return 0; }
		return -1;
	}
	return -1;
}

/*: omit expired contacts from a parsed read row before
 * usrloc sees them.  expires==0 is permanent (always kept); expires + grace <=
 * now is expired (omitted); an absent / non-integer expires is fail-closed
 * (treated expired, never served).  Pure read mutation of @row_dict — NO writes
 * to NATS.  If every contact is omitted the row keeps an empty contacts dict. */
void cdbn_row_filter_expired_contacts(cdb_dict_t *row_dict, time_t now, int grace)
{
	struct list_head *pos;

	if (!row_dict)
		return;
	list_for_each(pos, row_dict) {
		cdb_pair_t *pair = list_entry(pos, cdb_pair_t, list);
		struct list_head *cpos, *ctmp;

		if (pair->val.type != CDB_DICT)
			continue;
		if (pair->key.name.len != 8 ||
		    memcmp(pair->key.name.s, "contacts", 8) != 0)
			continue;

		list_for_each_safe(cpos, ctmp, &pair->val.val.dict) {
			cdb_pair_t *c = list_entry(cpos, cdb_pair_t, list);
			int64_t exp;
			int omit;

			if (c->val.type != CDB_DICT)
				continue;
			if (dict_int_field(&c->val.val.dict, "expires", 7, &exp) != 0)
				omit = 1;   /* fail-closed: absent / unparseable */
			else
				omit = contact_is_expired(exp, now, grace);
			if (omit) {
				list_del(&c->list);
				free_one_pair(c);
			}
		}
		break;             /* only one top-level "contacts" */
	}
}
