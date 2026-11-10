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
 * cachedb_nats_json_ser.c — JSON escape / sink / serializer helpers
 *
 * Owns the RFC 8259 string escaper, the single-buffer JSON sink, the
 * cdb_dict_t -> JSON serializer, KV key percent-encoding, the PK
 * target-key builder and the seed-document builder used by the
 * query() / update() callbacks in cachedb_nats_json.c.
 *
 * Split out of cachedb_nats_json.c (proc-TU split); the search index
 * lives in the cachedb_nats_fts module.  Cross-TU private declarations
 * are in cachedb_nats_json_internal.h.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../cachedb/cachedb.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_dl.h"   /* libnats function-pointer table */

#include "cachedb_nats_json.h"
#include "cachedb_nats.h"
#include "cachedb_nats_stats.h"
#include "cachedb_nats_dbase.h"
#include "cachedb_nats_json_internal.h"

/* module parameters (defined in cachedb_nats.c) */
extern char *fts_json_prefix;
extern int   fts_json_prefix_len;   /* cached at mod_init */
extern int   nats_cas_retries;   /* defined in cachedb_nats.c */


/* ------------------------------------------------------------------ */
/*        JSON escape / sink / serializer / key encoding             */
/* ------------------------------------------------------------------ */

/*
 * json_escape() — RFC 8259 string escape.
 *
 * Writes the JSON-escaped form of @in (without surrounding quotes)
 * into @out.  Returns the number of bytes written, or -1 if the
 * escaped form does not fit (including the trailing NUL).
 *
 * Escapes: " \ \b \f \n \r \t -> short forms; other bytes < 0x20 ->
 * \uXXXX; everything else passes through verbatim.
 *
 * The worst-case expansion is 6 bytes per input byte ( ...).
 */
static int json_escape(const char *in, int in_len, char *out, int out_sz)
{
	int i, w = 0;
	if (out_sz <= 0) return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		const char *esc = NULL;
		char short_buf[2];

		switch (c) {
		case '"':  esc = "\\\""; break;
		case '\\': esc = "\\\\"; break;
		case '\b': esc = "\\b";  break;
		case '\f': esc = "\\f";  break;
		case '\n': esc = "\\n";  break;
		case '\r': esc = "\\r";  break;
		case '\t': esc = "\\t";  break;
		default:
			if (c < 0x20) {
				/* "\u00xx" is 6 chars; snprintf also needs 1 byte for
				 * the NUL, so require out_sz - w >= 7 (>= not >). */
				if (w + 6 >= out_sz) return -1;
				w += snprintf(out + w, out_sz - w,
					"\\u%04x", c);
				continue;
			}
			short_buf[0] = (char)c;
			short_buf[1] = '\0';
			esc = short_buf;
		}
		{
			int n = (int)strlen(esc);
			if (w + n >= out_sz) return -1;
			memcpy(out + w, esc, n);
			w += n;
		}
	}
	if (w >= out_sz) return -1;
	out[w] = '\0';
	return w;
}

#ifdef UNIT_TESTS
int cn_ut_json_escape_buf(const char *in, int in_len, char *out, int out_sz)
{
	return json_escape(in, in_len, out, out_sz);
}
#endif

/* _json_set_field() (legacy string-only setter) was removed when
 * Tier-1 #1's _json_apply_pair / json_sink_t took over the entry
 * point — gcc with -Werror=unused-function rightly flagged the
 * leftover.  The sink-based path covers all the cases the old
 * helper handled (string field set / append) plus the typed-pair
 * surface (int / null / nested object / subkey-merge). */

/* ------------------------------------------------------------------ */
/*  Single-buffer JSON sink — replaces per-pair malloc-then-splice.    */
/* ------------------------------------------------------------------ */


int cdbn_sink_init(json_sink_t *s, int initial)
{
	s->cap = initial > 16 ? initial : 16;
	s->len = 0;
	s->oom = 0;
	s->buf = pkg_malloc(s->cap);
	if (!s->buf) { s->oom = 1; return -1; }
	s->buf[0] = '\0';
	return 0;
}

static int sink_grow(json_sink_t *s, int need)
{
	int newcap;
	char *nb;
	if (s->oom) return -1;
	if (s->len + need < s->cap) return 0;
	newcap = s->cap;
	while (newcap <= s->len + need) {
		if (newcap > INT_MAX / 2) { s->oom = 1; return -1; }
		newcap *= 2;
	}
	nb = pkg_realloc(s->buf, newcap);
	if (!nb) { s->oom = 1; return -1; }
	s->buf = nb;
	s->cap = newcap;
	return 0;
}

int cdbn_sink_write(json_sink_t *s, const char *p, int n)
{
	if (s->oom || n <= 0) return s->oom ? -1 : 0;
	if (sink_grow(s, n + 1) < 0) return -1;
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	s->buf[s->len] = '\0';
	return 0;
}

int cdbn_sink_putc(json_sink_t *s, char c)
{
	return cdbn_sink_write(s, &c, 1);
}

/* Compute exactly how many bytes json_escape will emit for `n` input
 * bytes.  This is a tight character-by-character scan but a single
 * pass over the input -- much cheaper than over-reserving 6*n bytes
 * per string and forcing the sink to amortise large growth steps on
 * a write that almost never escapes (typical SIP URIs / JSON values
 * escape < 1%).
 *
 * Matches the rules in json_escape exactly:
 *   '"' '\\' '\b' '\f' '\n' '\r' '\t'  -> 2 bytes each
 *   any other control char (< 0x20)    -> 6 bytes (\u00xx)
 *   anything else                      -> 1 byte
 */
static int json_escape_len(const char *in, int in_len)
{
	int i;
	long long out = 0;          /* int64 so the 6x worst case can't overflow */
	if (in_len < 0)
		return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		switch (c) {
		case '"': case '\\':
		case '\b': case '\f': case '\n':
		case '\r': case '\t':
			out += 2;
			break;
		default:
			out += (c < 0x20) ? 6 : 1;
		}
	}
	/* The escaped string must still be addressable with an int length. */
	if (out > 0x7FFFFFFFLL)
		return -1;
	return (int)out;
}

int cdbn_sink_emit_string(json_sink_t *s, const char *p, int n)
{
	int esc_len;
	int needed;
	if (s->oom) return -1;
	/* Two-pass: count exact escape size first, then allocate.
	 * Saves ~5x on worst-case reservation for typical inputs (no
	 * escapes), which on a multi-MB doc with many string fields
	 * eliminates a substantial fraction of grow / memcpy churn. */
	esc_len = json_escape_len(p, n);
	if (esc_len < 0) { s->oom = 1; return -1; }  /* bad length / overflow */
	needed  = esc_len + 2; /* + 2 quotes */
	if (sink_grow(s, needed + 1) < 0) return -1;
	s->buf[s->len++] = '"';
	if (esc_len > 0) {
		/* json_escape reserves one byte of out_sz for a trailing NUL
		 * (and rejects an exact fit), so it needs esc_len + 1 to emit
		 * esc_len escaped bytes.  Passing bare esc_len made it return
		 * -1 for ANY non-empty string, tripping the sink's sticky oom
		 * flag and truncating the output.  The sink already reserved
		 * the byte (grow took needed + 1); the NUL is overwritten by
		 * the closing quote below. */
		int written = json_escape(p, n, s->buf + s->len, esc_len + 1);
		if (written < 0) { s->oom = 1; return -1; }
		s->len += written;
	}
	s->buf[s->len++] = '"';
	s->buf[s->len] = '\0';
	return 0;
}

/* Emit a JSON string whose bytes are ALREADY escaped — i.e. a name or
 * value slice that came straight out of cdbn_parse_json_string() and still
 * points into the source document.  Those bytes carry their original
 * RFC 8259 escaping (\", \\, \uXXXX, …) verbatim, so they must be copied
 * through raw with surrounding quotes.  Re-running them through
 * cdbn_sink_emit_string() would escape the backslashes a second time
 * (\" -> \\\", \\ -> \\\\) and corrupt the name on every update. */
int cdbn_sink_emit_raw_string(json_sink_t *s, const char *p, int n)
{
	if (s->oom) return -1;
	if (cdbn_sink_putc(s, '"') < 0) return -1;
	if (cdbn_sink_write(s, p, n) < 0) return -1;
	return cdbn_sink_putc(s, '"');
}

int cdbn_sink_emit_int(json_sink_t *s, int64_t v)
{
	/* plain divide-loop: the old per-field "%lld" formatter
	 * parsed a format string for every integer of every row (expires,
	 * cseq, last_mod, row_exp, ... a dozen per REGISTER).  The
	 * negative arm negates via unsigned arithmetic so INT64_MIN is
	 * well-defined. */
	char     tmp[24];               /* -9223372036854775808 = 20 chars */
	char    *p = tmp + sizeof(tmp);
	uint64_t u = (v < 0) ? -(uint64_t)v : (uint64_t)v;

	do {
		*--p = (char)('0' + (u % 10));
		u /= 10;
	} while (u);
	if (v < 0)
		*--p = '-';
	return cdbn_sink_write(s, p, (int)(tmp + sizeof(tmp) - p));
}

/* Transfer ownership of the buffer to the caller; sink resets to empty.
 * Caller frees the returned pointer with pkg_free(). */
char *cdbn_sink_take(json_sink_t *s, int *out_len)
{
	char *r;
	if (s->oom) {
		pkg_free(s->buf);
		s->buf = NULL; s->len = 0; s->cap = 0;
		return NULL;
	}
	r = s->buf;
	if (out_len) *out_len = s->len;
	s->buf = NULL; s->len = 0; s->cap = 0;
	return r;
}

/* Recursively emit a cdb_dict_t as a JSON object directly into the
 * sink — single growable buffer, no per-pair malloc churn.
 *
 * Pairs are written in list order with ',' separators.  Subkey-bearing
 * pairs and pair->unset are honoured: unset subkeys are simply omitted
 * from the output object (a fresh inner dict has no prior state to
 * remove from), and subkey-bearing sets emit "field":{ "subkey":val }.
 *
 * Returns 0 on success, -1 on OOM or unknown pair type. */
static int sink_emit_cdb_dict(json_sink_t *s, const cdb_dict_t *dict)
{
	struct list_head *pos;
	cdb_pair_t *pair;
	int first = 1;

	if (cdbn_sink_putc(s, '{') < 0) return -1;

	list_for_each(pos, dict) {
		pair = list_entry(pos, cdb_pair_t, list);

		/* Inside a fresh dict, an unset pair simply omits the
		 * (sub)key.  No prior state to remove from. */
		if (pair->unset)
			continue;

		if (!first && cdbn_sink_putc(s, ',') < 0) return -1;
		first = 0;

		if (cdbn_sink_emit_string(s, pair->key.name.s,
				pair->key.name.len) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;

		/* If a subkey is present, the field's JSON value is itself
		 * an object whose only entry is the subkey -> value pair. */
		if (pair->subkey.len > 0 && pair->subkey.s) {
			if (cdbn_sink_putc(s, '{') < 0) return -1;
			if (cdbn_sink_emit_string(s, pair->subkey.s,
					pair->subkey.len) < 0) return -1;
			if (cdbn_sink_putc(s, ':') < 0) return -1;
		}

		switch (pair->val.type) {
		case CDB_STR:
			if (cdbn_sink_emit_string(s, pair->val.val.st.s,
					pair->val.val.st.len) < 0) return -1;
			break;
		case CDB_INT32:
			if (cdbn_sink_emit_int(s, pair->val.val.i32) < 0) return -1;
			break;
		case CDB_INT64:
			if (cdbn_sink_emit_int(s, pair->val.val.i64) < 0) return -1;
			break;
		case CDB_NULL:
			if (cdbn_sink_write(s, "null", 4) < 0) return -1;
			break;
		case CDB_DICT:
			if (sink_emit_cdb_dict(s, &pair->val.val.dict) < 0)
				return -1;
			break;
		default:
			LM_ERR("unknown cdb pair type %d for field '%.*s'\n",
				pair->val.type, pair->key.name.len,
				pair->key.name.s); /* not PII: field name only */
			s->oom = 1;
			return -1;
		}

		if (pair->subkey.len > 0 && pair->subkey.s) {
			if (cdbn_sink_putc(s, '}') < 0) return -1;
		}
	}

	if (cdbn_sink_putc(s, '}') < 0) return -1;
	return 0;
}

/* Backwards-compatible wrapper: serialize dict into a malloc'd JSON
 * object string.  Replaces the old per-pair-_json_apply_pair pattern
 * with a single growable buffer; caller still frees with pkg_free(). */
char *cdbn_serialize_cdb_dict(const cdb_dict_t *dict, int *out_len)
{
	json_sink_t s;
	if (cdbn_sink_init(&s, 256) < 0) return NULL;
	if (sink_emit_cdb_dict(&s, dict) < 0) {
		pkg_free(s.buf);
		return NULL;
	}
	return cdbn_sink_take(&s, out_len);
}


static int sink_kv_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
	/* '\\' removed from the safe set: it must be '=HH'-escaped, both
	 * to satisfy the project's backslash-adversarial rule and to keep the
	 * encoded key unambiguous. '.' and '/' stay literal (valid NATS subject
	 * token chars; keeps `nats kv` greppability); keys that would yield an
	 * EMPTY subject token are rejected by cdbn_kv_key_validate() on the PK path. */
	case '-': case '_': case '/': case '.':
		return 1;
	}
	return 0;
}

/* Validate an already-encoded usrloc row key (the AoR portion, not the
 * fts_json_prefix which ends on a token boundary). NATS rejects a subject with
 * an empty token, so a leading '.', trailing '.', or '..' would make JetStream
 * reject the publish and the REGISTER would be silently lost. Reject such keys
 * (and the empty key) up-front so the save fails loudly instead. The only '.'
 * left after encoding are literal dots passed through from the input.
 * Returns 0 if the key is a valid subject, -1 to reject. */
int cdbn_kv_key_validate(const char *enc, int enc_len)
{
	int i;
	if (!enc || enc_len <= 0)
		return -1;                                   /* empty key */
	if (enc[0] == '.' || enc[enc_len - 1] == '.')
		return -1;                                   /* leading/trailing empty token */
	for (i = 1; i < enc_len; i++)
		if (enc[i] == '.' && enc[i - 1] == '.')
			return -1;                           /* empty middle token */
	return 0;
}

/* Encode @in into NATS-KV-safe form with '=HH' escape for unsafe
 * bytes. Caller must pkg_free(). NATS-KV subject tokens reject
 * characters outside [-./_=a-zA-Z0-9]; usrloc AoRs commonly contain
 * '@' which would otherwise produce kvStore "Invalid Argument"
 * errors and silently drop every REGISTER. The encoding is
 * round-trippable: literal '=' becomes '=3D'. */
char *cdbn_kv_encode_key(const char *in, int in_len, int *out_len)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, w = 0;
	int cap = in_len * 3 + 1;
	char *out = pkg_malloc(cap);
	if (!out) return NULL;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c != '=' && sink_kv_char_safe(c)) {
			out[w++] = (char)c;
		} else {
			out[w++] = '=';
			out[w++] = hex[(c >> 4) & 0xF];
			out[w++] = hex[c & 0xF];
		}
	}
	out[w] = '\0';
	if (out_len) *out_len = w;
	return out;
}

/*
 * Build the PK target key ("<fts_json_prefix>" + percent-encoded value)
 * into @stackbuf if it fits, otherwise into a heap buffer.  Avoids the two
 * mallocs the PK fast path otherwise pays per usrloc read/write for
 * typically <100-byte keys.  Returns the key pointer (stackbuf or heap) and
 * sets *heap to 1 when heap-allocated (pkg), or NULL on OOM.  Free with:
 *   if (heap) pkg_free(ptr);
 */
char *cdbn_pk_target_key(const char *val, int val_len,
	char *stackbuf, int stackcap, int *heap)
{
	static const char hex[] = "0123456789ABCDEF";
	int plen = (fts_json_prefix && *fts_json_prefix)
		? fts_json_prefix_len : 0;
	int max_total = plen + val_len * 3 + 1;   /* worst-case encode */
	char *buf;
	int i, w;

	*heap = 0;
	if (max_total <= stackcap) {
		buf = stackbuf;
	} else {
		buf = pkg_malloc(max_total);
		if (!buf)
			return NULL;
		*heap = 1;
	}

	if (plen)
		memcpy(buf, fts_json_prefix, plen);
	w = plen;
	for (i = 0; i < val_len; i++) {
		unsigned char c = (unsigned char)val[i];
		if (c != '=' && sink_kv_char_safe(c)) {
			buf[w++] = (char)c;
		} else {
			buf[w++] = '=';
			buf[w++] = hex[(c >> 4) & 0xF];
			buf[w++] = hex[c & 0xF];
		}
	}
	buf[w] = '\0';
	return buf;
}

/* Build a malloc'd seed JSON document {"<field>":"<val>"} for the
 * first-insert path. Both field name and value are RFC 8259 escaped.
 * If field is NULL/empty, returns "{}" so the doc is still a valid JSON
 * object. Returns NULL on error. Caller must pkg_free(). */
char *cdbn_build_seed_doc(const char *field, int flen,
	const char *val, int vlen, int *out_len)
{
	char *buf, *esc_field, *esc_val;
	int esc_field_len, esc_val_len;
	int new_len;

	if (flen <= 0 || !field) {
		buf = pkg_malloc(3);
		if (!buf) return NULL;
		memcpy(buf, "{}", 3);
		*out_len = 2;
		return buf;
	}
	if (flen > (INT_MAX - 16) / 6 || vlen > (INT_MAX - 16) / 6)
		return NULL;

	esc_field = pkg_malloc(flen * 6 + 1);
	esc_val   = pkg_malloc((vlen > 0 ? vlen : 1) * 6 + 1);
	if (!esc_field || !esc_val) {
		pkg_free(esc_field); pkg_free(esc_val);
		return NULL;
	}
	esc_field_len = json_escape(field, flen, esc_field, flen * 6 + 1);
	esc_val_len   = vlen > 0
		? json_escape(val, vlen, esc_val, vlen * 6 + 1)
		: 0;
	if (esc_field_len < 0 || esc_val_len < 0) {
		pkg_free(esc_field); pkg_free(esc_val);
		return NULL;
	}

	new_len = 2 + esc_field_len + 3 + esc_val_len + 2;
	buf = pkg_malloc(new_len + 1);
	if (!buf) { pkg_free(esc_field); pkg_free(esc_val); return NULL; }
	buf[0] = '{';
	buf[1] = '"';
	memcpy(buf + 2, esc_field, esc_field_len);
	buf[2 + esc_field_len]     = '"';
	buf[2 + esc_field_len + 1] = ':';
	buf[2 + esc_field_len + 2] = '"';
	memcpy(buf + 2 + esc_field_len + 3, esc_val, esc_val_len);
	buf[2 + esc_field_len + 3 + esc_val_len]     = '"';
	buf[2 + esc_field_len + 3 + esc_val_len + 1] = '}';
	buf[new_len] = '\0';
	pkg_free(esc_field); pkg_free(esc_val);
	*out_len = new_len;
	return buf;
}

