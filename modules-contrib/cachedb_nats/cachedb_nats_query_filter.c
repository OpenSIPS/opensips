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

#include <stdint.h>
#include <string.h>

#include "cachedb_nats_query_filter.h"
#include "cachedb_nats_json_internal.h"   /* the JSON walkers */

/* a top-level field's value, as the raw token in the document */
struct doc_val {
	const char *p;   /* string content (no quotes) or the number token */
	int len;
	int is_str;      /* 1 string, 0 number; other types are not found */
};

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* decode a JSON string's escapes into out (UTF-8); -1 if malformed or
 * longer than out_size.  Surrogate pairs are not combined (a lone
 * \uD8xx is encoded as is), which only matters for comparisons with
 * non-BMP filter values. */
static int json_unescape(const char *in, int n, char *out, int out_size)
{
	int i, o = 0;

	for (i = 0; i < n; i++) {
		unsigned int cp;
		int k;

		if (in[i] != '\\') {
			if (o >= out_size)
				return -1;
			out[o++] = in[i];
			continue;
		}
		if (++i >= n)
			return -1;
		switch (in[i]) {
		case '"': case '\\': case '/': cp = (unsigned char)in[i]; break;
		case 'b': cp = '\b'; break;
		case 'f': cp = '\f'; break;
		case 'n': cp = '\n'; break;
		case 'r': cp = '\r'; break;
		case 't': cp = '\t'; break;
		case 'u':
			if (i + 4 >= n)
				return -1;
			for (cp = 0, k = 1; k <= 4; k++) {
				int h = hexval(in[i + k]);
				if (h < 0)
					return -1;
				cp = (cp << 4) | (unsigned int)h;
			}
			i += 4;
			break;
		default:
			return -1;
		}
		if (cp < 0x80) {
			if (o + 1 > out_size)
				return -1;
			out[o++] = (char)cp;
		} else if (cp < 0x800) {
			if (o + 2 > out_size)
				return -1;
			out[o++] = (char)(0xC0 | (cp >> 6));
			out[o++] = (char)(0x80 | (cp & 0x3F));
		} else {
			if (o + 3 > out_size)
				return -1;
			out[o++] = (char)(0xE0 | (cp >> 12));
			out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
			out[o++] = (char)(0x80 | (cp & 0x3F));
		}
	}
	return o;
}

/* find the top-level field @name; 1 found (string or number), 0 not
 * found or another type, -1 malformed document */
static int doc_field(const char *json, int len, const str *name,
		struct doc_val *v)
{
	const char *p = json, *end = json + len, *f, *val;
	int flen;

	p = cdbn_skip_ws(p, end);
	if (p >= end || *p != '{')
		return -1;
	p++;
	for (;;) {
		p = cdbn_skip_ws(p, end);
		if (p >= end)
			return -1;
		if (*p == '}')
			return 0;
		if (*p == ',') {
			p = cdbn_skip_ws(p + 1, end);
			if (p >= end)
				return -1;
		}
		p = cdbn_parse_json_string(p, end, &f, &flen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':')
			return -1;
		p = cdbn_skip_ws(p + 1, end);
		if (p >= end)
			return -1;
		val = p;
		if (*p == '"') {
			p = cdbn_parse_json_string(p, end, &v->p, &v->len);
			if (!p)
				return -1;
			v->is_str = 1;
		} else {
			p = cdbn_skip_json_value(p, end);
			if (!p || p == val)
				return -1;
			v->p = val;
			v->len = (int)(p - val);
			v->is_str = 0;
		}
		if (flen == name->len && !memcmp(f, name->s, flen)) {
			if (!v->is_str && !((*val >= '0' && *val <= '9') || *val == '-'))
				return 0;   /* object, array, true, false, null */
			return 1;
		}
	}
}

/* a JSON number that is a plain integer fitting int64; -1 otherwise */
static int doc_int(const struct doc_val *v, int64_t *out)
{
	int i = 0, neg = 0;
	uint64_t n = 0;

	if (i < v->len && v->p[i] == '-') {
		neg = 1;
		i++;
	}
	if (i >= v->len)
		return -1;
	for (; i < v->len; i++) {
		if (v->p[i] < '0' || v->p[i] > '9')
			return -1;   /* fraction, exponent */
		if (n > (UINT64_C(9223372036854775808) - (v->p[i] - '0')) / 10)
			return -1;
		n = n * 10 + (uint64_t)(v->p[i] - '0');
	}
	if (!neg && n > INT64_MAX)
		return -1;
	*out = neg ? (int64_t)(0 - n) : (int64_t)n;
	return 0;
}

static int op_holds(enum cdb_filter_op op, int cmp)
{
	switch (op) {
	case CDB_OP_EQ:  return cmp == 0;
	case CDB_OP_LT:  return cmp < 0;
	case CDB_OP_LTE: return cmp <= 0;
	case CDB_OP_GT:  return cmp > 0;
	case CDB_OP_GTE: return cmp >= 0;
	}
	return 0;
}

int cdbn_doc_matches(const char *json, int len, const cdb_filter_t *filter)
{
	const cdb_filter_t *f;
	struct doc_val v;
	char buf[1024];

	/* the whole document must be well-formed, not just up to the field */
	if (len <= 0 || !json || !cdbn_skip_json_value(json, json + len))
		return 0;

	for (f = filter; f; f = f->next) {
		int cmp;

		if (doc_field(json, len, &f->key.name, &v) != 1)
			return 0;
		if (f->val.is_str) {
			int n, m;

			if (!v.is_str)
				return 0;
			n = json_unescape(v.p, v.len, buf, sizeof buf);
			if (n < 0)
				return 0;
			m = n < f->val.s.len ? n : f->val.s.len;
			cmp = memcmp(buf, f->val.s.s, m);
			if (cmp == 0)
				cmp = (n > f->val.s.len) - (n < f->val.s.len);
		} else {
			int64_t n;

			if (v.is_str || doc_int(&v, &n) < 0)
				return 0;
			cmp = (n > f->val.i) - (n < f->val.i);
		}
		if (!op_holds(f->op, cmp))
			return 0;
	}
	return 1;
}
