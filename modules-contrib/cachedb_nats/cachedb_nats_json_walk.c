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
 * cachedb_nats_json_walk.c — the shared, dependency-free JSON walkers
 * (cdbn_skip_ws, cdbn_parse_json_string, cdbn_skip_json_value, cdbn_safe_json_to_dict)
 * used by this module's JSON layer AND by the optional cachedb_nats_fts
 * module (declared in cachedb_nats_json_internal.h).  Split into their
 * own TU so unit tests can link them without dragging either module's
 * full dependency graph.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../../dprint.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_json.h"
#include "cachedb_nats_json_internal.h"

/*
 * Defensive limits for broker-supplied JSON documents before they reach
 * the recursive cJSON_Parse() (see json_parse_guard).  cJSON recurses
 * one C stack frame per nesting level with no internal cap, so an
 * attacker who can publish to the KV bucket could otherwise crash a SIP
 * worker with a deeply nested value.  Depth 64 is far beyond any real
 * usrloc/cachedb document; the byte cap matches NATS's default
 * max_payload (1 MiB).
 */
#define NATS_JSON_MAX_DEPTH  64
#define NATS_JSON_MAX_BYTES  (1 * 1024 * 1024)

/**
 * cdbn_skip_ws() — Advance past JSON whitespace characters.
 *
 * Skips spaces, tabs, newlines, and carriage returns.  All JSON parser
 * entry points call this before inspecting the next token.  Returns a
 * pointer to the first non-whitespace character, or @end if the buffer
 * is exhausted.
 */
const char *cdbn_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	return p;
}

/**
 * cdbn_parse_json_string() — Parse a JSON quoted string with escape handling.
 *
 * Expects @p to point at the opening double-quote.  Scans forward,
 * honouring backslash-escaped characters (\\, \", \n, etc.) so that
 * embedded quotes do not terminate the string early.  On success, sets
 * *out to the first character after the opening quote and *out_len to
 * the raw byte length (escape sequences are NOT decoded — the returned
 * slice points directly into the original buffer).
 *
 * Returns a pointer past the closing quote, or NULL on malformed input.
 */
const char *cdbn_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;

	if (p >= end || *p != '"')
		return NULL;
	p++; /* skip opening quote */
	start = p;

	while (p < end && *p != '"') {
		if (*p == '\\') {
			p++; /* skip escaped char */
			if (p >= end)
				return NULL;
		}
		p++;
	}
	if (p >= end)
		return NULL;

	*out = start;
	*out_len = (int)(p - start);
	p++; /* skip closing quote */
	return p;
}

/**
 * cdbn_skip_json_value() — Skip over any JSON value without extracting it.
 *
 * Handles all six JSON value types via a simple state machine:
 *   - Strings:  scan to closing quote, respecting backslash escapes.
 *   - Objects / Arrays: track brace/bracket depth, skipping over nested
 *     strings (to avoid miscounting braces inside string literals).
 *   - Primitives (number, bool, null): advance until the next structural
 *     character or whitespace.
 *
 * Returns a pointer past the value, or NULL on malformed input.
 */
const char *cdbn_skip_json_value(const char *p, const char *end)
{
	int depth;

	p = cdbn_skip_ws(p, end);
	if (p >= end)
		return NULL;

	/*
	 * JSON parser state machine — dispatch on the first character to
	 * determine the value type, then advance past the entire value.
	 */
	switch (*p) {
	case '"': /* string — scan to unescaped closing quote */
		p++;
		while (p < end && *p != '"') {
			if (*p == '\\') {
				p++; /* skip the escaped character */
				if (p >= end) return NULL;
			}
			p++;
		}
		return (p < end) ? p + 1 : NULL;

	case '{': /* object */
	case '[': /* array  */
		/* depth-tracking: increment on open, decrement on close */
		depth = 1;
		p++;
		while (p < end && depth > 0) {
			if (*p == '{' || *p == '[') depth++;
			else if (*p == '}' || *p == ']') depth--;
			else if (*p == '"') {
				/* skip embedded strings so their content cannot
				 * be mistaken for structural characters */
				p++;
				while (p < end && *p != '"') {
					if (*p == '\\') { p++; if (p >= end) return NULL; }
					p++;
				}
				if (p >= end) return NULL;
			}
			p++;
		}
		/* ran out of input before the closing bracket: malformed */
		return depth == 0 ? p : NULL;

	default: /* number, bool, null — consume until delimiter */
		while (p < end && *p != ',' && *p != '}' && *p != ']'
				&& *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
			p++;
		return p;
	}
}

/**
 * json_parse_guard() — defensive pre-validation of broker-supplied JSON
 * before it is handed to the recursive cJSON_Parse() in cdb_json_to_dict.
 *
 * The bundled cJSON (lib/cJSON.c) recurses one C stack frame per nesting
 * level with no depth cap, so a deeply nested document published by
 * anyone able to write to the KV bucket would exhaust the SIP worker's
 * stack and crash it.  This guard is pure and iterative (no recursion,
 * no allocation).  It rejects (returns -1):
 *   - NULL / non-positive / oversized (> @max_bytes) input,
 *   - any raw embedded NUL — invalid JSON that would otherwise silently
 *     truncate the document at the C-string boundary,
 *   - object/array nesting deeper than @max_depth.
 * Brace/bracket counting skips over string literals (respecting '\'
 * escapes) so structural characters inside strings are not miscounted.
 * Returns 0 when the document is safe to parse.
 *
 * Mirrored by test/test_json_parse_guard.c — keep the two in sync.
 */
static int json_parse_guard(const char *data, int data_len,
		int max_depth, int max_bytes)
{
	int i, depth = 0, in_string = 0;

	if (!data || data_len <= 0 || data_len > max_bytes)
		return -1;

	if (memchr(data, '\0', (size_t)data_len) != NULL)
		return -1;

	for (i = 0; i < data_len; i++) {
		unsigned char c = (unsigned char)data[i];
		if (in_string) {
			if (c == '\\') { i++; continue; }   /* skip escaped byte */
			if (c == '"') in_string = 0;
			continue;
		}
		if (c == '"') { in_string = 1; continue; }
		if (c == '{' || c == '[') {
			if (++depth > max_depth) return -1;
		} else if (c == '}' || c == ']') {
			if (depth > 0) depth--;
		}
	}
	return 0;
}

/**
 * cdbn_safe_json_to_dict() — guard + parse a broker-supplied JSON document.
 *
 * Runs json_parse_guard() to reject hostile input (deep nesting, raw
 * NUL, oversize), then hands cdb_json_to_dict() a guaranteed
 * NUL-terminated copy — the kvEntry value bytes are not contractually
 * NUL-terminated, and the recursive C-string parser must never run off
 * the end of the value buffer.  Small documents use a stack buffer; only
 * large ones touch the allocator.  Returns 0 on success, -1 on rejection
 * or parse failure.
 */
int cdbn_safe_json_to_dict(const char *data, int data_len, cdb_dict_t *out)
{
	char stackbuf[1024];
	char *buf;
	int rc;

	if (json_parse_guard(data, data_len,
			NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES) != 0) {
		LM_WARN("rejecting broker JSON document (%d bytes): failed "
			"depth/size/NUL guard before parse\n", data_len);
		return -1;
	}

	if (data_len < (int)sizeof(stackbuf)) {
		buf = stackbuf;
	} else {
		buf = pkg_malloc(data_len + 1);
		if (!buf) {
			LM_ERR("no pkg memory for %d-byte JSON parse copy\n",
				data_len);
			return -1;
		}
	}
	memcpy(buf, data, data_len);
	buf[data_len] = '\0';

	rc = cdb_json_to_dict(buf, out, NULL);

	if (buf != stackbuf)
		pkg_free(buf);
	return rc;
}


/*
 * The ONE top-level field iterator behind the row-mutation
 * paths.  Walks `{ "name": <value>, ... }` and hands the cb each
 * field's name span (raw, still-escaped bytes between the quotes) and
 * value span (raw bytes; a nested object/array is one span).  The cb
 * returns 0 to continue, <0 to abort.
 *
 * Returns 0 after a complete walk, -1 on malformed JSON, a cb abort,
 * or bad arguments.  Pure: no allocation, no logging.
 */
int cdbn_json_foreach_top_field(const char *json, int len,
	json_field_cb cb, void *ud)
{
	const char *p, *end;

	if (!json || len <= 0 || !cb)
		return -1;
	p = json;
	end = json + len;
	p = cdbn_skip_ws(p, end);
	if (p >= end || *p != '{')
		return -1;
	p++;
	while (p < end) {
		const char *fname, *vstart, *vend;
		int flen;

		p = cdbn_skip_ws(p, end);
		if (p >= end)
			return -1;              /* unterminated object */
		if (*p == '}')
			return 0;               /* complete walk */
		if (*p == ',') { p++; continue; }

		p = cdbn_parse_json_string(p, end, &fname, &flen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, end);
		vstart = p;
		p = cdbn_skip_json_value(p, end);
		if (!p || p == vstart)
			return -1;
		vend = p;

		if (cb(fname, flen, vstart, vend, ud) < 0)
			return -1;
	}
	return -1;                          /* ran off the end */
}
