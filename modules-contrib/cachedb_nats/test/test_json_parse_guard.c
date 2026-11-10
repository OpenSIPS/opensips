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
 *
 * Regression test: broker-supplied KV values reach cdb_json_to_dict()
 * (cachedb/cachedb_dict.c) which hands them to OpenSIPS's bundled
 * cJSON_Parse().  That parser recurses one C stack frame per nesting
 * level (lib/cJSON.c: parse_value -> parse_array/parse_object ->
 * parse_value) with NO depth limit, so a deeply nested document such as
 * "[[[[ ... ]]]]" published by anyone who can write to the broker drives
 * the SIP worker into stack exhaustion and a crash.
 *
 * The fix is a pure, iterative pre-validation guard,
 * json_parse_guard(data, len, max_depth, max_bytes), called at the two
 * cachedb_nats query call sites (cachedb_nats_json.c) BEFORE the data is
 * handed to cdb_json_to_dict().  It rejects:
 *   - NULL / non-positive / oversized (> max_bytes) input,
 *   - any raw embedded NUL (invalid JSON; would truncate the document),
 *   - object/array nesting deeper than max_depth.
 * Brace/bracket counting skips string literals so structural bytes
 * inside strings are not miscounted.
 *
 * This test carries a synced copy of the production guard (same pattern
 * as test_intern_unit.c / test_json_escape.c — self-contained, no
 * OpenSIPS link), and a `naive_recursive_parse()` that faithfully models
 * cJSON's per-level recursion to prove the guarded input is exactly the
 * input that would blow the stack.
 *
 * Through the exported read-path parser cdbn_safe_json_to_dict(), which
 * runs the static guard (depth 64, 1 MiB, no NUL) with the production
 * limits before cdb_json_to_dict; the guard's log line tells a guard
 * refusal from a parse failure.  The "synced copy" of the guard, the
 * recursion model and the copied limits are gone; nesting is built from
 * objects (an array is refused by the parser anyway).
 *                                     "deep nesting rejected" assertions
 *                                     FAIL, proving the test has teeth.
 */

#include <tap.h>
#include <stdlib.h>
#include <string.h>

#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

#define CHECK(cond, msg) ok((cond), "json_parse_guard: %s", (msg))
#define GUARD_LOG "failed depth/size/NUL guard"

/* {"a":{"a":...{}...}} -- @n objects deep */
static char *make_nested(int n)
{
	char *b = malloc((size_t)n * 6 + 1);
	int i, w = 0;

	if (!b)
		return NULL;
	for (i = 0; i < n - 1; i++) {
		memcpy(b + w, "{\"a\":", 5);
		w += 5;
	}
	b[w++] = '{';
	for (i = 0; i < n; i++)
		b[w++] = '}';
	b[w] = '\0';
	return b;
}

/* 0 parsed, -1 refused; *guarded: the guard (not the parser) refused */
static int parse(const char *data, int len, int *guarded)
{
	cdb_dict_t d;
	int rc;

	cn_ut_fake_log_clear();
	INIT_LIST_HEAD(&d);
	rc = cdbn_safe_json_to_dict(data, len, &d);
	if (rc == 0)
		cdb_free_entries(&d, NULL);
	*guarded = strstr(cn_ut_fake_log(), GUARD_LOG) != NULL;
	return rc;
}

void cn_ut_json_parse_guard(void)
{
	int g, rc;
	char *doc;

	cn_ut_fake_begin();

	{
		const char *flat = "{\"aor\":\"sip:a@b\",\"expires\":\"60\"}";
		CHECK(parse(flat, (int)strlen(flat), &g) == 0, "flat usrloc-style object accepted");
	}
	doc = make_nested(64);
	CHECK(doc && parse(doc, (int)strlen(doc), &g) == 0, "nesting exactly at max_depth (64) accepted");
	free(doc);
	{
		const char *s = "{\"k\":\"[[[[[[[[[[[[[[[[[[[[[[[[ {{{{{{ not real ]]]]\"}";
		CHECK(parse(s, (int)strlen(s), &g) == 0, "brackets inside a JSON string are not counted");
	}

	doc = make_nested(64 + 5000);
	rc = doc ? parse(doc, (int)strlen(doc), &g) : 0;
	CHECK(rc == -1 && g, "deep nesting (5064) rejected by the guard before the parser");
	free(doc);
	doc = make_nested(65);
	rc = doc ? parse(doc, (int)strlen(doc), &g) : 0;
	CHECK(rc == -1 && g, "nesting one past max_depth rejected by the guard");
	free(doc);

	{
		int n = 1024 * 1024 + 1, w;
		doc = malloc((size_t)n + 1);
		if (doc) {
			w = snprintf(doc, (size_t)n + 1, "{\"a\":\"");
			memset(doc + w, 'x', (size_t)(n - w - 2));
			doc[n - 2] = '"';
			doc[n - 1] = '}';
			doc[n] = '\0';
		}
		rc = doc ? parse(doc, n, &g) : 0;
		CHECK(rc == -1 && g, "a document over 1 MiB rejected by the guard");
		free(doc);
	}
	{
		const char buf[] = {'{','"','a','"',':','"','x','\0','y','"','}'};
		CHECK(parse(buf, (int)sizeof buf, &g) == -1 && g,
			"embedded NUL rejected by the guard (no silent truncation)");
	}
	CHECK(parse(NULL, 5, &g) == -1 && g, "NULL data rejected");
	CHECK(parse("{}", 0, &g) == -1 && g, "zero length rejected");
	rc = parse("]]]]}", 5, &g);
	CHECK(rc == -1 && !g, "unbalanced closers pass the guard (no underflow) and fail the parse");

	cn_ut_fake_end();
}
