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
 * test_doc_filter.c -- cdbn_doc_matches(): CacheDB filters evaluated on a
 * stored JSON document (the query path for non-equality / integer
 * filters, e.g. usrloc's NAT-pinging "aorhash in [min, max)").
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "../cachedb_nats_query_filter.h"

#include "cn_ut.h"



#define CHECK(c, m) do { if (!(c)) { fail("doc_filter: %s", m); } \
	else pass("doc_filter: %s", m); } while (0)

static cdb_filter_t F[4];

/* filter list: spec "name op i:123" or "name op s:text", up to 4, AND */
static const cdb_filter_t *mk(int n, ...)
{
	va_list ap;
	int i;
	va_start(ap, n);
	for (i = 0; i < n; i++) {
		const char *name = va_arg(ap, const char *);
		int op = va_arg(ap, int);
		int is_str = va_arg(ap, int);
		memset(&F[i], 0, sizeof F[i]);
		F[i].key.name.s = (char *)name;
		F[i].key.name.len = strlen(name);
		F[i].op = op;
		F[i].val.is_str = is_str;
		if (is_str) {
			const char *s = va_arg(ap, const char *);
			F[i].val.s.s = (char *)s;
			F[i].val.s.len = strlen(s);
		} else
			F[i].val.i = va_arg(ap, int);
		F[i].next = (i + 1 < n) ? &F[i + 1] : NULL;
	}
	va_end(ap);
	return &F[0];
}

/* the document is followed in its buffer by more fields, which a read
 * past its length would see (no ASan here) */
#define TAIL ",\"aorhash\":7,\"tail\":\"x\"}"

static int m(const char *doc, const cdb_filter_t *f)
{
	int n = strlen(doc);
	char d[1024];

	memcpy(d, doc, n);
	memcpy(d + n, TAIL, sizeof TAIL);
	return cdbn_doc_matches(d, n, f);
}

#define I(name, op, v)  name, op, 0, v
#define S(name, op, v)  name, op, 1, v

void cn_ut_doc_filter(void)
{
	const char *doc =
		"{\"aor\":\"alice@example.com\",\"aorhash\":1234567,"
		"\"contacts\":{\"c1\":{\"expires\":3600}},\"neg\":-5,"
		"\"big\":2147483648,\"frac\":1.5,\"exp\":1e3,"
		"\"esc\":\"a\\\"b\\\\c\\/d\",\"uni\":\"caf\\u00e9\","
		"\"empty\":\"\",\"nul\":null,\"bool\":true}";

	diag("integer comparisons:");
	CHECK(m(doc, mk(1, I("aorhash", CDB_OP_EQ, 1234567))) == 1, "EQ");
	CHECK(m(doc, mk(1, I("aorhash", CDB_OP_GTE, 1234567))) == 1, "GTE at the value");
	CHECK(m(doc, mk(1, I("aorhash", CDB_OP_GT, 1234567))) == 0, "GT at the value");
	CHECK(m(doc, mk(1, I("aorhash", CDB_OP_LT, 1234568))) == 1, "LT above");
	CHECK(m(doc, mk(1, I("aorhash", CDB_OP_LTE, 1234566))) == 0, "LTE below");
	CHECK(m(doc, mk(2, I("aorhash", CDB_OP_GTE, 1000), I("aorhash", CDB_OP_LT, 2000000))) == 1,
		"range [1000, 2000000) contains it (the pinging query)");
	CHECK(m(doc, mk(2, I("aorhash", CDB_OP_GTE, 1000), I("aorhash", CDB_OP_LT, 1000000))) == 0,
		"range [1000, 1000000) does not");
	CHECK(m(doc, mk(1, I("neg", CDB_OP_LT, 0))) == 1, "negative numbers");
	CHECK(m(doc, mk(1, I("big", CDB_OP_GT, 2147483647))) == 1,
		"a stored value beyond int32 compares as 64-bit");
	CHECK(m(doc, mk(1, I("frac", CDB_OP_EQ, 1))) == 0, "1.5 is not an integer");
	CHECK(m(doc, mk(1, I("frac", CDB_OP_GT, 0))) == 0, "... for any operator");
	CHECK(m(doc, mk(1, I("exp", CDB_OP_EQ, 1000))) == 0, "1e3 is not a plain integer");

	diag("string comparisons:");
	CHECK(m(doc, mk(1, S("aor", CDB_OP_EQ, "alice@example.com"))) == 1, "EQ");
	CHECK(m(doc, mk(1, S("aor", CDB_OP_EQ, "alice@example.co"))) == 0, "EQ prefix is not equal");
	CHECK(m(doc, mk(1, S("aor", CDB_OP_GT, "alice"))) == 1, "longer sorts after its prefix");
	CHECK(m(doc, mk(1, S("aor", CDB_OP_LT, "bob"))) == 1, "LT");
	CHECK(m(doc, mk(1, S("aor", CDB_OP_GTE, "alice@example.com"))) == 1, "GTE equal");
	CHECK(m(doc, mk(1, S("esc", CDB_OP_EQ, "a\"b\\c/d"))) == 1,
		"escaped quote, backslash and slash are decoded");
	CHECK(m(doc, mk(1, S("uni", CDB_OP_EQ, "caf\xc3\xa9"))) == 1, "\\u00e9 decodes to UTF-8");
	CHECK(m(doc, mk(1, S("empty", CDB_OP_EQ, ""))) == 1, "empty string");

	diag("no match:");
	CHECK(m(doc, mk(1, I("missing", CDB_OP_GTE, 0))) == 0, "missing field");
	CHECK(m(doc, mk(1, I("aor", CDB_OP_GTE, 0))) == 0, "integer filter on a string");
	CHECK(m(doc, mk(1, S("aorhash", CDB_OP_EQ, "1234567"))) == 0, "string filter on a number");
	CHECK(m(doc, mk(1, I("nul", CDB_OP_EQ, 0))) == 0, "null field");
	CHECK(m(doc, mk(1, I("bool", CDB_OP_EQ, 1))) == 0, "boolean field");
	CHECK(m(doc, mk(1, I("expires", CDB_OP_EQ, 3600))) == 0, "nested fields are not top-level");
	CHECK(m(doc, mk(1, I("aorhas", CDB_OP_EQ, 1234567))) == 0, "field name prefix");
	CHECK(m(doc, mk(1, I("aorhash2", CDB_OP_EQ, 1234567))) == 0, "longer field name");

	diag("malformed documents:");
	CHECK(m("", mk(1, I("a", CDB_OP_EQ, 1))) == 0, "empty");
	CHECK(m("[1]", mk(1, I("a", CDB_OP_EQ, 1))) == 0, "not an object");
	CHECK(m("{\"a\":12", mk(1, I("a", CDB_OP_EQ, 12))) == 0, "truncated");
	CHECK(m("{\"a\":5,\"c\":{\"d\":1}", mk(1, I("a", CDB_OP_EQ, 5))) == 0,
		"truncated inside a nested object that ends in '}'");
	CHECK(m("{\"a\":5,\"c\":[1,2", mk(1, I("a", CDB_OP_EQ, 5))) == 0,
		"truncated inside an array");
	CHECK(m("{\"a\":}", mk(1, I("a", CDB_OP_EQ, 0))) == 0, "missing value");
	CHECK(m("{\"a\":\"x\\u12\"}", mk(1, S("a", CDB_OP_EQ, "x"))) == 0, "bad \\u escape");
	CHECK(m("{\"a\":99999999999999999999}", mk(1, I("a", CDB_OP_GT, 0))) == 0,
		"number overflowing int64");
	CHECK(m("{\"x\":1", mk(1, I("aorhash", CDB_OP_EQ, 7))) == 0,
		"a field after the document's length (in its buffer) is not seen");

	diag("layout:");
	CHECK(m("{ \"a\" : 5 , \"b\" :\t\"x\" }", mk(2, I("a", CDB_OP_EQ, 5), S("b", CDB_OP_EQ, "x"))) == 1,
		"whitespace everywhere");
	CHECK(m("{\"a\":5}", NULL) == 1, "no filter matches");
	{
		/* a NUL inside a string value is just a byte */
		static const char d[] = "{\"a\":\"x\0y\",\"b\":7}";
		CHECK(cdbn_doc_matches(d, sizeof d - 1, mk(1, I("b", CDB_OP_EQ, 7))) == 1,
			"embedded NUL in an earlier value");
	}
}
