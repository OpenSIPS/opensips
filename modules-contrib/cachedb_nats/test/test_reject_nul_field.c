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
 * Reject-at-write any contact field
 * that carries an embedded NUL.  An OpenSIPS `str` is length-based, so a `0x00`
 * byte is reachable in fields like `ua`/`attr`.  Such a value CANNOT round-trip:
 * the reader is `cJSON_Parse` + `str.len = strlen(valuestring)`
 * (cachedb/cachedb_dict.c:565), so an interior NUL silently truncates the value
 * — corruption.  A raw NUL in the wire buffer is already caught by
 * `json_parse_guard`, but the ESCAPED form `\u0000` slips through the guard,
 * is decoded by cJSON into a `0x00`, and then truncates on `strlen`.  v1 refuses
 * the save (no partial row, integrity counter ++) for EITHER form.
 *
 * field_has_nul(s,len) is the byte-level detector: 1 if @s contains a raw
 * `0x00` OR the 6-byte JSON escape `\u0000` (decodes to NUL); else 0.  It is
 * fail-closed: a value embedding the literal escape sequence is conservatively
 * refused (a real SIP UA/attr never carries it; correctness over permissiveness).
 *
 * Through the real cdbn_dict_has_nul_field (a one-field dict per value;
 * nested dicts too) and a real update (nats_cache_update on fakes), which
 * refuses such a field and writes nothing.  The carried scanner is gone.
 */
#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../cachedb/cachedb.h"
#include "../../../cachedb/cachedb_dict.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_json.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

#define CHECK(cond, msg) ok((cond), "reject_nul_field: %s", (msg))

/* the production check on a dict holding the one value */
static int field_has_nul(const char *s, int len)
{
	cdb_dict_t d;
	str v;
	int r;

	v.s = (char *)s;
	v.len = len;
	INIT_LIST_HEAD(&d);
	cdb_dict_add_str(&d, "ua", 2, &v);
	r = cdbn_dict_has_nul_field(&d);
	cdb_free_entries(&d, NULL);
	return r;
}
#define HASNUL(lit) field_has_nul((lit), (int)(sizeof(lit) - 1))

/* the same value one dict down (contacts -> c1 -> ua) */
static int nested_has_nul(const char *s, int len)
{
	cdb_dict_t top;
	cdb_pair_t *p;
	str v;
	int r;

	INIT_LIST_HEAD(&top);
	p = cn_ut_mk_pair("c1", 2, NULL, 0);
	if (!p)
		return -1;
	p->val.type = CDB_DICT;
	INIT_LIST_HEAD(&p->val.val.dict);
	v.s = (char *)s;
	v.len = len;
	cdb_dict_add_str(&p->val.val.dict, "ua", 2, &v);
	cdb_dict_add(p, &top);
	r = cdbn_dict_has_nul_field(&top);
	cdb_free_entries(&top, NULL);
	return r;
}

void cn_ut_reject_nul_field(void)
{

	diag("clean fields are accepted (no NUL):");
	CHECK(HASNUL("alice@example.com") == 0, "plain AoR-ish value accepted");
	CHECK(field_has_nul("", 0) == 0, "empty value accepted");
	CHECK(field_has_nul(NULL, 0) == 0, "NULL value accepted (defensive)");
	CHECK(HASNUL("Acme-UA/3.14 (x86_64)") == 0, "typical UA string accepted");
	CHECK(HASNUL("version0000build") == 0, "bare '0000' digits NOT a false positive");
	CHECK(HASNUL("u0000") == 0, "'u0000' without backslash accepted");

	diag("a raw 0x00 byte is rejected:");
	{ const char v[] = {'a','\0','b'};  CHECK(field_has_nul(v, 3) == 1, "interior raw NUL rejected"); }
	{ const char v[] = {'\0','a','b'};  CHECK(field_has_nul(v, 3) == 1, "leading raw NUL rejected"); }
	{ const char v[] = {'a','b','\0'};  CHECK(field_has_nul(v, 3) == 1, "trailing raw NUL rejected"); }
	{ const char v[] = {'\0'};          CHECK(field_has_nul(v, 1) == 1, "lone raw NUL rejected"); }

	diag("the escaped form \\u0000 is equally rejected:");
	CHECK(HASNUL("\\u0000") == 1, "bare \\u0000 rejected");
	CHECK(HASNUL("ua\\u0000evil") == 1, "interior \\u0000 rejected");
	CHECK(HASNUL("\\u0000tail") == 1, "leading \\u0000 rejected");
	CHECK(HASNUL("head\\u0000") == 1, "trailing \\u0000 rejected");

	diag("adversarial: non-NUL escapes must NOT be rejected:");
	CHECK(HASNUL("line\\none") == 0, "\\n (newline escape) accepted");
	CHECK(HASNUL("tab\\tend") == 0, "\\t accepted");
	CHECK(HASNUL("back\\\\slash") == 0, "\\\\ (escaped backslash) accepted");
	CHECK(HASNUL("char\\u0041A") == 0, "\\u0041 (letter 'A') accepted");
	CHECK(HASNUL("ctrl\\u0001x") == 0, "\\u0001 (SOH, not NUL) accepted");
	CHECK(HASNUL("max\\uffff") == 0, "\\uffff accepted");
	CHECK(HASNUL("trunc\\u00") == 0, "truncated \\u00 at end accepted (no match)");
	CHECK(HASNUL("trunc\\u000") == 0, "truncated \\u000 at end accepted (no match)");

	diag("nested, and through an update:");
	{
		const char v[] = {'a','\0','b'};
		CHECK(nested_has_nul(v, 3) == 1, "a raw NUL one dict down is found");
		CHECK(nested_has_nul("ok", 2) == 0, "a clean nested value is not");
	}
	{
		cachedb_con con;
		nats_cachedb_con ncon;
		cdb_filter_t f;
		cdb_dict_t pairs;
		str ua = { "ev\0il", 5 };
		int rc;

		cn_ut_fake_begin();
		memset(&con, 0, sizeof con);
		memset(&ncon, 0, sizeof ncon);
		ncon.kv = (kvStore *)cn_ut_fake_kv();
		con.data = &ncon;
		memset(&f, 0, sizeof f);
		f.key.name.s = "aor";
		f.key.name.len = 3;
		f.key.is_pk = 1;
		f.op = CDB_OP_EQ;
		f.val.is_str = 1;
		f.val.s.s = "alice";
		f.val.s.len = 5;
		INIT_LIST_HEAD(&pairs);
		cdb_dict_add_str(&pairs, "ua", 2, &ua);
		rc = nats_cache_update(&con, &f, &pairs);
		CHECK(rc == -1 && cf.seq[0] == '\0', "an update carrying a NUL field is refused before any KV call");
		CHECK(strstr(cn_ut_fake_log(), "embedded NUL") != NULL, "... and logged (value redacted)");
		cdb_free_entries(&pairs, NULL);
		cn_ut_fake_end();
	}
}
