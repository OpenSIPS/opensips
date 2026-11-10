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
 * Regression test: cachedb_nats_json.c::nats_cache_update silently dropped
 * every non-string pair. usrloc's cdb_flush_urecord passes contacts as
 * CDB_DICT pairs, so contacts vanished. Top-level integers (e.g. aorhash)
 * vanished. CDB_NULL pairs vanished. Pair->subkey was ignored entirely,
 * meaning every contact-update would replace the whole "contacts" map.
 * Pair->unset was ignored, meaning contact deletes were silent no-ops.
 *
 * On the real single-pass merge apply_pairs_one_pass() (UNIT_TESTS
 * wrapper cn_ut_apply_pairs_one_pass) with real cdb_pair_t updates: a
 * subkey pair carries a nested dict, as usrloc sends it.  The carried
 * _json_apply_pair model is gone.  Added: a backslash in a value and a
 * quote in a field name.
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"

char *cn_ut_apply_pairs_one_pass(const char *json, int json_len,
	const cdb_dict_t *pairs, int *out_len);

static cdb_dict_t pairs;

/* one pair @key[.@subkey] into `pairs`; its value is set by the caller */
static cdb_pair_t *pair(const char *key, const char *subkey, int unset)
{
	cdb_pair_t *p;

	INIT_LIST_HEAD(&pairs);
	p = cn_ut_mk_pair(key, (int)strlen(key), subkey,
		subkey ? (int)strlen(subkey) : 0);
	if (!p)
		return NULL;
	p->unset = (char)unset;
	p->val.type = CDB_NULL;
	cdb_dict_add(p, &pairs);
	return p;
}

static void check(const char *label, const char *json, const char *want)
{
	int len = -1;
	char *out = cn_ut_apply_pairs_one_pass(json, (int)strlen(json), &pairs, &len);

	ok(out && !strcmp(out, want) && len == (int)strlen(want),
		"update_nested_dict: %s (got %s)", label, out ? out : "<NULL>");
	if (out)
		pkg_free(out);
	cdb_free_entries(&pairs, NULL);
}

void cn_ut_update_nested_dict(void)
{
	cdb_pair_t *p;

	INIT_LIST_HEAD(&pairs);
	{ str v = str_init("bob"); cdb_dict_add_str(&pairs, "aor", 3, &v); }
	check("A: replace string field", "{\"aor\":\"alice\"}", "{\"aor\":\"bob\"}");

	INIT_LIST_HEAD(&pairs);
	cdb_dict_add_int32(&pairs, "aorhash", 7, 12345);
	check("B: append int field", "{\"aor\":\"alice@x\"}", "{\"aor\":\"alice@x\",\"aorhash\":12345}");

	INIT_LIST_HEAD(&pairs);
	cdb_dict_add_int64(&pairs, "last_mod", 8, 1746630000123ULL);
	check("C: append int64 field", "{}", "{\"last_mod\":1746630000123}");

	INIT_LIST_HEAD(&pairs);
	cdb_dict_add_null(&pairs, "path", 4);
	check("D: append null field", "{\"aor\":\"a\"}", "{\"aor\":\"a\",\"path\":null}");

	p = pair("contacts", "ct1", 0);
	p->val.type = CDB_DICT;
	INIT_LIST_HEAD(&p->val.val.dict);
	/* the core dict helpers prepend: add in reverse order */
	cdb_dict_add_int32(&p->val.val.dict, "expires", 7, 60);
	{ str v = str_init("sip:alice@1.2.3.4"); cdb_dict_add_str(&p->val.val.dict, "contact", 7, &v); }
	check("E: nested object created via subkey", "{\"aor\":\"alice@x\"}",
		"{\"aor\":\"alice@x\",\"contacts\":{\"ct1\":{\"contact\":\"sip:alice@1.2.3.4\",\"expires\":60}}}");

	p = pair("contacts", "ct2", 0);
	p->val.type = CDB_DICT;
	INIT_LIST_HEAD(&p->val.val.dict);
	cdb_dict_add_int32(&p->val.val.dict, "expires", 7, 120);
	check("F: add second subkey to existing object",
		"{\"aor\":\"a\",\"contacts\":{\"ct1\":{\"expires\":60}}}",
		"{\"aor\":\"a\",\"contacts\":{\"ct1\":{\"expires\":60},\"ct2\":{\"expires\":120}}}");

	pair("contacts", "ct1", 1);
	check("G: unset subkey removes one contact",
		"{\"aor\":\"a\",\"contacts\":{\"ct1\":{\"x\":1},\"ct2\":{\"y\":2}}}",
		"{\"aor\":\"a\",\"contacts\":{\"ct2\":{\"y\":2}}}");

	pair("contacts", "ct1", 1);
	check("H: unset last subkey leaves {}", "{\"contacts\":{\"ct1\":{\"x\":1}}}", "{\"contacts\":{}}");

	pair("aorhash", NULL, 1);
	check("I: unset top-level field", "{\"aor\":\"a\",\"aorhash\":42}", "{\"aor\":\"a\"}");

	INIT_LIST_HEAD(&pairs);
	{ str v = str_init("Ev\"il/1"); cdb_dict_add_str(&pairs, "ua", 2, &v); }
	check("J: string field escapes quote", "{}", "{\"ua\":\"Ev\\\"il/1\"}");

	INIT_LIST_HEAD(&pairs);
	{ str v = str_init("a\\b"); cdb_dict_add_str(&pairs, "ua", 2, &v); }
	check("K: a backslash in a value is escaped", "{}", "{\"ua\":\"a\\\\b\"}");

	INIT_LIST_HEAD(&pairs);
	{ str v = str_init("v"); cdb_dict_add_str(&pairs, "k\"ey", 4, &v); }
	check("L: a quote in a field name is escaped", "{}", "{\"k\\\"ey\":\"v\"}");
}
