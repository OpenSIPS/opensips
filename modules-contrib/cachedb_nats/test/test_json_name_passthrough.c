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
 * Existing JSON field / subkey NAMES come out of the parser still escaped
 * (cdbn_parse_json_string does not decode \" \\ \uXXXX); an update must
 * copy them through raw.  Re-escaping them doubled the backslashes on
 * every write.  On the real single-pass merge apply_pairs_one_pass
 * (UNIT_TESTS wrapper cn_ut_apply_pairs_one_pass): names with escaped
 * quotes, backslashes and \u escapes survive repeated updates byte for
 * byte (a fixed point), top-level and as contacts subkeys.  Replaces
 * tests/test_json_name_passthrough.c (its carried emitter and greps).
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"

char *cn_ut_apply_pairs_one_pass(const char *json, int json_len,
	const cdb_dict_t *pairs, int *out_len);

/* @n updates setting x=5 (top level) or contacts.c9 (subkey) */
static char *apply_n(const char *doc, int subkey, int n)
{
	char *cur = NULL, *next;
	const char *in = doc;
	int i, len = (int)strlen(doc), nl;

	for (i = 0; i < n; i++) {
		cdb_dict_t pairs;

		INIT_LIST_HEAD(&pairs);
		if (subkey) {
			cdb_pair_t *p;

			p = cn_ut_mk_pair("contacts", 8, "c9", 2);
			if (!p)
				break;
			p->val.type = CDB_DICT;
			INIT_LIST_HEAD(&p->val.val.dict);
			cdb_dict_add_int32(&p->val.val.dict, "expires", 7, 0);
			cdb_dict_add(p, &pairs);
		} else
			cdb_dict_add_int32(&pairs, "x", 1, 5);
		next = cn_ut_apply_pairs_one_pass(in, len, &pairs, &nl);
		cdb_free_entries(&pairs, NULL);
		if (cur)
			pkg_free(cur);
		cur = next;
		if (!cur)
			return NULL;
		in = cur;
		len = nl;
	}
	return cur;
}

static void keeps(const char *label, const char *doc, const char *name, int subkey)
{
	char *o1 = apply_n(doc, subkey, 1), *o3 = apply_n(doc, subkey, 3);

	ok(o1 && strstr(o1, name), "json_name_passthrough: %s: name kept byte for byte (%s)",
		label, o1 ? o1 : "<NULL>");
	ok(o1 && o3 && !strcmp(o1, o3), "json_name_passthrough: %s: a fixed point across repeated updates", label);
	if (o1) pkg_free(o1);
	if (o3) pkg_free(o3);
}

void cn_ut_json_name_passthrough(void)
{
	keeps("escaped quote", "{\"foo\\\"bar\":1}", "\"foo\\\"bar\":1", 0);
	keeps("escaped backslash", "{\"a\\\\b\":1}", "\"a\\\\b\":1", 0);
	keeps("\\u escape", "{\"caf\\u00e9\":1}", "\"caf\\u00e9\":1", 0);
	keeps("contact subkey with a quote", "{\"contacts\":{\"c\\\"1\":{\"expires\":0}}}",
		"\"c\\\"1\":{\"expires\":0}", 1);
	keeps("contact subkey with a backslash", "{\"contacts\":{\"c\\\\1\":{\"expires\":0}}}",
		"\"c\\\\1\":{\"expires\":0}", 1);
}
