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
 * Skew-safe write-side hygiene.
 *
 * On update(), drop an already-expired contact ONLY IF it is among the subkeys
 * THIS update explicitly set/unset, and only when `expires != 0 && expires + S
 * <= now` (S = max skew = nats_reap_grace).  The writer MUST NOT iterate the
 * other, merged-in contacts and delete ones it judges expired by node-local
 * `now`: usrloc flushes only a delta, so a node whose clock leads by S would
 * otherwise collaterally delete another node's still-live binding — a wrongful,
 * unrecoverable deletion.  Bulk expiry of untouched contacts is the reaper's job.
 *
 * The safety property is STRUCTURAL: the drop set is built only from the touched
 * pairs, so an untouched contact is never even considered — proven below by
 * keeping an untouched-yet-expired contact while dropping a touched-and-expired
 * one in the same row.
 *
 * On the real cdbn_row_drop_expired_own() with real update pairs (a
 * contacts subkey pair carrying {"expires": N}); the carried
 * contact_is_expired / contacts_drop_subkeys and the variant are gone.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e (a node with a leading clock
 * must not delete another node's live binding) vs the production merge.
 */
#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"

#define CHECK(cond, msg) ok((cond), "write_hygiene_scope: %s", (msg))

static int has(const char *hay, const char *needle) { return hay && strstr(hay, needle) != NULL; }

/* drop the touched (@ids, new expiries @exps) that are already expired */
static char *own(const char *doc, const char **ids, const int64_t *exps, int n,
	time_t now, int grace)
{
	cdb_dict_t pairs;
	int i, len = -1;
	char *o;

	INIT_LIST_HEAD(&pairs);
	for (i = 0; i < n; i++) {
		cdb_pair_t *p;

		p = cn_ut_mk_pair("contacts", 8, ids[i], (int)strlen(ids[i]));
		if (!p)
			return NULL;
		p->val.type = CDB_DICT;
		INIT_LIST_HEAD(&p->val.val.dict);
		cdb_dict_add_int64(&p->val.val.dict, "expires", 7, (uint64_t)exps[i]);
		cdb_dict_add(p, &pairs);
	}
	o = cdbn_row_drop_expired_own(doc, (int)strlen(doc), &pairs, now, grace, &len);
	cdb_free_entries(&pairs, NULL);
	return o;
}

/* is one touched contact with new expiry @e dropped (now=1000, S=5)? */
static int expired(int64_t e)
{
	const char *ids[1] = { "c" };
	char *o = own("{\"contacts\":{\"c\":{\"expires\":1}}}", ids, &e, 1, 1000, 5);
	int r = o ? !has(o, "\"c\":") : -1;

	if (o)
		pkg_free(o);
	return r;
}

void cn_ut_write_hygiene_scope(void)
{
	char *o;

	diag("expiry decision (now=1000, grace S=5):");
	CHECK(expired(990) == 1, "990+5<=1000 => expired");
	CHECK(expired(995) == 1, "995+5==1000 boundary => expired");
	CHECK(expired(996) == 0, "996+5>1000 => live (within skew)");
	CHECK(expired(2000) == 0, "future expiry => live");
	CHECK(expired(0) == 0, "expires==0 (permanent) => never expired");
	CHECK(expired(5000000000LL) == 0, "int64 future expiry => live");

	diag("drops exactly the touched-expired subkeys:");
	{
		const char *ids[1] = { "b" };
		int64_t e[1] = { 1 };
		o = own("{\"contacts\":{\"a\":{\"expires\":1},\"b\":{\"expires\":2},\"c\":{\"expires\":3}},\"aorhash\":7}",
			ids, e, 1, 1000, 5);
		CHECK(has(o, "\"a\":") && has(o, "\"c\":") && !has(o, "\"b\":"), "drop middle 'b' keeps a,c");
		CHECK(has(o, "\"aorhash\":7"), "aorhash preserved");
		if (o) pkg_free(o);
	}
	{
		const char *ids[2] = { "a", "b" };
		int64_t e[2] = { 1, 2 };
		o = own("{\"contacts\":{\"a\":{\"expires\":1},\"b\":{\"expires\":2}}}", ids, e, 2, 1000, 5);
		CHECK(has(o, "\"contacts\":{}"), "drop all => empty contacts {}");
		if (o) pkg_free(o);
	}
	{
		const char *ids[1] = { "zzz" };
		int64_t e[1] = { 1 };
		o = own("{\"contacts\":{\"a\":{\"expires\":1}},\"aorhash\":7}", ids, e, 1, 1000, 5);
		CHECK(has(o, "\"a\":"), "drop nonexistent id => unchanged");
		if (o) pkg_free(o);
		o = own("{\"foo\":1,\"bar\":\"x\"}", ids, e, 1, 1000, 5);
		CHECK(o && !strcmp(o, "{\"foo\":1,\"bar\":\"x\"}"), "non-contacts doc unchanged");
		if (o) pkg_free(o);
	}

	diag("scope: touched-expired dropped, touched-live + UNTOUCHED kept:");
	{
		const char *ids[2] = { "own_exp", "own_live" };
		int64_t e[2] = { 900, 2000 };
		o = own("{\"contacts\":{\"own_exp\":{\"expires\":900},\"own_live\":{\"expires\":2000},"
			"\"other_exp\":{\"expires\":100}},\"aorhash\":7}", ids, e, 2, 1000, 5);
		CHECK(!has(o, "\"own_exp\":"), "touched + expired 'own_exp' dropped");
		CHECK(has(o, "\"own_live\":"), "touched + live 'own_live' kept");
		CHECK(has(o, "\"other_exp\":"), "UNTOUCHED expired 'other_exp' KEPT (no collateral delete)");
		if (o) pkg_free(o);
	}
}
