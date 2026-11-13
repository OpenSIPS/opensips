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
 * Regression test: nats_cache_update treated NATS_NOT_FOUND from kvStore_Get
 * as a fatal error, so the very first cdbf.update() against a fresh AoR
 * key returned -1 and the contact never landed in NATS. usrloc relies on
 * cdbf.update having upsert semantics in cluster_mode=full-sharing-cachedb,
 * so this single bug blocked every initial REGISTER from being persisted.
 *
 * The fix synthesizes a seed JSON document {"<filter-field>":"<filter-val>"}
 * from the row_filter on first-create, attempts kvStore_CreateString to
 * place it atomically, and falls through to the existing apply-pairs +
 * UpdateString CAS path. If CreateString loses a race (another writer
 * created the key between our Get and our Create), the next CAS-loop
 * iteration's Get finds the now-existing doc and proceeds via Update.
 *
 * This file unit-tests the two helpers introduced for the fix:
 *   cdbn_build_seed_doc()    — render a single-field JSON object for the seed.
 *   _json_apply_pair()   — already covered by test_update_nested_dict, used
 *                          here to verify the seed → apply → final flow.
 *
 * REWORK: the first-insert path no
 * longer WRITES the seed.  The old flow (Get NOT_FOUND -> CreateString(seed)
 * -> CAS-update at the create's revision) left an un-TTL'd seed revision at
 * the bottom of the key's history; on a history-keeping bucket the key then
 * ROLLED BACK to that immortal seed when the TTL'd head expired.  Now update_fetch_or_seed returns the seed purely as the merge
 * base with rev==0 (JetStream sequences are 1-based, so 0 is unambiguous
 * "no prior message") and the single CAS write creates the FULL row with its
 * TTL.  The fetch decision skeleton below locks that contract:
 *
 * On the real cdbn_build_seed_doc (goldens A-E, F: the seed parses as
 * an object) and, for G, the real update on fakes (cn_ut_fake.h): a first
 * insert writes ONE create of the merged doc -- never a standalone seed
 * first (the immortal-seed bug) -- and marker / live rows are written at
 * their revision.  The fetch_or_seed_decision model is gone.
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb.h"
#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static void check(const char *label, char *out, const char *want)
{
	ok(out && !strcmp(out, want), "update_creates_doc: %s (got %s)", label, out ? out : "<NULL>");
	if (out)
		pkg_free(out);
}

static int count(const char *hay, const char *needle)
{
	int c = 0;
	const char *p = hay;

	while ((p = strstr(p, needle))) {
		c++;
		p += strlen(needle);
	}
	return c;
}

void cn_ut_update_creates_doc(void)
{
	char *out;
	int len, rc, parsed;
	cdb_dict_t d;
	cachedb_con con;
	nats_cachedb_con ncon;
	cdb_filter_t f;
	cdb_dict_t pairs;

	check("A: seed for usrloc-style AoR filter",
		cdbn_build_seed_doc("aor", 3, "alice@example.com", 17, &len),
		"{\"aor\":\"alice@example.com\"}");
	check("B: empty value yields empty quoted string",
		cdbn_build_seed_doc("aor", 3, "", 0, &len), "{\"aor\":\"\"}");
	check("C: null field yields empty object",
		cdbn_build_seed_doc(NULL, 0, "anything", 8, &len), "{}");
	check("D: value escaping works",
		cdbn_build_seed_doc("aor", 3, "ev\"il", 5, &len), "{\"aor\":\"ev\\\"il\"}");
	check("E: field-name escaping",
		cdbn_build_seed_doc("a\\b", 3, "v", 1, &len), "{\"a\\\\b\":\"v\"}");
	out = cdbn_build_seed_doc("aor", 3, "alice", 5, &len);
	INIT_LIST_HEAD(&d);
	parsed = out && cdbn_safe_json_to_dict(out, len, &d) == 0 && !list_empty(&d);
	ok(parsed, "update_creates_doc: F: seed parses as a JSON object");
	cdb_free_entries(&d, NULL);
	if (out)
		pkg_free(out);

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
	cdb_dict_add_int32(&pairs, "x", 1, 5);

	cf.get.status = NATS_NOT_FOUND;
	rc = nats_cache_update(&con, &f, &pairs);
	ok(rc == 0 && count(cf.seq, "create:") == 1 && count(cf.seq, "publish") == 0
		&& strstr(cf.published, "\"x\":5"),
		"update_creates_doc: G: first insert -> ONE create of the merged doc, no seed write (%s)", cf.seq);

	cf.seq[0] = '\0';
	cf.get.status = NATS_OK;                  /* a MaxAge marker at rev 9 */
	cf.get.val = NULL;
	cf.get.val_len = 0;
	cf.get.rev = 9;
	rc = nats_cache_update(&con, &f, &pairs);
	ok(rc == 0 && count(cf.seq, "publish:9,") == 1 && count(cf.seq, "create") == 0,
		"update_creates_doc: G: over a marker -> ONE write CAS'd at the marker rev (%s)", cf.seq);

	cf.seq[0] = '\0';
	cf.get.val = "{\"aor\":\"alice\"}";       /* a live row at rev 4 */
	cf.get.val_len = (int)strlen(cf.get.val);
	cf.get.rev = 4;
	rc = nats_cache_update(&con, &f, &pairs);
	ok(rc == 0 && count(cf.seq, "publish:4,") == 1,
		"update_creates_doc: G: live row -> CAS at the entry rev");
	cdb_free_entries(&pairs, NULL);
	cn_ut_fake_end();
}
