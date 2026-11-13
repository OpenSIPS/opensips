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
 * Migration /
 * mixed-version read tolerance for the cachedb_nats-private `schema_version`
 * top-level peer.
 *
 * On a rolling upgrade the bucket is SHARED by old and new nodes:
 *   - a LEGACY row was written before schema_version existed => NO schema_version;
 *   - a NEWER node may write a HIGHER schema_version than this node knows.
 * The read path MUST tolerate both — read best-effort, NEVER reject a row or
 * crash on the version value — or every real upgrade breaks.
 *
 * The production read path achieves this STRUCTURALLY: `is_private_top_key`
 * matches "schema_version" (and "row_exp") by NAME and `cdbn_row_strip_private_keys`
 * removes the peer before usrloc sees it; the version VALUE is never parsed or
 * branched on.  So absent / 1 / any-higher all read identically.
 *
 * This test pins that invariant two ways:
 *   (1) the carried `is_private_top_key` strips schema_version by NAME for any
 *       value (it never inspects the value);
 *   (2) a carried `_schema_read_accept(present, version)` models the read
 *       decision: the lenient (production) reader ACCEPTS every shape; the RED
 *       arm models the feared regression — a strict validator that rejects an
 *       absent or unknown-higher version, which would break every upgrade.
 *
 * On the real cdbn_row_strip_private_keys and a real primary-key read
 * (nats_cache_query on fakes, cn_ut_pk_read): rows without, with the
 * current, with a future or a nonsense schema_version are all read, and
 * the private peers never reach usrloc.  The SCHEMA_STRICT variant and the
 * carried model are gone.
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

#define CHECK(cond, msg) ok((cond), "schema_version_legacy: %s", (msg))

/* is @name still in the dict after the private peers are stripped? */
static int kept(const char *name)
{
	static const char *names[] = { "schema_version", "row_exp", "contacts",
		"aorhash", "schema_versio", "schema_version2", "Schema_Version" };
	cdb_dict_t d;
	struct list_head *it;
	unsigned i;
	int found = 0;

	INIT_LIST_HEAD(&d);
	for (i = 0; i < sizeof names / sizeof names[0]; i++)
		cdb_dict_add_int32(&d, names[i], (int)strlen(names[i]), 1);
	cdbn_row_strip_private_keys(&d);
	list_for_each(it, &d) {
		cdb_pair_t *p = list_entry(it, cdb_pair_t, list);
		if (p->key.name.len == (int)strlen(name) &&
				!memcmp(p->key.name.s, name, p->key.name.len))
			found = 1;
	}
	cdb_free_entries(&d, NULL);
	return found;
}

static void read_row(const char *label, const char *sv)
{
	char row[256];
	int rows, nc, np;

	snprintf(row, sizeof row, "{\"aor\":\"alice\",\"contacts\":{\"c1\":"
		"{\"expires\":0}}%s%s}", sv ? ",\"schema_version\":" : "", sv ? sv : "");
	rows = cn_ut_pk_read("alice", row, &nc, &np);
	ok(rows == 1 && nc == 1 && np == 0,
		"schema_version_legacy: %s => read, private peer stripped (rows %d, contacts %d, private %d)",
		label, rows, nc, np);
}

void cn_ut_schema_version_legacy(void)
{
	diag("schema_version is a private peer stripped by NAME (value never read):");
	CHECK(!kept("schema_version"), "\"schema_version\" => private (stripped)");
	CHECK(!kept("row_exp"), "\"row_exp\" => private (stripped)");
	CHECK(kept("contacts"), "\"contacts\" => NOT private (kept)");
	CHECK(kept("aorhash"), "\"aorhash\" => NOT private (kept)");
	CHECK(kept("schema_versio"), "truncated name => not matched");
	CHECK(kept("schema_version2"), "longer name => not matched");
	CHECK(kept("Schema_Version"), "other case => not matched (names are exact)");

	diag("the read path accepts legacy AND future rows (read best-effort):");
	cn_ut_fake_begin();
	read_row("LEGACY: schema_version ABSENT", NULL);
	read_row("current: schema_version=1", "1");
	read_row("FUTURE: schema_version=2", "2");
	read_row("FUTURE: schema_version=99", "99");
	read_row("odd: schema_version=0", "0");
	read_row("boundary: schema_version=INT_MAX", "2147483647");
	read_row("adversarial: negative schema_version", "-1");
	read_row("adversarial: a string schema_version", "\"v2\"");
	cn_ut_fake_end();
}
