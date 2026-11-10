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
 * The cdb_row_t handed back
 * to usrloc must be exactly {contacts, aorhash}.  `row_exp` and `schema_version`
 * are cachedb_nats-PRIVATE top-level peers (reaper/expiry + mixed-version
 * metadata); usrloc must never see them.  They are stripped at row assembly —
 * top-level peers, not members of any contact subdict, so the strip is a
 * top-level walk, not a per-contact one.
 *
 * This Tier-1 exercises the real intrusive-list surgery with the SAME list.h
 * primitives the production strip uses (list_for_each_safe / list_del), so ASan
 * catches a use-after-free / skipped-node / leak in the removal loop.  A minimal
 * `tpair` mirrors cdb_pair_t {key.name, val.type, list}.
 *
 * On the real cdbn_row_strip_private_keys(), over rows parsed by the
 * read path's cdbn_safe_json_to_dict() (the carried pair model and
 * STRIP_CURRENT are gone).  Added: a private peer of another type (a
 * string, an object) is stripped and freed too, and a row of private
 * peers only becomes empty.
 */
#include <tap.h>
#include <string.h>

#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"

#define CHECK(cond, msg) ok((cond), "strip_private_keys: %s", (msg))

static cdb_dict_t d;

static int parse_strip(const char *json)
{
	INIT_LIST_HEAD(&d);
	if (cdbn_safe_json_to_dict(json, (int)strlen(json), &d) < 0)
		return -1;
	cdbn_row_strip_private_keys(&d);
	return 0;
}

static int has_key(const char *k)
{
	struct list_head *it;

	list_for_each(it, &d) {
		cdb_pair_t *p = list_entry(it, cdb_pair_t, list);
		if (p->key.name.len == (int)strlen(k) && !memcmp(p->key.name.s, k, p->key.name.len))
			return 1;
	}
	return 0;
}

static int count(void)
{
	struct list_head *it;
	int n = 0;

	list_for_each(it, &d)
		n++;
	return n;
}

void cn_ut_strip_private_keys(void)
{
	diag("private peers stripped (head, middle), public shape preserved:");
	CHECK(parse_strip("{\"schema_version\":1,\"contacts\":{\"c1\":{\"expires\":0}},"
		"\"row_exp\":0,\"aorhash\":7}") == 0, "row parsed");
	CHECK(!has_key("row_exp"), "row_exp stripped");
	CHECK(!has_key("schema_version"), "schema_version stripped");
	CHECK(has_key("contacts"), "contacts retained");
	CHECK(has_key("aorhash"), "aorhash retained");
	CHECK(count() == 2, "exactly {contacts, aorhash} remain");
	cdb_free_entries(&d, NULL);

	diag("precise name match (no false strip), tail position:");
	CHECK(parse_strip("{\"contacts\":{},\"aorhash\":7,\"row_exposure\":1,"
		"\"schema\":1,\"schema_version\":1}") == 0, "row parsed");
	CHECK(has_key("row_exposure"), "'row_exposure' NOT stripped (prefix, not row_exp)");
	CHECK(has_key("schema"), "'schema' NOT stripped (prefix, not schema_version)");
	CHECK(!has_key("schema_version"), "tail-position schema_version stripped");
	CHECK(count() == 4, "only schema_version removed: contacts+aorhash+row_exposure+schema");
	cdb_free_entries(&d, NULL);

	diag("adversarial:");
	CHECK(parse_strip("{\"row_exp\":\"x\",\"schema_version\":{\"a\":1},\"aorhash\":7}") == 0
		&& count() == 1 && has_key("aorhash"),
		"private peers of another type (string, object) stripped too");
	cdb_free_entries(&d, NULL);
	CHECK(parse_strip("{\"row_exp\":1,\"schema_version\":1}") == 0 && count() == 0,
		"a row of private peers only becomes empty");
	cdb_free_entries(&d, NULL);
	cdbn_row_strip_private_keys(NULL);
	CHECK(1, "a NULL dict is a no-op");
}
