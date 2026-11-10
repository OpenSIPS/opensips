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
 * Read-side expiry filter.
 *
 * On query(), each contact in the row is filtered before usrloc sees it:
 *   - expires == 0  (permanent)            -> ALWAYS emitted;
 *   - expires != 0 && expires + S <= now   -> OMITTED (S = nats_reap_grace);
 *   - absent / unparseable expires         -> treated EXPIRED, omitted
 *                                             (fail-closed: never serve an
 *                                             unparseable binding);
 *   - else (live)                          -> emitted.
 * G2 is defense-in-depth atop usrloc's own VALID_CONTACT re-check; with no
 * in-memory copy the reaper is the sole *physical* cleanup, so the read MUST
 * perform ZERO writes — no inline purge/CAS (asserted by the Tier-2 e2e).  If
 * every contact is filtered the row is returned with an empty contacts dict.
 *
 * _omit_contact(has_expires, expires, now, grace): the per-contact decision
 * (1 = omit).  The surgery below removes omitted contacts from a list with the
 * SAME list.h primitives the production filter uses, so ASan catches a UAF /
 * skipped-node / leak in the removal loop.
 *
 * On the real read filter cdbn_row_filter_expired_contacts(), over rows
 * parsed by the module's own cdbn_safe_json_to_dict() (the read path's
 * parser).  The carried contact model and READFILT_CURRENT are gone.
 * Added: a non-integer and a negative expires.
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../cachedb_nats_json_internal.h"
#include "../../../cachedb/cachedb_dict.h"

#include "cn_ut.h"

#define CHECK(cond, msg) ok((cond), "read_expiry_filter: %s", (msg))

static cdb_dict_t row;

/* parse {"aor":..,"contacts":{<contacts>}} and run the read filter */
static int filter(const char *contacts, long now, int grace)
{
	char json[512];
	int n = snprintf(json, sizeof json, "{\"aor\":\"a\",\"contacts\":{%s}}", contacts);

	INIT_LIST_HEAD(&row);
	if (cdbn_safe_json_to_dict(json, n, &row) < 0)
		return -1;
	cdbn_row_filter_expired_contacts(&row, (time_t)now, grace);
	return 0;
}

static cdb_dict_t *contacts_of(void)
{
	struct list_head *it;

	list_for_each(it, &row) {
		cdb_pair_t *p = list_entry(it, cdb_pair_t, list);
		if (p->key.name.len == 8 && !memcmp(p->key.name.s, "contacts", 8) &&
				p->val.type == CDB_DICT)
			return &p->val.val.dict;
	}
	return NULL;
}

static int has_id(const char *id)
{
	cdb_dict_t *c = contacts_of();
	struct list_head *it;

	if (!c)
		return 0;
	list_for_each(it, c) {
		cdb_pair_t *p = list_entry(it, cdb_pair_t, list);
		if (p->key.name.len == (int)strlen(id) && !memcmp(p->key.name.s, id, p->key.name.len))
			return 1;
	}
	return 0;
}

static int count(void)
{
	cdb_dict_t *c = contacts_of();
	struct list_head *it;
	int n = 0;

	if (!c)
		return -1;
	list_for_each(it, c)
		n++;
	return n;
}

/* one contact: is it still served? */
static int served(const char *contact, long now, int grace)
{
	char c[128];
	int r;

	snprintf(c, sizeof c, "\"c\":%s", contact);
	if (filter(c, now, grace) < 0)
		return -1;
	r = has_id("c");
	cdb_free_entries(&row, NULL);
	return r;
}

void cn_ut_read_expiry_filter(void)
{
	const long now = 1000;
	const int S = 5;

	diag("per-contact decision (now=1000, S=5):");
	CHECK(served("{\"expires\":2000}", now, S) == 1, "future expiry => emitted");
	CHECK(served("{\"expires\":996}", now, S) == 1, "996+5>1000 => live, emitted (within skew)");
	CHECK(served("{\"expires\":995}", now, S) == 0, "995+5==1000 boundary => omitted");
	CHECK(served("{\"expires\":900}", now, S) == 0, "900+5<=1000 => expired, omitted");
	CHECK(served("{\"expires\":0}", now, S) == 1, "expires==0 (permanent) => ALWAYS emitted");
	CHECK(served("{\"ua\":\"x\"}", now, S) == 0, "absent expires => fail-closed, omitted");
	CHECK(served("{\"expires\":\"2000\"}", now, S) == 0, "a string expires => fail-closed, omitted");
	CHECK(served("{\"expires\":-5}", now, S) == 0, "a negative expires is in the past => omitted");

	diag("filter surgery keeps live+permanent, drops expired+absent:");
	CHECK(filter("\"live\":{\"expires\":2000},\"expired\":{\"expires\":900},"
		"\"perm\":{\"expires\":0},\"noexp\":{\"q\":1},\"boundary\":{\"expires\":995}",
		now, S) == 0, "row parsed");
	CHECK(has_id("live") && has_id("perm"), "live + permanent kept");
	CHECK(!has_id("expired"), "expired omitted");
	CHECK(!has_id("noexp"), "absent-expires omitted (fail-closed)");
	CHECK(!has_id("boundary"), "boundary expires+S==now omitted");
	CHECK(count() == 2, "exactly the 2 live/permanent contacts remain");
	cdb_free_entries(&row, NULL);

	diag("all-expired row => empty contacts (not an error):");
	CHECK(filter("\"a\":{\"expires\":100},\"b\":{\"q\":1}", now, S) == 0 && count() == 0,
		"every contact expired => empty contacts dict");
	cdb_free_entries(&row, NULL);
}
