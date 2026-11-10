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
 * Registration-observability MI: cdbn_reg_row_scan -- one pass over a
 * stored usrloc row producing the per-AoR summary the MI commands (and the
 * reaper's piggybacked gauges) are built from:
 *
 *   aor slice, stored/active/expired/permanent contact counts,
 *   soonest non-permanent expiry (INT64_MAX when nothing expires),
 *   max last_mod, and ua=/contact= substring hits (raw, escaped text).
 *
 * Fail-closed rules (mirror the read path): a contact whose `expires` is
 * absent or non-integer counts as EXPIRED (stored but never served) and
 * contributes nothing to soonest_exp; a contacts member that is not an
 * object counts the same way.  A doc without a top-level "contacts" object
 * is NOT a usrloc row (-1) -- the MI must count it as other_docs, never
 * guess.
 *
 *                                active contact, no fail-closed handling,
 * Runs on the production code (carried copies and the variant
 * build are gone).
 */
#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "../cachedb_nats_reg.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"


#define CHECK(cond, msg) do { if (!(cond)) { fail("reg_row_scan: %s", msg); } \
	else pass("reg_row_scan: %s", msg); } while (0)

void cn_ut_reg_row_scan(void)
{
	struct reg_row_info o;
	const time_t NOW = 1000000;
	const int G = 5;

	diag("typical mixed row: active + expired + permanent:");
	{
		const char *doc =
			"{\"aor\":\"alice@example.com\",\"aorhash\":7,\"contacts\":{"
			"\"k1\":{\"contact\":\"sip:a@10.0.0.1:5060\",\"expires\":1000100,"
			"\"ua\":\"Yealink T54W\",\"last_mod\":999990},"
			"\"k2\":{\"contact\":\"sip:a@10.0.0.2:5060\",\"expires\":999900,"
			"\"ua\":\"Zoiper 5\",\"last_mod\":999500},"
			"\"k3\":{\"contact\":\"sip:a@10.0.0.3:5060\",\"expires\":0,"
			"\"last_mod\":999999}"
			"},\"row_exp\":1000100,\"schema_version\":1}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0, "usrloc row recognized");
		CHECK(o.aor_len == 17 && memcmp(o.aor, "alice@example.com", 17) == 0,
			"aor slice extracted");
		CHECK(o.n_contacts == 3, "3 stored contacts");
		CHECK(o.n_active == 1, "1 active (k1: future expiry)");
		CHECK(o.n_expired == 1, "1 expired (k2: past expires+grace)");
		CHECK(o.n_perm == 1, "1 permanent (k3: expires=0)");
		CHECK(o.soonest_exp == 1000100,
			"soonest = the ACTIVE upcoming expiry (dead k2 does not rank)");
		CHECK(o.last_mod == 999999, "last_mod = max over contacts");
	}

	diag("ua=/contact= substring hits over raw (escaped) values:");
	{
		const char *doc =
			"{\"aor\":\"b@x\",\"contacts\":{"
			"\"k1\":{\"expires\":1000100,\"ua\":\"evil\\\"quote agent\","
			"\"contact\":\"sip:b@host;transport=tcp\"}}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			"quote", 5, NULL, 0, &o) == 0 && o.ua_hit == 1,
			"ua needle matches across an escaped quote (raw text match)");
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			"Yealink", 7, NULL, 0, &o) == 0 && o.ua_hit == 0,
			"non-matching ua needle: no hit");
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, "transport=tcp", 13, &o) == 0 && o.ct_hit == 1,
			"contact needle matches inside the URI ('=' in value)");
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, "callid", 6, &o) == 0 && o.ct_hit == 0,
			"needles never match OTHER fields (no cross-field bleed)");
	}

	diag("fail-closed classification:");
	{
		const char *doc =
			"{\"aor\":\"c@x\",\"contacts\":{"
			"\"k1\":{\"ua\":\"noexp\"},"
			"\"k2\":{\"expires\":\"1000100\"},"
			"\"k3\":7,"
			"\"k4\":{\"expires\":1000100}}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0, "row with poison members still scans");
		CHECK(o.n_contacts == 4, "all 4 stored members counted");
		CHECK(o.n_expired == 3,
			"missing expires, string expires, non-object member: ALL fail closed");
		CHECK(o.n_active == 1 && o.soonest_exp == 1000100,
			"the one well-formed contact classifies normally");
	}

	diag("boundary + big values:");
	{
		const char *doc =
			"{\"aor\":\"d@x\",\"contacts\":{"
			"\"k1\":{\"expires\":999995},"
			"\"k2\":{\"expires\":5000000000}}}";
		/* k1: expires+grace == now exactly => expired (mirrors read filter) */
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0 &&
			o.n_expired == 1 && o.n_active == 1,
			"expires+grace==now boundary => expired");
		CHECK(o.soonest_exp == 5000000000LL, "post-2038 expiry survives (int64)");
	}

	diag("empty / degenerate rows:");
	{
		const char *doc = "{\"aor\":\"e@x\",\"contacts\":{}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0 &&
			o.n_contacts == 0 && o.soonest_exp == REG_NO_EXPIRY,
			"empty contacts: zero counts, no-expiry sentinel");
	}
	{
		const char *doc = "{\"x\":1}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == -1,
			"doc without contacts => NOT a usrloc row (-1, counted as other)");
	}
	{
		const char *doc = "{\"aor\":\"f@x\",\"contacts\":[1,2]}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == -1,
			"contacts not an object => refused, never guessed");
	}
	{
		const char *doc = "not json at all";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == -1, "non-JSON => -1");
	}

	diag("backslash torture (keys and values):");
	{
		const char *doc =
			"{\"aor\":\"g\\\\@x\",\"contacts\":{"
			"\"k\\\\1\":{\"expires\":1000100,\"ua\":\"back\\\\slash\"}}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			"back\\\\slash", 11, NULL, 0, &o) == 0 &&
			o.n_active == 1 && o.ua_hit == 1,
			"escaped backslashes in key/value do not derail the walk");
	}
}
