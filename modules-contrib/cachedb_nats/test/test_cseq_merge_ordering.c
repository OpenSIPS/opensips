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
 * Same-subkey merge ordering.
 *
 * On a collision for the SAME contact subkey, the merge MUST keep the higher
 * `cseq` (tie-broken by `last_mod`) and discard a stale write — even if its CAS
 * would otherwise succeed.  CAS alone protects the row across DIFFERENT contacts;
 * without a cseq check the same-contact path is blind last-writer-wins and can
 * roll a binding backward versus the SQL backend (e.g. a delayed/retransmitted
 * REGISTER with an older cseq overwriting the current binding).
 *
 * The decision engages ONLY when BOTH values carry a `cseq` (usrloc contacts).
 * For any other subkey (a non-usrloc cachedb_nats consumer, or a value that is
 * not a JSON object), cdbn_cseq_new_wins returns 1 → last-writer-wins, exactly the
 * generic merge's current behavior (so the existing merge tests are unaffected).
 *
 * Runs on the production code (carried copies and the variant
 * build are gone).
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e (an out-of-order REGISTER
 * must not roll a binding backward) vs the production sink_merge_subkeys.
 */
#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

#define CHECK(cond, msg) do { if (!(cond)) { fail("cseq_merge_ordering: %s", msg); } \
	else pass("cseq_merge_ordering: %s", msg); } while (0)
/* wins(new, old): does the new value supersede the old? */
static int wins(const char *n, const char *o)
{ return cdbn_cseq_new_wins(n, (int)strlen(n), o, (int)strlen(o)); }

void cn_ut_cseq_merge_ordering(void)
{

	diag("higher cseq wins:");
	CHECK(wins("{\"cseq\":5,\"ua\":\"new\"}", "{\"cseq\":3,\"ua\":\"old\"}") == 1,
	      "new cseq 5 > old 3 => new wins (overwrite)");
	/* the load-bearing case: a STALE write (lower cseq) must be DISCARDED. */
	CHECK(wins("{\"cseq\":3,\"ua\":\"stale\"}", "{\"cseq\":5,\"ua\":\"cur\"}") == 0,
	      "new cseq 3 < old 5 => stale discarded (keep existing)");
	CHECK(wins("{\"cseq\":100}", "{\"cseq\":99}") == 1, "100 > 99 => new");
	CHECK(wins("{\"cseq\":99}", "{\"cseq\":100}") == 0, "99 < 100 => old");

	diag("tie on cseq => higher last_mod wins:");
	CHECK(wins("{\"cseq\":5,\"last_mod\":2000}", "{\"cseq\":5,\"last_mod\":1000}") == 1,
	      "equal cseq, newer last_mod => new wins");
	CHECK(wins("{\"cseq\":5,\"last_mod\":1000}", "{\"cseq\":5,\"last_mod\":2000}") == 0,
	      "equal cseq, older last_mod => stale discarded");
	CHECK(wins("{\"cseq\":5,\"last_mod\":1000}", "{\"cseq\":5,\"last_mod\":1000}") == 0,
	      "exact duplicate (cseq+last_mod equal) => discarded (not strictly newer)");
	CHECK(wins("{\"cseq\":5,\"last_mod\":5000000000}", "{\"cseq\":5,\"last_mod\":4000000000}") == 1,
	      "int64 last_mod tie-break (post-2038)");

	diag("last-writer-wins fallback when cseq is absent:");
	CHECK(wins("{\"ua\":\"x\"}", "{\"cseq\":5}") == 1, "new lacks cseq => overwrite (current behavior)");
	CHECK(wins("{\"cseq\":3}", "{\"ua\":\"x\"}") == 1, "old lacks cseq => overwrite");
	CHECK(wins("{\"ua\":\"a\"}", "{\"ua\":\"b\"}") == 1, "neither has cseq => overwrite (non-usrloc subkey)");
	CHECK(wins("\"a string\"", "{\"cseq\":5}") == 1, "new not an object => overwrite");
	CHECK(wins("{\"cseq\":5}", "42") == 1, "old not an object => overwrite");

	diag("adversarial: tie with one side missing last_mod:");
	CHECK(wins("{\"cseq\":5,\"last_mod\":1}", "{\"cseq\":5}") == 1, "new has last_mod 1, old missing(0) => new wins");
	CHECK(wins("{\"cseq\":5}", "{\"cseq\":5,\"last_mod\":1}") == 0, "new missing last_mod(0) < old 1 => discarded");
	CHECK(wins("{\"cseq\":-1}", "{\"cseq\":-2}") == 1, "signed cseq compare (-1 > -2)");
}
