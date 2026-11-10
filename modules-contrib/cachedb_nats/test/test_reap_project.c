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
 * The reaper's per-row projection (cdbn_reap_project_survivors() and the
 * due gate cdbn_reap_row_due_json()): drop the contacts that are due,
 * recompute row_exp over the survivors, keep the rest of the document.
 * Replaces tests/test_reap_project.c, whose carried copy had drifted from
 * production (6 arguments; production takes 8 and also returns row_exp).
 * Same cases and expected values; row_exp is read from the function's own
 * out-parameter instead of being parsed back out of the document.
 *
 * A contact is due when expires + grace <= now (inclusive); a contact
 * with no integer expires is due (fail-closed); expires == 0 is permanent.
 */

#include <tap.h>
#include <string.h>
#include <time.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"

#define NOW 1000
#define S 5

static int n;
static int64_t rexp;

/* the projection of `doc`; n and rexp get its survivor count and row_exp */
static char *proj(const char *doc)
{
	int len = 0, same = 0;

	n = -99;
	rexp = -99;
	return cdbn_reap_project_survivors(doc, doc ? (int)strlen(doc) : 5,
		(time_t)NOW, S, &n, &len, &rexp, &same);
}

static int count(const char *hay, const char *needle)
{
	int c = 0;
	const char *p = hay;

	while ((p = strstr(p, needle)) != NULL) {
		c++;
		p += strlen(needle);
	}
	return c;
}

#define T(cond, msg) ok((cond), "reap_project: %s", (msg))

void cn_ut_reap_project(void)
{
	char *o;

	o = proj("{\"contacts\":{\"a\":{\"expires\":900},\"b\":{\"expires\":5000}},\"aorhash\":7}");
	T(o != NULL, "projection returns a document");
	T(n == 1, "exactly 1 survivor (b live, a due at 900+5<=1000)");
	T(o && strstr(o, "\"b\":") != NULL, "live contact b retained");
	T(o && strstr(o, "\"a\":") == NULL, "due contact a dropped");
	T(rexp == 5000, "row_exp recomputed over SURVIVORS (5000), not 900");
	T(o && strstr(o, "\"aorhash\":7") != NULL, "other top-level fields preserved");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"expires\":995}}}");
	T(o && n == 0, "expires 995 + grace 5 == now 1000 => due (0 survivors)");
	T(o && strstr(o, "\"a\":") == NULL, "boundary contact dropped");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"expires\":996}}}");
	T(o && n == 1, "expires 996 + grace 5 > now => kept");
	T(rexp == 996, "row_exp == 996");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"callid\":\"x\"},\"b\":{\"expires\":5000}}}");
	T(o && n == 1, "unprovable contact a dropped, b survives");
	T(o && strstr(o, "\"a\":") == NULL, "absent-expires contact dropped (fail-closed)");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"expires\":0},\"b\":{\"expires\":900}}}");
	T(o && n == 1, "permanent a kept, expired b dropped");
	T(o && strstr(o, "\"a\":") != NULL, "permanent contact retained");
	T(rexp == 0, "any permanent survivor => row_exp 0");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"expires\":900},\"b\":{\"expires\":800}},\"aorhash\":7}");
	T(o && n == 0, "all contacts due => 0 survivors");
	T(o && strstr(o, "\"contacts\":{}") != NULL, "empty contacts object emitted");
	T(rexp == 0, "row_exp 0 over empty survivor set");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"expires\":5000},\"b\":{\"expires\":4000}}}");
	T(o && n == 2, "both live => 2 survivors");
	T(rexp == 4000, "row_exp == min(5000,4000) == 4000");
	if (o) pkg_free(o);

	o = proj("{\"contacts\":{\"a\":{\"expires\":5000}},\"row_exp\":111,\"schema_version\":1}");
	T(rexp == 5000, "stale row_exp:111 recomputed to 5000");
	T(o && count(o, "\"row_exp\"") == 1, "exactly one row_exp key");
	T(o && count(o, "\"schema_version\"") == 1, "exactly one schema_version key");
	if (o) pkg_free(o);

	o = proj("{\"foo\":1}");
	T(o && n == -1, "no contacts => n_survivors -1 (reaper skips)");
	T(o && strcmp(o, "{\"foo\":1}") == 0, "doc returned byte-for-byte");
	if (o) pkg_free(o);

	T(cdbn_reap_row_due_json("{\"row_exp\":900}", 15, NOW, S) == 1, "row_exp 900 +5<=1000 => due (1)");
	T(cdbn_reap_row_due_json("{\"row_exp\":996}", 15, NOW, S) == 0, "row_exp 996 +5>1000 => not due (0)");
	T(cdbn_reap_row_due_json("{\"row_exp\":0}", 13, NOW, S) == 0, "row_exp 0 (permanent) => never due (0)");
	T(cdbn_reap_row_due_json("{\"aorhash\":7}", 13, NOW, S) == -1, "absent row_exp => -1 (legacy, fail-closed project)");
	T(cdbn_reap_row_due_json("{\"row_exp\":5000000000}", 22, NOW, S) == 0, "post-2038 row_exp not due (int64, no clamp)");

	T(proj("[1,2,3]") == NULL, "non-object top-level => NULL");
	T(proj("{\"contacts\":}") == NULL, "contacts value not an object => NULL");
	T(proj("") == NULL, "empty => NULL");
	T(proj(NULL) == NULL, "NULL => NULL");
}
