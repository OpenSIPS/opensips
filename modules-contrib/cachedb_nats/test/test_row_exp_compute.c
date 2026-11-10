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
 * Compute the
 * row-level expiry sentinel `row_exp` from the merged contact set and emit it
 * (plus `schema_version`) as cachedb_nats-private top-level peers, WITHOUT
 * disturbing a non-usrloc document.
 *
 * Part A — row_exp_min(exp[], n):
 *   - 0 is the "permanent / never auto-expire" sentinel.  expires==0 means a
 *     permanent contact; if ANY contact is permanent the whole row is
 *     permanent => row_exp == 0.
 *   - an empty contact set (or NULL) yields 0 (nothing to expire).
 *   - otherwise row_exp == min(expires) over the contacts.
 *   - int64 THROUGHOUT: no int32 clamp, so post-2038 epochs survive.
 *   - only 0 is the sentinel; a negative (already-past) expiry is a real
 *     candidate value, NOT a permanent marker.
 *
 * Part B — cdbn_row_finalize_metadata(json,len): recompute row_exp+schema_version
 *   over the MERGED contacts and re-emit them as top-level peers
 *, replacing any stale ones; a document with no top-level
 *   "contacts" object is returned byte-for-byte unchanged (other cachedb_nats
 *   consumers must never be reshaped).
 *
 * Runs on the production code (carried copies and the variant
 * build are gone).
 *                               clamps/mis-drives both row_exp_min AND the
 *                               row_exp emitted by cdbn_row_finalize_metadata
 *
 * Rule 6: the GREEN copy here mirrors the production helpers in
 * cachedb_nats_json.c; the AUTHORITATIVE round-trip proof is the Tier-2
 * test_usrloc_roundtrip_int64_e2e.sh vs production.
 */
#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../cachedb_nats_json_internal.h"
#include "../cachedb_nats_expiry.h"
#include "../../../mem/mem.h"

#include "cn_ut.h"

#define CHECK(cond, msg) do { if (!(cond)) { fail("row_exp_compute: %s", msg); } \
	else pass("row_exp_compute: %s", msg); } while (0)

/* row_exp of a row whose contacts expire at @exp (via finalize; the
 * min helper itself is static) */
static int64_t row_exp_min(const int64_t *exp, int n)
{
	char doc[512];
	int w, i, ol;
	int64_t re = INT64_MIN;
	char *o;

	if (!exp)
		n = 0;            /* "NULL set" = a row with no contacts */
	w = snprintf(doc, sizeof doc, "{\"contacts\":{");
	for (i = 0; i < n; i++)
		w += snprintf(doc + w, sizeof doc - w, "%s\"c%d\":{\"expires\":%lld}",
			i ? "," : "", i, (long long)exp[i]);
	snprintf(doc + w, sizeof doc - w, "}}");
	o = cdbn_row_finalize_metadata(doc, (int)strlen(doc), &ol, &re, NULL, NULL);
	if (!o)
		return INT64_MIN;
	pkg_free(o);
	return re;
}

#define EXPECT(arr, want, msg) do { \
	int64_t _g = row_exp_min((arr), (int)(sizeof(arr)/sizeof((arr)[0]))); \
	if (_g != (want)) { fail("row_exp_compute: %s (got %lld want %lld)", msg, \
		(long long)_g, (long long)(want)); } \
	else pass("row_exp_compute: %s", msg); } while (0)

/* Extract the int64 immediately after the first "row_exp": in @out. */
static int64_t _rowexp_of(const char *out)
{
	const char *m = strstr(out, "\"row_exp\":");
	if (!m) return INT64_MIN;
	m += strlen("\"row_exp\":");
	return (int64_t)strtoll(m, NULL, 10);
}
static int _count(const char *hay, const char *needle)
{
	int c = 0; const char *p = hay;
	while ((p = strstr(p, needle))) { c++; p += strlen(needle); }
	return c;
}
/* finalize a literal doc; returns pkg output (caller pkg_frees). */
static char *_fin(const char *doc)
{
	int ol;
	return cdbn_row_finalize_metadata(doc, (int)strlen(doc), &ol, NULL, NULL, NULL);
}

void cn_ut_row_exp_compute(void)
{

	diag("[A] min over non-zero expiries:");
	{ int64_t a[] = {100, 50, 200};   EXPECT(a, 50,  "min{100,50,200} == 50"); }
	{ int64_t a[] = {200, 100, 50};   EXPECT(a, 50,  "order-independent: min{200,100,50} == 50"); }
	{ int64_t a[] = {42};             EXPECT(a, 42,  "single contact => its own expiry"); }

	diag("[A] any expires==0 (permanent) => row_exp==0:");
	{ int64_t a[] = {100, 0, 50};     EXPECT(a, 0,   "permanent contact present => 0"); }
	{ int64_t a[] = {0, 0};           EXPECT(a, 0,   "all permanent => 0"); }
	{ int64_t a[] = {-5, 0, 100};     EXPECT(a, 0,   "permanent beats a past expiry => 0"); }

	diag("[A] empty / NULL set => 0:");
	CHECK(row_exp_min(NULL, 0) == 0, "NULL,0 => 0");
	CHECK(row_exp_min(NULL, 5) == 0, "NULL,n => 0 (defensive)");
	{ int64_t a[] = {7}; CHECK(row_exp_min(a, 0) == 0, "n==0 => 0 (empty contact set)"); }

	diag("[A] int64: no int32 clamp (post-2038 epochs survive):");
	{ int64_t a[] = {5000000000LL, 4000000000LL}; EXPECT(a, 4000000000LL, "min of >2038 epochs preserved"); }
	{ int64_t a[] = {1LL << 40};      EXPECT(a, 1LL << 40, "single 2^40 expiry not truncated"); }
	{ int64_t a[] = {1LL << 40, 0};   EXPECT(a, 0,        "permanent still wins over a huge expiry"); }
	{ int64_t a[] = {INT64_MAX, 9000000000LL}; EXPECT(a, 9000000000LL, "INT64_MAX never the min here"); }

	diag("[A] adversarial: negatives are real candidates (only 0 is sentinel):");
	{ int64_t a[] = {-5, 100};        EXPECT(a, -5, "negative (past) expiry is the min => row due now"); }
	{ int64_t a[] = {-1};             EXPECT(a, -1, "lone negative preserved (not treated as permanent)"); }

	diag("[B] finalize emits row_exp + schema_version peers:");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":100},\"c2\":{\"expires\":50}},\"aorhash\":7}");
	  CHECK(o != NULL, "finalize returns a document");
	  CHECK(o && _rowexp_of(o) == 50, "row_exp == min(100,50) == 50");
	  CHECK(o && strstr(o, "\"schema_version\":1") != NULL, "schema_version:1 emitted");
	  CHECK(o && strstr(o, "\"aorhash\":7") != NULL, "aorhash preserved");
	  CHECK(o && strstr(o, "\"contacts\":") != NULL, "contacts preserved");
	  if (o) pkg_free(o); }

	diag("[B] permanent contact => row_exp 0 in output:");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":0},\"c2\":{\"expires\":50}},\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 0, "permanent member => row_exp 0"); if (o) pkg_free(o); }

	diag("[B] int64 expiry survives the finalize emit:");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":5000000000}},\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 5000000000LL, "row_exp 5e9 emitted intact (no int32 clamp)"); if (o) pkg_free(o); }

	diag("[B] stale private peers are replaced, not duplicated:");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":50}},\"row_exp\":999,\"schema_version\":1,\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 50, "stale row_exp:999 recomputed to 50");
	  CHECK(o && _count(o, "\"row_exp\"") == 1, "exactly one row_exp key");
	  CHECK(o && _count(o, "\"schema_version\"") == 1, "exactly one schema_version key");
	  if (o) pkg_free(o); }

	diag("[B] empty contacts object => row_exp 0:");
	{ char *o = _fin("{\"contacts\":{},\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 0, "no contacts => row_exp 0"); if (o) pkg_free(o); }

	diag("[B] non-usrloc doc (no contacts) returned byte-for-byte:");
	{ const char *in = "{\"foo\":1,\"bar\":\"x\"}";
	  char *o = _fin(in);
	  CHECK(o && strcmp(o, in) == 0, "doc without contacts unchanged");
	  CHECK(o && strstr(o, "row_exp") == NULL, "no row_exp injected into non-usrloc doc");
	  if (o) pkg_free(o); }
}
