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
 * The search query (fts_query_match_keys() in fts_query.c): an AND chain
 * of field=value filters resolved against the index, on private index and
 * intern instances.  Replaces tests/test_query_keyset_refcount.c (a
 * refcount model plus greps) and tests/test_intersect_uaf.c (a carried
 * intersection under ASan).
 *
 * The matched keys are not copied under the index lock: the query hands
 * back the interned key pointers with one reference taken on each, and
 * fts_release_keyset() gives them back.  Over-releasing would free a key
 * the index still uses; under-releasing would leak it.  After a query and
 * its release every key's reference count is where it was before.
 */

#include <tap.h>
#include <string.h>

#include "../fts_index.h"
#include "../fts_intern.h"
#include "../../../cachedb/cachedb_types.h"

#include "fts_ut.h"

#define A "{\"f\":\"x\",\"g\":\"y\"}"
#define B "{\"f\":\"x\",\"g\":\"y\"}"
#define C "{\"f\":\"x\",\"g\":\"z\"}"
#define D "{\"f\":\"w\"}"

static const char *keys[] = { "q.A", "q.B", "q.C", "q.D" };
static const char *docs[] = { A, B, C, D };
static char *probe[4];
static int base[4];

static void filter(cdb_filter_t *f, const char *field, const char *value,
	cdb_filter_t *next)
{
	memset(f, 0, sizeof *f);
	f->key.name.s = (char *)field;
	f->key.name.len = (int)strlen(field);
	f->op = CDB_OP_EQ;
	f->val.is_str = 1;
	f->val.s.s = (char *)value;
	f->val.s.len = (int)strlen(value);
	f->next = next;
}

/* how many of keys[] are among out[0..n) */
static int has(char **out, int n, int which)
{
	int i;

	for (i = 0; i < n; i++)
		if (out[i] == probe[which])
			return 1;
	return 0;
}

static int at_base(void)
{
	int i;

	for (i = 0; i < 4; i++)
		if (nats_intern_refcount(probe[i]) != base[i])
			return 0;
	return 1;
}

static void queries(void)
{
	cdb_filter_t f1, f2;
	char **out = NULL;
	int n = -1, i;

	filter(&f1, "f", "x", NULL);
	ok(fts_query_match_keys(&f1, &out, &n) == 0 && n == 3 &&
		has(out, n, 0) && has(out, n, 1) && has(out, n, 2) && !has(out, n, 3),
		"query: f=x matches the three documents that have it");
	ok(nats_intern_refcount(probe[0]) == base[0] + 1,
		"query: each match is handed back with one reference taken");
	fts_release_keyset(out, n);
	ok(at_base(), "query: releasing the result gives every reference back");

	filter(&f2, "g", "y", NULL);
	filter(&f1, "f", "x", &f2);
	out = NULL;
	n = -1;
	ok(fts_query_match_keys(&f1, &out, &n) == 0 && n == 2 &&
		has(out, n, 0) && has(out, n, 1),
		"query: f=x AND g=y keeps the two that have both");
	fts_release_keyset(out, n);
	ok(at_base(), "query: the AND drops its references to the keys it filtered out");

	filter(&f2, "g", "nothing", NULL);
	filter(&f1, "f", "x", &f2);
	out = NULL;
	n = -1;
	ok(fts_query_match_keys(&f1, &out, &n) == 0 && n == 0,
		"query: an AND with no match is an empty success");
	fts_release_keyset(out, n);
	filter(&f2, "g", "y", NULL);
	filter(&f1, "f", "w", &f2);
	out = NULL;
	n = -1;
	ok(fts_query_match_keys(&f1, &out, &n) == 0 && n == 0,
		"query: disjoint filters intersect to nothing");
	fts_release_keyset(out, n);
	ok(at_base(), "query: the empty results release nothing they did not take");

	filter(&f1, "f", "x", NULL);
	f1.op = CDB_OP_LT;
	ok(fts_query_match_keys(&f1, &out, &n) < 0, "query: only = is supported");
	ok(at_base(), "query: a refused query takes no reference");

	/* a filter on a non-string value is skipped: it constrains nothing */
	filter(&f2, "g", "y", NULL);
	f2.val.is_str = 0;
	filter(&f1, "f", "x", &f2);
	out = NULL;
	n = -1;
	ok(fts_query_match_keys(&f1, &out, &n) == 0 && n == 3,
		"query: a non-string filter is skipped (f=x still matches three)");
	fts_release_keyset(out, n);
	ok(at_base(), "query: and its result releases cleanly");
	(void)i;
}

void fts_ut_query(void)
{
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;
	int i, okay = 1;

	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);
	if (nats_intern_init(64) < 0 || nats_json_index_init() < 0)
		okay = 0;
	for (i = 0; okay && i < 4; i++) {
		if (nats_json_index_add(keys[i], (int)strlen(keys[i]), docs[i],
				(int)strlen(docs[i])) < 0)
			okay = 0;
		probe[i] = nats_intern_acquire(keys[i], (int)strlen(keys[i]));
		base[i] = probe[i] ? nats_intern_refcount(probe[i]) : -1;
	}
	ok(okay, "query: four documents on a private index");
	if (okay)
		queries();
	for (i = 0; i < 4; i++)
		if (probe[i])
			nats_intern_release(probe[i]);
	nats_json_index_destroy();
	nats_intern_destroy();
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
