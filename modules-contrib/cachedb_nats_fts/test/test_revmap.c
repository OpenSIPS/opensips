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
 * The reverse map (document key -> the field:value entries it was indexed
 * under) that lets the KV watcher's delete-by-key path remove a document
 * from only those entries (nats_json_index_remove_by_revmap), instead of
 * walking every bucket under every shard lock.  On private index and
 * intern instances.  Replaces tests/test_revmap_delete.c, which carried a
 * model of the map.  Its lock-discipline assertion (the reverse-map lock
 * is never held during the forward work) has no in-process form; the
 * threaded put/take check runs here on the real map.
 */

#include <tap.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "../fts_index.h"
#include "../fts_intern.h"
#include "../../../cachedb/cachedb_types.h"

#include "fts_ut.h"

static int matches(const char *field, const char *value)
{
	cdb_filter_t f;
	char **out = NULL;
	int n = -1;

	memset(&f, 0, sizeof f);
	f.key.name.s = (char *)field;
	f.key.name.len = (int)strlen(field);
	f.op = CDB_OP_EQ;
	f.val.is_str = 1;
	f.val.s.s = (char *)value;
	f.val.s.len = (int)strlen(value);
	if (fts_query_match_keys(&f, &out, &n) < 0)
		return -1;
	fts_release_keyset(out, n);
	return n;
}

static int add(const char *key, const char *doc)
{
	return nats_json_index_add(key, (int)strlen(key), doc, (int)strlen(doc));
}

static int rm(const char *key)
{
	return nats_json_index_remove_by_revmap(key, (int)strlen(key));
}

#define THREADS 4
#define PER_THREAD 200

static void *churn(void *arg)
{
	int t = (int)(long)arg, i;
	char key[32], doc[64];

	for (i = 0; i < PER_THREAD; i++) {
		snprintf(key, sizeof key, "rv.%d.%d", t, i);
		snprintf(doc, sizeof doc, "{\"t\":\"%d\",\"i\":\"%d\"}", t, i);
		add(key, doc);
		if (i % 2)
			rm(key);
	}
	for (i = 0; i < PER_THREAD; i += 2) {
		snprintf(key, sizeof key, "rv.%d.%d", t, i);
		rm(key);
	}
	return NULL;
}

static void revmap(void)
{
	pthread_t th[THREADS];
	int i, n = 0;

	ok(add("rv.doc1", "{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\"}") == 0 &&
		add("rv.doc2", "{\"a\":\"1\"}") == 0 && nats_json_index_count() == 2,
		"revmap: two documents indexed");
	ok(rm("rv.doc1") == 0 && nats_json_index_count() == 1,
		"revmap: removing by key takes the document out");
	ok(matches("a", "1") == 1 && matches("b", "2") == 0 && matches("c", "3") == 0,
		"revmap: from every entry it was indexed under, and only those");
	ok(rm("rv.doc1") == -1,
		"revmap: a second removal misses (the caller falls back to a full walk)");

	ok(add("rv.doc2", "{\"x\":\"9\"}") == 0 && rm("rv.doc2") == 0 &&
		matches("x", "9") == 0 && nats_json_index_count() == 0,
		"revmap: a re-added key is removed with the fields it has now");

	for (i = 0; i < THREADS; i++)
		if (pthread_create(&th[i], NULL, churn, (void *)(long)i) == 0)
			n++;
	for (i = 0; i < n; i++)
		pthread_join(th[i], NULL);
	ok(n == THREADS && nats_json_index_count() == 0,
		"revmap: %d threads adding and removing their own keys leave it empty",
		THREADS);
	ok(matches("t", "0") == 0 && matches("i", "1") == 0,
		"revmap: and no entry still names a removed key");
}

void fts_ut_revmap(void)
{
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;

	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);
	if (nats_intern_init(64) == 0 && nats_json_index_init() == 0)
		revmap();
	else
		ok(0, "revmap: a private index");
	nats_json_index_destroy();
	nats_intern_destroy();
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
