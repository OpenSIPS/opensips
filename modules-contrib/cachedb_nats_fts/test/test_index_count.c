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
 * The search index's document count (nats_json_index_count()), on the
 * live index.  Replaces tests/test_index_add_idempotent.c,
 * tests/test_index_count.c and tests/test_index_count_gated.c, which
 * carried copies of the counting.
 *
 * A node's own write is indexed twice (inline, then the watcher's echo of
 * the same put), and a periodic resync adds every key again: the count
 * must follow the documents, not the adds.  Removing a key that was never
 * indexed (a seed create, a duplicate delete) must not decrement it.
 */

#include <tap.h>
#include <string.h>

#include "../fts_index.h"

#include "fts_ut.h"

#define DOC "{\"user\":\"alice\",\"domain\":\"example.com\"}"

static int add(const char *key)
{
	return nats_json_index_add(key, (int)strlen(key), DOC, (int)strlen(DOC));
}

static int rm(const char *key)
{
	return nats_json_index_remove(key, (int)strlen(key));
}

void fts_ut_index_count(void)
{
	int base = nats_json_index_count();
	nats_search_idx *saved;

	ok(base >= 0, "index_count: the live index is initialised (%d documents)", base);

	ok(add("ut_cnt.alice") == 0 && nats_json_index_count() == base + 1,
		"index_count: a first add counts one document");
	add("ut_cnt.alice");
	add("ut_cnt.alice");
	ok(nats_json_index_count() == base + 1,
		"index_count: the watcher's echo and a resync re-add count nothing more");
	add("ut_cnt.bob");
	add("ut_cnt.bob");
	ok(nats_json_index_count() == base + 2, "index_count: distinct keys count once each");

	rm("ut_cnt.alice");
	add("ut_cnt.alice");
	add("ut_cnt.alice");
	ok(nats_json_index_count() == base + 2,
		"index_count: an update (remove, add, echo) nets zero");

	ok(rm("ut_cnt.never") == 0 && nats_json_index_count() == base + 2,
		"index_count: removing a never-indexed key does not decrement");
	rm("ut_cnt.alice");
	rm("ut_cnt.bob");
	ok(nats_json_index_count() == base, "index_count: both removed, back to the start");
	rm("ut_cnt.bob");
	ok(nats_json_index_count() == base,
		"index_count: a spurious remove does not go below the start");

	saved = g_idx;   /* this process's pointer to the shared index */
	g_idx = NULL;
	ok(nats_json_index_count() == -1, "index_count: no index answers -1");
	g_idx = saved;
	ok(nats_json_index_count() == base, "index_count: the index is back");
}
