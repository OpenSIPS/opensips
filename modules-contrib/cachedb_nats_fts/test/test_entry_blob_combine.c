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
 * Behavioural (ASan+LSan, REAL TUs): the single-allocation
 * index-entry blob and its inline->external keys[] growth, exercised
 * through the production fts_index.c (replaces the file_contains()
 * source-pattern version of this test).
 *
 * The layout being locked: get_or_create_entry_in packs the entry
 * struct + field_value + an inline keys[NATS_IDX_KEYS_INLINE] array
 * into ONE shm blob; entry_add_key migrates keys[] to a separate
 * allocation when it grows past the inline capacity; free_entry must
 * free the external keys[] and must NOT free the inline one (an
 * interior pointer).  None of that is directly visible through the
 * API -- but under ASan/LSan every way to get it wrong is fatal:
 *   - freeing the inline keys[] => invalid free (interior pointer);
 *   - leaking the external keys[] on free => LSan leak at exit;
 *   - losing the inline contents on growth => the migrated keys are
 *     no longer removable and the count/refcount contracts go red;
 *   - a second allocation per entry that free_entry doesn't know
 *     about => LSan leak.
 *
 * Both arms share one identical single-field JSON so every doc key
 * lands in the SAME field entry:
 *   - sub-threshold arm: 3 keys (keys[] stays inline), then index
 *     destroy -- a wrong shm_free of the inline array aborts;
 *   - growth arm: NATS_IDX_KEYS_INLINE+4 keys (forces the inline ->
 *     external migration), every key then removed one by one via
 *     revmap -- each hit proves the migrated array kept the early
 *     inline keys; the final counts prove the entry and the interned
 *     keys were fully freed.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <nats/nats.h>

#include "../fts_index.h"
#include "../fts_intern.h"
#include "../../../cachedb/cachedb_dict.h"



#include "fts_ut.h"


/* ── harness ────────────────────────────────────────────────────── */

#define ASSERT(cond, msg) ok((cond), "entry_blob_combine: %s", (msg))

/* one identical single-field doc => every key shares ONE field entry */
static const char *doc = "{\"domain\":\"example.com\"}";

static void add_keys(int n, const char *prefix)
{
	int i, dlen = (int)strlen(doc), ok = 1;
	char msg[64];
	for (i = 0; i < n; i++) {
		char key[32];
		snprintf(key, sizeof(key), "%s%02d", prefix, i);
		if (nats_json_index_add(key, (int)strlen(key), doc,
				dlen) != 0)
			ok = 0;
	}
	snprintf(msg, sizeof(msg), "%d keys added into the shared entry", n);
	ASSERT(ok && nats_json_index_count() == n, msg);
	snprintf(msg, sizeof(msg), "%d doc keys interned", n);
	ASSERT(nats_intern_size() == n, msg);
}

void fts_ut_entry_blob_combine(void)
{
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;

	int i;
	const int grow_n = NATS_IDX_KEYS_INLINE + 4;

	/* this process's live index, reverse map and intern table go
	 * aside: the test inits and destroys instances of its own */
	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);

	ASSERT(nats_intern_init(64) == 0, "intern init");

	/* ── sub-threshold arm: keys[] stays inline ──────────────────── */
	ASSERT(nats_json_index_init() == 0, "index init (inline arm)");
	add_keys(3, "inline_");
	/* destroy while inline: a free of the interior inline keys[]
	 * pointer aborts under ASan; a missed blob free leaks */
	nats_json_index_destroy();
	ASSERT(nats_intern_size() == 0,
	       "inline-arm destroy released every interned key");

	/* ── growth arm: force inline -> external migration ──────────── */
	ASSERT(nats_json_index_init() == 0, "index init (growth arm)");
	add_keys(grow_n, "grow_");

	/* every key -- including the early ones that lived in the inline
	 * array before migration -- must still be attached and removable */
	for (i = 0; i < grow_n; i++) {
		char key[32];
		snprintf(key, sizeof(key), "grow_%02d", i);
		if (nats_json_index_remove_by_revmap(key,
				(int)strlen(key)) != 0) {
			ok(0, "entry_blob_combine: key %s lost across the "
				"inline->external migration", key);
		}
	}
	ASSERT(nats_json_index_count() == 0,
	       "all keys removed after growth (none lost in migration)");
	ASSERT(nats_intern_size() == 0,
	       "entry fully freed: every interned key released");

	/* removing the last key freed the entry (and its external keys[]
	 * -- LSan catches it at exit if not); a fresh add still works */
	ASSERT(nats_json_index_add("post", 4, doc, (int)strlen(doc)) == 0,
	       "index still serviceable after entry teardown");
	nats_json_index_destroy();
	ASSERT(nats_intern_size() == 0, "final destroy is clean");

	nats_intern_destroy();

	/* the live ones go back */
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
