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
 * Behavioural (ASan, REAL TUs): the FTS write-side entry
 * points take an explicit key LENGTH — no strlen on the hot path, and a
 * key need not be NUL-terminated.  Every key handed to the index here
 * is a heap slice of EXACTLY key_len bytes with no terminator: if any
 * production path still runs strlen()/str*cpy() over the key, ASan
 * trips heap-buffer-overflow and the test fails.
 *
 * Contracts:
 *   - add/remove_by_revmap/remove/remove_fields accept (key, key_len)
 *     slices; indexing is by VALUE (a different buffer with the same
 *     bytes removes what another added);
 *   - re-adding the same sliced key stays idempotent (count == 1);
 *   - remove_fields with the old JSON removes the targeted entries.
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

#define ASSERT(cond, msg) ok((cond), "fts_key_len: %s", (msg))

/* A NON-NUL-terminated copy of key_len bytes, followed by guard bytes
 * that differ from slice to slice and only then a NUL: code that runs
 * strlen() over the key instead of using key_len reads a longer key, and
 * one that differs per buffer, so lookups and dedup by value break. */
#define GUARD 16
static char *key_slice(const char *s, int *out_len)
{
	static int nth;
	int n = (int)strlen(s), i;
	char *p = malloc(n + GUARD + 1);

	memcpy(p, s, n);
	nth++;
	for (i = 0; i < GUARD; i++)
		p[n + i] = (char)('A' + (nth * 7 + i) % 26);
	p[n + GUARD] = '\0';
	*out_len = n;
	return p;
}

void fts_ut_fts_key_len(void)
{
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;

	const char *doc  = "{\"aor\":\"alice@example.com\",\"domain\":\"example.com\"}";
	const char *doc2 = "{\"aor\":\"bob@example.com\",\"domain\":\"example.com\"}";
	int dlen = (int)strlen(doc), d2len = (int)strlen(doc2);
	char *k1, *k1b, *k2;
	int k1_len, k1b_len, k2_len;

	/* this process's live index, reverse map and intern table go
	 * aside: the test inits and destroys instances of its own */
	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);

	/* The intern table must be live: without it, acquire falls back
	 * to per-call strdup and the pointer-compare removal paths can
	 * never match (production initialises it in mod_init). */
	ASSERT(nats_intern_init(64) == 0, "intern init");
	ASSERT(nats_json_index_init() == 0, "index init");

	k1  = key_slice("json_doc.alice", &k1_len);
	k1b = key_slice("json_doc.alice", &k1b_len);   /* same bytes, other buf */
	k2  = key_slice("json_doc.bob", &k2_len);

	/* add via non-terminated slices */
	ASSERT(nats_json_index_add(k1, k1_len, doc, dlen) == 0,
		"add(sliced key) indexes without a terminator");
	ASSERT(nats_json_index_count() == 1, "count 1 after first add");

	ASSERT(nats_json_index_add(k1, k1_len, doc, dlen) == 0,
		"re-add same sliced key succeeds");
	ASSERT(nats_json_index_count() == 1, "idempotent: count still 1");

	ASSERT(nats_json_index_add(k2, k2_len, doc2, d2len) == 0,
		"second sliced key indexes");
	ASSERT(nats_json_index_count() == 2, "count 2 after second add");

	/* revmap fast delete by VALUE: a different buffer, same bytes */
	ASSERT(nats_json_index_remove_by_revmap(k1b, k1b_len) == 0,
		"remove_by_revmap(other buffer, same bytes) hits");
	ASSERT(nats_json_index_count() == 1, "count 1 after revmap remove");
	ASSERT(nats_json_index_remove_by_revmap(k1b, k1b_len) == -1,
		"second revmap remove misses (already gone)");

	/* targeted remove_fields with the OLD json, then the full-walk
	 * remove as the fallback contract */
	ASSERT(nats_json_index_remove_fields(k2, k2_len, doc2, d2len) == 0,
		"remove_fields(sliced key) succeeds");
	ASSERT(nats_json_index_remove(k2, k2_len) == 0,
		"remove(sliced key) full walk is clean after remove_fields");
	ASSERT(nats_json_index_count() == 0, "index empty at the end");

	free(k1); free(k1b); free(k2);

	/* the live ones go back */
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
