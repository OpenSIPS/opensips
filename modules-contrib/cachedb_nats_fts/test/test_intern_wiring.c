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
 * Behavioural (ASan, REAL TUs): the index<->intern wiring,
 * exercised through the production fts_index.c + fts_intern.c
 * (replaces the file_contains() source-pattern version of this
 * test).  The optimisation this locks: the doc key is interned ONCE
 * per document, however many field entries reference it -- if
 * entry_add_key ever regresses to per-field strdup, the size/refcount
 * contracts here go red.
 *
 * Contracts:
 *   - init-required degrade: with no intern table, an index add
 *     interns nothing (the gotcha production avoids by initialising
 *     the table in the FTS module's mod_init -- that lifecycle hook
 *     itself is exercised end-to-end by sip_e2e cases 030/120/140,
 *     which fail hard if mod_init stops initialising the table);
 *   - one intern node per doc key, not per indexed field;
 *   - the index's references are intern references: removing the doc
 *     releases ALL of them (refcount returns to probe-only);
 *   - duplicate add of the same doc does not leak references;
 *   - index destroy with live docs releases every interned key.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <nats/nats.h>

#include "../fts_index.h"
#include "../fts_intern.h"

#include "fts_ut.h"

#define ASSERT(cond, msg) ok((cond), "intern_wiring: %s", (msg))

void fts_ut_intern_wiring(void)
{
	/* this process's live index, reverse map and intern table go aside:
	 * the sequence below inits and destroys its own */
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;

	/* two indexed string fields -> two field entries per doc */
	const char *doc = "{\"aor\":\"alice@example.com\",\"domain\":\"example.com\"}";
	int dlen = (int)strlen(doc);
	const char *key = "json_doc.alice";
	int klen = (int)strlen(key);
	char *probe;
	int rc_with_index;

	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);

	/* ── init-required degrade: no intern table, nothing interned ── */
	ASSERT(nats_json_index_init() == 0, "index init (no intern table yet)");
	(void)nats_json_index_add(key, klen, doc, dlen);
	ASSERT(nats_intern_size() == 0,
	       "without nats_intern_init, an index add interns nothing");
	nats_json_index_destroy();

	/* ── production wiring: intern table first (mod_init order) ──── */
	ASSERT(nats_intern_init(64) == 0, "intern init");
	ASSERT(nats_json_index_init() == 0, "index re-init");

	ASSERT(nats_json_index_add(key, klen, doc, dlen) == 0, "doc indexed");
	ASSERT(nats_json_index_count() == 1, "index holds one doc");
	ASSERT(nats_intern_size() == 1,
	       "ONE intern node per doc key, not one per indexed field");

	probe = nats_intern_acquire(key, klen);
	ASSERT(probe != NULL, "probe acquire of the live doc key");
	rc_with_index = nats_intern_refcount(probe);
	ASSERT(rc_with_index >= 3,
	       "index holds interned references (>=2 field entries + probe)");

	/* duplicate add must not leak references */
	ASSERT(nats_json_index_add(key, klen, doc, dlen) == 0, "doc re-added");
	ASSERT(nats_intern_refcount(probe) == rc_with_index,
	       "re-adding the same doc leaks no intern references");
	ASSERT(nats_intern_size() == 1, "still one intern node after re-add");

	/* removing the doc releases every index-held reference */
	ASSERT(nats_json_index_remove_by_revmap(key, klen) == 0, "doc removed");
	ASSERT(nats_intern_refcount(probe) == 1,
	       "remove released ALL index references (probe-only left)");
	nats_intern_release(probe);
	ASSERT(nats_intern_size() == 0, "intern table empty after remove");

	/* index destroy with live docs releases interned keys too */
	ASSERT(nats_json_index_add(key, klen, doc, dlen) == 0,
	       "doc indexed again before destroy");
	ASSERT(nats_intern_size() == 1, "interned again");
	nats_json_index_destroy();
	ASSERT(nats_intern_size() == 0,
	       "index destroy released every interned key");

	nats_intern_destroy();

	/* the private ones are destroyed: the live ones go back */
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
