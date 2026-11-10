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
 * Behavioral regression test: a KV snapshot that stalls mid-stream
 * (NATS_TIMEOUT after the subscription is established but before the
 * end-of-snapshot sentinel) must be treated as a FAILED snapshot.
 *
 * The defect: drain_kv_snapshot() broke out of its loop on
 * NATS_TIMEOUT and returned the partial entry count as success, and
 * nats_json_index_rebuild() then atomically swapped the PARTIAL shadow
 * index over the complete live one (it even coerced a -1 drain to
 * count=0 and swapped an empty index).  Non-PK queries silently missed
 * every document not delivered before the stall, until the next
 * rebuild.
 *
 * Contract asserted here:
 *   - a truncated snapshot makes nats_json_index_build() return -1
 *     (not the partial count);
 *   - a truncated snapshot makes nats_json_index_rebuild() return -1
 *     AND leave the live index untouched (document count preserved);
 *   - a complete snapshot (entries + sentinel) still rebuilds and
 *     swaps normally.
 *
 * Compiles and links the REAL production TUs (../../cachedb_nats_fts/fts_index.c
 * + ../../cachedb_nats_fts/fts_intern.c); the nats_dl watcher functions are replaced
 * with a scripted fake stream, and the pkg/shm allocators with malloc
 * wrappers (single-threaded test: the shm lock is a real-but-uncontended
 * gen_lock_t).
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <nats/nats.h>

#include "../fts_index.h"
#include "../fts_intern.h"
#include "../../nats/nats_bind.h"


/* referenced by a cold path we never execute */

#include "fts_ut.h"

/* ── scripted fake KV watcher stream via nats_dl ────────────────── */


enum step_kind { STEP_ENTRY, STEP_SENTINEL, STEP_TIMEOUT };
struct step {
	enum step_kind kind;
	const char *key;
	const char *val;
};

static const struct step *stream;
static int stream_pos;
static int watchall_calls;

#define FAKE_WATCHER ((kvWatcher *)0x6001)
#define FAKE_KV      ((kvStore *)0x1001)

static natsStatus fake_kvWatchOptions_Init(kvWatchOptions *o)
{ memset(o, 0, sizeof(*o)); return NATS_OK; }
static natsStatus fake_kvStore_WatchAll(kvWatcher **w, kvStore *kv,
	const kvWatchOptions *o)
{ (void)kv; (void)o; watchall_calls++; *w = FAKE_WATCHER; return NATS_OK; }
static void fake_kvWatcher_Destroy(kvWatcher *w) { (void)w; }

static natsStatus fake_kvWatcher_Next(kvEntry **e, kvWatcher *w,
	int64_t timeout)
{
	const struct step *s = &stream[stream_pos];
	(void)w; (void)timeout;
	switch (s->kind) {
	case STEP_TIMEOUT:
		return NATS_TIMEOUT;          /* stall: do not advance */
	case STEP_SENTINEL:
		stream_pos++;
		*e = NULL;
		return NATS_OK;
	case STEP_ENTRY:
	default:
		*e = (kvEntry *)(uintptr_t)(stream_pos + 1);
		stream_pos++;
		return NATS_OK;
	}
}

static const struct step *entry_step(const kvEntry *e)
{ return &stream[(int)(uintptr_t)e - 1]; }

static const char *fake_kvEntry_Key(const kvEntry *e)
{ return entry_step(e)->key; }
static const char *fake_kvEntry_ValueString(const kvEntry *e)
{ return entry_step(e)->val; }
static int fake_kvEntry_ValueLen(const kvEntry *e)
{ return (int)strlen(entry_step(e)->val); }
static void fake_kvEntry_Destroy(kvEntry *e) { (void)e; }
static const char *fake_natsStatus_GetText(natsStatus s)
{ (void)s; return "fake-status"; }

static natsStatus fail_kvStore_WatchAll(kvWatcher **w, kvStore *kv,
	const kvWatchOptions *o)
{ (void)w; (void)kv; (void)o; return NATS_ERR; }

/* ── harness ────────────────────────────────────────────────────── */

#define ASSERT(cond, msg) ok((cond), "index_partial_snapshot: %s", (msg))

void fts_ut_index_partial_snapshot(void)
{
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;

	int rc;
	struct nats_binds real_api;
	static nats_dl_funcs_t fake_dl;

	/* this process's live index, reverse map and intern table go
	 * aside: the test inits and destroys instances of its own */
	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);
	ASSERT(nats_intern_init(64) == 0, "a private intern table");

	/* the FTS module's libnats table: a zeroed fake for this test, the
	 * assignments below fill it (nats_dl is *nats_api.dl) */
	real_api = nats_api;
	memset(&fake_dl, 0, sizeof fake_dl);
	nats_api.dl = &fake_dl;

	nats_dl.kvWatchOptions_Init = fake_kvWatchOptions_Init;
	nats_dl.kvStore_WatchAll = fake_kvStore_WatchAll;
	nats_dl.kvWatcher_Next = fake_kvWatcher_Next;
	nats_dl.kvWatcher_Destroy = fake_kvWatcher_Destroy;
	nats_dl.kvEntry_Key = fake_kvEntry_Key;
	nats_dl.kvEntry_ValueString = fake_kvEntry_ValueString;
	nats_dl.kvEntry_ValueLen = fake_kvEntry_ValueLen;
	nats_dl.kvEntry_Destroy = fake_kvEntry_Destroy;
	nats_dl.natsStatus_GetText = fake_natsStatus_GetText;

	ASSERT(nats_json_index_init() == 0, "index init");

	/* seed the LIVE index with two complete documents */
	ASSERT(nats_json_index_add("doc.a1", 6, "{\"aor\":\"alice\"}", 16) == 0,
		"seed doc a1");
	ASSERT(nats_json_index_add("doc.a2", 6, "{\"aor\":\"anna\"}", 15) == 0,
		"seed doc a2");
	ASSERT(nats_json_index_count() == 2, "live index holds 2 documents");

	/* 1. THE DEFECT — rebuild over a truncated snapshot must fail AND
	 * keep the prior live index (no partial swap). */
	{
		static const struct step s[] = {
			{ STEP_ENTRY, "doc.b", "{\"aor\":\"bob\"}" },
			{ STEP_TIMEOUT, NULL, NULL },
		};
		stream = s; stream_pos = 0;
		rc = nats_json_index_rebuild(FAKE_KV, "doc.");
		ASSERT(rc == -1, "truncated snapshot fails index_rebuild (-1)");
		ASSERT(nats_json_index_count() == 2,
			"failed rebuild keeps the prior live index (2 docs, "
			"no partial swap)");
	}

	/* 2. complete snapshot (entry + sentinel) still swaps normally */
	{
		static const struct step s[] = {
			{ STEP_ENTRY, "doc.b", "{\"aor\":\"bob\"}" },
			{ STEP_SENTINEL, NULL, NULL },
		};
		stream = s; stream_pos = 0;
		rc = nats_json_index_rebuild(FAKE_KV, "doc.");
		ASSERT(rc >= 0, "complete snapshot rebuild succeeds");
		ASSERT(nats_json_index_count() == 1,
			"complete rebuild swapped in the 1-doc snapshot");
	}

	/* 3. WatchAll failing outright must also fail the rebuild and keep
	 * the live index (previously: swapped in an EMPTY index) */
	{
		nats_dl.kvStore_WatchAll = fail_kvStore_WatchAll;
		rc = nats_json_index_rebuild(FAKE_KV, "doc.");
		ASSERT(rc == -1, "WatchAll failure fails index_rebuild (-1)");
		ASSERT(nats_json_index_count() == 1,
			"failed rebuild keeps prior index (no empty swap)");
		nats_dl.kvStore_WatchAll = fake_kvStore_WatchAll;
	}

	/* 4. STARTUP BUILD over a truncated snapshot: the partial count
	 * must NOT be reported as a successful build.  (Runs last: the
	 * additive startup build leaves partial entries in the live index
	 * either way; only the return code is under test.) */
	{
		static const struct step s[] = {
			{ STEP_ENTRY, "doc.c", "{\"aor\":\"carol\"}" },
			{ STEP_TIMEOUT, NULL, NULL },
		};
		stream = s; stream_pos = 0;
		rc = nats_json_index_build(FAKE_KV, "doc.");
		ASSERT(rc == -1, "truncated snapshot fails index_build (-1)");
	}

	nats_json_index_destroy();
	nats_intern_destroy();
	nats_api = real_api;

	/* the live ones go back */
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
