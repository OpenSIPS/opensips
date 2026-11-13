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
 * nats_kv_enum_live_values(): the reaper's value-carrying watch pass.
 * Bench-measured motivation (2026-07-07, 30k AoRs): the previous
 * kvStore_Keys() + per-key kvStore_Get() enumeration issues O(bucket)
 * synchronous round trips per tick and drags REGISTER p99/max from
 * ~1 ms to 27-88 ms while the sweep overlaps traffic.  The contract
 * locked here (against the PRODUCTION TU, #included directly):
 *
 *   - one kvStore_WatchAll pass, IgnoreDeletes set, values included;
 *     every delivered entry visits the callback exactly once, in
 *     order, and is destroyed by the enumerator exactly once,
 *   - ZERO kvStore_Get / kvStore_Keys calls -- the whole point,
 *   - the NULL entry from kvWatcher_Next() (initial-data sentinel)
 *     ends the pass: returns the visit count, watcher stopped and
 *     destroyed, live updates never consumed,
 *   - empty bucket: sentinel first -> 0 visits, no callback,
 *   - WatchAll failure / NULL watcher -> EWATCH, nothing else runs,
 *   - Next failure mid-pass (timeout) -> ENEXT, already-delivered
 *     entries stay visited+destroyed, watcher stopped and destroyed,
 *   - callback abort (< 0) -> EABORT, same cleanup guarantees,
 *   - argument guards: NULL kv / NULL cb / timeout <= 0 -> EARG with
 *     no libnats call at all.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../../nats/nats_bind.h"
#include "../cachedb_nats_reap_enum.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

/* ── scripted fake libnats ───────────────────────────────────────── */

/* The dl table global lives in modules-contrib/nats/nats_dl.c which is NOT linked
 * here; this test provides its own instance with stubs for exactly the
 * functions the enumerator may touch.  Signatures come from nats.h via
 * __typeof__, so any drift is a compile error. */

static struct {
	int watchall_calls;
	int next_calls;
	int stop_calls;
	int destroy_calls;
	int entry_destroys;
	int get_calls;         /* MUST stay 0 */
	int keys_calls;        /* MUST stay 0 */
	natsStatus watchall_rc;
	kvWatcher *watchall_out;    /* watcher handle WatchAll "creates" */
	/* Next script: rc + entry per call, up to 8 steps. */
	int next_step;
	natsStatus next_rc[8];
	kvEntry *next_entry[8];
} S;

static char fake_watcher_mem;        /* opaque token addresses */
static char fake_entry_mem[4];

#define FAKE_WATCHER  ((kvWatcher *)&fake_watcher_mem)
#define FAKE_ENTRY(i) ((kvEntry *)&fake_entry_mem[i])

static natsStatus stub_kvWatchOptions_Init(kvWatchOptions *o)
{
	memset(o, 0, sizeof(*o));
	return NATS_OK;
}
static natsStatus stub_kvStore_WatchAll(kvWatcher **w, kvStore *kv,
	const kvWatchOptions *o)
{
	(void)kv;
	S.watchall_calls++;
	/* the enumerator must ask for IgnoreDeletes (Keys() parity) */
	if (o == NULL || !o->IgnoreDeletes)
		return NATS_INVALID_ARG;
	*w = S.watchall_out;
	return S.watchall_rc;
}
static natsStatus stub_kvWatcher_Next(kvEntry **e, kvWatcher *w, int64_t tmo)
{
	int i = S.next_step++;
	(void)w;
	S.next_calls++;
	if (tmo <= 0)
		return NATS_INVALID_ARG;
	if (i >= 8)
		return NATS_TIMEOUT;
	*e = S.next_entry[i];
	return S.next_rc[i];
}
static natsStatus stub_kvWatcher_Stop(kvWatcher *w)
{ (void)w; S.stop_calls++; return NATS_OK; }
static void stub_kvWatcher_Destroy(kvWatcher *w)
{ (void)w; S.destroy_calls++; }
static void stub_kvEntry_Destroy(kvEntry *e)
{ (void)e; S.entry_destroys++; }
static natsStatus stub_kvStore_Get(kvEntry **e, kvStore *kv, const char *k)
{ (void)e; (void)kv; (void)k; S.get_calls++; return NATS_NOT_FOUND; }
static natsStatus stub_kvStore_Keys(kvKeysList *l, kvStore *kv,
	const kvWatchOptions *o)
{ (void)l; (void)kv; (void)o; S.keys_calls++; return NATS_NOT_FOUND; }
static const char *stub_natsStatus_GetText(natsStatus s)
{ (void)s; return "stub-status"; }


static void reset(void)
{
	memset(&S, 0, sizeof(S));
	S.watchall_rc = NATS_OK;
	S.watchall_out = FAKE_WATCHER;

	memset(&nats_dl, 0, sizeof(nats_dl));
	nats_dl.kvWatchOptions_Init = stub_kvWatchOptions_Init;
	nats_dl.kvStore_WatchAll = stub_kvStore_WatchAll;
	nats_dl.kvWatcher_Next = stub_kvWatcher_Next;
	nats_dl.kvWatcher_Stop = stub_kvWatcher_Stop;
	nats_dl.kvWatcher_Destroy = stub_kvWatcher_Destroy;
	nats_dl.kvEntry_Destroy = stub_kvEntry_Destroy;
	nats_dl.kvStore_Get = stub_kvStore_Get;
	nats_dl.kvStore_Keys = stub_kvStore_Keys;
	nats_dl.natsStatus_GetText = stub_natsStatus_GetText;
}

/* ── visitor spy ─────────────────────────────────────────────────── */

static struct {
	int calls;
	kvEntry *seen[8];
	int abort_at;          /* 1-based call number to abort on; 0 = never */
} V;

static int spy_cb(kvEntry *e, void *arg)
{
	(void)arg;
	if (V.calls < 8)
		V.seen[V.calls] = e;
	V.calls++;
	return (V.abort_at && V.calls == V.abort_at) ? -1 : 0;
}

static void reset_all(void) { reset(); memset(&V, 0, sizeof(V)); }

#define CHECK(cond, msg) do { if (!(cond)) { fail("reap_watch_enum: %s", msg); } \
	else pass("reap_watch_enum: %s", msg); } while (0)

static kvStore *FAKE_KV = (kvStore *)&fake_watcher_mem;   /* any token */

void cn_ut_reap_watch_enum(void)
{
	int rc;
	cn_ut_fake_begin();

	diag("== happy path: 3 entries then sentinel ==");
	reset_all();
	S.next_rc[0] = NATS_OK; S.next_entry[0] = FAKE_ENTRY(0);
	S.next_rc[1] = NATS_OK; S.next_entry[1] = FAKE_ENTRY(1);
	S.next_rc[2] = NATS_OK; S.next_entry[2] = FAKE_ENTRY(2);
	S.next_rc[3] = NATS_OK; S.next_entry[3] = NULL;   /* sentinel */
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, spy_cb, NULL);
	CHECK(rc == 3, "returns visit count 3");
	CHECK(V.calls == 3, "callback ran exactly 3 times");
	CHECK(V.seen[0] == FAKE_ENTRY(0) && V.seen[1] == FAKE_ENTRY(1)
	      && V.seen[2] == FAKE_ENTRY(2), "entries visited in order");
	CHECK(S.entry_destroys == 3, "every delivered entry destroyed once");
	CHECK(S.watchall_calls == 1, "one WatchAll pass");
	CHECK(S.stop_calls == 1 && S.destroy_calls == 1,
	      "watcher stopped and destroyed");
	CHECK(S.get_calls == 0, "ZERO kvStore_Get calls (the whole point)");
	CHECK(S.keys_calls == 0, "ZERO kvStore_Keys calls");
	CHECK(S.next_calls == 4, "stops at the sentinel (no extra Next)");

	diag("== empty bucket: sentinel first ==");
	reset_all();
	S.next_rc[0] = NATS_OK; S.next_entry[0] = NULL;
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, spy_cb, NULL);
	CHECK(rc == 0, "empty bucket returns 0");
	CHECK(V.calls == 0, "callback never ran");
	CHECK(S.stop_calls == 1 && S.destroy_calls == 1,
	      "watcher still stopped and destroyed");

	diag("== WatchAll failure ==");
	reset_all();
	S.watchall_rc = NATS_ERR;
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_EWATCH, "EWATCH on WatchAll failure");
	CHECK(V.calls == 0 && S.next_calls == 0, "nothing consumed");
	CHECK(S.destroy_calls == 0, "no watcher to destroy");

	diag("== WatchAll NATS_OK but NULL watcher ==");
	reset_all();
	S.watchall_out = NULL;
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_EWATCH, "EWATCH on NULL watcher");
	CHECK(S.next_calls == 0, "Next never called on NULL watcher");

	diag("== Next timeout mid-pass ==");
	reset_all();
	S.next_rc[0] = NATS_OK; S.next_entry[0] = FAKE_ENTRY(0);
	S.next_rc[1] = NATS_OK; S.next_entry[1] = FAKE_ENTRY(1);
	S.next_rc[2] = NATS_TIMEOUT; S.next_entry[2] = NULL;
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_ENEXT, "ENEXT on mid-pass timeout");
	CHECK(V.calls == 2, "entries before the failure were visited");
	CHECK(S.entry_destroys == 2, "and destroyed");
	CHECK(S.stop_calls == 1 && S.destroy_calls == 1,
	      "watcher stopped and destroyed on the error path");

	diag("== callback abort ==");
	reset_all();
	V.abort_at = 2;
	S.next_rc[0] = NATS_OK; S.next_entry[0] = FAKE_ENTRY(0);
	S.next_rc[1] = NATS_OK; S.next_entry[1] = FAKE_ENTRY(1);
	S.next_rc[2] = NATS_OK; S.next_entry[2] = FAKE_ENTRY(2);
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_EABORT, "EABORT when callback aborts");
	CHECK(V.calls == 2, "no visits past the abort");
	CHECK(S.entry_destroys == 2,
	      "the aborting call's entry is still destroyed");
	CHECK(S.stop_calls == 1 && S.destroy_calls == 1,
	      "watcher stopped and destroyed after abort");

	diag("== argument guards ==");
	reset_all();
	rc = nats_kv_enum_live_values(NULL, 5000, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_EARG, "NULL kv -> EARG");
	rc = nats_kv_enum_live_values(FAKE_KV, 5000, NULL, NULL);
	CHECK(rc == NATS_KV_ENUM_EARG, "NULL cb -> EARG");
	rc = nats_kv_enum_live_values(FAKE_KV, 0, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_EARG, "timeout 0 -> EARG");
	rc = nats_kv_enum_live_values(FAKE_KV, -5, spy_cb, NULL);
	CHECK(rc == NATS_KV_ENUM_EARG, "negative timeout -> EARG");
	CHECK(S.watchall_calls == 0 && S.next_calls == 0,
	      "guards fire before any libnats call");

	cn_ut_fake_end();
}
