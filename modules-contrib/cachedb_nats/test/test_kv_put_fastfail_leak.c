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
 * Behavioral regression tests for the w_nats_kv_put / w_nats_kv_update
 * fast-fail paths and the w_nats_kv_get pvar-set contract.
 *
 * Defect 1 (pkg leak): values >= NATS_NATIVE_VAL_BUF (4096) are
 * pkg_malloc'd into a heap buffer BEFORE the disconnected fast-fail
 * check, and that check did a bare `return -1` without freeing — leaking
 * up to payload size per call for the whole duration of a broker outage.
 * Contract: a disconnected put/update must return -1 with ZERO
 * outstanding pkg allocations (the connectivity gate runs before any
 * copy, as w_nats_request already does).
 *
 * Defect 2 (ignored pv_set_value): w_nats_kv_get ignored the return of
 * pv_set_value(), so a failed pvar write still returned 1 (success) and
 * the script read a STALE value as if it were fresh.  Contract: if the
 * value pvar cannot be set, w_nats_kv_get returns -1.
 *
 * Like test_kv_epoch_refresh.c, this compiles and links the REAL
 * production TU (../cachedb_nats_native.c); the process seams (dprint,
 * pkg allocator, nats_pool, the nats_dl libnats function table,
 * pv_set_value) are swapped for instrumented fakes.
 * In the module build: the pool fakes go into nats_api, the CAS write
 * runs the real nats_kv_put_row on the fixture's publish fakes, the pvar
 * write goes through the UNIT_TESTS seam cn_ut_pv_set_value, and the pkg
 * accounting is the real allocator's used size (PKG_GET_USED): "no
 * outstanding allocation" holds exactly, "no copy at all" weakens to "no
 * net pkg change" (an alloc + free in between would pass).  The pkg fakes keep
 * a live-allocation balance — the "pkg-stats delta" assertions below.
 * The binary is also ASan'd, so a leaked buffer additionally trips
 * LeakSanitizer at exit.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../../../pvar.h"
#include "../../../mi/mi.h"
#include "../cachedb_nats_native.h"
#include "../cachedb_nats_dbase.h"
#include "../cachedb_nats_expiry.h"
#include "../../nats/nats_bind.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static int fake_connected = 1;
static kvStore *fake_kv = (kvStore *)0x1001;
static int get_kv_calls;

static int f_is_connected(void) { return fake_connected; }
static kvStore *f_get_kv(const char *bucket, int replicas, int history,
	int64_t ttl)
{
	(void)bucket; (void)replicas; (void)history; (void)ttl;
	get_kv_calls++;
	return fake_kv;
}

/* ── controllable fakes: the nats_dl libnats table ──────────────── */


#define FAKE_ENTRY ((kvEntry *)0x3001)
static const char *fake_entry_val = "fresh-value";

static natsStatus fake_kvStore_Get(kvEntry **e, kvStore *kv, const char *k)
{ (void)kv; (void)k; *e = FAKE_ENTRY; return NATS_OK; }
static natsStatus fake_kvStore_PutString(uint64_t *rev, kvStore *kv,
	const char *k, const char *v)
{ (void)kv; (void)k; (void)v; if (rev) *rev = 3; return NATS_OK; }
/* the length-aware Put: records (data, len) so the test can
 * prove the ORIGINAL bytes travel uncopied, embedded NUL included. */
static const void *put_last_data;
static int         put_last_len;
static natsStatus fake_kvStore_Put(uint64_t *rev, kvStore *kv,
	const char *k, const void *data, int len)
{ (void)kv; (void)k; put_last_data = data; put_last_len = len;
  if (rev) *rev = 3;
  return NATS_OK; }
static const char *fake_kvEntry_ValueString(const kvEntry *e)
{ (void)e; return fake_entry_val; }
static int fake_kvEntry_ValueLen(const kvEntry *e)
{ (void)e; return (int)strlen(fake_entry_val); }
static uint64_t fake_kvEntry_Revision(const kvEntry *e)
{ (void)e; return 42; }
static void fake_kvEntry_Destroy(kvEntry *e) { (void)e; }
static const char *fake_natsStatus_GetText(natsStatus s)
{ (void)s; return "fake-status"; }

/* ── controllable fake: pv_set_value ────────────────────────────── */

static int pv_rc = 0;          /* forced return of pv_set_value      */
static int pv_calls;

static int f_pv(struct sip_msg *msg, pv_spec_p sp, int op, pv_value_t *value)
{
	(void)msg; (void)sp; (void)op; (void)value;
	pv_calls++;
	return pv_rc;
}

/* ── harness ────────────────────────────────────────────────────── */

#define ASSERT(cond, msg) do { \
	if (!(cond)) { fail("kv_put_fastfail_leak: %s", msg); } \
	else         { pass("kv_put_fastfail_leak: %s", msg);            } \
} while (0)

#define DUMMY_MSG  ((struct sip_msg *)0x4001)
#define DUMMY_SPEC ((pv_spec_t *)0x5001)

extern int (*cn_ut_pv_set_value)(struct sip_msg *msg, pv_spec_p sp, int op,
	pv_value_t *value);

/* pkg balance against the allocator's own accounting */
#define PKG_MARK()   (u0 = PKG_GET_USED())
#define pkg_live     ((long)(PKG_GET_USED() - u0))
#define pkg_allocs   pkg_live

void cn_ut_kv_put_fastfail_leak(void)
{
	str bucket = { "b", 1 };
	str key = { "k1", 2 };
	str bigval, smallval;
	int rc, expected_rev = 1;
	unsigned long u0 = 0;
	int (*real_pv)(struct sip_msg *, pv_spec_p, int, pv_value_t *) = cn_ut_pv_set_value;

	cn_ut_fake_begin();
	nats_api.pool_is_connected = f_is_connected;
	nats_api.pool_get_kv = f_get_kv;
	cn_ut_pv_set_value = f_pv;

	/* install the libnats fakes into the dl table */
	nats_dl.kvStore_Get = fake_kvStore_Get;
	nats_dl.kvStore_PutString = fake_kvStore_PutString;
	nats_dl.kvStore_Put = fake_kvStore_Put;
	nats_dl.kvEntry_ValueString = fake_kvEntry_ValueString;
	nats_dl.kvEntry_ValueLen = fake_kvEntry_ValueLen;
	nats_dl.kvEntry_Revision = fake_kvEntry_Revision;
	nats_dl.kvEntry_Destroy = fake_kvEntry_Destroy;
	nats_dl.natsStatus_GetText = fake_natsStatus_GetText;

	/* an 8 KB value — forces the pkg_malloc'd copy path (>= 4096) */
	bigval.len = 8192;
	bigval.s = malloc(bigval.len);
	memset(bigval.s, 'x', bigval.len);
	smallval.s = "small";
	smallval.len = 5;

	/* 1. THE LEAK — disconnected fast-fail with a >4 KB value must not
	 * leave a pkg allocation behind (put) */
	fake_connected = 0;
	PKG_MARK();
	rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &bigval);
	ASSERT(rc == -1, "disconnected kv_put returns -1");
	ASSERT(pkg_live == 0,
		"disconnected kv_put leaves ZERO outstanding pkg allocations");
	ASSERT(pkg_allocs == 0,
		"disconnected kv_put does not even copy the value (gate first)");

	/* 2. same for update */
	PKG_MARK();
	rc = w_nats_kv_update(DUMMY_MSG, &bucket, &key, &bigval, &expected_rev);
	ASSERT(rc == -1, "disconnected kv_update returns -1");
	ASSERT(pkg_live == 0,
		"disconnected kv_update leaves ZERO outstanding pkg allocations");
	ASSERT(pkg_allocs == 0,
		"disconnected kv_update does not even copy the value (gate first)");

	/* 3. small (stack-buffer) values on the same path: still -1, still
	 * no pkg traffic */
	PKG_MARK();
	rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &smallval);
	ASSERT(rc == -1 && pkg_live == 0,
		"disconnected kv_put with small value: -1, no pkg delta");

	/* 4. connected happy paths: the value rides the
	 * length-aware kvStore_Put UNCOPIED -- no pkg traffic even for a
	 * >4 KB value (the old copy existed solely to gain a NUL). */
	fake_connected = 1;
	PKG_MARK();
	put_last_data = NULL; put_last_len = -1;
	rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &bigval);
	ASSERT(rc == 1, "connected kv_put (8 KB) succeeds");
	ASSERT(pkg_live == 0 && pkg_allocs == 0,
		"connected kv_put makes NO value copy at all");
	ASSERT(put_last_data == (const void *)bigval.s &&
	       put_last_len == bigval.len,
		"kv_put hands the ORIGINAL (ptr,len) to the length-aware Put");

	cf.seq[0] = '\0';
	PKG_MARK();
	rc = w_nats_kv_update(DUMMY_MSG, &bucket, &key, &bigval, &expected_rev);
	ASSERT(rc == 1 && strstr(cf.seq, "publish") != NULL, "connected kv_update succeeds");
	ASSERT(pkg_live == 0 && pkg_allocs == 0,
		"connected kv_update makes NO value copy at all");
	ASSERT(cf.msg_data == bigval.s && cf.msg_len == bigval.len,
		"kv_update hands the ORIGINAL (ptr,len) into the CAS write");

	/* 4a. embedded NUL: the *String API silently truncated such a
	 * value at the NUL; the length-aware call must carry ALL bytes. */
	{
		str nulval;
		nulval.s = "abc\0def";
		nulval.len = 7;
		put_last_data = NULL; put_last_len = -1;
		rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &nulval);
		ASSERT(rc == 1, "kv_put accepts an embedded-NUL value");
		ASSERT(put_last_len == 7 &&
		       put_last_data == (const void *)nulval.s,
			"all 7 bytes (NUL included) reach the broker write");
	}

	/* 4b. empty value: no allocation on any arm */
	{
		str empty = { NULL, 0 };
		PKG_MARK();
		rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &empty);
		ASSERT(rc == 1 && pkg_live == 0,
			"connected kv_put with empty value: ok, no pkg delta");
	}

	/* 5. IGNORED pv_set_value — a failed pvar write must fail the get.
	 * The fake entry delivers a value, but the pvar layer rejects it:
	 * returning 1 here hands the script a STALE $var as fresh. */
	pv_rc = -1;
	pv_calls = 0;
	PKG_MARK();
	rc = w_nats_kv_get(DUMMY_MSG, &bucket, &key, DUMMY_SPEC, NULL);
	ASSERT(pv_calls == 1, "kv_get attempted the pvar write");
	ASSERT(rc == -1, "kv_get returns -1 when the value pvar set fails");
	ASSERT(pkg_live == 0, "kv_get failure path stays pkg-balanced");

	/* 6. pvar write succeeding: get succeeds and stays balanced */
	pv_rc = 0;
	PKG_MARK();
	rc = w_nats_kv_get(DUMMY_MSG, &bucket, &key, DUMMY_SPEC, NULL);
	ASSERT(rc == 1, "kv_get succeeds when the pvar set succeeds");
	ASSERT(pkg_live == 0, "kv_get success path stays pkg-balanced");

	free(bigval.s);
	cn_ut_pv_set_value = real_pv;
	cn_ut_fake_end();
}
