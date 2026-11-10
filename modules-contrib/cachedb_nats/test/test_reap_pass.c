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
 * A reaper pass (nats_cdb_reaper_tick) on fakes (cn_ut_fake.h): it
 * enumerates the bucket with ONE watch (kvStore_WatchAll, values riding
 * along) -- no kvStore_Keys and no per-key kvStore_Get storm -- and for
 * each due usrloc row either CAS-deletes it (no live contact left: a
 * KV-Operation DEL marker at the row's revision) or CAS-writes the
 * survivors at that revision; rows not due and keys outside the json_
 * prefix are left alone.  Replaces tests/test_reap_enum_wiring.c (a
 * source-pattern test).
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <nats/nats.h>

#include "../cachedb_nats_expiry.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static char row_a[256], row_b[256], row_c[256];

static void put(int i, const char *key, const char *val, uint64_t rev)
{
	cf.next[i].status = NATS_OK;
	cf.next[i].key = key;
	cf.next[i].op = kvOp_Put;
	cf.next[i].val = val;
	cf.next[i].val_len = val ? (int)strlen(val) : 0;
	cf.next[i].rev = rev;
	cf.n_next = i + 1;
}

void cn_ut_reap_pass(void)
{
	long long now = (long long)time(NULL), past = now - 100000, fut = now + 100000;

	snprintf(row_a, sizeof row_a, "{\"aor\":\"a\",\"contacts\":{\"c1\":"
		"{\"expires\":%lld}},\"row_exp\":%lld}", past, past);
	snprintf(row_b, sizeof row_b, "{\"aor\":\"b\",\"contacts\":{\"c1\":"
		"{\"expires\":%lld},\"c2\":{\"expires\":%lld}},\"row_exp\":%lld}",
		past, fut, past);
	snprintf(row_c, sizeof row_c, "{\"aor\":\"c\",\"contacts\":{\"c1\":"
		"{\"expires\":%lld}},\"row_exp\":%lld}", fut, fut);

	cn_ut_fake_begin();
	put(0, "json_a", row_a, 11);         /* every contact expired */
	put(1, "json_b", row_b, 12);         /* one of two expired */
	put(2, "json_c", row_c, 13);         /* not due */
	put(3, "other", row_a, 14);          /* outside the prefix */
	put(4, NULL, NULL, 0);               /* the "enumerated" sentinel */
	cf.next[4].op = 0;
	nats_cdb_reaper_tick(0, NULL);
	diag("seq: %s", cf.seq);

	ok(!strncmp(cf.seq, "get_kv,watch,", 13),
		"reap_pass: the bucket is enumerated by one watch");
	ok(strstr(cf.seq, "get:") == NULL, "reap_pass: no per-key Get (no GET storm)");
	ok(strstr(cf.seq, "msg:$KV.unit_tests.json_a,header:KV-Operation=DEL,publish:11,") != NULL,
		"reap_pass: a row with no live contact: DEL marker CAS'd at its revision");
	ok(strstr(cf.seq, "msg:$KV.unit_tests.json_b,publish:12,") != NULL,
		"reap_pass: a row with a survivor: rewritten at its revision");
	ok(strstr(cf.published, "c2") != NULL && strstr(cf.published, "\"c1\"") == NULL,
		"reap_pass: ... keeping the live contact only");
	ok(strstr(cf.seq, "json_c") == NULL, "reap_pass: a row not due is not written");
	ok(strstr(cf.seq, "other") == NULL, "reap_pass: a key outside the prefix is skipped");
	ok(strstr(cf.seq, "stop,destroy,") != NULL, "reap_pass: the transient watcher is torn down");
	ok(strstr(cn_ut_fake_log(), "reclaimed 2 row(s)") != NULL, "reap_pass: two rows reclaimed");
	cn_ut_fake_end();
}
