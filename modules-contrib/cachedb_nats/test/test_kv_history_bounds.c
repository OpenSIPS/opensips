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
 * nats_kv_history() builds a JSON array of a key's revisions into an
 * 8 KiB pkg buffer with a chain of snprintf(buf + pos, size - pos, ...);
 * snprintf returns what it WOULD have written, so on truncation pos could
 * pass the buffer end, size - pos go negative (a huge size_t) and the
 * next writes run off the heap buffer.  The fix clamps pos after every
 * advance (HIST_ADVANCE) and bounds the per-value escape loop.
 * The real w_nats_kv_history on fakes (cn_ut_fake.h): many oversized,
 * escape-heavy revisions; the value handed to the result pvar (captured
 * through the UNIT_TESTS seam cn_ut_pv_set_value) stays inside the
 * buffer, NUL-terminated at its length, the truncation is logged, and a
 * small history is complete and exact.  Replaces
 * tests/test_kv_history_bounds.c (its carried loop and the ASan net:
 * an overrun is now caught only through the result's bounds).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../nats/nats_bind.h"
#include "../../../pvar.h"
#include "../cachedb_nats_native.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

extern int (*cn_ut_pv_set_value)(struct sip_msg *msg, pv_spec_p sp, int op,
	pv_value_t *value);

#define HIST_BUF 8192
#define N_ENTRIES 40

static struct cn_ut_entry ents[N_ENTRIES];
static kvEntry *ent_ptrs[N_ENTRIES];
static int n_ents;
static char big[1200];

static char got[2 * HIST_BUF];
static int got_len, got_strlen, n_pv;

static natsStatus f_history(kvEntryList *list, kvStore *kv, const char *key,
	const kvWatchOptions *o)
{
	(void)kv; (void)key; (void)o;
	list->Entries = ent_ptrs;
	list->Count = n_ents;
	return NATS_OK;
}
static void f_list_destroy(kvEntryList *list) { (void)list; }

static int f_pv(struct sip_msg *msg, pv_spec_p sp, int op, pv_value_t *v)
{
	(void)msg; (void)sp; (void)op;
	n_pv++;
	got_len = v->rs.len;
	got_strlen = (int)strnlen(v->rs.s, sizeof got);
	memcpy(got, v->rs.s, got_strlen < (int)sizeof got - 1 ? got_strlen : (int)sizeof got - 1);
	got[got_strlen < (int)sizeof got - 1 ? got_strlen : (int)sizeof got - 1] = '\0';
	return 0;
}

static int run(int n, const char *val)
{
	str key = str_init("k1");
	int i, rc;
	int (*real_pv)(struct sip_msg *, pv_spec_p, int, pv_value_t *) = cn_ut_pv_set_value;

	n_ents = n;
	for (i = 0; i < n; i++) {
		memset(&ents[i], 0, sizeof ents[i]);
		ents[i].status = NATS_OK;
		ents[i].key = "k1";
		ents[i].val = val;
		ents[i].val_len = (int)strlen(val);
		ents[i].rev = (uint64_t)(i + 1);
		ent_ptrs[i] = (kvEntry *)&ents[i];
	}
	nats_dl.kvStore_History = f_history;
	nats_dl.kvEntryList_Destroy = f_list_destroy;
	cn_ut_pv_set_value = f_pv;
	n_pv = 0;
	got_len = got_strlen = -1;
	rc = w_nats_kv_history(NULL, &key, (pv_spec_t *)0x5001);
	cn_ut_pv_set_value = real_pv;
	return rc;
}

void cn_ut_kv_history_bounds(void)
{
	int rc;

	/* every byte a '"': each one doubles when escaped */
	memset(big, '"', sizeof big - 1);
	big[sizeof big - 1] = '\0';

	cn_ut_fake_begin();
	rc = run(N_ENTRIES, big);
	ok(rc > 0 && n_pv == 1, "kv_history_bounds: an oversized history still returns a value (rc %d)", rc);
	ok(got_len >= 0 && got_len < HIST_BUF, "kv_history_bounds: the result stays inside the 8 KiB buffer (len %d)", got_len);
	ok(got_strlen == got_len, "kv_history_bounds: NUL-terminated exactly at its length (%d vs %d)", got_strlen, got_len);
	ok(got_len > 0 && got[0] == '[' && got[got_len - 1] == ']',
		"kv_history_bounds: still a closed JSON array");
	ok(strstr(cn_ut_fake_log(), "exceeds") != NULL, "kv_history_bounds: the truncation is logged");

	rc = run(2, "a\"b\\c\x01");
	ok(rc > 0 && !strcmp(got, "[{\"rev\":1,\"value\":\"a\\\"b\\\\c\\u0001\"},"
		"{\"rev\":2,\"value\":\"a\\\"b\\\\c\\u0001\"}]"),
		"kv_history_bounds: a small history is complete and escaped (%s)", got);
	cn_ut_fake_end();
}
