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
 * A raw "KV KEYS" query builds a cdb_raw_entry reply that the cachedb
 * core frees with free_raw_fetch(reply, expected_kv_no, rows): each row
 * must therefore have max(expected_kv_no, 1) columns, the extra ones
 * zeroed (they free as NULL).  One column per row made the core free read
 * past every row.  The real nats_cache_raw_query_impl on fakes, freed by
 * the real core free_raw_fetch, with the pkg balance checked through the
 * allocator (PKG_GET_USED).  Replaces tests/test_raw_query_cols.c (its
 * column model, the core-free model and greps).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../nats/nats_bind.h"
#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb.h"
#include "../cachedb_nats.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static char *keys[] = { "json_alice", "json_bob" };

static natsStatus f_keys(kvKeysList *l, kvStore *kv, const kvWatchOptions *o)
{
	(void)kv; (void)o;
	l->Keys = keys;
	l->Count = 2;
	return NATS_OK;
}
static void f_keys_destroy(kvKeysList *l) { (void)l; }

/* rows of a KV KEYS reply asked for @cols columns; *zeroed: the extra
 * columns are all zero; the reply is freed as the core frees it */
static int keys_reply(int cols, int *zeroed, int *names_ok, long *pkg_delta)
{
	cachedb_con con;
	nats_cachedb_con ncon;
	str attr = str_init("KV KEYS");
	cdb_raw_entry **reply = NULL;
	int n = -1, i, j, rc, ncols = cols >= 1 ? cols : 1;
	unsigned long u0 = PKG_GET_USED();

	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	con.data = &ncon;
	rc = nats_cache_raw_query_impl(&con, &attr, &reply, cols, &n);
	*zeroed = 1;
	*names_ok = 1;
	for (i = 0; rc == 0 && reply && i < n; i++) {
		if (reply[i][0].type != CDB_STR || reply[i][0].val.s.len != (int)strlen(keys[i]) ||
				memcmp(reply[i][0].val.s.s, keys[i], reply[i][0].val.s.len))
			*names_ok = 0;
		for (j = 1; j < ncols; j++)
			if (reply[i][j].type != 0 || reply[i][j].val.s.s != NULL)
				*zeroed = 0;
	}
	if (rc == 0 && reply)
		free_raw_fetch(reply, ncols, n);
	*pkg_delta = (long)(PKG_GET_USED() - u0);
	return rc == 0 ? n : -1;
}

void cn_ut_raw_query_cols(void)
{
	int n, z, names;
	long d;

	cn_ut_fake_begin();
	nats_dl.kvStore_Keys = f_keys;
	nats_dl.kvKeysList_Destroy = f_keys_destroy;

	n = keys_reply(1, &z, &names, &d);
	ok(n == 2 && names && d == 0, "raw_query_cols: 1 column: both keys, freed balanced (rows %d, pkg %ld)", n, d);
	n = keys_reply(3, &z, &names, &d);
	ok(n == 2 && names, "raw_query_cols: 3 columns: both keys in column 0");
	ok(z, "raw_query_cols: 3 columns: the extra columns are zeroed");
	ok(d == 0, "raw_query_cols: 3 columns: the core frees it in bounds and balanced (pkg %ld)", d);
	n = keys_reply(0, &z, &names, &d);
	ok(n == 2 && d == 0, "raw_query_cols: expected_kv_no 0 clamps to 1 column");
	n = keys_reply(-5, &z, &names, &d);
	ok(n == 2 && d == 0, "raw_query_cols: a negative expected_kv_no clamps to 1 column");
	cn_ut_fake_end();
}
