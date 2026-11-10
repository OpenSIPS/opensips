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
 * With the broker down, every operation must fail at once -- no pool
 * call, no KV call (a worker would otherwise block for the full
 * JetStream timeout per REGISTER) -- and after a reconnect the con->data
 * operations must take a fresh KV handle before touching it (the old one
 * is destroyed by the pool: a dangling handle).  A failed query still
 * initialises its result (usrloc frees it on any failure) and a failed
 * raw query still clears its out-parameters.  All on the real operations
 * with fakes (cn_ut_fake.h).  Replaces the source-pattern tests
 * test_allops_fastfail.c, test_query_res_init.c and
 * test_outparam_contracts.c.
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../pvar.h"
#include "../../../cachedb/cachedb.h"
#include "../../../cachedb/cachedb_dict.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_json.h"
#include "../cachedb_nats_native.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static cachedb_con con;
static nats_cachedb_con ncon;

static void fake_con(void)
{
	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	ncon.bucket_name = "unit_tests";
	con.data = &ncon;
}

void cn_ut_disconnected_ops(void)
{
	cdb_filter_t f;
	cdb_res_t res;
	cdb_dict_t pairs;
	cdb_raw_entry **reply;
	int reply_no, rc, er = 1;
	str key = str_init("k"), sub = str_init("s"), val = str_init("v");
	str b = str_init(""), attr = str_init("SELECT");

	memset(&f, 0, sizeof f);
	f.key.name.s = "aor";
	f.key.name.len = 3;
	f.key.is_pk = 1;
	f.op = CDB_OP_EQ;
	f.val.is_str = 1;
	f.val.s.s = "alice";
	f.val.s.len = 5;

	cn_ut_fake_begin();
	fake_con();
	cf.connected = 0;

	/* garbage in the out-parameters, as a caller's stack would hold */
	memset(&res, 0x5a, sizeof res);
	rc = nats_cache_query(&con, &f, &res);
	ok(rc == -1, "disconnected_ops: query fails fast");
	ok(res.count == 0 && list_empty(&res.rows),
		"disconnected_ops: ... with its result initialised (usrloc frees it)");

	INIT_LIST_HEAD(&pairs);
	cdb_dict_add_int32(&pairs, "x", 1, 5);
	ok(nats_cache_update(&con, &f, &pairs) == -1, "disconnected_ops: update fails fast");
	cdb_free_entries(&pairs, NULL);
	INIT_LIST_HEAD(&pairs);

	reply = (cdb_raw_entry **)0x1;
	reply_no = 77;
	ok(nats_cache_raw_query_impl(&con, &attr, &reply, 1, &reply_no) == -1,
		"disconnected_ops: raw query fails fast");
	ok(reply == NULL && reply_no == 0,
		"disconnected_ops: ... with *reply NULL and *reply_no 0");

	memset(&res, 0x5a, sizeof res);
	ok(nats_cache_map_get(&con, &key, &res) == -1, "disconnected_ops: map_get fails fast");
	ok(nats_cache_map_set(&con, &key, &sub, &pairs) == -1, "disconnected_ops: map_set fails fast");
	ok(nats_cache_map_remove(&con, &key, &sub) == -1, "disconnected_ops: map_remove fails fast");

	ok(w_nats_kv_get(NULL, &b, &key, (pv_spec_t *)0x5001, NULL) == -1, "disconnected_ops: kv_get fails fast");
	ok(w_nats_kv_put(NULL, &b, &key, &val) == -1, "disconnected_ops: kv_put fails fast");
	ok(w_nats_kv_update(NULL, &b, &key, &val, &er) == -1, "disconnected_ops: kv_update fails fast");
	ok(w_nats_kv_delete(NULL, &b, &key) == -1, "disconnected_ops: kv_delete fails fast");
	ok(w_nats_kv_revision(NULL, &b, &key, (pv_spec_t *)0x5001) == -1, "disconnected_ops: kv_revision fails fast");
	ok(w_nats_kv_history(NULL, &key, (pv_spec_t *)0x5001) == -1, "disconnected_ops: kv_history fails fast");
	ok(cf.seq[0] == '\0', "disconnected_ops: not one pool or KV call was made (%s)", cf.seq);

	diag("after a reconnect: a fresh handle before any KV call:");
	cf.connected = 1;
	cf.epoch = 1;                     /* the handle was taken at epoch 0 */
	cf.get.status = NATS_NOT_FOUND;
	rc = nats_cache_query(&con, &f, &res);
	ok(rc == 0 && !strncmp(cf.seq, "get_kv,get:", 11),
		"disconnected_ops: query re-takes the KV handle first (%s)", cf.seq);
	cdb_free_rows(&res);
	cn_ut_fake_end();
}
