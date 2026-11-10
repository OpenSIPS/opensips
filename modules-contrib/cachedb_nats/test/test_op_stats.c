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
 * The broker-degradation counters: fastfail_rejected (an op refused up
 * front: pool disconnected, or the post-reconnect handle refresh failed),
 * op_failed (an op that reached the broker and got a hard error -- a
 * NOT_FOUND miss is not one), watcher_restarts (a rebuild after the
 * first build).  Driven through the real operations and watcher loop on
 * fakes (cn_ut_fake.h), read from this process's stats slot.  Replaces
 * tests/test_op_stats.c (its counting model and header greps).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../cachedb/cachedb.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_stats.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

#define STAT(f) ({ nats_cdb_stats_t *_s = nats_cdb_stats_slot(); \
	_s ? (long)atomic_load(&_s->f) : -1L; })

void cn_ut_op_stats(void)
{
	cachedb_con con;
	nats_cachedb_con ncon;
	str attr = str_init("k"), val;
	long ff0, of0, wr0;
	int rc;

	ok(nats_cdb_stats_slot() != NULL, "op_stats: this process has a stats slot");
	cn_ut_fake_begin();
	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	ncon.bucket_name = "unit_tests";
	con.data = &ncon;
	ff0 = STAT(fastfail_rejected);
	of0 = STAT(op_failed);
	wr0 = STAT(watcher_restarts);

	cf.connected = 0;
	rc = nats_cache_get(&con, &attr, &val);
	ok(rc < 0 && STAT(fastfail_rejected) == ff0 + 1, "op_stats: a disconnected op counts as fastfail_rejected");
	cf.connected = 1;
	cf.epoch = 1;                          /* reconnect ... */
	cf.kv_null = 1;                        /* ... and the refresh fails */
	rc = nats_cache_get(&con, &attr, &val);
	ok(rc < 0 && STAT(fastfail_rejected) == ff0 + 2, "op_stats: a failed handle refresh counts as fastfail_rejected");
	ok(STAT(op_failed) == of0, "op_stats: ... neither is an op_failed");

	cf.kv_null = 0;
	cf.get.status = NATS_NOT_FOUND;
	rc = nats_cache_get(&con, &attr, &val);
	ok(STAT(op_failed) == of0, "op_stats: a NOT_FOUND miss is not an op_failed (rc %d)", rc);
	cf.get.status = NATS_ERR;
	rc = nats_cache_get(&con, &attr, &val);
	ok(rc < 0 && STAT(op_failed) == of0 + 1, "op_stats: a hard KV error counts as op_failed");
	cn_ut_fake_end();

	cn_ut_fake_begin();
	cf.next[0].status = NATS_OK;           /* caught up, then a reconnect */
	cf.next[0].reconnect = 1;
	cf.n_next = 1;
	cn_ut_watcher_run();
	ok(STAT(watcher_restarts) == wr0 + 1,
		"op_stats: one rebuild after a reconnect = one restart (the first build is not one) (%s)", cf.seq);
	cn_ut_fake_end();
}
