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
 * An index hit whose KV row is gone (another node deleted it after this
 * node indexed it) must not be skipped silently: the query evicts the
 * stale index entry and counts index_miss_kv, and returns the rows that
 * do exist.  The index query path of nats_cache_query on fakes (index
 * binds on, cn_ut_fake.h).  Replaces tests/test_index_stale_recovery.c
 * (source greps).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_json.h"
#include "../cachedb_nats_stats.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

static cachedb_con con;
static nats_cachedb_con ncon;

static void fake_con(void)
{
	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	con.data = &ncon;
}

static unsigned long misses(void)
{
	nats_cdb_stats_t *s = nats_cdb_stats_slot();

	return s ? atomic_load(&s->index_miss_kv) : 0;
}

void cn_ut_index_stale_recovery(void)
{
	cdb_filter_t f;
	cdb_res_t res;
	unsigned long m0;
	int rc;

	cn_ut_fake_begin();
	fake_con();
	memset(&f, 0, sizeof f);
	f.key.name.s = "domain";
	f.key.name.len = 6;
	f.op = CDB_OP_EQ;
	f.val.is_str = 1;
	f.val.s.s = "example.com";
	f.val.s.len = 11;
	cf.match[0] = "json_gone";
	cf.n_match = 1;
	cf.get.status = NATS_NOT_FOUND;          /* deleted by another node */
	m0 = misses();
	rc = nats_cache_query(&con, &f, &res);
	ok(rc == 0 && res.count == 0, "index_stale_recovery: a stale hit returns no row (rc %d)", rc);
	ok(strstr(cf.seq, "query,get:json_gone,remove:json_gone,") != NULL,
		"index_stale_recovery: ... the stale entry is evicted from the index (%s)", cf.seq);
	ok(misses() == m0 + 1, "index_stale_recovery: ... and index_miss_kv counts it");
	ok(cf.n_release == 1, "index_stale_recovery: the matched key set is released");
	cdb_free_rows(&res);

	cf.seq[0] = '\0';
	cf.get.status = NATS_OK;                 /* the row is there */
	cf.get.val = "{\"aor\":\"alice\",\"contacts\":{\"c1\":{\"expires\":0}}}";
	cf.get.val_len = (int)strlen(cf.get.val);
	rc = nats_cache_query(&con, &f, &res);
	ok(rc == 0 && res.count == 1 && strstr(cf.seq, "remove") == NULL && misses() == m0 + 1,
		"index_stale_recovery: a live hit is returned, nothing evicted (rows %d)", res.count);
	cdb_free_rows(&res);
	cn_ut_fake_end();
}
