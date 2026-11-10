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
 * The search index is an optional module (cachedb_nats_fts) bound at
 * mod_init through its binds, not a cachedb_nats modparam.  This suite's
 * cfg does not load it, so in the running module: no binds (cdbn_fts_on
 * 0), no enable_search_index modparam, a non-PK update is refused naming
 * the missing module, a non-PK query falls back to a bucket scan, and the
 * watcher leaves the (absent) index alone.  Replaces
 * tests/test_enable_search_index.c (source greps).  LOST: the FTS
 * module's own mod_init / destroy ownership (another module's code).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../../sr_module.h"
#include "../../../cachedb/cachedb.h"
#include "../../../cachedb/cachedb_dict.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

void cn_ut_fts_optional(void)
{
	struct sr_module *m;
	const param_export_t *p;
	int has_param = 0, rc, live_fts_on = cdbn_fts_on;
	cachedb_con con;
	nats_cachedb_con ncon;
	cdb_filter_t f;
	cdb_dict_t pairs;
	cdb_res_t res;

	ok(live_fts_on == 0, "fts_optional: no cachedb_nats_fts loaded -> no index binds");
	for (m = modules; m; m = m->next)
		if (m->exports && !strcmp(m->exports->name, "cachedb_nats"))
			for (p = m->exports->params; p && p->name; p++)
				if (!strcmp(p->name, "enable_search_index"))
					has_param = 1;
	ok(!has_param, "fts_optional: no enable_search_index modparam");

	cn_ut_fake_begin();
	cdbn_fts_on = 0;
	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	con.data = &ncon;
	memset(&f, 0, sizeof f);
	f.key.name.s = "domain";
	f.key.name.len = 6;
	f.key.is_pk = 0;                       /* not the primary key */
	f.op = CDB_OP_EQ;
	f.val.is_str = 1;
	f.val.s.s = "example.com";
	f.val.s.len = 11;
	INIT_LIST_HEAD(&pairs);
	cdb_dict_add_int32(&pairs, "x", 1, 5);

	rc = nats_cache_update(&con, &f, &pairs);
	ok(rc == -1 && strstr(cn_ut_fake_log(), "cachedb_nats_fts) is not loaded"),
		"fts_optional: non-PK update refused, naming the missing module (rc %d)", rc);
	ok(strstr(cf.seq, "create") == NULL && strstr(cf.seq, "publish") == NULL,
		"fts_optional: ... and nothing written");
	cdb_free_entries(&pairs, NULL);

	cf.seq[0] = '\0';
	cf.next[0].status = NATS_OK;           /* an empty bucket */
	cf.n_next = 1;
	rc = nats_cache_query(&con, &f, &res);
	ok(rc == 0 && res.count == 0 && strstr(cf.seq, "watch") != NULL,
		"fts_optional: non-PK query without the index -> bucket scan (rc %d, %s)", rc, cf.seq);
	cdb_free_rows(&res);
	cn_ut_fake_end();

	diag("the watcher leaves the index alone:");
	cn_ut_fake_begin();
	cdbn_fts_on = 0;
	cf.next[0].status = NATS_OK;
	cf.next[0].key = "json_alice";
	cf.next[0].op = kvOp_Put;
	cf.next[0].val = "{\"aor\":\"alice\"}";
	cf.next[0].val_len = 15;
	cf.next[1].status = NATS_OK;
	cf.next[1].key = "json_bob";
	cf.next[1].op = kvOp_Delete;
	cf.n_next = 2;
	cn_ut_watcher_run();
	ok(strstr(cf.seq, "rebuild") == NULL && strstr(cf.seq, "add:") == NULL &&
		strstr(cf.seq, "revmap:") == NULL && strstr(cf.seq, "remove:") == NULL,
		"fts_optional: no rebuild, add or remove without the binds (%s)", cf.seq);
	cn_ut_fake_end();
}
