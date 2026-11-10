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
 * The update path must not merge into a stored doc that carries an
 * embedded NUL: copying data_len bytes and then measuring with strlen
 * would truncate at the NUL and the merge would silently drop the rest of
 * the row.  update_fetch_or_seed (cn_ut_update_fetch_or_seed on a fake
 * kvStore_Get) refuses such a doc; a clean one keeps its full length.
 * Replaces tests/test_update_nul_poison.c (its model and greps).
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

int cn_ut_update_fetch_or_seed(nats_cachedb_con *ncon, const cdb_filter_t *f,
	const char *key, char **json, int *len, uint64_t *rev);

static int fetch(const char *val, int len, char **json, int *out_len)
{
	cdb_filter_t f;
	uint64_t rev;

	memset(&f, 0, sizeof f);
	f.key.name.s = "aor";
	f.key.name.len = 3;
	f.val.is_str = 1;
	f.val.s.s = "alice";
	f.val.s.len = 5;
	cf.get.status = NATS_OK;
	cf.get.val = val;
	cf.get.val_len = len;
	cf.get.rev = 4;
	*json = NULL;
	*out_len = -1;
	return cn_ut_update_fetch_or_seed(&ncon, &f, "json_alice", json, out_len, &rev);
}

void cn_ut_update_nul_poison(void)
{
	static const char clean[] = "{\"aor\":\"alice\",\"contacts\":{}}";
	static const char poison[] = "{\"aor\":\"al\0ice\",\"contacts\":{\"c1\":{}}}";
	char *json;
	int len, rc;

	cn_ut_fake_begin();
	fake_con();
	rc = fetch(clean, (int)sizeof clean - 1, &json, &len);
	ok(rc == 0 && json && len == (int)sizeof clean - 1,
		"update_nul_poison: clean doc: full length preserved (len %d)", len);
	if (json)
		pkg_free(json);
	rc = fetch(poison, (int)sizeof poison - 1, &json, &len);
	ok(rc == -1 && !json,
		"update_nul_poison: doc with an embedded NUL is REJECTED, not truncated (rc %d)", rc);
	ok(cf.n_entry_destroy == 2, "update_nul_poison: both entries destroyed");
	cn_ut_fake_end();
}
