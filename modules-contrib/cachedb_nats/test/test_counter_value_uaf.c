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
 * The counter read-modify-write (nats_cache_add / _sub) must not touch the
 * stored value after kvEntry_Destroy(): kvEntry_ValueString points into
 * the entry, and the "not a valid 32-bit integer" error used to log that
 * pointer after the destroy (a use-after-free read).  The fake entry's
 * buffer is overwritten on destroy, so a read after it logs X's instead
 * of the value (no ASan needed).  Replaces tests/test_counter_value_uaf.c
 * (its SIMULATE_UAF_BUG model and source greps are gone).
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

void cn_ut_counter_value_uaf(void)
{
	str attr = str_init("hits");
	int nv = -1, rc;
	const char *log;

	cn_ut_fake_begin();
	fake_con();
	strcpy(cf.val_buf, "999999999999999999999999");
	cf.scribble = 1;
	cf.get.status = NATS_OK;
	cf.get.val = cf.val_buf;
	cf.get.val_len = (int)strlen(cf.val_buf);
	cf.get.rev = 3;
	rc = nats_cache_add(&con, &attr, 1, 0, &nv);
	log = cn_ut_fake_log();
	ok(rc < 0, "counter_value_uaf: an out-of-range stored counter refuses the op (rc %d)", rc);
	ok(strstr(log, "('999999999999999999999999')") != NULL,
		"counter_value_uaf: the error names the stored value, read before the destroy");
	ok(strstr(log, "XXXX") == NULL, "counter_value_uaf: nothing read from the freed entry");
	ok(cf.n_entry_destroy == 1, "counter_value_uaf: the entry is destroyed once");
	ok(strstr(cf.seq, "publish") == NULL && strstr(cf.seq, "create") == NULL,
		"counter_value_uaf: nothing written");
	cn_ut_fake_end();
}
