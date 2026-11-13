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
 * The registration MI scans (nats_reg_summary / nats_reg_list) enumerate
 * the bucket with the shared value-carrying watch (nats_kv_enum_live_values:
 * one WatchAll, values riding along) -- no kvStore_Keys and no per-key
 * kvStore_Get storm.  The real scan (reg_scan_bucket via the UNIT_TESTS
 * wrapper cn_ut_reg_scan, cachedb_nats_reg.c) on fakes (cn_ut_fake.h):
 * every usrloc row is handed to the row callback with its contacts
 * counted, and the libnats calls are exactly the watch.  Replaces
 * tests/test_reg_scan_enum.c (source greps + a model pass).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "cn_ut.h"
#include "cn_ut_fake.h"

int cn_ut_reg_scan(int *rows, long *contacts);

void cn_ut_reg_scan_enum(void)
{
	int rows = -1, rc;
	long contacts = -1;

	cn_ut_fake_begin();
	cf.next[0].status = NATS_OK;
	cf.next[0].key = "json_alice";
	cf.next[0].op = kvOp_Put;
	cf.next[0].val = "{\"aor\":\"alice\",\"contacts\":{\"c1\":{\"expires\":0},\"c2\":{\"expires\":0}}}";
	cf.next[0].val_len = (int)strlen(cf.next[0].val);
	cf.next[1] = cf.next[0];
	cf.next[1].key = "json_bob";
	cf.next[1].val = "{\"aor\":\"bob\",\"contacts\":{\"c1\":{\"expires\":0}}}";
	cf.next[1].val_len = (int)strlen(cf.next[1].val);
	cf.next[2].status = NATS_OK;           /* enumerated */
	cf.n_next = 3;
	rc = cn_ut_reg_scan(&rows, &contacts);
	ok(rc >= 0 && rows == 2 && contacts == 3,
		"reg_scan_enum: both rows scanned, contacts counted (rc %d, rows %d, contacts %ld)", rc, rows, contacts);
	ok(!strcmp(cf.seq, "get_kv,watch,stop,destroy,"),
		"reg_scan_enum: one value-carrying watch, no Keys, no per-key Get (%s)", cf.seq);
	cn_ut_fake_end();
}
