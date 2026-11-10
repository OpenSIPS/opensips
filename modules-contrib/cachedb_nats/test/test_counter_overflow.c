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
 * The counter read-modify-write (nats_cache_add / nats_cache_sub) on a
 * broker-supplied value: the new value is computed in 64 bits and an op
 * that would leave the 32-bit range is refused -- never wrapped, never
 * truncated -- and nothing is written.  The real ops on fakes
 * (cn_ut_fake.h); replaces tests/test_counter_overflow.c (its
 * counter_add model is gone).
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <nats/nats.h>

#include "../../../cachedb/cachedb.h"
#include "../cachedb_nats.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

/* nats_cache_add / _sub on a fake connection whose stored counter is
 * @stored (NULL: absent).  Returns the op result; *written: the value
 * written ("" when nothing was). */
static int counter_op(const char *stored, int delta, int *new_val,
	const char **written)
{
	cachedb_con con;
	nats_cachedb_con ncon;
	str attr = str_init("hits");
	int rc;

	memset(&con, 0, sizeof con);
	memset(&ncon, 0, sizeof ncon);
	ncon.kv = (kvStore *)cn_ut_fake_kv();
	con.data = &ncon;
	cf.seq[0] = '\0';
	cf.published[0] = '\0';
	if (stored) {
		snprintf(cf.val_buf, sizeof cf.val_buf, "%s", stored);
		cf.get.status = NATS_OK;
		cf.get.val = cf.val_buf;
		cf.get.val_len = (int)strlen(cf.val_buf);
		cf.get.rev = 3;
	} else
		cf.get.status = NATS_NOT_FOUND;
	*new_val = 12345;
	rc = delta >= 0 ? nats_cache_add(&con, &attr, delta, 0, new_val)
		: nats_cache_sub(&con, &attr, -delta, 0, new_val);
	*written = (strstr(cf.seq, "update_string") || strstr(cf.seq, "create_string"))
		? cf.published : "";
	return rc;
}

void cn_ut_counter_overflow(void)
{
	int nv, rc;
	const char *w;
	char s[32];

	cn_ut_fake_begin();
	rc = counter_op("5", 3, &nv, &w);
	ok(rc == 0 && nv == 8 && !strcmp(w, "8"), "counter_overflow: 5 + 3 = 8 written (rc %d, %s)", rc, w);
	rc = counter_op(NULL, 1, &nv, &w);
	ok(rc == 0 && nv == 1 && !strcmp(w, "1") && strstr(cf.seq, "create_string"),
		"counter_overflow: an absent counter is created at the delta");
	snprintf(s, sizeof s, "%d", INT_MAX);
	rc = counter_op(s, 1, &nv, &w);
	ok(rc == -1 && !*w, "counter_overflow: INT_MAX + 1 refused, not wrapped, nothing written");
	snprintf(s, sizeof s, "%d", INT_MIN);
	rc = counter_op(s, -1, &nv, &w);
	ok(rc == -1 && !*w, "counter_overflow: INT_MIN - 1 refused, not wrapped");
	rc = counter_op(s, 0, &nv, &w);
	ok(rc == 0 && nv == INT_MIN, "counter_overflow: INT_MIN itself is a valid counter");
	rc = counter_op("4294967296", 0, &nv, &w);
	ok(rc == -1 && !*w, "counter_overflow: 2^32 stored refused (not truncated)");
	rc = counter_op("999999999999999999999999", 1, &nv, &w);
	ok(rc == -1 && !*w, "counter_overflow: beyond int64 refused");
	snprintf(s, sizeof s, "%d", INT_MAX - 1);
	rc = counter_op(s, 1, &nv, &w);
	ok(rc == 0 && nv == INT_MAX, "counter_overflow: up to INT_MAX exactly is fine");
	cn_ut_fake_end();
}
