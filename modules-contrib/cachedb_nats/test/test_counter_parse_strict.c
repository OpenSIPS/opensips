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
 * The stored counter value must be a real integer: a non-numeric or
 * trailing-garbage value is refused (not silently read as 0, which would
 * reset the counter), an empty value is refused, an absent counter is
 * the create path.  Through the real nats_cache_add on fakes
 * (cn_ut_fake.h); replaces tests/test_counter_parse_strict.c (its
 * counter_parse copy and source grep are gone).
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

void cn_ut_counter_parse_strict(void)
{
	int nv, rc;
	const char *w;

	cn_ut_fake_begin();
	rc = counter_op("42", 1, &nv, &w);
	ok(rc == 0 && nv == 43, "counter_parse_strict: a plain integer parses (rc %d, %d)", rc, nv);
	rc = counter_op("  -7 ", 1, &nv, &w);
	ok(rc == 0 && nv == -6, "counter_parse_strict: a signed, whitespace-padded integer parses");
	rc = counter_op(NULL, 4, &nv, &w);
	ok(rc == 0 && nv == 4, "counter_parse_strict: an absent counter is the create path");
	rc = counter_op("abc", 1, &nv, &w);
	ok(rc == -1 && !*w, "counter_parse_strict: non-numeric REFUSED (not reset to 0)");
	rc = counter_op("12abc", 1, &nv, &w);
	ok(rc == -1 && !*w, "counter_parse_strict: trailing garbage refused");
	rc = counter_op("", 1, &nv, &w);
	ok(rc == -1 && !*w, "counter_parse_strict: an empty value refused");
	rc = counter_op("1099511627776", 0, &nv, &w);
	ok(rc == -1 && !*w, "counter_parse_strict: beyond 32 bits refused");
	rc = counter_op("1\\2", 0, &nv, &w);
	ok(rc == -1 && !*w, "counter_parse_strict: a backslash inside refused");
	cn_ut_fake_end();
}
