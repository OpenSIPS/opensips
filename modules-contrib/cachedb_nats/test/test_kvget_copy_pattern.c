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
 * nats_kv_get() hands the script a value that lives in the kvEntry's own
 * buffer; the entry is destroyed before the pvar is set, so the pvar must
 * get a COPY (a pvar setter that kept the pointer would read freed
 * memory).  The real w_nats_kv_get on fakes (cn_ut_fake.h): the fake
 * entry's buffer is overwritten on destroy, and the pvar write (captured
 * through the UNIT_TESTS seam cn_ut_pv_set_value) must see the value
 * intact, not in the entry's buffer, with its full length (an embedded
 * NUL included).  Replaces tests/test_kvget_copy_pattern.c (its
 * buggy/fixed model pair and child-process harness are gone).
 */

#include <tap.h>
#include <string.h>
#include <nats/nats.h>

#include "../../nats/nats_bind.h"
#include "../../../pvar.h"
#include "../cachedb_nats_native.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

extern int (*cn_ut_pv_set_value)(struct sip_msg *msg, pv_spec_p sp, int op,
	pv_value_t *value);

static char seen[128];
static int seen_len, in_entry, n_pv;

static int f_pv(struct sip_msg *msg, pv_spec_p sp, int op, pv_value_t *v)
{
	(void)msg; (void)op;
	if (sp != (pv_spec_p)0x5001)
		return 0;                 /* the rev pvar */
	n_pv++;
	in_entry = v->rs.s >= cf.val_buf && v->rs.s < cf.val_buf + sizeof cf.val_buf;
	seen_len = v->rs.len;
	memcpy(seen, v->rs.s, v->rs.len < (int)sizeof seen ? v->rs.len : (int)sizeof seen);
	return 0;
}

static int get(const char *val, int len)
{
	str b = str_init(""), k = str_init("call.1.state");
	int (*real_pv)(struct sip_msg *, pv_spec_p, int, pv_value_t *) = cn_ut_pv_set_value;
	int rc;

	memcpy(cf.val_buf, val, len);
	cf.scribble = 1;
	cf.get.status = NATS_OK;
	cf.get.val = cf.val_buf;
	cf.get.val_len = len;
	cf.get.rev = 9;
	n_pv = 0;
	seen_len = -1;
	cn_ut_pv_set_value = f_pv;
	rc = w_nats_kv_get(NULL, &b, &k, (pv_spec_t *)0x5001, (pv_spec_t *)0x5002);
	cn_ut_pv_set_value = real_pv;
	return rc;
}

void cn_ut_kvget_copy_pattern(void)
{
	int rc;

	cn_ut_fake_begin();
	rc = get("ringing", 7);
	ok(rc == 1 && n_pv == 1, "kvget_copy_pattern: kv_get succeeds and sets the value pvar (rc %d)", rc);
	ok(cf.n_entry_destroy == 1, "kvget_copy_pattern: the entry is destroyed");
	ok(!in_entry, "kvget_copy_pattern: the pvar is handed a copy, not the entry's buffer");
	ok(seen_len == 7 && !memcmp(seen, "ringing", 7),
		"kvget_copy_pattern: the value is intact after the entry was freed");

	rc = get("a\0b", 3);
	ok(rc == 1 && seen_len == 3 && !memcmp(seen, "a\0b", 3) && !in_entry,
		"kvget_copy_pattern: an embedded-NUL value keeps all its bytes");
	cn_ut_fake_end();
}
