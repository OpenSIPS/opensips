/*
 * Copyright (C) 2026 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <tap.h>
#include <stdio.h>

#include "../../../str.h"
#include "../dlg.h"
#include "../ua_api.h"
#include "../b2b_entities.h"

/* opensips.cfg sets 16 server and 8 client hash entries */

static str mk_key(char *buf, size_t size, unsigned int hash_index)
{
	str key;

	key.s = buf;
	key.len = snprintf(buf, size, "B2B.%u.1.1.1", hash_index);
	return key;
}

static void test_parse_key(void)
{
	char buf[64];
	str key;
	unsigned int h, l;

	ok(server_hsize == 16 && client_hsize == 8, "table sizes");

	key = mk_key(buf, sizeof buf, 15);
	ok(b2b_parse_key(&key, server_hsize, &h, &l) == 0 && h == 15 && l == 1,
		"last server hash index is accepted");
	key = mk_key(buf, sizeof buf, 16);
	ok(b2b_parse_key(&key, server_hsize, &h, &l) < 0,
		"hash index past the server table is rejected");

	key = mk_key(buf, sizeof buf, 7);
	ok(b2b_parse_key(&key, client_hsize, &h, &l) == 0 && h == 7,
		"last client hash index is accepted");
	key = mk_key(buf, sizeof buf, 8);
	ok(b2b_parse_key(&key, client_hsize, &h, &l) < 0,
		"hash index past the client table is rejected");

	key = mk_key(buf, sizeof buf, 4294967295U);
	ok(b2b_parse_key(&key, server_hsize, &h, &l) < 0,
		"huge hash index is rejected");

	ok(b2b_et_hsize(B2B_SERVER) == 16 && b2b_et_hsize(B2B_CLIENT) == 8 &&
		b2b_et_hsize(B2B_NONE) == 16, "table size by entity type");
}

static void test_lookup_out_of_range(void)
{
	char buf[64];
	str key;

	/* fits the server table, not the client one */
	key = mk_key(buf, sizeof buf, 12);
	ok(b2b_entity_exists(B2B_CLIENT, &key) == 0,
		"client lookup past the client table finds nothing");
	ok(ua_entity_delete(B2B_NONE, &key, 0, 0) < 0,
		"lookup in both tables past the client table finds nothing");

	/* a miss must not leave a table locked */
	key = mk_key(buf, sizeof buf, 3);
	ok(ua_entity_delete(B2B_NONE, &key, 0, 0) < 0 &&
		ua_entity_delete(B2B_NONE, &key, 0, 0) < 0 &&
		b2b_entity_exists(B2B_SERVER, &key) == 0 &&
		b2b_entity_exists(B2B_CLIENT, &key) == 0,
		"a miss in both tables leaves no lock held");

	key = mk_key(buf, sizeof buf, 1000);
	ok(b2b_entity_exists(B2B_SERVER, &key) == 0,
		"server lookup past the server table finds nothing");
	ok(ua_entity_delete(B2B_NONE, &key, 0, 0) < 0,
		"lookup in both tables past both tables finds nothing");
}

void mod_tests(void)
{
	test_parse_key();
	test_lookup_out_of_range();
}
