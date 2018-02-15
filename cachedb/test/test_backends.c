/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <tap.h>

#include "../../str.h"
#include "../../cachedb/cachedb.h"
#include "../../sr_module.h"
#include "../../modparam.h"

static void test_cachedb_api(const char *cachedb_name)
{
	str key = str_init("foo"),
	    val = str_init("bar"), cdb_str;

	init_str(&cdb_str, cachedb_name);

	ok(cachedb_store(&cdb_str, &key, &val, 0) == 1, "store key");

	memset(&val, 0, sizeof val);
	ok(cachedb_fetch(&cdb_str, &key, &val) == 1, "fetch key");
	cmp_mem(val.s, "bar", 3, "check fetched value");

	ok(cachedb_remove(&cdb_str, &key) == 1, "remove key");

	memset(&val, 1, sizeof val);
	ok(cachedb_fetch(&cdb_str, &key, &val) == -2, "fetch non-existing key");
}

void init_cachedb_tests(void)
{
	if (load_module("cachedb_mongodb.so") != 0) {
		printf("failed to load mongo\n");
		exit(-1);
	}

	if (set_mod_param_regex("cachedb_mongodb", "cachedb_url", STR_PARAM,
	    "mongodb://10.0.0.4:27017/OpensipsTests.Opensips.Tests") != 0) {
		printf("failed to set mongo url\n");
		exit(-1);
	}
}

void test_cachedb_backends(void)
{
	test_cachedb_api("mongodb");
	todo();
	test_cachedb_api("cassandra");
	end_todo;
}
