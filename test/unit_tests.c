/*
 * Starting point for writing and including OpenSIPS unit tests
 *
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

#include "../cachedb/test/test_backends.h"
#include "../lib/test/test_csv.h"

#include "../lib/list.h"
#include "../dprint.h"
#include "../sr_module.h"

void init_unit_tests(void) {
	set_mpath("modules/");
	//init_cachedb_tests();
}

int run_unit_tests(void) {
	//test_cachedb_backends();
	test_lib_csv();
	done_testing();
}
