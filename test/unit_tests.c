/*
 * Entry point for including and running OpenSIPS unit tests (core + modules)
 *
 * Copyright (C) 2018-2020 OpenSIPS Solutions
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

#include "../cachedb/test/test_cachedb.h"
#include "../lib/test/test_csv.h"
#include "../parser/test/test_parser.h"
#include "../mem/test/test_malloc.h"
#include "test_ut.h"

#include "../lib/list.h"
#include "../globals.h"
#include "../context.h"
#include "../dprint.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"

#include "unit_tests.h"

void init_unit_tests(void)
{
	if (!strcmp(testing_module, "core")) {
		set_mpath("modules/");
		solve_module_dependencies(modules);
		init_cachedb_tests();
		//init_malloc_tests();
	}

	ensure_global_context();
}

int run_unit_tests(void)
{
	char *error;
	void *mod_handle;
	mod_tests_f mod_tests;

	/* core tests */
	if (!strcmp(testing_module, "core")) {
		//test_malloc();
		test_cachedb();
		test_lib_csv();
		test_parser();
		test_ut();

	/* module tests */
	} else {
		mod_handle = get_mod_handle(testing_module);
		if (!mod_handle) {
			LM_ERR("module not loaded / not found: '%s'\n", testing_module);
			return -1;
		}

		mod_tests = (mod_tests_f)dlsym(mod_handle, DLSYM_PREFIX "mod_tests");
		if ((error = (char *)dlerror())) {
			LM_ERR("failed to locate 'mod_tests' in '%s': %s\n",
			       testing_module, error);
			return -1;
		}

		mod_tests();
	}

	done_testing();
}
