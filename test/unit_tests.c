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

#include "../db/test/test_db.h"
#include "../cachedb/test/test_cachedb.h"
#include "../lib/test/test_csv.h"
#include "../lib/test/test_digest_auth.h"
#include "../parser/test/test_parser.h"
#include "../mem/test/test_malloc.h"
#include "../mem/test/test_hg_malloc.h"
#include "test_ut.h"

#include "../str.h"
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
		add_mpath("modules/");
		solve_module_dependencies(modules);
		init_cachedb_tests();
		//init_malloc_tests();
#ifdef HG_MALLOC
		/* the allocator suites run when HG_MALLOC is selected, e.g.
		 * make test UT_ALLOC=HG_MALLOC UT_MEM="-m 64:1024 -M 16:256" */
		if (hg_ut_selected())
			init_malloc_tests();
#endif
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
		/* remember to update the Makefile.test OpenSIPS command-line with at
		 * least "-m2048 -M128" before stress-testing any of the allocators! */
		//test_malloc();
#ifdef HG_MALLOC
		if (hg_ut_selected()) {
			test_hg_malloc();
			test_malloc();
		}
#endif
		test_cachedb();
		test_lib_csv();
		test_parser();
		test_ut();
		test_lib_digest_auth();
		test_db();

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
