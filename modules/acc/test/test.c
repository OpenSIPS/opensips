/*
 * Copyright (C) 2023 OpenSIPS Solutions
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

#include "../../../dprint.h"

#include "../acc_logic.h"


static void test_acc_flags(void)
{
	unsigned long long types, flags, mask;
	int t = 1;

	/* 1. Single backend, no flags */
	mask = acc_bitmask_set(DO_ACC_LOG, NULL);
	ok(is_log_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_aaa_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_db_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_evi_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_failed_on(mask), "test-acc-flags-%d", t++);


	/* 2. ... which we reset: */
	types = DO_ACC_LOG;
	mask = acc_bitmask_reset(&types, NULL, mask);
	ok(!is_log_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_failed_on(mask), "test-acc-flags-%d", t++);


	/* 3. Multi-backends, multi-flags */
	flags = DO_ACC_CDR|DO_ACC_MISSED;
	mask = acc_bitmask_set(DO_ACC_LOG|DO_ACC_DB, &flags);
	ok(is_log_acc_on(mask), "test-acc-flags-%d", t++);
	ok(is_log_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(is_log_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_aaa_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_failed_on(mask), "test-acc-flags-%d", t++);

	ok(is_db_acc_on(mask), "test-acc-flags-%d", t++);
	ok(is_db_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(is_db_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_evi_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_failed_on(mask), "test-acc-flags-%d", t++);


	/* 4. reset 1 x flag on 1 x backend */
	types = DO_ACC_DB;
	flags = DO_ACC_MISSED;
	mask = acc_bitmask_reset(&types, &flags, mask);
	ok(is_log_acc_on(mask), "test-acc-flags-%d", t++);
	ok(is_log_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(is_log_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_aaa_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_failed_on(mask), "test-acc-flags-%d", t++);

	ok(is_db_acc_on(mask), "test-acc-flags-%d", t++);
	ok(is_db_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_evi_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_failed_on(mask), "test-acc-flags-%d", t++);


	/* 5. resetting the last flag on a backend resets acc too */
	types = DO_ACC_DB;
	flags = DO_ACC_CDR;
	mask = acc_bitmask_reset(&types, &flags, mask);
	ok(is_log_acc_on(mask), "test-acc-flags-%d", t++);
	ok(is_log_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(is_log_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_aaa_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_db_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_evi_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_failed_on(mask), "test-acc-flags-%d", t++);


	/* 6. similar reset, except with multiple flags */
	types = DO_ACC_LOG;
	flags = DO_ACC_CDR|DO_ACC_MISSED;
	mask = acc_bitmask_reset(&types, &flags, mask);
	ok(!is_log_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_log_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_aaa_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_aaa_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_db_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_db_failed_on(mask), "test-acc-flags-%d", t++);

	ok(!is_evi_acc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_cdr_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_mc_on(mask), "test-acc-flags-%d", t++);
	ok(!is_evi_failed_on(mask), "test-acc-flags-%d", t++);

}


void mod_tests(void)
{
	test_acc_flags();
}
