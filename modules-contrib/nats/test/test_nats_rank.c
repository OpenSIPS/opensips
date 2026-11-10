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
 */

/*
 * test_nats_rank.c — Unit test for nats_pool_should_init().
 *
 * Build standalone:
 *   make -C modules-contrib/nats/tests test_nats_rank && ./test_nats_rank (part of make check)
 *
 * Run:
 *   modules-contrib/nats/tests/test_nats_rank
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include "../nats_pool.h"
#include "../../../sr_module.h"

#include "nats_ut.h"

struct rank_case {
	int rank;
	int expected;
	const char *label;
};

static const struct rank_case cases[] = {
	{ PROC_MAIN,      0, "PROC_MAIN (0, attendant)" },
	{ PROC_TIMER,     1, "PROC_TIMER (-1) -- must init: usrloc/dialog "
	                     "expiry events are raised here" },
	{ PROC_MODULE,    1, "PROC_MODULE (-2, HTTPD/MI)" },
	{ PROC_TCP_MAIN,  0, "PROC_TCP_MAIN (-4, TLS holder)" },
	{ -3,             0, "rank -3 (module-exported)" },
	{ -5,             0, "rank -5 (module-exported)" },
	{ -100,           0, "rank -100 (module-exported)" },
	{ 1,              1, "rank 1 (first SIP worker)" },
	{ 2,              1, "rank 2" },
	{ 4,              1, "rank 4" },
	{ 8,              1, "rank 8" },
	{ 16,             1, "rank 16" },
	{ 32,             1, "rank 32" },
};

void nats_ut_nats_rank(void)
{
	size_t i;
	const size_t n = sizeof(cases) / sizeof(cases[0]);

	for (i = 0; i < n; i++)
		cmp_ok(nats_pool_should_init(cases[i].rank), "==",
			cases[i].expected, "%s", cases[i].label);
}
