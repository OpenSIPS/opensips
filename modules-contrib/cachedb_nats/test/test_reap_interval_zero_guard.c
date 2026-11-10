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
 * reap_interval <= 0 turns the reaper off.  The reaper is the only expiry
 * mechanism, so such a config must be REFUSED at startup.
 *
 *   gcc ...                -> the FIXED guard => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_interval_zero_guard test_reap_interval_zero_guard.c
 */
#include <tap.h>
#include <stdio.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"


#define CHECK(cond, msg) do { if (!(cond)) { fail("reap_interval_zero_guard: %s", msg); } \
	else pass("reap_interval_zero_guard: %s", msg); } while (0)

void cn_ut_reap_interval_zero_guard(void)
{

	diag("a real reaper interval starts:");
	CHECK(cdbn_reap_interval_guard(30) == 0, "interval 30 => ok");
	CHECK(cdbn_reap_interval_guard(1) == 0, "interval 1 => ok");

	diag("reaper-off (interval<=0) is REFUSED:");
	CHECK(cdbn_reap_interval_guard(0) == -1, "interval 0 => REFUSED");
	CHECK(cdbn_reap_interval_guard(-1) == -1, "negative interval => refused");

}
