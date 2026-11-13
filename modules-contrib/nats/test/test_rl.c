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
 * nats_rl_pass -- the one-per-interval log gate behind the
 * outage logging policy (rate-limited WARN on repeat + DBG per call).
 * Pure decision helper, header-only; this locks its contract:
 *
 *   - first call on a zeroed slot passes (and stamps),
 *   - calls within the interval are blocked,
 *   - a call at/after slot+interval passes and re-stamps,
 *   - interval <= 0 means "no limiting" (always pass),
 *   - a clock that jumps BACKWARDS re-arms the gate instead of
 *     silencing the site until the clock catches back up,
 *   - slots are independent.
 */

#include <tap.h>
#include <stdio.h>
#include <time.h>

#include "../nats_rl.h"

#include "nats_ut.h"

#define CHECK(cond, label) ok((cond), "%s", (label))

void nats_ut_rl(void)
{
	time_t a = 0, b = 0;

	/* first call passes and stamps */
	CHECK(nats_rl_pass(&a, 1000, 30) == 1, "first call passes");
	CHECK(a == 1000, "first call stamps the slot");

	/* within the interval: blocked, stamp untouched */
	CHECK(nats_rl_pass(&a, 1001, 30) == 0, "t+1 is blocked");
	CHECK(nats_rl_pass(&a, 1029, 30) == 0, "t+interval-1 is blocked");
	CHECK(a == 1000, "blocked calls do not re-stamp");

	/* at the interval boundary: passes and re-stamps */
	CHECK(nats_rl_pass(&a, 1030, 30) == 1, "t+interval passes");
	CHECK(a == 1030, "pass re-stamps to now");

	/* interval <= 0 disables limiting entirely */
	CHECK(nats_rl_pass(&a, 1031, 0) == 1, "interval 0 always passes");
	CHECK(nats_rl_pass(&a, 1031, -5) == 1, "negative interval always passes");

	/* clock jumping backwards re-arms rather than silencing the
	 * site until wall time catches back up to the stale stamp */
	a = 5000;
	CHECK(nats_rl_pass(&a, 4000, 30) == 1, "backwards clock re-arms");
	CHECK(a == 4000, "backwards pass re-stamps to the new now");

	/* independent slots */
	a = 0; b = 0;
	CHECK(nats_rl_pass(&a, 100, 30) == 1 && nats_rl_pass(&b, 100, 30) == 1,
		"slots are independent (both first-pass)");
	CHECK(nats_rl_pass(&a, 110, 30) == 0 && nats_rl_pass(&b, 130, 30) == 1,
		"one slot blocked does not block the other");
}
