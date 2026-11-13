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
 * Regression test: nats_cache_update and nats_cache_add/sub used a
 * hot-spin CAS retry loop with no backoff. On heavy contention this
 * pegged the worker on the broker and let exhaustion silently drop
 * the write. Replace with bounded jittered exponential backoff.
 *
 * This file tests the pure deterministic upper-bound helper
 * nats_cas_backoff_max_us(attempt) used by both CAS loops:
 *   - returns 0 for attempt 0 (no delay before first retry)
 *   - exponential growth: 50, 100, 200, ... µs
 *   - capped at 5000 µs (5 ms ceiling)
 *   - never larger than the cap regardless of attempt count
 *
 * The actual sleep uses full-jitter (random in [0, max]) which is not
 * tested here because randomness; only the upper bound is asserted.
 */

#include <tap.h>
#include "../cachedb_nats_stats.h"

#include "cn_ut.h"


static void check_eq(const char *label, unsigned long got, unsigned long want)
{
	ok(got == want, "cas_backoff: %s (got %lu, want %lu us)", label, got, want);
}

static void check_le(const char *label, unsigned long got, unsigned long ceil)
{
	ok(got <= ceil, "cas_backoff: %s (got %lu, ceiling %lu us)", label, got, ceil);
}

void cn_ut_cas_backoff(void)
{
	int i;

	/* attempt 0 = first try, no prior failure → no sleep */
	check_eq("attempt 0 returns 0", nats_cas_backoff_max_us(0), 0);

	/* exponential growth from BASE = 50 µs */
	check_eq("attempt 1 = base 50us",  nats_cas_backoff_max_us(1), 50);
	check_eq("attempt 2 = 100us",      nats_cas_backoff_max_us(2), 100);
	check_eq("attempt 3 = 200us",      nats_cas_backoff_max_us(3), 200);
	check_eq("attempt 4 = 400us",      nats_cas_backoff_max_us(4), 400);
	check_eq("attempt 5 = 800us",      nats_cas_backoff_max_us(5), 800);
	check_eq("attempt 6 = 1600us",     nats_cas_backoff_max_us(6), 1600);
	check_eq("attempt 7 = 3200us",     nats_cas_backoff_max_us(7), 3200);

	/* cap: attempt 8 would naively be 6400 but is clamped to 5000 */
	check_eq("attempt 8 capped at 5000us",
		nats_cas_backoff_max_us(8), 5000);
	check_eq("attempt 100 capped at 5000us",
		nats_cas_backoff_max_us(100), 5000);

	/* negative input clamped to 0 */
	check_eq("negative attempt -> 0",  nats_cas_backoff_max_us(-5), 0);

	/* across the full default budget (10 retries), the worst-case total
	 * sleep is the sum of upper bounds.  Assert it stays under 50 ms. */
	{
		unsigned long total = 0;
		for (i = 1; i <= 10; i++)
			total += nats_cas_backoff_max_us(i);
		check_le("sum over 10 retries <= 50000 us", total, 50000);
	}
}
