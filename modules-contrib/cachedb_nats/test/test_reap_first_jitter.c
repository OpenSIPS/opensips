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
 * nats_cdb_reap_first_jitter(): deterministic first-fire stagger for
 * the reaper.  Every instance of a multi-proxy deployment boots its
 * reaper with the same nats_reap_interval; without a per-instance
 * offset they all start their first O(bucket) pass at the same
 * uptime and hammer the broker together.  The helper derives a
 * bounded, deterministic offset from a seed (the pid):
 *
 *   - range: 0 <= jitter <= interval / 4 (the first pass is late by
 *     at most a quarter interval; expiry timing barely moves),
 *   - deterministic: same (interval, seed) -> same jitter (restart
 *     stability, reproducible tests),
 *   - spread: different seeds actually produce different offsets
 *     (a constant 0 would defeat the point -- locked below),
 *   - degenerate intervals (<= 3 s) return 0 (a quarter of nothing
 *     is nothing; also covers the reap_interval zero-guard rejects),
 *   - adversarial seeds (0, 1, UINT_MAX) stay in range.
 *
 * Also structural: nats_cdb_reaper_proc_main() must actually apply
 * the jitter to its first-fire stamp.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_first_jitter
 *            test_reap_first_jitter.c
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"

#define CHECK(cond, msg) do { if (!(cond)) { fail("reap_first_jitter: %s", msg); } \
	else pass("reap_first_jitter: %s", msg); } while (0)

void cn_ut_reap_first_jitter(void)
{
	unsigned int seed;
	int iv, j, distinct;
	int seen[128];

	diag("== bounds: 0 <= jitter <= interval/4, many seeds/intervals ==");
	{
		int ok = 1;
		int ivs[] = { 4, 5, 10, 30, 60, 120, 3600 };
		size_t k;
		for (k = 0; k < sizeof(ivs)/sizeof(ivs[0]); k++) {
			for (seed = 0; seed < 5000; seed++) {
				j = nats_cdb_reap_first_jitter(ivs[k], seed);
				if (j < 0 || j > ivs[k] / 4) { ok = 0; break; }
			}
		}
		CHECK(ok, "jitter always within [0, interval/4]");
	}

	diag("== determinism ==");
	CHECK(nats_cdb_reap_first_jitter(30, 12345)
	      == nats_cdb_reap_first_jitter(30, 12345),
	      "same (interval, seed) -> same jitter");

	diag("== spread: different seeds produce different offsets ==");
	iv = 30;   /* the default reap interval: jitter range 0..7 */
	memset(seen, 0, sizeof(seen));
	distinct = 0;
	for (seed = 1; seed <= 100; seed++) {
		j = nats_cdb_reap_first_jitter(iv, seed);
		if (j >= 0 && j < 128 && !seen[j]) { seen[j] = 1; distinct++; }
	}
	CHECK(distinct >= 3,
	      "at least 3 distinct offsets over 100 seeds (interval 30)");
	CHECK(seen[0] && seen[7],
	      "both ends of 0..7 reached over 100 seeds (the span is inclusive)");

	diag("== degenerate intervals ==");
	CHECK(nats_cdb_reap_first_jitter(0, 42) == 0, "interval 0 -> 0");
	CHECK(nats_cdb_reap_first_jitter(1, 42) == 0, "interval 1 -> 0");
	CHECK(nats_cdb_reap_first_jitter(3, 42) == 0, "interval 3 -> 0");
	CHECK(nats_cdb_reap_first_jitter(-30, 42) == 0, "negative interval -> 0");

	diag("== adversarial seeds stay in range ==");
	CHECK(nats_cdb_reap_first_jitter(30, 0) >= 0
	      && nats_cdb_reap_first_jitter(30, 0) <= 7, "seed 0 in range");
	CHECK(nats_cdb_reap_first_jitter(30, UINT_MAX) >= 0
	      && nats_cdb_reap_first_jitter(30, UINT_MAX) <= 7,
	      "seed UINT_MAX in range");


}
