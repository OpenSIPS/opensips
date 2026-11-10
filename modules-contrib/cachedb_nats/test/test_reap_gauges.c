/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 * test_reap_gauges.c -- the reap_last_* gauges describe the last complete
 * reaper pass; a failed or partial enumeration must not overwrite them
 * (it reported an empty bucket during a JetStream hiccup) and is counted
 * in reap_enum_failures.
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../cachedb_nats_reap_gauges.h"
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"

#include "../../../pt.h"
#include "../cachedb_nats_stats.h"

/* the module's stats slots and this process's number are set aside for
 * the test: a local table, written as process 3 (the reaper's slot) */
static nats_cdb_stats_t slots[NATS_CDB_STATS_MAX_PROCS];

#define CHECK(cond, msg) do { if (!(cond)) { fail("reap_gauges: %s", msg); } \
	else pass("reap_gauges: %s", msg); } while (0)
#define G(f) ((unsigned long)atomic_load(&slots[3].f))

void cn_ut_reap_gauges(void)
{
	struct reap_pass_gauges full = { 120, 100, 150, 140, 5, 7 };
	struct reap_pass_gauges partial = { 0, 0, 0, 0, 0, 0 };
	struct reap_pass_gauges half = { 60, 50, 75, 70, 2, 3 };
	nats_cdb_stats_t *real = nats_cdb_stats;
	int real_pn = process_no;

	memset(slots, 0, sizeof slots);
	nats_cdb_stats = slots;
	process_no = 3;

	diag("a complete pass publishes its gauges:");
	reap_publish_pass(0, &full, 1000, 42);
	CHECK(G(reap_last_run) == 1000, "reap_last_run = pass time");
	CHECK(G(reap_last_ms) == 42, "reap_last_ms = pass duration");
	CHECK(G(reap_last_keys) == 120 && G(reap_last_aors) == 100,
		"keys / aors published");
	CHECK(G(reap_last_contacts) == 150 && G(reap_last_active) == 140 &&
		G(reap_last_permanent) == 5 && G(reap_last_due) == 7,
		"contacts / active / permanent / due published");
	CHECK(G(reap_enum_failures) == 0, "no failure counted");

	diag("a failed enumeration keeps the last complete pass:");
	reap_publish_pass(-2, &partial, 2000, 5);
	CHECK(G(reap_last_run) == 1000, "reap_last_run unchanged");
	CHECK(G(reap_last_aors) == 100 && G(reap_last_contacts) == 150,
		"no empty bucket reported");
	CHECK(G(reap_enum_failures) == 1, "reap_enum_failures counted");

	diag("a pass that stopped half way is not published either:");
	reap_publish_pass(-3, &half, 3000, 900);
	CHECK(G(reap_last_aors) == 100 && G(reap_last_ms) == 42,
		"partial totals not published");
	CHECK(G(reap_enum_failures) == 2, "second failure counted");

	diag("the next complete pass publishes again:");
	reap_publish_pass(0, &half, 4000, 30);
	CHECK(G(reap_last_run) == 4000 && G(reap_last_aors) == 50,
		"new totals published");
	CHECK(G(reap_enum_failures) == 2, "failures are a counter, not reset");

	diag("an empty bucket is a valid complete pass:");
	reap_publish_pass(0, &partial, 5000, 1);
	CHECK(G(reap_last_run) == 5000 && G(reap_last_aors) == 0,
		"zero totals published when the pass completed");

	diag("only this process' slot is written:");
	CHECK(slots[0].reap_last_run == 0 && slots[4].reap_enum_failures == 0,
		"other slots untouched");


	nats_cdb_stats = real;
	process_no = real_pn;
}
