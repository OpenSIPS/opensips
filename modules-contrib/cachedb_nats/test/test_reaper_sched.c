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
 * The reaper process's due-scheduler, nats_cdb_proc_sched_due(): the
 * reaper pass and the periodic FTS resync each fire once their interval
 * has elapsed, a fired job's stamp moves to now (one run after a long
 * stall, no catch-up burst), interval <= 0 disables a job, the jobs are
 * independent.  The behavioural half of tests/test_reaper_dedicated_proc.c,
 * ported whole (its export half: test_mod_exports.c).
 */

#include <tap.h>
#include <string.h>

#include "../cachedb_nats_expiry.h"

#include "cn_ut.h"

#define CHECK(cond, msg) ok((cond), "reaper_sched: %s", (msg))

void cn_ut_reaper_sched(void)
{
	nats_cdb_proc_sched_t sc;
	int reap = -1, resync = -1;

	memset(&sc, 0, sizeof(sc));
	sc.last_reap = sc.last_resync = 1000;
	nats_cdb_proc_sched_due(&sc, 1000 + 29, 30, 60, &reap, &resync);
	CHECK(reap == 0 && resync == 0, "nothing fires before one full interval");

	nats_cdb_proc_sched_due(&sc, 1000 + 30, 30, 60, &reap, &resync);
	CHECK(reap == 1 && resync == 0,
		"reap fires at its interval; resync (longer) does not");
	CHECK(sc.last_reap == 1030, "a fired job advances its own stamp to now");
	CHECK(sc.last_resync == 1000, "an idle job's stamp is untouched");

	nats_cdb_proc_sched_due(&sc, 1000 + 60, 30, 60, &reap, &resync);
	CHECK(reap == 1 && resync == 1, "both fire when both intervals have elapsed");

	/* a long stall (proc blocked in a slow pass): ONE run, no burst */
	nats_cdb_proc_sched_due(&sc, 1060 + 500, 30, 60, &reap, &resync);
	CHECK(reap == 1 && resync == 1, "due after a long stall");
	nats_cdb_proc_sched_due(&sc, 1060 + 501, 30, 60, &reap, &resync);
	CHECK(reap == 0 && resync == 0,
		"no catch-up burst: stamps reset to now, not to now-k*iv");

	sc.last_reap = sc.last_resync = 0;
	nats_cdb_proc_sched_due(&sc, 99999, 0, -5, &reap, &resync);
	CHECK(reap == 0 && resync == 0, "interval <= 0 disables the job (0 and negative)");

	sc.last_reap = sc.last_resync = 2000;
	nats_cdb_proc_sched_due(&sc, 2100, 0, 60, &reap, &resync);
	CHECK(reap == 0 && resync == 1, "resync fires alone when the reaper is disabled");

	/* a clock stepped backwards: nothing is due, nothing moves */
	sc.last_reap = sc.last_resync = 5000;
	nats_cdb_proc_sched_due(&sc, 4000, 30, 60, &reap, &resync);
	CHECK(reap == 0 && resync == 0 && sc.last_reap == 5000 && sc.last_resync == 5000,
		"clock stepped back: nothing fires, stamps untouched");
}
