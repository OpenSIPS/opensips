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
 * The periodic index resync (nats_cdb_periodic_resync) runs in a process
 * that never connected on its own, so the pool's process-local
 * "connected" flag is 0 there: gating on it skipped every tick and the
 * periodic rebuild never ran.  It must get the KV handle (which connects
 * lazily) and rebuild; with no handle (broker down) it skips the tick.
 * On fakes (cn_ut_fake.h).  Replaces tests/test_resync_timer.c, a
 * source-pattern test.
 */

#include <tap.h>
#include <string.h>

#include "../cachedb_nats_watch.h"

#include "cn_ut.h"
#include "cn_ut_fake.h"

void cn_ut_resync_timer(void)
{
	cn_ut_fake_begin();
	cf.connected = 0;              /* this process never connected */
	nats_cdb_periodic_resync(0, NULL);
	ok(!strcmp(cf.seq, "get_kv,rebuild,"),
		"resync_timer: not connected yet -> KV handle fetched, index rebuilt (%s)", cf.seq);
	cn_ut_fake_end();

	cn_ut_fake_begin();
	cf.kv_null = 1;                /* broker down: no handle */
	nats_cdb_periodic_resync(0, NULL);
	ok(!strcmp(cf.seq, "get_kv,"), "resync_timer: no KV handle -> tick skipped, no rebuild");
	cn_ut_fake_end();

	cn_ut_fake_begin();
	cf.rebuild_rc = -1;
	nats_cdb_periodic_resync(0, NULL);
	ok(strstr(cn_ut_fake_log(), "index rebuild failed") != NULL,
		"resync_timer: a failed rebuild is logged");
	cn_ut_fake_end();
}
