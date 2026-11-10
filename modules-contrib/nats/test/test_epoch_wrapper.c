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
 * nats_epoch.h -- the epoch-tagged handle idiom, over the real pool:
 *
 *   - save/current: a tag is current until the connection reconnects,
 *   - snapshot/adopt: the refresh protocol -- adopting a snapshot taken
 *     before a reconnect that lands mid-refresh leaves the tag stale (the
 *     next check refreshes again; adopting a re-read epoch would pair the
 *     old connection's handle with the new epoch for good),
 *   - lost: stale or disconnected.
 *
 * The epoch and the connected flag are moved the way production moves
 * them: by the pool's own libnats callbacks, taken from the fake libnats
 * of nats_ut_fake.c.
 */

#include <tap.h>

#include "../nats_pool.h"
#include "../nats_epoch.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

static void reconnect(void)
{ nf.reconnected_cb(nats_pool_get(), NULL); }
static void disconnect(void)
{ nf.disconnected_cb(nats_pool_get(), NULL); }

void nats_ut_epoch_wrapper(void)
{
	nats_epoch_t e;
	int snap;

	nats_ut_begin();
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0
	    || nats_pool_get() == NULL) {
		nats_ut_end();
		fail("epoch: pool setup");
		return;
	}

	/* save/current across a reconnect */
	nats_epoch_save(&e);
	ok(nats_epoch_current(&e), "fresh tag is current");
	reconnect();
	ok(!nats_epoch_current(&e), "tag stale after a reconnect");
	nats_epoch_save(&e);
	ok(nats_epoch_current(&e), "re-save catches up");

	/* refresh protocol: snapshot before the acquire */
	snap = nats_epoch_snapshot();
	reconnect();                      /* lands mid-refresh */
	/* ... handle acquired here, from the old connection ... */
	nats_epoch_adopt(&e, snap);
	ok(!nats_epoch_current(&e),
		"adopting the pre-acquire snapshot leaves the tag stale "
		"(the next call refreshes again)");
	snap = nats_epoch_snapshot();
	nats_epoch_adopt(&e, snap);
	ok(nats_epoch_current(&e), "no reconnect during the refresh: current");

	/* lost = stale or disconnected */
	nats_epoch_save(&e);
	ok(!nats_epoch_lost(&e), "current + connected: not lost");
	disconnect();
	ok(nats_epoch_current(&e) && nats_epoch_lost(&e),
		"disconnected: lost even while current");
	reconnect();
	ok(nats_epoch_lost(&e), "reconnected since the tag: lost");
	nats_epoch_save(&e);
	ok(!nats_epoch_lost(&e), "tagged again after the reconnect: not lost");

	nats_ut_end();
}
