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
 * The async RPC tunables: the slot pool size (async_rpc_slots, clamped
 * to 1..65536 at slot init) and the guard-tick interval
 * (async_rpc_poll_ms, clamped to 1..1000 ms).  Replaces
 * tests/test_rpc_tunables.c (carried copies of both clamps plus greps).
 * The suite's opensips.cfg sets async_rpc_slots below the floor.
 */

#include <tap.h>

#include "../../../sr_module.h"
#include "../nats_rpc_slot.h"
#include "../nats_rpc_async.h"

#include "nc_ut.h"

static long poll_ns(int ms)
{
	int saved = nats_rpc_async_poll_ms;
	long ns;

	nats_rpc_async_poll_ms = ms;
	ns = nc_ut_async_poll_ns();
	nats_rpc_async_poll_ms = saved;
	return ns;
}

void nc_ut_rpc_tunables(void)
{
	ok(find_param_export("nats_consumer", "async_rpc_slots", INT_PARAM) &&
		find_param_export("nats_consumer", "async_rpc_poll_ms", INT_PARAM),
		"rpc_tunables: both modparams are exported");
	ok(nats_rpc_slot_total_count() == 1,
		"rpc_tunables: async_rpc_slots=0 gives a pool of one slot");

	ok(poll_ns(100) == 100000000L, "rpc_tunables: 100 ms by default");
	ok(poll_ns(5) == 5000000L, "rpc_tunables: 5 ms honoured");
	ok(poll_ns(1) == 1000000L, "rpc_tunables: 1 ms honoured");
	ok(poll_ns(0) == 1000000L, "rpc_tunables: 0 ms floored to 1 ms");
	ok(poll_ns(-5) == 1000000L, "rpc_tunables: negative floored to 1 ms");
	ok(poll_ns(1000) == 1000000000L, "rpc_tunables: 1000 ms honoured");
	ok(poll_ns(99999) == 1000000000L, "rpc_tunables: capped at 1000 ms");
}
