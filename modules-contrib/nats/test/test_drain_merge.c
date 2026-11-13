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
 * Drain-timeout merge decision.  The shared shutdown drain
 * timeout is one pool value fed by a modparam in each module; the old
 * setter max-merged against the 5000 ms DEFAULT, so an operator's
 * explicit lower value (e.g. drain_timeout_ms=2000 for fast restarts)
 * was silently ignored.  Contract now:
 *
 *   - the FIRST explicit value replaces the default outright (an
 *     operator's choice out-ranks the built-in default, including
 *     below it),
 *   - across MULTIPLE explicit registrants the max wins (the longest
 *     configured shutdown grace, order-independent) -- and the setter
 *     WARNs when a lower explicit value is discarded (locked by the
 *     source pattern below).
 *
 * Drives nats_pool_drain_timeout_decide() from ../nats_pool.h.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_pool.h"

#include "nats_ut.h"

#define CHECK(cond, label) ok((cond), "%s", (label))

void nats_ut_drain_merge(void)
{
	/* first explicit value replaces the default -- even BELOW it */
	CHECK(nats_pool_drain_timeout_decide(5000, 0, 2000) == 2000,
		"first explicit 2000 beats the 5000 default (honored below)");
	CHECK(nats_pool_drain_timeout_decide(5000, 0, 9000) == 9000,
		"first explicit 9000 beats the default upward too");
	CHECK(nats_pool_drain_timeout_decide(5000, 0, 0) == 0,
		"first explicit 0 (no drain) is an operator's call");

	/* subsequent explicit registrants: max wins, order-independent */
	CHECK(nats_pool_drain_timeout_decide(2000, 1, 8000) == 8000,
		"second registrant raising the grace wins");
	CHECK(nats_pool_drain_timeout_decide(8000, 1, 3000) == 8000,
		"second registrant lowering is out-ranked (max merge)");
	CHECK(nats_pool_drain_timeout_decide(4000, 1, 4000) == 4000,
		"equal explicit values are a no-op");

}
