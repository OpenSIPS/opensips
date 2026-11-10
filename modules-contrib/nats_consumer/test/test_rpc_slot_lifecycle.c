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
 * Depth/coverage test for the async-RPC slot allocator (nats_rpc_slot.c).
 * The other slot tests exercise the generation/reply protocol; this drives the
 * full allocator lifecycle and its edge/error paths, which were previously
 * uncovered:
 *   - init count clamp (0 -> 1), double-init, total_count
 *   - claim -> CLAIMED, publish -> INFLIGHT, inflight_count accounting
 *   - pool exhaustion: claim on a full pool returns NULL
 *   - publish on a non-CLAIMED slot returns -1
 *   - lookup by idx (hit) and out-of-range / FREE (NULL)
 *   - abandon (INFLIGHT -> ABANDONED) and free (-> FREE), then reuse
 *
 * Built with a 1-slot pool (-DNATS_RPC_SLOT_COUNT=1) so exhaustion is one claim
 * away; the count is also set via the runtime var to exercise the clamp.
 *
 * Runs in the nats_consumer unit test suite on the module's live slot
 * pool (one slot), with the consumer process held.
 */

#include <tap.h>
#include <stdio.h>
#include <stdatomic.h>
#include "../nats_rpc_slot.h"

#include "nc_ut.h"

#define CHECK(cond, label) ok((cond), "rpc_slot_lifecycle: %s", (label))

static int state_of(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->state, memory_order_acquire);
}

void nc_ut_rpc_slot_lifecycle(void)
{
	nats_rpc_slot_t *a, *b;

	/* the live pool: async_rpc_slots=0 in the cfg, clamped up to 1 */
	CHECK(nats_rpc_slot_total_count() == 1, "total_count == 1 (clamped)");

	/* double init is a no-op success (already initialised). */
	CHECK(nats_rpc_slot_init() == 0, "double init returns 0 (already init)");

	CHECK(nats_rpc_slot_inflight_count() == 0, "inflight starts at 0");

	/* claim -> CLAIMED. */
	a = nats_rpc_slot_claim();
	CHECK(a != NULL, "claim returns a slot");
	CHECK(a && state_of(a) == NATS_RPC_SLOT_CLAIMED, "claimed slot is CLAIMED");
	CHECK(nats_rpc_slot_inflight_count() == 1, "inflight == 1 after claim");
	/* a fresh claim carries no wake owner until the worker
	 * stamps its process_no just before publish. */
	CHECK(a && atomic_load_explicit(&a->owner_proc,
			memory_order_relaxed) == -1,
		"claim resets owner_proc to -1 (no wake owner yet)");

	/* pool is now full (1 slot) -> next claim returns NULL. */
	b = nats_rpc_slot_claim();
	CHECK(b == NULL, "claim on a full pool returns NULL");

	/* lookup by idx: hit + out-of-range. */
	CHECK(nats_rpc_slot_lookup(a->slot_idx) == a, "lookup(idx) finds the slot");
	CHECK(nats_rpc_slot_lookup(9999) == NULL, "lookup(out-of-range) is NULL");

	/* publish CLAIMED -> INFLIGHT; a second publish (not CLAIMED) fails. */
	CHECK(nats_rpc_slot_publish(a) == 0, "publish CLAIMED -> INFLIGHT");
	CHECK(a && state_of(a) == NATS_RPC_SLOT_INFLIGHT, "state is INFLIGHT");
	CHECK(nats_rpc_slot_publish(a) == -1, "publish on non-CLAIMED slot fails");

	/* abandon INFLIGHT -> ABANDONED. */
	CHECK(nats_rpc_slot_abandon(a) == NATS_RPC_SLOT_ABANDONED,
		"abandon INFLIGHT -> ABANDONED");

	/* free returns the slot to the pool. */
	nats_rpc_slot_free(a,
		atomic_load_explicit(&(a)->generation, memory_order_relaxed));
	CHECK(nats_rpc_slot_inflight_count() == 0, "inflight == 0 after free");
	CHECK(nats_rpc_slot_lookup(a->slot_idx) == NULL,
		"lookup on a freed (FREE) slot is NULL");

	/* the slot is reusable after free.  A stale owner_proc from the
	 * previous claim must not leak into the new one: a consumer-side
	 * wake for the old claim would otherwise target whatever worker
	 * owned the slot last. */
	if (a) atomic_store_explicit(&a->owner_proc, 17, memory_order_relaxed);
	b = nats_rpc_slot_claim();
	CHECK(b == a, "the freed slot is re-claimed (reuse)");
	CHECK(b && atomic_load_explicit(&b->owner_proc,
			memory_order_relaxed) == -1,
		"re-claim clears a stale owner_proc from the previous claim");
	nats_rpc_slot_free(b,
		atomic_load_explicit(&(b)->generation, memory_order_relaxed));

}
