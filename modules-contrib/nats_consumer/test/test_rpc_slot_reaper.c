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
 * RPC-slot orphan reaper.  A worker that dies mid-RPC leaks its
 * slot forever (the only path back to FREE was the worker's own
 * timerfd resume); the shared pool exhausts and every async
 * nats_request system-wide fails -5 until restart.  The reaper --
 * modeled on the msg-ref reaper -- runs in the consumer main loop and
 * reclaims any non-FREE slot whose owner is provably gone:
 *
 *   - INFLIGHT/DELIVERED/ABANDONED with a worker-stamped deadline:
 *     reaped after deadline + slack (a live worker's own resume frees
 *     at the deadline, long before the slack expires),
 *   - CLAIMED with no deadline yet (death between claim and publish):
 *     reaped after a fixed claim TTL,
 *   - DELIVERING is NEVER reaped (the consumer's libnats thread has
 *     the claim pinned mid-reply),
 *   - the generation is bumped BEFORE the state CAS so late replies
 *     and stale IPC entries are invalidated first,
 *   - g_inflight_count is repaired, the reap counter is bumped.
 *
 * The reaper also forces nats_rpc_slot_free() to be GENERATION-GUARDED:
 * a very late worker resume freeing a reaped-and-recycled slot must not
 * clobber the new claim.  This test drives the PRODUCTION
 * ../nats_rpc_slot.c under a 1-slot pool so every claim recycles the
 * SAME slot (the guarded-free scenario needs slot identity: production
 * always frees the slot its generation was captured from).
 *
 * Runs in the nats_consumer unit test suite on the module's live slot
 * pool (one slot), with the consumer process held.
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>

#include "../nats_rpc_slot.h"

#include "nc_ut.h"

#define CHECK(cond, label) ok((cond), "rpc_slot_reaper: %s", (label))

#define US  1000000LL
#define NOW (1000000LL * US)   /* an arbitrary "now" */

static uint32_t gen_of(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->generation, memory_order_relaxed);
}

void nc_ut_rpc_slot_reaper(void)
{
	nats_rpc_slot_t *a, *b;
	uint32_t gen_a, gen_b;
	uint64_t reaped0;

	CHECK(nats_rpc_slot_total_count() == 1, "the live pool has 1 slot");
	reaped0 = nats_rpc_slot_orphans_reaped_total();

	/* ── dead worker mid-flight: reaped after deadline + slack ───── */
	a = nats_rpc_slot_claim();
	CHECK(a != NULL, "claim slot A");
	gen_a = gen_of(a);
	CHECK(nats_rpc_slot_publish(a) == 0, "publish A (INFLIGHT)");
	atomic_store_explicit(&a->deadline_us, NOW - 2 * US,
		memory_order_relaxed);           /* deadline long past */

	CHECK(nats_rpc_slot_reap_orphans(NOW) == 0,
		"deadline past but slack not yet: NOT reaped");
	CHECK(nats_rpc_slot_reap_orphans(
			NOW + NATS_RPC_SLOT_REAP_SLACK_US) == 1,
		"deadline + slack elapsed: reaped");
	CHECK(gen_of(a) == gen_a + 1,
		"generation bumped by the reap (late replies invalidated)");
	CHECK(!nats_rpc_slot_entry_is_current(a, gen_a),
		"stale IPC entry from the dead claim is no longer current");
	CHECK(nats_rpc_slot_inflight_count() == 0,
		"inflight count repaired");
	CHECK(nats_rpc_slot_orphans_reaped_total() == reaped0 + 1,
		"orphan-reap counter bumped");

	/* ── dead worker between claim and publish: claim TTL ────────── */
	a = nats_rpc_slot_claim();
	CHECK(a != NULL, "re-claim works after the reap");
	atomic_store_explicit(&a->claimed_at_us, NOW - 1 * US,
		memory_order_relaxed);           /* young claim */
	CHECK(nats_rpc_slot_reap_orphans(NOW) == 0,
		"young CLAIMED slot (no deadline yet): NOT reaped");
	atomic_store_explicit(&a->claimed_at_us,
		NOW - NATS_RPC_SLOT_REAP_CLAIM_TTL_US - 1,
		memory_order_relaxed);
	CHECK(nats_rpc_slot_reap_orphans(NOW) == 1,
		"CLAIMED older than the claim TTL: reaped");

	/* ── DELIVERING is pinned: never reaped ──────────────────────── */
	a = nats_rpc_slot_claim();
	CHECK(a != NULL && nats_rpc_slot_publish(a) == 0,
		"claim+publish for the DELIVERING case");
	{
		int expected = NATS_RPC_SLOT_INFLIGHT;
		CHECK(atomic_compare_exchange_strong(&a->state, &expected,
				NATS_RPC_SLOT_DELIVERING),
			"consumer pins the claim (DELIVERING)");
	}
	atomic_store_explicit(&a->deadline_us, NOW - 10 * US,
		memory_order_relaxed);
	CHECK(nats_rpc_slot_reap_orphans(NOW + 10 * NATS_RPC_SLOT_REAP_SLACK_US) == 0,
		"DELIVERING slot is never reaped, however old");
	{
		/* the consumer finishes the reply: DELIVERING -> DELIVERED;
		 * with the owner dead, the NEXT pass reaps the DELIVERED */
		int expected = NATS_RPC_SLOT_DELIVERING;
		CHECK(atomic_compare_exchange_strong(&a->state, &expected,
				NATS_RPC_SLOT_DELIVERED),
			"consumer unpins (DELIVERED)");
	}
	CHECK(nats_rpc_slot_reap_orphans(
			NOW + 10 * NATS_RPC_SLOT_REAP_SLACK_US) == 1,
		"orphaned DELIVERED reaped on the next pass");
	CHECK(nats_rpc_slot_inflight_count() == 0,
		"inflight count clean after the DELIVERING episode");

	/* ── generation-guarded free: late resume cannot clobber ─────── */
	a = nats_rpc_slot_claim();
	CHECK(a != NULL && nats_rpc_slot_publish(a) == 0,
		"claim+publish victim slot");
	gen_a = gen_of(a);
	atomic_store_explicit(&a->deadline_us, NOW - 2 * US,
		memory_order_relaxed);
	CHECK(nats_rpc_slot_reap_orphans(
			NOW + NATS_RPC_SLOT_REAP_SLACK_US) == 1,
		"victim reaped");
	b = nats_rpc_slot_claim();          /* 1-slot pool: b IS a */
	CHECK(b == a, "the reaped slot is recycled by the new claim");
	gen_b = gen_of(b);
	nats_rpc_slot_free(a, gen_a);       /* dead claim's late free */
	CHECK(atomic_load_explicit(&b->state, memory_order_acquire)
			== NATS_RPC_SLOT_CLAIMED,
		"stale-generation free is a NO-OP (new claim intact)");
	CHECK(nats_rpc_slot_inflight_count() == 1,
		"inflight count untouched by the stale free");
	nats_rpc_slot_free(b, gen_b);
	CHECK(atomic_load_explicit(&b->state, memory_order_acquire)
			== NATS_RPC_SLOT_FREE &&
	      nats_rpc_slot_inflight_count() == 0,
		"correct-generation free releases the slot");
}
