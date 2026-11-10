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
 * Regression test: the worker->consumer async-RPC IPC entry used to
 * carry only the slot index.  The consumer's publish_cb looked the slot
 * up and published it whenever its state was INFLIGHT.  That is unsafe
 * under slot reuse:
 *
 *   1. Worker A claims slot S (generation G), publishes (state INFLIGHT),
 *      and enqueues an IPC entry {slot_idx = S}.
 *   2. Worker A times out, abandons, and FREEs slot S before the consumer
 *      drains the IPC.
 *   3. Worker B claims slot S (generation G+1), publishes (INFLIGHT), and
 *      enqueues {slot_idx = S}.
 *   4. The consumer drains BOTH entries.  Both see slot S in INFLIGHT, so
 *      publish_cb publishes B's request TWICE -- a duplicate RPC.
 *
 * The fix tags each IPC entry with the slot's generation at enqueue and
 * has publish_cb skip an entry whose generation no longer matches the
 * slot's current claim (nats_rpc_slot_entry_is_current()).  Then A's
 * stale entry (gen G) is dropped and only B's entry (gen G+1) publishes.
 *
 * This test drives the REAL slot API (../nats_rpc_slot.c under the SHM
 * shim) and is compiled with -DNATS_RPC_SLOT_COUNT=1 so claim() always
 * returns the same slot, forcing the reuse the bug needs.  The consumer
 * drain decision is modelled by would_publish():
 *
 *   -DSIMULATE_PREFIX_BUG -> state-only check (pre-fix): publishes BOTH
 *                            entries -> the count==1 assertion FAILS.
 *   (default)             -> nats_rpc_slot_entry_is_current(): publishes
 *                            only the current entry -> ALL PASS.
 *
 * Runs in the nats_consumer unit test suite on the module's live slot
 * pool (one slot), with the consumer process held.
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>

#include "../nats_rpc_slot.h"
#include "../nats_rpc_ipc.h"

#include "nc_ut.h"

#define CHECK(cond, label) ok((cond), "rpc_ipc_generation: %s", (label))

/* The decision publish_cb makes for one drained IPC entry. */
static int would_publish(const nats_rpc_ipc_msg_t *e)
{
	nats_rpc_slot_t *s = nats_rpc_slot_lookup(e->slot_idx);
	return nats_rpc_slot_entry_is_current(s, e->generation);
}

void nc_ut_rpc_ipc_generation(void)
{
	nats_rpc_slot_t   *sa, *sb;
	nats_rpc_ipc_msg_t entry_a, entry_b;
	uint32_t           gen_a, gen_b;
	int                published;

	CHECK(nats_rpc_slot_total_count() == 1, "the live pool has 1 slot");

	/* ── step 1: worker A claims + publishes slot S (gen G) ───────── */
	sa = nats_rpc_slot_claim();
	CHECK(sa != NULL, "worker A claims a slot");
	CHECK(nats_rpc_slot_publish(sa) == 0, "worker A publishes (INFLIGHT)");
	gen_a = atomic_load_explicit(&sa->generation, memory_order_relaxed);
	entry_a.slot_idx   = sa->slot_idx;
	entry_a.generation = gen_a;

	/* While A is still the current claim, its entry is publishable. */
	CHECK(would_publish(&entry_a) == 1,
		"A's entry publishes while A is the current claim");

	/* ── step 2: A times out -> abandon + free ────────────────────── */
	(void)nats_rpc_slot_abandon(sa);
	nats_rpc_slot_free(sa,
		atomic_load_explicit(&(sa)->generation, memory_order_relaxed));

	/* ── step 3: worker B re-claims the SAME slot (gen G+1) ───────── */
	sb = nats_rpc_slot_claim();
	CHECK(sb != NULL, "worker B re-claims a slot");
	CHECK(sb == sa, "B re-claimed the very same slot (forced reuse)");
	CHECK(nats_rpc_slot_publish(sb) == 0, "worker B publishes (INFLIGHT)");
	gen_b = atomic_load_explicit(&sb->generation, memory_order_relaxed);
	entry_b.slot_idx   = sb->slot_idx;
	entry_b.generation = gen_b;

	CHECK(gen_b != gen_a, "generation advanced across the reuse");

	/* ── step 4: consumer drains BOTH entries (A stale, B current) ── */
	published = 0;
	if (would_publish(&entry_a)) published++;   /* A: stale */
	if (would_publish(&entry_b)) published++;   /* B: current */

	/* The core contract: B's request is published exactly once.  Under
	 * the pre-fix state-only check this is 2 (the double-publish bug). */
	CHECK(published == 1,
		"slot reuse publishes the request exactly once (no double-publish)");

	/* A's stale entry specifically must be dropped. */
	CHECK(would_publish(&entry_a) == 0, "A's stale entry is skipped");
	/* B's current entry specifically must be published. */
	CHECK(would_publish(&entry_b) == 1, "B's current entry is published");

	/* ── abandoned slot: entry skipped regardless of generation ───── */
	(void)nats_rpc_slot_abandon(sb);   /* INFLIGHT -> ABANDONED */
	CHECK(would_publish(&entry_b) == 0,
		"entry for an ABANDONED slot is skipped");
	nats_rpc_slot_free(sb,
		atomic_load_explicit(&(sb)->generation, memory_order_relaxed));


}
