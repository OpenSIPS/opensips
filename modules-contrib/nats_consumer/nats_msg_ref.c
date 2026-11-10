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
 */

/*
 * nats_msg_ref.c — process-local natsMsg reference table
 *
 * For each (handle_idx, slot_idx) the consumer process keeps the live
 * natsMsg* plus a 16-bit generation counter; the ack token encodes the
 * generation so a stale ack after ring wrap is detected and ignored.
 * Also owns the orphan reap (a worker that died after popping but
 * before acking must not leak its slot forever).
 *
 * Split out of nats_consumer_proc.c (proc-TU split); cross-TU private
 * declarations live in nats_consumer_proc_internal.h.
 */

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <sys/timerfd.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"
#include "../nats/nats_str.h"

#include "nats_handle_registry.h"
#include "nats_ring.h"
#include "nats_ack_ipc.h"
#include "nats_ack.h"
#include "nats_consumer_proc.h"
#include "nats_rpc_consumer.h"
#include "nats_rpc_ipc.h"
#include "nats_consumer_proc_internal.h"

/* ── natsMsg ref table ───────────────────────────────────────── */

/*
 * Process-local 2D ref table: for each (handle_idx, slot_idx) we keep
 * the live natsMsg* plus a 16-bit generation counter bumped every
 * time the slot is reused.  The ack token encodes generation so a
 * stale ack (one issued for a natsMsg that has already been acked and
 * the slot reused) is detected and ignored.
 *
 * The ring-capacity dimension is sized at first use of a handle in
 * store_msg_ref().  Rings may share the same capacity
 * (NATS_HANDLE_RING_CAPACITY) or override it per-handle via
 * `ring_capacity` at bind time; we key off the handle's ring
 * object so any per-handle capacity is honoured.
 */

/* Reclaim a msg-ref slot if it has been outstanding longer than the
 * effective orphan TTL: a worker that died after popping a message but
 * before acking would otherwise leak its slot forever.  This value is the
 * FLOOR; the reaper uses max(this, 2 * the row's ack_wait_ms) so a
 * slow-but-live worker still within a large ack_wait is never reaped (see
 * reap_orphan_msg_refs).  Generously larger than any reasonable JetStream
 * ack_wait (default 30s); the broker has long since redelivered an orphan
 * this old, so its original ack would be rejected anyway. */
#define NATS_MSG_REF_ORPHAN_TTL_US   (120LL * 1000000LL)


/* Count of orphaned msg-ref slots reclaimed (telemetry). */
static unsigned long g_msg_ref_orphans_reaped;


msg_ref_row_t g_msg_refs[NATS_REGISTRY_MAX_HANDLES];

/*
 * Per-index generation seed, persisted ACROSS a row free so a re-allocated
 * row (same handle_idx rebound after unbind) does not restart generations at
 * 0.  The ack token packs a 16-bit generation that only disambiguates slot
 * reuse within one incarnation; without a persistent seed a stale un-acked
 * token from a previous bind of the same index could collide with a new
 * incarnation's slot generation and mis-ack a different message.  purge saves
 * (max slot generation + 1) here; ensure_row seeds every slot of a fresh row
 * from it, so a new incarnation's generations are strictly greater than any a
 * stale token can carry.  Zero for a never-used index (identical to the old
 * behaviour for the common no-reuse case).
 */
static uint16_t g_row_gen_seed[NATS_REGISTRY_MAX_HANDLES];

int ensure_row(uint16_t handle_idx, uint32_t capacity)
{
	msg_ref_row_t *row;
	uint32_t i;
	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES)
		return -1;
	row = &g_msg_refs[handle_idx];
	if (row->slots)
		return 0;
	row->slots = (msg_ref_slot_t *)calloc(capacity, sizeof(msg_ref_slot_t));
	if (!row->slots) {
		LM_ERR("nats_consumer_proc: oom for msg-ref row "
			"handle_idx=%u capacity=%u\n",
			(unsigned)handle_idx, (unsigned)capacity);
		return -1;
	}
	row->capacity  = capacity;
	row->next_slot = 0;
	/* Seed generations from the persisted per-index value so a stale token
	 * from a prior incarnation of this index cannot match a new slot. */
	for (i = 0; i < capacity; i++)
		row->slots[i].generation = g_row_gen_seed[handle_idx];
	return 0;
}

/* Reserve a slot, stash the natsMsg, return the packed ack_token.
 * On failure (no free slot) returns 0 and sets *ok to 0. */
uint64_t store_msg_ref(uint16_t handle_idx, uint32_t ring_capacity,
                              int ack_wait_ms, natsMsg *m, int *ok)
{
	msg_ref_row_t  *row;
	msg_ref_slot_t *slot;
	uint32_t        i, start;

	*ok = 0;
	if (ensure_row(handle_idx, ring_capacity) < 0)
		return 0;
	row = &g_msg_refs[handle_idx];
	/* Record the handle's ack_wait so the orphan reaper can scale its TTL
	 * above it (a slow-but-live worker within ack_wait must not be reaped). */
	row->ack_wait_ms = ack_wait_ms;

	/* Scan from next_slot for a free slot.  The ring and the ref
	 * table are the same size by construction, so if the ring ever
	 * has room (the worker hasn't acked yet for some outstanding
	 * slot), we should also have a free entry.  If not, the worker
	 * is lagging acks -- return the "full" signal and let the caller
	 * skip the push. */
	start = row->next_slot;
	for (i = 0; i < row->capacity; i++) {
		uint32_t idx = (start + i) % row->capacity;
		slot = &row->slots[idx];
		if (!slot->in_use) {
			slot->msg           = m;
			slot->in_use        = 1;
			slot->generation    = (uint16_t)(slot->generation + 1);
			slot->claimed_at_us = now_monotonic_us();
			row->next_slot      = (idx + 1) % row->capacity;
			*ok = 1;
			return nats_ack_token_pack(handle_idx, idx, slot->generation);
		}
	}

	LM_WARN("nats_consumer_proc: msg-ref table full for handle_idx=%u; "
		"worker is not acking fast enough\n", (unsigned)handle_idx);
	return 0;
}

/* Take the msg out of the ref table if generation matches.  Returns
 * the natsMsg* (which the caller MUST destroy after calling the
 * requested ack action), or NULL if the slot is stale / unused. */
natsMsg *release_msg_ref(uint64_t token)
{
	uint16_t         handle_idx = nats_ack_token_handle(token);
	uint32_t         slot_idx   = nats_ack_token_slot(token);
	uint16_t         gen        = nats_ack_token_generation(token);
	msg_ref_row_t   *row;
	msg_ref_slot_t  *slot;
	natsMsg         *m;

	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES)
		return NULL;
	row = &g_msg_refs[handle_idx];
	if (!row->slots || slot_idx >= row->capacity)
		return NULL;
	slot = &row->slots[slot_idx];
	if (!slot->in_use) {
		LM_DBG("nats_consumer_proc: stale ack for token=0x%016lx "
			"(slot already free)\n", (unsigned long)token);
		return NULL;
	}
	if (slot->generation != gen) {
		LM_DBG("nats_consumer_proc: generation mismatch for "
			"token=0x%016lx (expected gen=%u got %u) -- stale ack\n",
			(unsigned long)token,
			(unsigned)slot->generation, (unsigned)gen);
		return NULL;
	}
	m = slot->msg;
	slot->msg    = NULL;
	slot->in_use = 0;
	/* keep generation; next use bumps it again. */
	return m;
}

/*
 * Purge every outstanding msg-ref for a handle: destroy each in-use
 * natsMsg, free the row's slots buffer, and zero the row.  Called from
 * EVERY subscription-destroy site (retire teardown, vanished/GC'd-consumer
 * recreate, reconnect-epoch refresh).  A delivered/fetched natsMsg stores a
 * raw msg->sub pointer with no refcount on the subscription; once the sub is
 * natsSubscription_Destroy'd, acking any still-held msg would deref a freed
 * subscription (use-after-free).  Destroying the messages here severs that
 * dangling reference -- the broker redelivers any un-acked JetStream message
 * on reconnect, so dropping our local copy is also the correct semantics.
 * Runs in the consumer process's single-threaded main loop (no locking).
 */
void purge_msg_ref_row(uint16_t handle_idx)
{
	msg_ref_row_t *row;
	uint32_t i;

	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES)
		return;
	row = &g_msg_refs[handle_idx];
	if (row->slots) {
		uint16_t maxg = g_row_gen_seed[handle_idx];
		for (i = 0; i < row->capacity; i++) {
			msg_ref_slot_t *slot = &row->slots[i];
			if (slot->generation > maxg)
				maxg = slot->generation;
			if (slot->in_use && slot->msg) {
				nats_dl.natsMsg_Destroy(slot->msg);
				slot->msg    = NULL;
				slot->in_use = 0;
			}
		}
		/* Persist a seed strictly above every generation this incarnation
		 * used, so a stale ack token cannot match a slot after the index is
		 * rebound (see g_row_gen_seed).  Saved before free(). */
		g_row_gen_seed[handle_idx] = (uint16_t)(maxg + 1);
		free(row->slots);
	}
	row->slots     = NULL;
	row->capacity  = 0;
	row->next_slot = 0;
}

/*
 * Reclaim msg-ref slots that have been outstanding longer than
 * NATS_MSG_REF_ORPHAN_TTL_US -- the worker that owned them died before
 * acking.  Destroys the leaked natsMsg, frees the slot (bumping the
 * generation so a late ack is rejected), and counts it.  Runs in the
 * consumer process's single-threaded main loop, so no locking is needed.
 * Returns the number of slots reaped.
 */
int reap_orphan_msg_refs(void)
{
	long long now = now_monotonic_us();
	int reaped = 0;
	uint32_t h, i;

	for (h = 0; h < NATS_REGISTRY_MAX_HANDLES; h++) {
		msg_ref_row_t *row = &g_msg_refs[h];
		long long ttl_us;
		if (!row->slots)
			continue;
		/* Scale the orphan TTL above the handle's ack_wait so a slow-but-live
		 * worker still within its ack_wait window is never reaped (the broker
		 * has not yet redelivered).  Floor at the 120s default; use twice the
		 * ack_wait when that is larger. */
		ttl_us = NATS_MSG_REF_ORPHAN_TTL_US;
		if (row->ack_wait_ms > 0) {
			long long w = 2LL * (long long)row->ack_wait_ms * 1000LL;
			if (w > ttl_us)
				ttl_us = w;
		}
		for (i = 0; i < row->capacity; i++) {
			msg_ref_slot_t *slot = &row->slots[i];
			if (!slot->in_use)
				continue;
			if (now - slot->claimed_at_us <= ttl_us)
				continue;
			if (slot->msg)
				nats_dl.natsMsg_Destroy(slot->msg);
			slot->msg        = NULL;
			slot->in_use     = 0;
			slot->generation = (uint16_t)(slot->generation + 1);
			g_msg_ref_orphans_reaped++;
			reaped++;
		}
	}
	if (reaped > 0)
		LM_WARN("nats_consumer_proc: reaped %d orphaned msg-ref slot(s) "
			"(worker died mid-processing?); total reaped=%lu\n",
			reaped, g_msg_ref_orphans_reaped);
	return reaped;
}
