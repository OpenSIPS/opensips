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
 * nats_ack_ipc.c -- consumer-process side of the worker ack hop
 *: the ipc_send_rpc handlers (one per JetStream ack verb),
 * the apply switch they share, the ACK_NEXT refill hints, and the
 * SHM counters behind the ack_ipc_* MI stats.  Split out of
 * nats_consumer_proc.c (which keeps the main loop + fetch path).
 * Unit-locked in test/test_ack_ipc_actions.c.
 */

#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../nats/nats_bind.h"
#include "../nats/nats_pool.h"

#include "nats_handle_registry.h"
#include "nats_ack_ipc.h"
#include "nats_ack.h"
#include "nats_consumer_proc_internal.h"

/* ── worker ack hop ───────────────────────────────────── */

/* SHM counters behind the ack_ipc_* MI stats.  The pipe has no
 * readable depth, so depth is derived: sent - drained (floored). */
typedef struct nats_ack_ipc_stats_blk {
	_Atomic uint64_t sent;      /* worker: ipc_send_rpc succeeded */
	_Atomic uint64_t drained;   /* consumer: handler ran */
	_Atomic uint64_t dropped;   /* worker: send refused */
} nats_ack_ipc_stats_blk_t;

static nats_ack_ipc_stats_blk_t *g_ack_ipc_stats;

int nats_ack_ipc_stats_init(void)
{
	g_ack_ipc_stats = shm_malloc(sizeof(*g_ack_ipc_stats));
	if (!g_ack_ipc_stats) {
		LM_ERR("nats_consumer: shm_malloc for ack IPC stats failed\n");
		return -1;
	}
	memset(g_ack_ipc_stats, 0, sizeof(*g_ack_ipc_stats));
	return 0;
}

void nats_ack_ipc_stats_destroy(void)
{
	if (g_ack_ipc_stats) {
		shm_free(g_ack_ipc_stats);
		g_ack_ipc_stats = NULL;
	}
}

void nats_ack_ipc_count_sent(int ok)
{
	if (!g_ack_ipc_stats)
		return;
	atomic_fetch_add_explicit(ok ? &g_ack_ipc_stats->sent
	                             : &g_ack_ipc_stats->dropped,
		1, memory_order_relaxed);
}

uint64_t nats_ack_ipc_enqueued_total(void)
{
	return g_ack_ipc_stats ? atomic_load_explicit(&g_ack_ipc_stats->sent,
		memory_order_relaxed) : 0;
}

uint64_t nats_ack_ipc_drained_total(void)
{
	return g_ack_ipc_stats ? atomic_load_explicit(
		&g_ack_ipc_stats->drained, memory_order_relaxed) : 0;
}

uint64_t nats_ack_ipc_dropped_total(void)
{
	return g_ack_ipc_stats ? atomic_load_explicit(
		&g_ack_ipc_stats->dropped, memory_order_relaxed) : 0;
}

uint32_t nats_ack_ipc_depth(void)
{
	uint64_t snt = nats_ack_ipc_enqueued_total();
	uint64_t drn = nats_ack_ipc_drained_total();

	return snt > drn ? (uint32_t)(snt - drn) : 0;
}

/* Per-handle ACK_NEXT refill hints: set by the ack handlers on this
 * tick, consumed (and cleared) by the main loop right after the pump.
 * Proc-local single-thread state -- the successor of the old
 * drain_ack_ctx next_bits. */
static uint64_t g_ack_next_bits[(NATS_REGISTRY_MAX_HANDLES + 63) / 64];

static void ack_next_set(uint16_t handle_idx)
{
	if (handle_idx < NATS_REGISTRY_MAX_HANDLES)
		g_ack_next_bits[handle_idx / 64] |=
			(uint64_t)1 << (handle_idx % 64);
}

int nats_ack_next_take(uint16_t handle_idx)
{
	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES)
		return 0;
	if ((g_ack_next_bits[handle_idx / 64] >> (handle_idx % 64)) & 1) {
		g_ack_next_bits[handle_idx / 64] &=
			~((uint64_t)1 << (handle_idx % 64));
		return 1;
	}
	return 0;
}

/* AckSync budget per consumer tick.  Each natsMsg_AckSync is a
 * full broker round-trip executed serially inside the IPC drain; a
 * worker-side burst of nats_ack_next() used to head-of-line-block
 * every other queued ack AND the fetch sweep behind N x RTT.  The
 * first NATS_ACK_SYNC_PER_TICK_MAX ack_nexts per tick keep the
 * synchronous "broker definitively saw the ack before the refill"
 * ordering; past the budget the ack degrades to the async
 * natsMsg_Ack -- identical at-least-once semantics (the sync form
 * only narrows a crash-window redelivery), no RTT pileup.  Reset by
 * the consumer main loop each iteration. */
static int g_ack_sync_this_tick;

void nats_ack_ipc_tick_reset(void)
{
	g_ack_sync_this_tick = 0;
}

/* Apply one worker ack action.  Runs in the consumer process (the
 * only libnats-safe context for JetStream ack calls).  Returns 0 if
 * applied, -1 for a stale token (already released / re-claimed). */
static int apply_ack_action(uint64_t token, nats_ack_action_e action,
	uint32_t delay_ms)
{
	natsMsg    *nmsg;
	natsStatus  s;
	uint16_t           h_idx = nats_ack_token_handle(token);
	proc_sub_state_t  *cb_ss = (h_idx < NATS_REGISTRY_MAX_HANDLES)
	                          ? g_subs_by_idx[h_idx] : NULL;
	nats_handle_t     *cb_h  = cb_ss ? cb_ss->h_ref : NULL;

	nmsg = release_msg_ref(token);
	if (!nmsg) {
		/* Stale or already-released.  release_msg_ref logged at DBG. */
		return -1;
	}

	switch (action) {
		case NATS_ACK_ACTION_ACK:
			s = nats_dl.natsMsg_Ack(nmsg, NULL);
			if (s == NATS_OK && cb_h)
				hstat_add(cb_h, &cb_h->acks, 1);
			break;
		case NATS_ACK_ACTION_ACK_NEXT:
			/* nats.c 3.13 does not expose the server's +NXT ack-and-pull
			 * payload via the public API, so we fall back to:
			 *   1) an ack (synchronous while the per-tick budget lasts
			 *      -- see g_ack_sync_this_tick above -- so the broker
			 *      has definitively seen it before we ask for a
			 *      refill; async past the budget), and
			 *   2) flag the originating handle so the outer loop runs an
			 *      extra pull_one_batch() for it on this tick rather
			 *      than waiting for the next idle wake-up.
			 * This matches the user-observable semantics of +NXT
			 * (finish the current message and immediately hand me the
			 * next one) without depending on library internals. */
			if (++g_ack_sync_this_tick <= NATS_ACK_SYNC_PER_TICK_MAX)
				s = nats_dl.natsMsg_AckSync(nmsg, NULL, NULL);
			else
				s = nats_dl.natsMsg_Ack(nmsg, NULL);
			if (s == NATS_OK && cb_h)
				hstat_add(cb_h, &cb_h->acks, 1);
			ack_next_set(h_idx);
			break;
		case NATS_ACK_ACTION_NAK:
			s = nats_dl.natsMsg_Nak(nmsg, NULL);
			if (s == NATS_OK && cb_h)
				hstat_add(cb_h, &cb_h->naks, 1);
			break;
		case NATS_ACK_ACTION_NAK_DELAY:
			/* the delay is in milliseconds: nats.c converts to the
			 * nanoseconds the server expects */
			s = nats_dl.natsMsg_NakWithDelay(nmsg, (int64_t)delay_ms,
				NULL);
			if (s == NATS_OK && cb_h)
				hstat_add(cb_h, &cb_h->naks, 1);
			break;
		case NATS_ACK_ACTION_TERM:
			s = nats_dl.natsMsg_Term(nmsg, NULL);
			if (s == NATS_OK && cb_h)
				hstat_add(cb_h, &cb_h->terms, 1);
			break;
		case NATS_ACK_ACTION_IN_PROGRESS:
			s = nats_dl.natsMsg_InProgress(nmsg, NULL);
			/* in_progress does NOT finalize the message; we must
			 * keep it alive.  Put it back in the ref table under
			 * the same token (same handle, slot, and generation). */
			{
				uint32_t slot_idx = nats_ack_token_slot(token);
				uint16_t gen      = nats_ack_token_generation(token);
				msg_ref_slot_t *slot;
				if (h_idx < NATS_REGISTRY_MAX_HANDLES &&
				    g_msg_refs[h_idx].slots &&
				    slot_idx < g_msg_refs[h_idx].capacity) {
					slot = &g_msg_refs[h_idx].slots[slot_idx];
					slot->msg        = nmsg;
					slot->in_use     = 1;
					slot->generation = gen;
					return 0;
				}
				/* Fall through to destroy if somehow invalid. */
			}
			break;
		default:
			LM_WARN("nats_consumer_proc: unknown ack action %u for "
				"token=0x%016lx\n",
				(unsigned)action, (unsigned long)token);
			s = NATS_OK;
			break;
	}

	if (s != NATS_OK) {
		LM_DBG("nats_consumer_proc: ack action=%u token=0x%016lx "
			"returned %s\n",
			(unsigned)action, (unsigned long)token,
			nats_dl.natsStatus_GetText(s));
	}

	nats_dl.natsMsg_Destroy(nmsg);
	return 0;
}

/* The ipc_send_rpc handlers, one per ack verb.  param is the
 * raw 64-bit token, except nak_delay whose param is a SHM payload
 * this side frees. */
static void ack_drained_bump(void)
{
	if (g_ack_ipc_stats)
		atomic_fetch_add_explicit(&g_ack_ipc_stats->drained, 1,
			memory_order_relaxed);
}

void nats_ack_ipc_on_ack(int sender, void *param)
{
	(void)sender;
	ack_drained_bump();
	(void)apply_ack_action((uint64_t)(uintptr_t)param,
		NATS_ACK_ACTION_ACK, 0);
}

void nats_ack_ipc_on_ack_next(int sender, void *param)
{
	(void)sender;
	ack_drained_bump();
	(void)apply_ack_action((uint64_t)(uintptr_t)param,
		NATS_ACK_ACTION_ACK_NEXT, 0);
}

void nats_ack_ipc_on_nak(int sender, void *param)
{
	(void)sender;
	ack_drained_bump();
	(void)apply_ack_action((uint64_t)(uintptr_t)param,
		NATS_ACK_ACTION_NAK, 0);
}

void nats_ack_ipc_on_nak_delay(int sender, void *param)
{
	nats_ack_nak_delay_t *d = (nats_ack_nak_delay_t *)param;

	(void)sender;
	ack_drained_bump();
	if (!d)
		return;
	(void)apply_ack_action(d->token, NATS_ACK_ACTION_NAK_DELAY,
		d->delay_ms);
	shm_free(d);
}

void nats_ack_ipc_on_term(int sender, void *param)
{
	(void)sender;
	ack_drained_bump();
	(void)apply_ack_action((uint64_t)(uintptr_t)param,
		NATS_ACK_ACTION_TERM, 0);
}

void nats_ack_ipc_on_in_progress(int sender, void *param)
{
	(void)sender;
	ack_drained_bump();
	(void)apply_ack_action((uint64_t)(uintptr_t)param,
		NATS_ACK_ACTION_IN_PROGRESS, 0);
}

