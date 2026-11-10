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
 * Worker acks ride core IPC: the ACTION is the ipc_send_rpc
 * function identity (nats_ack_ipc_on_ack / _nak / _term / _in_progress
 * / _ack_next, param = the 64-bit ack token verbatim) and only
 * NAK_DELAY -- the one action that cannot fit token+delay in a pointer
 * -- carries a small SHM payload the handler frees.  This test drives
 * the PRODUCTION handlers (../nats_consumer_proc.c + ../nats_msg_ref.c)
 * against a recording nats_dl table and asserts, per action:
 *
 *   - the right JetStream call is made on the right natsMsg,
 *   - the msg-ref is redeemed and the message destroyed afterwards --
 *     EXCEPT in_progress, which must re-stash the msg under the SAME
 *     token (a later ack must still find it),
 *   - ack_next sets the per-handle refill hint, observable (and
 *     cleared) via nats_ack_next_take(),
 *   - a stale token (already released) makes no JetStream call,
 *   - nak_delay converts ms -> ns and frees its SHM payload (ASan),
 *   - every handler bumps the drained stat; the sent/dropped stats
 *     count from the worker-side helper.
 *
 * Runs in the nats_consumer unit test suite, on this process's own ref
 * table, with the suite's fake libnats.
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <nats/nats.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../nats/nats_bind.h"
#include "../nats_handle_registry.h"
#include "../nats_consumer_proc.h"
#include "../nats_consumer_proc_internal.h"
#include "../nats_ack.h"
#include "../nats_ack_ipc.h"

#include "nc_ut.h"

/* ── recording nats_dl table ────────────────────────────────────── */


static struct {
	int ack, ack_sync, nak, nak_delay, term, in_progress, destroy;
	const natsMsg *last;
	int64_t last_delay;	/* as passed: natsMsg_NakWithDelay takes ms */
} rec;

static natsStatus r_ack(natsMsg *m, jsOptions *o)
{ (void)o; rec.ack++; rec.last = m; return 0; }
static natsStatus r_ack_sync(natsMsg *m, jsOptions *o, jsErrCode *e)
{ (void)o; (void)e; rec.ack_sync++; rec.last = m; return 0; }
static natsStatus r_nak(natsMsg *m, jsOptions *o)
{ (void)o; rec.nak++; rec.last = m; return 0; }
static natsStatus r_nak_delay(natsMsg *m, int64_t ns, jsOptions *o)
{ (void)o; rec.nak_delay++; rec.last = m; rec.last_delay = ns; return 0; }
static natsStatus r_term(natsMsg *m, jsOptions *o)
{ (void)o; rec.term++; rec.last = m; return 0; }
static natsStatus r_in_progress(natsMsg *m, jsOptions *o)
{ (void)o; rec.in_progress++; rec.last = m; return 0; }
static void r_destroy(natsMsg *m)
{ rec.destroy++; rec.last = m; }
static const char *r_text(natsStatus s) { (void)s; return ""; }

/* adds the recorders to the suite's fake table (nc_ut_begin() put it in
 * place: nats_dl is *nats_api.dl in the module) */
static void dl_install(void)
{
	nats_dl.natsMsg_Ack          = r_ack;
	nats_dl.natsMsg_AckSync      = r_ack_sync;
	nats_dl.natsMsg_Nak          = r_nak;
	nats_dl.natsMsg_NakWithDelay = r_nak_delay;
	nats_dl.natsMsg_Term         = r_term;
	nats_dl.natsMsg_InProgress   = r_in_progress;
	nats_dl.natsMsg_Destroy      = r_destroy;
	nats_dl.natsStatus_GetText   = r_text;
}

/* ── harness ────────────────────────────────────────────────────── */

#define CHECK(cond, label) ok((cond), "ack_ipc_actions: %s", (label))

#define H_IDX 3
#define CAP   8

static int fake1, fake2;

static uint64_t stash(natsMsg *m)
{
	int ok = 0;
	uint64_t tok = store_msg_ref(H_IDX, CAP, 30000, m, &ok);
	if (!ok) diag("store_msg_ref failed");
	return tok;
}

static void *tok_param(uint64_t tok)
{
	return (void *)(uintptr_t)tok;
}

void nc_ut_ack_ipc_actions(void)
{
	uint64_t tok;
	uint64_t drained0;

	/* the stats block is the module's own, made in mod_init */
	nc_ut_begin();
	memset(&rec, 0, sizeof rec);
	dl_install();
	drained0 = nats_ack_ipc_drained_total();

	diag("plain ack: JetStream Ack + destroy + ref released:");
	tok = stash((natsMsg *)&fake1);
	nats_ack_ipc_on_ack(0, tok_param(tok));
	CHECK(rec.ack == 1 && rec.last == (natsMsg *)&fake1,
		"natsMsg_Ack called on the stashed message");
	CHECK(rec.destroy == 1, "message destroyed after the ack");
	CHECK(release_msg_ref(tok) == NULL, "ref slot redeemed (token now stale)");
	CHECK(nats_ack_ipc_drained_total() == drained0 + 1,
		"drained stat bumped");

	diag("stale token: no JetStream call at all:");
	nats_ack_ipc_on_ack(0, tok_param(tok));
	CHECK(rec.ack == 1 && rec.destroy == 1,
		"replayed token is a no-op (no double ack/destroy)");

	diag("nak / term route to their JetStream calls:");
	tok = stash((natsMsg *)&fake1);
	nats_ack_ipc_on_nak(0, tok_param(tok));
	CHECK(rec.nak == 1, "natsMsg_Nak called");
	tok = stash((natsMsg *)&fake2);
	nats_ack_ipc_on_term(0, tok_param(tok));
	CHECK(rec.term == 1 && rec.last == (natsMsg *)&fake2,
		"natsMsg_Term called on the right message");
	CHECK(rec.destroy == 3, "both messages destroyed");

	diag("ack_next: AckSync + per-handle refill hint:");
	CHECK(nats_ack_next_take(H_IDX) == 0, "refill hint starts clear");
	tok = stash((natsMsg *)&fake1);
	nats_ack_ipc_on_ack_next(0, tok_param(tok));
	CHECK(rec.ack_sync == 1, "natsMsg_AckSync called (broker-confirmed)");
	CHECK(nats_ack_next_take(H_IDX) == 1, "refill hint set for the handle");
	CHECK(nats_ack_next_take(H_IDX) == 0, "take() clears the hint");

	diag("ack_next AckSync budget: a burst degrades to async Ack:");
	{
		/* Each AckSync is a full broker round-trip executed serially
		 * inside the consumer's IPC drain; a worker-side burst of
		 * nats_ack_next() used to head-of-line-block every other ack
		 * and the fetch sweep behind N x RTT.  Budget: the first
		 * NATS_ACK_SYNC_PER_TICK_MAX per tick stay synchronous (the
		 * broker has definitively seen them before the refill pull),
		 * the rest degrade to async Ack -- same at-least-once
		 * semantics, no serial RTT pileup.  The consumer loop resets
		 * the budget each iteration via nats_ack_ipc_tick_reset(). */
		int sync0, ack0, i;

		nats_ack_ipc_tick_reset();
		sync0 = rec.ack_sync; ack0 = rec.ack;
		for (i = 0; i < NATS_ACK_SYNC_PER_TICK_MAX + 2; i++) {
			tok = stash((natsMsg *)&fake1);
			nats_ack_ipc_on_ack_next(0, tok_param(tok));
		}
		CHECK(rec.ack_sync == sync0 + NATS_ACK_SYNC_PER_TICK_MAX,
			"burst: first NATS_ACK_SYNC_PER_TICK_MAX acks are AckSync");
		CHECK(rec.ack == ack0 + 2,
			"burst: past the budget the ack degrades to async Ack");
		CHECK(nats_ack_next_take(H_IDX) == 1,
			"refill hint still set by the degraded acks");
		(void)nats_ack_next_take(H_IDX);

		nats_ack_ipc_tick_reset();
		tok = stash((natsMsg *)&fake1);
		nats_ack_ipc_on_ack_next(0, tok_param(tok));
		CHECK(rec.ack_sync == sync0 + NATS_ACK_SYNC_PER_TICK_MAX + 1,
			"tick reset restores the AckSync budget");
		(void)nats_ack_next_take(H_IDX);
	}

	diag("in_progress: keeps the message alive under the SAME token:");
	tok = stash((natsMsg *)&fake2);
	{
		int destroys_before = rec.destroy;
		nats_ack_ipc_on_in_progress(0, tok_param(tok));
		CHECK(rec.in_progress == 1, "natsMsg_InProgress called");
		CHECK(rec.destroy == destroys_before,
			"message NOT destroyed (still pending)");
		CHECK(release_msg_ref(tok) == (natsMsg *)&fake2,
			"same token still redeems the message afterwards");
	}

	diag("nak_delay: SHM payload, ms->ns, freed by the handler (ASan):");
	tok = stash((natsMsg *)&fake1);
	{
		nats_ack_nak_delay_t *d = shm_malloc(sizeof(*d));
		d->token = tok;
		d->delay_ms = 1500;
		nats_ack_ipc_on_nak_delay(0, d);
		CHECK(rec.nak_delay == 1 && rec.last_delay == 1500,
			"NakWithDelay called with 1500 (milliseconds; nats.c converts)");
	}
	tok = stash((natsMsg *)&fake1);
	{
		nats_ack_nak_delay_t *d = shm_malloc(sizeof(*d));
		d->token = tok;
		d->delay_ms = UINT32_MAX;
		nats_ack_ipc_on_nak_delay(0, d);
		CHECK(rec.nak_delay == 2 && rec.last_delay == (int64_t)UINT32_MAX,
			"largest delay passed through unscaled (no overflow)");
	}

	diag("sent/dropped counters (worker-side helper):");
	{
		uint64_t s0 = nats_ack_ipc_enqueued_total();
		uint64_t d0 = nats_ack_ipc_dropped_total();
		nats_ack_ipc_count_sent(1);
		nats_ack_ipc_count_sent(0);
		CHECK(nats_ack_ipc_enqueued_total() == s0 + 1 &&
		      nats_ack_ipc_dropped_total() == d0 + 1,
			"count_sent(1)/count_sent(0) land in sent/dropped");
		/* 1 sent vs 6 drained in this test: depth must floor at 0,
		 * never wrap (sent - drained is momentarily "negative" when
		 * the consumer observes the pipe ahead of the counter). */
		CHECK(nats_ack_ipc_depth() == 0,
			"depth floors at 0 when drained >= sent");
	}

	purge_msg_ref_row(H_IDX);
	nc_ut_end();
}
