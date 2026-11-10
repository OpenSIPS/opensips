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
 * nats_ack_ipc.h -- worker -> consumer-process ack hop.
 *
 * Acks ride OpenSIPS core IPC.  The ACTION is the ipc_send_rpc
 * function identity -- one handler per JetStream ack verb -- and the
 * 64-bit ack token travels verbatim as the opaque param pointer, so
 * the hot path allocates nothing:
 *
 *   ipc_send_rpc(nats_consumer_proc_no(), nats_ack_ipc_on_ack,
 *                (void *)(uintptr_t)token);
 *
 * The one exception is NAK_DELAY: token + delay_ms cannot fit a
 * pointer, so it carries a small SHM payload the handler frees.
 *
 * The consumer process pumps its IPC fd from the main loop, gated on
 * a live broker connection, so acks wait in the pipe across
 * reconnects exactly like they used to wait in the SHM ring.  A send
 * refused (pipe full / consumer proc not up) surfaces the usual -2 to
 * the script; the message stays un-acked and JetStream redelivers.
 *
 * Handler behavior is unit-locked in test/test_ack_ipc_actions.c
 * (drives the production handlers against a recording nats_dl table).
 */

#ifndef NATS_ACK_IPC_H
#define NATS_ACK_IPC_H

#include <stdint.h>

/* Ack action vocabulary.  Kept for the worker-side dispatch and the
 * consumer-side apply switch -- the consumer process maps these into
 * calls on natsMsg_Ack / natsMsg_Nak / natsMsg_NakWithDelay /
 * natsMsg_InProgress / natsMsg_Term. */
typedef enum {
	NATS_ACK_ACTION_NOOP = 0,       /* ignored */
	NATS_ACK_ACTION_ACK,            /* natsMsg_Ack */
	NATS_ACK_ACTION_NAK,            /* natsMsg_Nak */
	NATS_ACK_ACTION_NAK_DELAY,      /* natsMsg_NakWithDelay */
	NATS_ACK_ACTION_TERM,           /* natsMsg_Term */
	NATS_ACK_ACTION_IN_PROGRESS,    /* natsMsg_InProgress */
	NATS_ACK_ACTION_ACK_NEXT,       /* natsMsg_AckSync + hint for an
	                                 * immediate pull refill.  nats.c
	                                 * 3.13 does not expose the server's
	                                 * native +NXT reply; we fall back
	                                 * to ack+ring-refill-on-next-tick. */
} nats_ack_action_e;

/* NAK_DELAY payload: SHM-allocated by the worker, freed by the
 * handler (or by the worker again if the send itself fails). */
typedef struct nats_ack_nak_delay {
	uint64_t token;
	uint32_t delay_ms;
} nats_ack_nak_delay_t;

/**
 * The ipc_send_rpc handlers, one per ack verb.
 *
 * Shared contract:
 *
 * @param sender  process_no of the sending worker; ignored.
 * @param param   The raw 64-bit ack token cast via uintptr_t -- except
 *                on_nak_delay, whose param is a worker-shm_malloc'd
 *                nats_ack_nak_delay_t * that THIS handler shm_free's
 *                (NULL is tolerated).
 * @return        nothing; a stale token (slot already released or
 *                re-used, detected by the packed generation) is a silent
 *                no-op.
 *
 * Effect: redeems the token from the process-local msg-ref table, calls
 * the matching natsMsg_Ack / Nak / NakWithDelay / Term / InProgress /
 * AckSync via nats_dl, bumps the per-handle SHM counters (relaxed
 * atomics), and destroys the natsMsg -- except in_progress, which puts
 * the still-live natsMsg back under the same token.  ack_next also flags
 * the handle for an immediate pull refill on this tick.
 *
 * Locking: none -- these run single-threaded.
 *
 * Context: consumer process ONLY, invoked from its main loop's IPC pump
 * (pump_worker_ipc -> ipc_handle_job); the only libnats-safe context for
 * JetStream ack calls.  Never run on a cnats callback thread.
 */
void nats_ack_ipc_on_ack(int sender, void *param);
void nats_ack_ipc_on_ack_next(int sender, void *param);
void nats_ack_ipc_on_nak(int sender, void *param);
void nats_ack_ipc_on_nak_delay(int sender, void *param);
void nats_ack_ipc_on_term(int sender, void *param);
void nats_ack_ipc_on_in_progress(int sender, void *param);

/* Per-tick AckSync budget for ACK_NEXT: the first
 * NATS_ACK_SYNC_PER_TICK_MAX per consumer tick use the synchronous
 * (round-trip) ack, the rest of a burst degrade to the async ack so
 * serial RTTs cannot head-of-line-block the IPC drain + fetch sweep.
 * The consumer main loop resets the budget every iteration. */
#ifndef NATS_ACK_SYNC_PER_TICK_MAX
#define NATS_ACK_SYNC_PER_TICK_MAX 4
#endif
/**
 * Reset the per-tick AckSync budget (see above).
 *
 * @return  nothing.
 *
 * Touches one process-local counter; no allocation, no locking.
 * Context: consumer process main loop, once per iteration before the
 * IPC drain.
 */
void nats_ack_ipc_tick_reset(void);

/**
 * SHM counters behind the ack_ipc_* MI stats.
 *
 * nats_ack_ipc_stats_init() shm_malloc's the counter block (freed by
 * nats_ack_ipc_stats_destroy()); @return 0 on success, -1 on SHM
 * exhaustion (all other functions then read as zero / no-op).
 * Contexts: init from mod_init (main process, pre-fork), destroy from
 * mod_destroy.
 *
 * nats_ack_ipc_count_sent(@ok): bump `sent` (@ok != 0) or `dropped`
 * (@ok == 0); called from the SIP-worker ack send path.  No return.
 *
 * The _total() getters and _depth() (= sent - drained, floored at 0)
 * are relaxed-atomic reads with no locking, callable from any process
 * (in practice the MI handlers); they return 0 while uninitialised.
 */
int      nats_ack_ipc_stats_init(void);
void     nats_ack_ipc_stats_destroy(void);
void     nats_ack_ipc_count_sent(int ok);
uint64_t nats_ack_ipc_enqueued_total(void);
uint64_t nats_ack_ipc_drained_total(void);
uint64_t nats_ack_ipc_dropped_total(void);
uint32_t nats_ack_ipc_depth(void);

#endif /* NATS_ACK_IPC_H */
