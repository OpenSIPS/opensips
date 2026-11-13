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
 * nats_ack.h -- script-callable ack / nak / term / in_progress.
 *
 * Each of these enqueues an IPC message to the consumer process which
 * translates it into the corresponding natsMsg_* call on the stored
 * natsMsg ref.  They all consult the per-worker current-message state
 * established by w_nats_fetch* and clear it on success so the same
 * message cannot be double-acked by accident.
 */

#ifndef NATS_ACK_H
#define NATS_ACK_H

#include <stdint.h>

/* Forward-declare sip_msg to avoid pulling in the full parser header
 * from callers that only need the token helpers (e.g. unit tests). */
struct sip_msg;

/**
 * Shared contract (every w_nats_* ack entry point below):
 *
 * @param msg  Current SIP message; unused (the ack target comes from the
 *             per-worker current-message state, not from the SIP msg).
 * @return  1  success -- the ack was enqueued to the consumer process.
 *         -1  no current message (nothing fetched, or already finalized).
 *         -2  consumer process not up, IPC pipe refused the send, or (for
 *             nak_delay) SHM exhaustion; the message stays un-acked and
 *             JetStream redelivers after ack_wait.
 *
 * Allocation: none on the hot path -- the 64-bit ack token travels packed
 * in the opaque ipc_send_rpc param.  Exception: w_nats_nak_delay
 * shm_malloc's a small nats_ack_nak_delay_t payload; the consumer-side
 * handler frees it (the sender frees it itself if the send is refused).
 *
 * Locking: none.  Only per-worker static state (the current-message /
 * batch buffers in nats_fetch.c) is consulted.
 *
 * Context: SIP worker script context (cmd_export, ALL_ROUTES).  On rc 1,
 * ack / nak / nak_delay / term / ack_next clear the current-message state
 * (and invalidate the selected batch slot) so a second call returns -1
 * instead of double-acking; in_progress / ack_progress deliberately keep
 * it, since the worker still intends to ack or nak later.
 */
int w_nats_ack  (struct sip_msg *msg);
int w_nats_nak  (struct sip_msg *msg);
/** @param delay_ms  Redelivery delay in ms; NULL or <= 0 means 0 (plain
 *                   nak).  Otherwise identical to the shared contract. */
int w_nats_nak_delay(struct sip_msg *msg, int *delay_ms);
int w_nats_term (struct sip_msg *msg);
int w_nats_in_progress(struct sip_msg *msg);

/* Batch-oriented ack helpers.
 *
 * nats_ack_next(): acknowledge the current message and hint the
 *   consumer process to refill the ring as soon as possible.  nats.c
 *   3.13 does not expose the native "+NXT" ack-and-pull mechanism on
 *   natsMsg_Ack; the consumer process therefore runs an immediate
 *   pull_one_batch() right after the ack completes for that
 *   subscription (documented fallback).  Semantically equivalent to
 *   nats_ack() followed by a zero-budget nats_fetch() on the same id.
 *
 * nats_ack_progress(): same as nats_in_progress() but exported under
 *   the canonical name.  nats_in_progress remains as an alias for
 *   backwards compatibility with earlier scripts. */
int w_nats_ack_next    (struct sip_msg *msg);
int w_nats_ack_progress(struct sip_msg *msg);

/**
 * Pack / unpack ack-token helpers.  Exported for the consumer process
 * which decodes tokens back to (handle_idx, slot_idx, generation).
 *
 * @param handle_idx / slot_idx / generation / tok  the token fields
 *        (16 + 32 + 16 bits) and the packed 64-bit token.
 * @return the packed token, resp. the extracted field.
 *
 * Pure inline functions on their arguments: no allocation, no locking;
 * safe in any process or thread.
 */

static inline uint64_t nats_ack_token_pack(uint16_t handle_idx,
                                           uint32_t slot_idx,
                                           uint16_t generation)
{
	return ((uint64_t)handle_idx     << 48)
	     | (((uint64_t)slot_idx & 0xFFFFFFFFu) << 16)
	     |  (uint64_t)generation;
}

static inline uint16_t nats_ack_token_handle(uint64_t tok)
{
	return (uint16_t)((tok >> 48) & 0xFFFFu);
}

static inline uint32_t nats_ack_token_slot(uint64_t tok)
{
	return (uint32_t)((tok >> 16) & 0xFFFFFFFFu);
}

static inline uint16_t nats_ack_token_generation(uint64_t tok)
{
	return (uint16_t)(tok & 0xFFFFu);
}

#endif /* NATS_ACK_H */
