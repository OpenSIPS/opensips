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
 * nats_rpc_async.h -- internal API of the async nats_request path.
 *
 * The async entry point itself (w_nats_request_async) is declared
 * in nats_rpc.h alongside the rest of the script-callable RPC
 * surface; that's the only symbol nats_consumer.c needs.  This
 * header exposes the state-machine primitives so the in-flight
 * unit test (test_async_request_inflight.c) can drive them in
 * isolation without linking libnats.
 *
 * All functions are process-local (per-worker); the in-flight
 * table is statically sized in nats_rpc_async.c and is not shared
 * across processes.
 */

#ifndef NATS_RPC_ASYNC_H
#define NATS_RPC_ASYNC_H

/* The in-flight ctx state machine that used to be declared here (the
 * per-worker inbox-subscription async transport) was superseded by the
 * consumer-routed SHM-slot transport and deleted. */

/**
 * Mint a UUIDv7 correlation id into the provided
 * buffer.
 *
 * @param out  Caller-owned destination buffer; NUL-terminated on
 *             success.  Nothing is allocated.
 * @param cap  Size of @out; must be at least 37 (36 chars + NUL).
 * @return     The written length (36) on success, 0 on truncation /
 *             clock failure / getrandom failure (callers treat 0 as
 *             "no correlation id available" and skip header staging).
 *
 * Pure function on caller memory (one CLOCK_REALTIME read + one
 * getrandom of 10 bytes); no locking; safe in any process or thread.
 * Production callers are the sync and async nats_request start paths
 * (SIP worker); exposed for unit tests that validate the version-7
 * nibble and variant bits without booting opensips.
 */
int nats_rpc_async_uuidv7_mint(char *out, size_t cap);

/**
 * Per-worker stash setter / getter for the most recent outbound
 * request's UUIDv7.
 *
 * _set:
 * @param id   Bytes to stash; copied (caller keeps ownership).  NULL or
 *             len <= 0 clears the stash; over-long input is truncated
 *             to 63 bytes.  Also clears the user-supplied override flag
 *             (recording a just-used id is NOT an override).
 * @param len  Length of @id in bytes.
 * @return     nothing.
 *
 * _get:
 * @param out_len  Optional out: stashed length (may be NULL).
 * @return         Pointer to the stash, or NULL when empty.  The
 *                 pointer is a module-owned per-worker static buffer --
 *                 do not free; valid until the next nats_request call
 *                 (or _set) on this worker.  Copy to outlive that.
 *
 * Both operate on per-worker static storage: no allocation, no locking
 * (SIP workers are single-threaded).  Context: SIP worker only -- the
 * request start paths (_set) and the $nats_request_id pvar getter
 * (_get), including resume routes after an async() yield.
 */
void        nats_rpc_async_request_id_set(const char *id, int len);
const char *nats_rpc_async_request_id_get(int *out_len);

/**
 * Pvar-write entry point: the script has assigned to $nats_request_id.
 * Stash the value with a consume-once flag so the NEXT nats_request
 * call uses it instead of minting a fresh UUIDv7.
 *
 * @param id   Value to stash; copied into the per-worker static buffer.
 *             NULL / len <= 0 clears both the pending override and the
 *             last-used stash, returning 0.
 * @param len  Length of @id in bytes.
 * @return     0 on success, -1 on validation failure (length > 63
 *             bytes, or embedded CR/LF -- would inject pseudo-headers
 *             into the NATS wire protocol).
 *
 * No allocation, no locking (per-worker static state).  Context: SIP
 * worker script context, via pv_set_nats_request_id.
 */
int nats_rpc_async_request_id_user_set(const char *id, int len);

/**
 * Start-path consumer: if a user-supplied id is pending, copy it to
 * @out and clear the pending flag.  Consume-once -- subsequent calls
 * revert to minting unless the script re-assigns.
 *
 * @param out  Caller-owned buffer; NUL-terminated on success.
 * @param cap  Size of @out; must exceed the stashed length.
 * @return     The length copied, or 0 when no override is pending (or
 *             @out is NULL / too small -- the override then stays
 *             pending).
 *
 * No allocation, no locking (per-worker static state).  Context: SIP
 * worker only, from the sync / async nats_request start paths.
 */
int nats_rpc_async_request_id_consume_user(char *out, int cap);


/* Per-call guard-timerfd tick interval (ms), tunable via the
 * nats_consumer "async_rpc_poll_ms" modparam. Replies resume
 * via the consumer's IPC wake; this tick only bounds timeout /
 * lost-wake detection.  Clamped to [1, 1000] when used. */
extern int nats_rpc_async_poll_ms;

#endif /* NATS_RPC_ASYNC_H */
