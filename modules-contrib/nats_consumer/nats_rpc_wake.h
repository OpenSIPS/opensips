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
 * nats_rpc_wake.h -- consumer -> worker reply wake for the async
 * nats_request transport.
 *
 * Without this hop the worker learns of a DELIVERED reply only
 * on the next tick of its per-call guard timerfd, so reply latency is
 * floored at the poll interval and every in-flight call costs periodic
 * timer wakeups.  Instead, the consumer process signals the claiming
 * worker the moment it publishes the reply:
 *
 *   ipc_send_rpc(slot->owner_proc, nats_rpc_async_on_wake,
 *                nats_rpc_ipc_pack(slot_idx, generation));
 *
 * and the worker-side handler pokes the call's guard timerfd to fire
 * immediately (preserving its periodic interval).  The reactor then
 * runs the normal resume function, which reads the slot state -- ALL
 * completion logic stays in resume_nats_request_slot; the wake is
 * purely an accelerator.  A lost or refused wake is harmless: the
 * coarse guard tick picks the reply up as before.
 *
 * The per-worker registry maps slot_idx -> (generation, timerfd) for
 * this worker's in-flight calls.  It is strictly process-local and
 * single-threaded: register/unregister run on the worker main thread
 * (script context) and on_wake runs on the same thread (reactor IPC
 * pump), so no locking is needed.  A wake whose generation does not
 * match the registered entry is a stale signal for a previous claim of
 * the slot and is dropped -- it must never poke another call's timer.
 *
 * The send side runs in the consumer process; calling ipc_send_rpc
 * from the libnats reply thread follows the established event_nats
 * pattern (ipc_dispatch_rpc from the subscription callback).
 */

#ifndef NATS_RPC_WAKE_H
#define NATS_RPC_WAKE_H

#include <stdint.h>

/**
 * Allocate the per-worker wake registry for @slots entries (the async
 * slot-pool size).  Idempotent: a second call returns 0 without
 * reallocating.
 *
 * @param slots  Number of entries; must be >= 1.
 * @return       0 on success (or already initialised); -1 on a bad size
 *               or allocation failure (replies then fall back to the
 *               guard tick).
 *
 * Allocation: the registry array is pkg_malloc'd (worker process-local);
 * nats_rpc_wake_destroy() frees it.
 *
 * Locking: none -- the registry is strictly process-local and
 * single-threaded (see the file-level comment).
 *
 * Context: SIP worker main thread; called lazily from the first async
 * nats_request in each worker (w_nats_request_async).
 */
int nats_rpc_wake_init(uint32_t slots);

/**
 * Free the per-worker wake registry (tests / worker teardown).
 * Idempotent; safe when never initialised.
 *
 * @return  nothing.
 *
 * Frees the pkg_malloc'd registry allocated by nats_rpc_wake_init().
 * No locking; SIP worker main thread (or unit-test harness) only.
 */
void nats_rpc_wake_destroy(void);

/**
 * Track an in-flight call: a wake for (@slot_idx, @gen) should poke
 * @timerfd.  Re-registering an index overwrites the previous entry
 * (slot reuse).
 *
 * @param slot_idx  Async slot index of the call.
 * @param gen       Claim generation; a wake carrying a different
 *                  generation is dropped by the handler.
 * @param timerfd   The call's worker-private guard timerfd (must be
 *                  >= 0); ownership stays with the caller.
 * @return          0 on success; -1 if the registry is not initialised,
 *                  the index is out of range or the fd is invalid.
 *
 * No allocation; writes one process-local registry entry.  No locking
 * (single-threaded per-worker state).  Context: SIP worker main thread,
 * from the async nats_request start path.
 */
int nats_rpc_wake_register(uint32_t slot_idx, uint32_t gen, int timerfd);

/**
 * Stop tracking @slot_idx.  Out-of-range / untracked / uninitialised
 * registry is a no-op.
 *
 * @param slot_idx  Async slot index to untrack.
 * @return          nothing.
 *
 * No allocation, no locking (process-local single-threaded state).
 * Context: SIP worker main thread -- the resume / teardown paths of the
 * async nats_request call that registered the entry.
 */
void nats_rpc_wake_unregister(uint32_t slot_idx);

/*
 * The ipc_send_rpc handler (runs in the claiming worker).  @param is
 * nats_rpc_ipc_pack(slot_idx, generation).  On a matching registered
 * entry, re-arms the guard timerfd to fire immediately while keeping
 * its periodic interval; every mismatch (uninitialised registry,
 * out-of-range index, untracked slot, stale generation) is a silent
 * no-op covered by the guard tick.
 */
void nats_rpc_async_on_wake(int sender, void *param);

/**
 * Consumer-process side: signal @owner_proc that slot @slot_idx /
 * generation @gen has a state change worth an immediate resume
 * (reply delivered or consumer-side abandon).
 *
 * @param owner_proc  process_no of the claiming worker; < 0 means the
 *                    claim never stamped an owner -- refused without an
 *                    IPC call.
 * @param slot_idx    Async slot index of the call.
 * @param gen         Claim generation; a stale generation is dropped by
 *                    the receiving worker's registry, never poking
 *                    another call's timer.
 * @return            0 when the IPC job was queued, -1 otherwise;
 *                    failure needs no handling beyond a debug log (the
 *                    guard tick is the fallback).
 *
 * Allocation: none -- the payload travels packed in the ipc_send_rpc
 * param pointer.  Locking: none.
 *
 * Context: consumer process only, from BOTH its main loop (abandon /
 * publish-failure paths) and its libnats reply callback thread
 * (on_inbox_reply); calling ipc_send_rpc from the cnats thread follows
 * the established event_nats pattern.
 */
int nats_rpc_wake_send(int owner_proc, uint32_t slot_idx, uint32_t gen);

#endif /* NATS_RPC_WAKE_H */
