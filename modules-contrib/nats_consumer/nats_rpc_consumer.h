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
 * nats_rpc_consumer.h -- consumer-process side of the
 * consumer-process-routed async nats_request transport.
 *
 * All three functions below are called from the dedicated
 * nats_consumer process (not from SIP workers).  They set up a
 * persistent libnats subscription on
 * `_INBOX.opensips.<consumer_pid>.>`, drain the worker -> consumer
 * IPC queue and publish for each entry, and on each reply land
 * the payload into the corresponding SHM slot and store its state
 * DELIVERED; the worker observes it on its next private-timerfd poll
 * (no fd is signalled).
 *
 * The libnats subscription callback runs on a libnats internal
 * thread inside the consumer process.  That context is known
 * safe for libnats threading (it's the same place where
 * JetStream pull subscriptions live today); the earlier
 * worker-side subscription pattern -- which crashed -- is gone.
 */

#ifndef NATS_RPC_CONSUMER_H
#define NATS_RPC_CONSUMER_H

/**
 * Set up the persistent inbox subscription against the consumer
 * process's libnats connection.  Idempotent: returns 0 immediately if
 * already subscribed.
 *
 * The wildcard subscribed to is
 * `_INBOX.opensips.<consumer_pid>.>`; each in-flight publish
 * sets reply-to to `_INBOX.opensips.<consumer_pid>.<slot_idx>`
 * so the callback can look the slot up in O(1) without a hash.
 *
 * @return  0 on success (or already subscribed), -1 on subscribe
 *          failure (pool down, permission denied, prefix overflow).
 *          Non-fatal: the consumer continues doing JetStream pull work;
 *          while the inbox is down, the async-request publish path
 *          abandons every call and the script sees a failure code.
 *
 * Allocation: the natsSubscription is created and owned by libnats;
 * stored in a process-local static and released only by
 * nats_rpc_consumer_unsubscribe().  No locking.
 *
 * Context: consumer process main loop ONLY -- once at startup, then
 * retried each tick while nats_rpc_consumer_inbox_ready() is 0.
 */
int nats_rpc_consumer_subscribe(void);

/**
 * Tear down the inbox subscription (Unsubscribe + Destroy on the
 * libnats object); idempotent when never subscribed.
 *
 * @return  nothing.
 *
 * No locking.  Context: consumer process only, at consumer shutdown
 * (before nats_pool teardown).
 */
void nats_rpc_consumer_unsubscribe(void);

/**
 * Whether the reply inbox subscription is currently live.
 *
 * @return  1 iff subscribed, else 0.  The consumer main loop retries
 *          nats_rpc_consumer_subscribe() while this is 0, and the IPC
 *          publish path abandons requests (rather than publishing to a
 *          deaf inbox) while this is 0.
 *
 * Plain read of a process-local pointer; no allocation, no locking.
 * Context: consumer process only (main loop + its IPC publish handler)
 * -- the value is meaningless in any other process.
 */
int nats_rpc_consumer_inbox_ready(void);

#include <stdint.h>

/**
 * The ipc_send_rpc handler for one worker->consumer publish
 * request.  Workers send it with
 *   ipc_send_rpc(nats_consumer_proc_no(), nats_rpc_ipc_on_publish,
 *                nats_rpc_ipc_pack(slot_idx, generation));
 *
 * @param sender  process_no of the sending worker; ignored.
 * @param param   nats_rpc_ipc_pack(slot_idx, generation) -- no
 *                allocation travels with it, nothing to free.
 * @return        nothing.  A stale entry (slot freed / re-claimed since
 *                the send, detected by state + generation) is skipped;
 *                connection-lost, deaf-inbox or publish failure CAS the
 *                slot INFLIGHT -> ABANDONED and IPC-wake the claiming
 *                worker so it fails fast.
 *
 * Effect: reads the slot's out_* fields, builds a natsMsg (created and
 * destroyed inside the call) with reply-to pointing back at our inbox,
 * and PublishMsg's it.  No locking (single-threaded IPC drain; slot
 * hand-off is via the slot's atomic state).
 *
 * Context: consumer process ONLY -- the main loop pumps its IPC fd,
 * gated on a live broker connection, so entries wait in the pipe across
 * reconnects.
 */
void nats_rpc_ipc_on_publish(int sender, void *param);

/**
 * SHM counters behind the rpc_ipc_* MI stats.
 *
 * nats_rpc_ipc_stats_init() shm_malloc's the counter block (freed by
 * nats_rpc_ipc_stats_destroy()); @return 0 on success, -1 on SHM
 * exhaustion (all other functions then read as zero / no-op).
 * Contexts: init from mod_init (main process, pre-fork), destroy from
 * mod_destroy.
 *
 * nats_rpc_ipc_count_sent(@ok): bump `sent` (@ok != 0) or `dropped`
 * (@ok == 0); called from the SIP-worker async-RPC send path.
 *
 * The _total() getters and _depth() (= sent - drained, floored at 0)
 * are relaxed-atomic reads with no locking, callable from any process
 * (in practice the MI handlers); they return 0 while uninitialised.
 */
int      nats_rpc_ipc_stats_init(void);
void     nats_rpc_ipc_stats_destroy(void);
void     nats_rpc_ipc_count_sent(int ok);
uint64_t nats_rpc_ipc_enqueued_total(void);
uint64_t nats_rpc_ipc_drained_total(void);
uint64_t nats_rpc_ipc_dropped_total(void);
uint32_t nats_rpc_ipc_depth(void);

#endif /* NATS_RPC_CONSUMER_H */
