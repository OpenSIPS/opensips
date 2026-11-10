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
 * nats_consumer_proc.h -- dedicated JetStream pull consumer process.
 *
 * The process is forked by the OpenSIPS core via a proc_export_t entry
 * registered in `module_exports.procs`.  It is the sole producer into
 * each handle's SHM ring: SIP workers only pop.  On fork it joins the
 * nats_pool, then loops forever reconciling subscriptions with the
 * registry and pulling batches.
 *
 * See nats_consumer_proc.c for the per-section design notes
 * (reconnect-aware subscription refresh, ack-IPC plumbing,
 * persistence integration, retire/reap teardown, etc.).
 */

#ifndef NATS_CONSUMER_PROC_H
#define NATS_CONSUMER_PROC_H

#include <stdatomic.h>

/**
 * Process entry point of the dedicated JetStream pull consumer process.
 * Matches the `mod_proc` signature expected by OpenSIPS' proc_export_t.
 *
 * @param rank  Rank assigned by the core at fork time; logged only.
 * @return      Never returns in normal operation (infinite main loop);
 *              the core treats return-from-main as an exiting child and
 *              reaps the process.
 *
 * Publishes its pt[] index to the SHM heartbeat block as its first act,
 * then retries nats_pool_get() until a broker connection + jsCtx exist.
 * All process-local allocations (proc_sub_state_t, msg-ref rows,
 * libnats objects) are libc-heap and owned by this process for its
 * lifetime.  Takes registry locks only transiently via the registry
 * API; the fetch / ack / reap phases run single-threaded.
 *
 * Context: called ONCE by the OpenSIPS core in the freshly-forked
 * consumer process (module_exports.procs).  Never call it elsewhere.
 */
void nats_consumer_proc_main(int rank);

/* Module-global Fetch tuning (definitions in nats_consumer.c).  Read
 * by the consumer process at every Fetch call; per-handle bind keys
 * (`fetch_batch=`, `fetch_timeout_ms=`) override these. */
extern int nats_consumer_fetch_batch;
extern int nats_consumer_fetch_timeout_ms;

/* Consumer-side poison-message cap (modparam `poison_max_deliver`, default
 * 0 = off).  When > 0, a delivered message whose NumDelivered exceeds it is
 * Termed by the consumer instead of being pushed to the worker ring, so a
 * permanently-failing message under max_deliver=0 cannot redeliver forever. */
extern int nats_consumer_poison_max_deliver;

/*
 * SHM-allocated heartbeat block.  The consumer process bumps tick
 * once per loop iteration and writes the current monotonic time
 * to last_tick_us.  A watchdog (MI handler, monitor module, external
 * exporter) compares (now - last_tick_us) against a staleness
 * threshold to detect a wedged or crashed consumer process.
 *
 * Allocated by mod_init (pre-fork) so all workers + the consumer
 * inherit the same SHM pointer.
 */
typedef struct nats_consumer_heartbeat {
	_Atomic unsigned long  tick;          /* monotonic loop counter */
	_Atomic long long      last_tick_us;  /* CLOCK_MONOTONIC microseconds */
	_Atomic int            consumer_pid;  /* pid of the consumer process */
	_Atomic int            consumer_proc_no; /* pt index, the
	                                          * ipc_send_rpc destination;
	                                          * -1 until the proc is up */
} nats_consumer_heartbeat_t;

extern nats_consumer_heartbeat_t *nats_consumer_hb;

/**
 * The consumer process's process-table index, published by the
 * proc itself as its first act.  Workers pass it to ipc_send_rpc for
 * the worker->consumer ack/RPC hops.
 *
 * @return  The consumer's pt[] index, or -1 while the proc is not (yet)
 *          up or the heartbeat block was never allocated -- senders
 *          fail fast with the usual capacity error.
 *
 * One acquire atomic load from the SHM heartbeat block; no allocation,
 * no locking.  Callable from any process (SIP workers on every ack /
 * async-RPC send, MI handlers).
 */
static inline int nats_consumer_proc_no(void)
{
	if (!nats_consumer_hb)
		return -1;
	return atomic_load_explicit(&nats_consumer_hb->consumer_proc_no,
		memory_order_acquire);
}

/**
 * Allocate and zero the SHM heartbeat block (nats_consumer_hb), with
 * consumer_proc_no seeded to -1 ("not up yet").
 *
 * @return  0 on success, -1 on shared-memory allocation failure.
 *
 * The block is shm_malloc'd and freed by nats_consumer_hb_destroy().
 * No locking.  Context: mod_init (main process, pre-fork) ONLY, so all
 * children inherit the same SHM pointer.
 */
int nats_consumer_hb_init(void);

/**
 * Free the SHM heartbeat block; idempotent (NULL-safe).
 *
 * @return  nothing.
 *
 * shm_free's the block allocated by nats_consumer_hb_init() and NULLs
 * the global.  No locking.  Context: mod_destroy (attendant, after the
 * children are gone).
 */
void nats_consumer_hb_destroy(void);

#ifdef UNIT_TESTS
/* the unit test suite's hold on the consumer process (see
 * nats_consumer_proc_internal.h); called from mod_init */
int nc_ut_hold_init(void);
#endif

#endif /* NATS_CONSUMER_PROC_H */
