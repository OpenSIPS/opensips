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
 */

/**
 * @file nats_rank.c
 * @brief OpenSIPS process-rank admission rule for NATS init.
 *
 * Placed in its own translation unit (rather than inlined in nats_pool.c)
 * so that unit tests can link it without dragging in the rest of the pool
 * and its OpenSIPS core dependencies (shm, logging, nats.c).  The function
 * is the single source of truth for the admission rule; both event_nats
 * and cachedb_nats call it from their mod_child_init.
 */

#include "../../sr_module.h"
#include "nats_pool.h"

int nats_pool_should_init(int rank)
{
	/*
	 * Ranks that must be able to PUBLISH to NATS:
	 *   - SIP workers (UDP + TCP, rank >= 1): route-driven events + KV ops.
	 *   - PROC_MODULE (HTTPD/MI): script/MI-driven publishes.
	 *   - PROC_TIMER: the OpenSIPS timer process raises a large class of
	 *     subscribable events SYNCHRONOUSLY in-process -- usrloc contact/AoR
	 *     EXPIRY (E_UL_CONTACT_EXPIRED ...), dialog timeouts, tm timers.
	 *     event_nats' raise callback runs in whatever process fires the
	 *     event, so without a connection here every timer-raised NATS
	 *     publish is dropped and mis-counted as a transient failure.  Many
	 *     of the module's headline events (registration/dialog lifecycle)
	 *     are timer-driven, so the timer MUST initialize.
	 * Everything else (attendant PROC_MAIN, PROC_TCP_MAIN, module-exported
	 * forks like the consumer/watcher procs) either does not raise events or
	 * has its own explicit initialization path.
	 */
	return (rank == PROC_MODULE || rank == PROC_TIMER || rank >= 1);
}
