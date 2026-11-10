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
 * nats_mi.h -- MI command declarations for the nats_consumer registry.
 *
 * Shared contract (every handler below):
 *
 * @param params  MI arguments; owned by the MI core, read-only here.
 * @param async   asynchronous-MI handle; unused (all these commands
 *                answer synchronously) and may be NULL.
 * @return        a pkg-allocated mi_response_t (init_mi_result_object /
 *                init_mi_error); ownership transfers to the MI core,
 *                which serializes and frees it (free_mi_response).
 *                NULL = allocation failure (the core answers 500).
 *
 * Process/locking context: callable from whichever process runs the MI
 * core (attendant / MI process).  Safe there by construction: the
 * handle registry, SHM rings, ack/RPC IPC queues and the slot pool are
 * allocated pre-fork in SHM, per-handle counters are C11 atomics, and
 * registry mutations below take the registry lock.  No broker I/O is
 * performed by any of these handlers.
 */

#ifndef NATS_MI_H
#define NATS_MI_H

#include "../../mi/item.h"
#include "../../mi/mi.h"

/* Bind a new consumer handle (stream/consumer/subject bind-string in
 * params); mutates the SHM registry under its lock.  Errors: parse
 * failure or a full registry. */
mi_response_t *mi_consumer_bind(const mi_params_t *params,
		struct mi_handler *async);

/* Unbind by handle id; idempotent (unknown id = MI error, no change). */
mi_response_t *mi_consumer_unbind(const mi_params_t *params,
		struct mi_handler *async);

/* Per-handle listing: bind config + lifetime counters + ring gauges.
 * Read-only snapshot; counters may move while serializing. */
mi_response_t *mi_consumer_list(const mi_params_t *params,
		struct mi_handler *async);

/* One flat object of cross-handle aggregates (rings, ack/RPC IPC,
 * slot pool) for back-pressure monitoring; documented field-by-field
 * in README.md.  Read-only. */
mi_response_t *mi_consumer_stats(const mi_params_t *params,
		struct mi_handler *async);

/* Consumer-process liveness snapshot (tick age + stale verdict) for
 * external watchdogs.  Read-only. */
mi_response_t *mi_consumer_health(const mi_params_t *params,
		struct mi_handler *async);

extern const mi_export_t nats_consumer_mi_cmds[];

#endif /* NATS_MI_H */
