/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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

/*
 * nats_jetstream.h — JetStream Management MI Commands
 *
 * Module:  event_nats
 *
 * MI commands for JetStream cluster administration:
 *   nats_account_info      — account stats (memory, storage, streams, consumers)
 *   nats_stream_list       — list all streams
 *   nats_stream_info       — detailed stream metadata
 *   nats_stream_create     — create a new stream
 *   nats_stream_delete     — delete a stream
 *   nats_stream_purge      — purge all messages in a stream
 *   nats_consumer_list     — list consumers for a stream
 *   nats_consumer_info     — detailed consumer metadata
 *   nats_consumer_create   — create a consumer
 *   nats_consumer_delete   — delete a consumer
 *   nats_msg_get           — get a message by sequence number
 *   nats_msg_delete        — delete a message by sequence number
 */

#ifndef NATS_JETSTREAM_H
#define NATS_JETSTREAM_H

#include "../../mi/mi.h"

/*
 * Shared contract (every handler below):
 *
 * @param params     MI arguments (stream/consumer names, sequence
 *                   numbers); owned by the MI core, read-only here.
 *                   Names are validated before any broker call.
 * @param async_hdl  asynchronous-MI handle; unused (all commands
 *                   answer synchronously) and may be NULL.
 * @return           a pkg-allocated mi_response_t; ownership transfers
 *                   to the MI core, which serializes and frees it
 *                   (free_mi_response).  NULL = allocation failure.
 *
 * Process/locking context: callable from whichever process runs the MI
 * core.  Unlike the registry MI, every handler here performs
 * SYNCHRONOUS broker I/O on the calling process' pool connection
 * (jsOpts.Wait-bounded) -- the MI call blocks for up to that timeout,
 * and broker-side errors come back as MI errors with the libnats
 * status text.  The mutating commands (create/delete/purge) are
 * cluster-administration surfaces: deletes and purges are permanent
 * and take effect broker-side immediately.
 */

/* Account info */
mi_response_t *mi_nats_account_info(const mi_params_t *params,
    struct mi_handler *async_hdl);

/* Stream management (mutating admin only -- the read-only
 * nats_stream_list/info MI commands are owned by cachedb_nats) */
mi_response_t *mi_nats_stream_create(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_stream_delete(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_stream_purge(const mi_params_t *params,
    struct mi_handler *async_hdl);

/* Consumer management */
mi_response_t *mi_nats_consumer_list(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_consumer_info(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_consumer_create(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_consumer_delete(const mi_params_t *params,
    struct mi_handler *async_hdl);

/* Message operations */
mi_response_t *mi_nats_msg_get(const mi_params_t *params,
    struct mi_handler *async_hdl);

mi_response_t *mi_nats_msg_delete(const mi_params_t *params,
    struct mi_handler *async_hdl);

#endif /* NATS_JETSTREAM_H */
