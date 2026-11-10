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
 * nats_bind.h -- for the sources of a module that uses the nats module
 * (event_nats, cachedb_nats, cachedb_nats_fts, nats_consumer): the pool
 * and libnats names (nats_pool_get(), nats_dl.<fn>, nats_redact_url(),
 * ...) resolve to the API bound into `nats_api` (nats_api_types.h).
 *
 * Include it before any other header of ../nats/: the inline helpers of
 * those headers then call through the API too.  It is light (no core
 * headers), so a module header shared with a unit-test shim can include
 * it.  The module's main file includes nats_bind_mod.h instead, which
 * defines the binding step.
 */

#ifndef NATS_BIND_H
#define NATS_BIND_H

#include "nats_api_types.h"

extern struct nats_binds nats_api;

#define nats_dl                                  (*nats_api.dl)
#define nats_pool_register                       nats_api.pool_register
#define nats_pool_register_default               nats_api.pool_register_default
#define nats_pool_unregister                     nats_api.pool_unregister
#define nats_pool_bind_tls                       nats_api.pool_bind_tls
#define nats_pool_get                            nats_api.pool_get
#define nats_pool_get_js                         nats_api.pool_get_js
#define nats_pool_get_kv                         nats_api.pool_get_kv
#define nats_pool_is_connected                   nats_api.pool_is_connected
#define nats_pool_get_reconnect_epoch            nats_api.pool_get_reconnect_epoch
#define nats_pool_has_servers                    nats_api.pool_has_servers
#define nats_pool_is_registered                  nats_api.pool_is_registered
#define nats_pool_should_init                    nats_api.pool_should_init
#define nats_pool_get_server_info                nats_api.pool_get_server_info
#define nats_pool_set_pub_ack_cb                 nats_api.pool_set_pub_ack_cb
#define nats_pool_bucket_maxage_ns               nats_api.pool_bucket_maxage_ns
#define nats_pool_bucket_mmps                    nats_api.pool_bucket_mmps
#define nats_pool_auth_configured                nats_api.pool_auth_configured
#define nats_pool_js_ack_timeout_ms              (*nats_api.js_ack_timeout_ms)
#define nats_pool_js_publish_retries             (*nats_api.js_publish_retries)
#define nats_pool_kv_op_timeout_ms               (*nats_api.kv_op_timeout_ms)
#define nats_pool_drain_timeout_ms               (*nats_api.drain_timeout_ms)
#define nats_pool_no_randomize                   (*nats_api.no_randomize)
#define nats_redact_url                          nats_api.redact_url
#define nats_redact_key                          nats_api.redact_key
#define nats_validate_publish_subject            nats_api.validate_publish_subject
#define nats_validate                            nats_api.validate

/* the headers below then declare types and inline helpers only */
#define NATS_POOL_NO_PROTOTYPES
#include "nats_pool.h"
#include "nats_redact.h"
#include "nats_validate.h"

#endif /* NATS_BIND_H */
