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
 * nats_api_types.h -- struct nats_binds, the API of the nats module
 * (nats.so).  Light: libnats and the nats module headers only, so module
 * headers that unit tests share with their test shims can include it
 * (through nats_bind.h).  Bind it with load_nats_api() (nats_api.h).
 */

#ifndef NATS_API_TYPES_H
#define NATS_API_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <nats/nats.h>

#include "nats_dl.h"
#include "nats_validate.h"

struct nats_binds {
	/* the libnats function table, filled by nats.so (nats_dl.h) */
	nats_dl_funcs_t *dl;

	/* connection pool (nats_pool.h) */
	int (*pool_register)(const char *url, const char *module,
		int reconnect_wait, int max_reconnect);
	int (*pool_register_default)(const char *url, const char *module,
		int reconnect_wait, int max_reconnect);
	void (*pool_unregister)(void);
	void (*pool_bind_tls)(const char *modname);
	natsConnection *(*pool_get)(void);
	jsCtx *(*pool_get_js)(void);
	kvStore *(*pool_get_kv)(const char *bucket, int replicas, int history,
		int64_t ttl_secs);
	int (*pool_is_connected)(void);
	int (*pool_get_reconnect_epoch)(void);
	int (*pool_has_servers)(void);
	int (*pool_is_registered)(void);
	int (*pool_should_init)(int rank);
	const char *(*pool_get_server_info)(void);
	void (*pool_set_pub_ack_cb)(void (*cb)(int outcome));
	int (*pool_bucket_maxage_ns)(const char *bucket, int64_t *out_ns);
	int (*pool_bucket_mmps)(const char *bucket, int64_t *out_mmps);
	int (*pool_auth_configured)(void);

	/* tunables of the shared connection, read by the modules */
	int *js_ack_timeout_ms;
	int *js_publish_retries;
	int *kv_op_timeout_ms;
	int *drain_timeout_ms;
	int *no_randomize;

	/* Apply a setting of the shared connection given to another module
	 * (no_randomize, reconnect_buf_size, drain_timeout_ms, user,
	 * password, token, creds_file, nkey, nkey_seed_file,
	 * kv_op_timeout_ms, js_ack_timeout_ms, js_publish_retries), with the
	 * same rules as the nats module parameter.  `type` is a modparam_t.
	 * Returns 0 or -1. */
	int (*set_param)(const char *name, unsigned int type, void *val);

	/* stateless helpers compiled into nats.so */
	void (*redact_url)(const char *url, char *out, size_t out_sz);
	void (*redact_key)(const char *key, char *out, size_t out_sz);
	int (*validate_publish_subject)(const char *s, int len);
	int (*validate)(const char *s, int len, nats_validate_mode_t mode);
};

typedef int (*load_nats_f)(struct nats_binds *binds);

#endif /* NATS_API_TYPES_H */
