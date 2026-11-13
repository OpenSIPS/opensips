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
 * Unit tests of the nats module ("make test-nats").  The suite's
 * opensips.cfg loads nats.so alone: no module registers with the pool,
 * so libnats is not loaded and no connection is attempted.
 */

#include <tap.h>

#include "nats_ut.h"

void mod_tests(void)
{
	/* first: the library is not loaded yet, and is left unloaded */
	nats_ut_nats_dl();
	nats_ut_drain_merge();
	nats_ut_epoch_wrapper();
	nats_ut_err_text();
	nats_ut_js_opts_policy();
	nats_ut_js_retry_policy();
	nats_ut_key_redaction();
	nats_ut_nats_auth();
	nats_ut_nats_bind();
	nats_ut_nats_ca_dir();
	nats_ut_nats_rank();
	nats_ut_pool_auth_opts();
	nats_ut_pool_connect();
	nats_ut_pool_connect_opts();
	nats_ut_pool_fork();
	nats_ut_pool_js_ack();
	nats_ut_pool_kv_cache();
	nats_ut_pool_merge();
	nats_ut_pool_refcount();
	nats_ut_redact_url();
	nats_ut_rl();
	nats_ut_server_info_redact();
	nats_ut_shared_params();
	nats_ut_srv_order();
	nats_ut_unsafe_log_clamp();
	nats_ut_url_scheme();
	nats_ut_validate_modes();
	nats_ut_validate_publish_subject();
	nats_ut_validate_subject_cache();
}
