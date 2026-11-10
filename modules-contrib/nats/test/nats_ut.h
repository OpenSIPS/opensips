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
 * Unit test suite of the nats module: one entry point per test file,
 * all run from mod_tests() (test.c).
 */

#ifndef NATS_UT_H
#define NATS_UT_H

void nats_ut_nats_dl(void);
void nats_ut_drain_merge(void);
void nats_ut_epoch_wrapper(void);
void nats_ut_err_text(void);
void nats_ut_js_opts_policy(void);
void nats_ut_js_retry_policy(void);
void nats_ut_key_redaction(void);
void nats_ut_nats_auth(void);
void nats_ut_nats_bind(void);
void nats_ut_nats_ca_dir(void);
void nats_ut_nats_rank(void);
void nats_ut_pool_auth_opts(void);
void nats_ut_pool_connect(void);
void nats_ut_pool_connect_opts(void);
void nats_ut_pool_fork(void);
void nats_ut_pool_js_ack(void);
void nats_ut_pool_kv_cache(void);
void nats_ut_pool_merge(void);
void nats_ut_pool_refcount(void);
void nats_ut_redact_url(void);
void nats_ut_rl(void);
void nats_ut_server_info_redact(void);
void nats_ut_shared_params(void);
void nats_ut_srv_order(void);
void nats_ut_unsafe_log_clamp(void);
void nats_ut_url_scheme(void);
void nats_ut_validate_modes(void);
void nats_ut_validate_publish_subject(void);
void nats_ut_validate_subject_cache(void);

#endif /* NATS_UT_H */
