/*
 * Copyright (C) 2021 - OpenSIPS Foundation
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 *
 */

#ifndef TLS_LIB_API_H
#define TLS_LIB_API_H

#include "../../net/tcp_conn_defs.h"
#include "../../trace_api.h"
#include "tls_helper.h"

/* TLS library specific conn ops */
typedef int (*tls_lib_conn_init_f)(struct tcp_connection *c,
	struct tls_domain *tls_dom);
typedef void (*tls_lib_conn_clean_f)(struct tcp_connection* c,
	struct tls_domain **tls_dom);
typedef int (*tls_lib_update_fd_f)(struct tcp_connection* c, int fd);
typedef int (*tls_lib_async_connect_f)(struct tcp_connection *con, int fd,
	int timeout, trace_dest t_dst);
typedef int (*tls_lib_write_f)(struct tcp_connection *c, int fd, const void *buf,
	size_t len, short *poll_events);
typedef int (*tls_lib_blocking_write_f)(struct tcp_connection *c, int fd,
	const char *buf, size_t len, int handshake_timeout, int send_timeout,
	trace_dest t_dst);
typedef int (*tls_lib_fix_read_conn_f)(struct tcp_connection *c, int fd,
	int async_timeout, trace_dest t_dst, int lock);
typedef int (*tls_lib_read_f)(struct tcp_connection * c,struct tcp_req *r);
typedef int (*tls_lib_conn_extra_match_f)(struct tcp_connection *c, void *id);

typedef int (*init_tls_dom_f)(struct tls_domain *tls_dom, int init_flags);
typedef void (*destroy_tls_dom_f)(struct tls_domain *tls_dom);
typedef int (*load_priv_key_f)(struct tls_domain *tls_dom, int from_file);

typedef int (*tls_sni_cb_f)(struct tls_domain *dom, struct tcp_connection *c,
	void *ssl_ctx, char *servername);
typedef int (*reg_tls_sni_cb_f)(tls_sni_cb_f cb);
typedef int (*switch_ssl_ctx_f)(struct tls_domain *dom, void *ssl_ctx);

typedef int (*is_peer_verified_f)(void *ssl);

typedef int (*get_tls_var_version_f)(void *ssl, str *res);
typedef int (*get_tls_var_desc_f)(void *ssl, str *res);
typedef int (*get_tls_var_cipher_f)(void *ssl, str *res);
typedef int (*get_tls_var_bits_f)(void *ssl, str *str_res, int *int_res);
typedef int (*get_tls_var_cert_vers_f)(int ind, void *ssl, str *res);
typedef int (*get_tls_var_sn_f)(int ind, void *ssl, str *str_res, int *int_res);
typedef int (*get_tls_var_comp_f)(int ind, void *ssl, str *res);
typedef int (*get_tls_var_alt_f)(int ind, void *ssl, str *res);
typedef int (*get_tls_var_check_cert_f)(int ind, void *ssl,
	str *str_res, int *int_res);
typedef int (*get_tls_var_validity_f)(int ind, void *ssl, str *res);

/* init flags for init_tls_dom_f */
#define TLS_DOM_CERT_FILE_FL (1<<0)
#define TLS_DOM_CA_FILE_FL   (1<<1)
#define TLS_DOM_DH_FILE_FL   (1<<2)

#define TLS_LIB_API_BINDS \
	tls_lib_conn_init_f tls_conn_init; \
	tls_lib_conn_clean_f tls_conn_clean; \
	tls_lib_update_fd_f tls_update_fd; \
	tls_lib_async_connect_f tls_async_connect; \
	tls_lib_write_f tls_write; \
	tls_lib_blocking_write_f tls_blocking_write; \
	tls_lib_fix_read_conn_f tls_fix_read_conn; \
	tls_lib_read_f tls_read; \
	tls_lib_conn_extra_match_f tls_conn_extra_match; \
	init_tls_dom_f init_tls_dom; \
	destroy_tls_dom_f destroy_tls_dom; \
	load_priv_key_f load_priv_key; \
	reg_tls_sni_cb_f reg_tls_sni_cb; \
	switch_ssl_ctx_f switch_ssl_ctx; \
	is_peer_verified_f is_peer_verified; \
	get_tls_var_version_f get_tls_var_version; \
	get_tls_var_desc_f get_tls_var_desc; \
	get_tls_var_cipher_f get_tls_var_cipher; \
	get_tls_var_bits_f get_tls_var_bits; \
	get_tls_var_cert_vers_f get_tls_var_cert_vers; \
	get_tls_var_sn_f get_tls_var_sn; \
	get_tls_var_comp_f get_tls_var_comp; \
	get_tls_var_alt_f get_tls_var_alt; \
	get_tls_var_check_cert_f get_tls_var_check_cert; \
	get_tls_var_validity_f get_tls_var_validity; \

#endif	/* TLS_LIB_API_H */
