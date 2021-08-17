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

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../locking.h"
#include "../../pt.h"
#include "../../net/tcp_conn_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../tls_mgm/tls_helper.h"

#include "wolfssl.h"
#include "wolfssl_api.h"

static int load_tls_wolfssl(struct wolfssl_binds *binds);

static int mod_init(void);
static void mod_destroy(void);

int _wolfssl_tls_conn_init(struct tcp_connection* c, struct tls_domain *tls_dom);
void _wolfssl_tls_conn_clean(struct tcp_connection *c,
	struct tls_domain **tls_dom);
int _wolfssl_tls_update_fd(struct tcp_connection *c, int fd);
int _wolfssl_tls_async_connect(struct tcp_connection *con, int fd,
	int timeout, trace_dest t_dst);
int _wolfssl_tls_write(struct tcp_connection *c, int fd, const void *buf,
	size_t len, short *poll_events);
int _wolfssl_tls_blocking_write(struct tcp_connection *c, int fd,
	const char *buf, size_t len, int handshake_timeout, int send_timeout,
	trace_dest t_dst);
int _wolfssl_tls_fix_read_conn(struct tcp_connection *c, int fd,
	int async_timeout, trace_dest t_dst, int lock);
int _wolfssl_tls_read(struct tcp_connection * c,struct tcp_req *r);
int _wolfssl_tls_conn_extra_match(struct tcp_connection *c, void *id);

int _wolfssl_init_tls_dom(struct tls_domain *d, int init_flags);
void _wolfssl_destroy_tls_dom(struct tls_domain *tls_dom);
int _wolfssl_load_priv_key(struct tls_domain *tls_dom, int from_file);
int _wolfssl_reg_sni_cb(tls_sni_cb_f cb);
int _wolfssl_switch_ssl_ctx(struct tls_domain *dom, void *ssl_ctx);

int _wolfssl_tls_var_comp(int ind, void *ssl, str *res);
int _wolfssl_tls_var_version(void *ssl, str *res);
int _wolfssl_tls_var_desc(void *ssl, str *res);
int _wolfssl_tls_var_cipher(void *ssl, str *res);
int _wolfssl_tls_var_bits(void *ssl, str *str_res, int *int_res);
int _wolfssl_tls_var_cert_vers(int ind, void *ssl, str *res);
int _wolfssl_tls_var_sn(int ind, void *ssl, str *str_res, int *int_res);
int _wolfssl_tls_var_alt(int ind, void *ssl, str *res);
int _wolfssl_tls_var_check_cert(int ind, void *ssl, str *str_res, int *int_res);
int _wolfssl_tls_var_validity(int ind, void *ssl, str *res);

_wolfssl_method_f ssl_methods[SSL_VERSIONS_SIZE];

static cmd_export_t cmds[] = {
	{"load_tls_wolfssl", (cmd_function)load_tls_wolfssl,
		{{0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports = {
	"tls_wolfssl",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	0,          /* OpenSIPS module dependencies */
	cmds,          /* exported functions */
	0,          /* exported async functions */
	0,          /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static void _wolfssl_init_ssl_methods(void)
{
	ssl_methods[TLS_USE_SSLv23-1] = wolfSSLv23_method;
	ssl_methods[TLS_USE_TLSv1-1] = wolfTLSv1_method;
	ssl_methods[TLS_USE_TLSv1_2-1] = wolfTLSv1_2_method;
	ssl_methods[TLS_USE_TLSv1_3-1] = wolfTLSv1_3_method;
}

static void *oss_malloc(size_t size)
{
	return shm_malloc(size);
}

static void oss_free(void *ptr)
{
	return shm_free(ptr);
}

static void *oss_realloc(void *ptr, size_t size)
{
	return shm_realloc(ptr, size);
}

static int mod_init(void)
{
	LM_INFO("initializing tls_wolfssl module\n");
	LM_INFO("wolfSSL version: %s\n", wolfSSL_lib_version());

	wolfSSL_SetAllocators(oss_malloc, oss_free, oss_realloc);
	wolfSSL_Init();

	_wolfssl_init_ssl_methods();

	return 0;
}

static void mod_destroy(void)
{
	LM_INFO("destroying tls_wolfssl module\n");

	wolfSSL_Cleanup();
}

int _wolfssl_has_session_ticket(WOLFSSL *ssl)
{
	static unsigned char buf[1024];
	unsigned int len = 1024;

	if (wolfSSL_get_SessionTicket(ssl, buf, &len) != SSL_SUCCESS)
		return 0;

	return len ? 1 : 0;
}

static int _wolfssl_is_peer_verified(void *ssl)
{
	long ssl_verify;
	WOLFSSL_X509 *x509_cert;
	int verify_mode;
	int peer_ok;

	ssl_verify = wolfSSL_get_verify_result(_WOLFSSL_READ_SSL(ssl));
	if ( ssl_verify != X509_V_OK ) {
		LM_INFO("verification of presented certificate failed... return -1\n");
		return -1;
	}

	/* now, we have only valid peer certificates or peers without certificates.
	 * Thus we have to check for the existence of a peer certificate
	 */
	x509_cert = wolfSSL_get_peer_certificate(_WOLFSSL_READ_SSL(ssl));
	if ( x509_cert == NULL ) {
		peer_ok = 0;

		/* if a session ticket is used, we cannot retrieve the peer cert but
		 * we might be able to determine if the peer did present one initailly
		 * and it has been verified */
		if (_wolfssl_has_session_ticket(_WOLFSSL_READ_SSL(ssl))) {
			verify_mode = wolfSSL_get_verify_mode(_WOLFSSL_READ_SSL(ssl));

			if (wolfSSL_GetSide(_WOLFSSL_READ_SSL(ssl)) == WOLFSSL_SERVER_END) {
				if ((verify_mode & SSL_VERIFY_PEER) &&
					(verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
					peer_ok = 1;
			} else {
				if (verify_mode & SSL_VERIFY_PEER)
					peer_ok = 1;
			}
		}

		if (!peer_ok) {
			LM_INFO("peer did not presented "
					"a certificate. Thus it could not be verified... return -1\n");
			return -1;
		}
	}

	wolfSSL_X509_free(x509_cert);

	LM_DBG("peer is successfully verified... done\n");
	return 0;
}

static int load_tls_wolfssl(struct wolfssl_binds *binds)
{
	binds->tls_conn_init = _wolfssl_tls_conn_init;
	binds->tls_conn_clean = _wolfssl_tls_conn_clean;
	binds->tls_update_fd = _wolfssl_tls_update_fd;
	binds->tls_async_connect = _wolfssl_tls_async_connect;
	binds->tls_write = _wolfssl_tls_write;
	binds->tls_blocking_write = _wolfssl_tls_blocking_write;
	binds->tls_fix_read_conn = _wolfssl_tls_fix_read_conn;
	binds->tls_read = _wolfssl_tls_read;
	binds->tls_conn_extra_match = _wolfssl_tls_conn_extra_match;

	binds->init_tls_dom = _wolfssl_init_tls_dom;
	binds->destroy_tls_dom = _wolfssl_destroy_tls_dom;
	binds->load_priv_key = _wolfssl_load_priv_key;
	binds->reg_tls_sni_cb = _wolfssl_reg_sni_cb;
	binds->switch_ssl_ctx = _wolfssl_switch_ssl_ctx;

	binds->is_peer_verified = _wolfssl_is_peer_verified;

	binds->get_tls_var_version = _wolfssl_tls_var_version;
	binds->get_tls_var_desc = _wolfssl_tls_var_desc;
	binds->get_tls_var_cipher = _wolfssl_tls_var_cipher;
	binds->get_tls_var_bits = _wolfssl_tls_var_bits;
	binds->get_tls_var_cert_vers = _wolfssl_tls_var_cert_vers;
	binds->get_tls_var_sn = _wolfssl_tls_var_sn;
	binds->get_tls_var_comp = _wolfssl_tls_var_comp;
	binds->get_tls_var_alt = _wolfssl_tls_var_alt;
	binds->get_tls_var_check_cert = _wolfssl_tls_var_check_cert;
	binds->get_tls_var_validity = _wolfssl_tls_var_validity;

	return 1;
}
