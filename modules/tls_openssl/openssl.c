/*
 * Copyright (C) 2021 - OpenSIPS Solutions
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

#ifdef __OS_linux
#define _GNU_SOURCE /* we need this for gettid() */
#endif

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../locking.h"
#include "../../pt.h"
#include "../../net/tcp_conn_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"

#include "openssl_helpers.h"
#include "openssl_api.h"

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && defined __OS_linux)
#include <features.h>
#if defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 2)
#define __OPENSSL_ON_EXIT
#endif
#endif
#endif

static int load_tls_openssl(struct openssl_binds *binds);

static int  mod_load(void);
static int mod_init(void);
static void mod_destroy(void);

/* openssl conn ops */
int openssl_tls_conn_init(struct tcp_connection* c, struct tls_domain *tls_dom);
void openssl_tls_conn_clean(struct tcp_connection *c,
	struct tls_domain **tls_dom);
int openssl_tls_update_fd(struct tcp_connection *c, int fd);
int openssl_tls_async_connect(struct tcp_connection *con, int fd,
	int timeout, trace_dest t_dst);
int openssl_tls_write(struct tcp_connection *c, int fd, const void *buf,
	size_t len, short *poll_events);
int openssl_tls_blocking_write(struct tcp_connection *c, int fd,
	const char *buf, size_t len, int handshake_timeout, int send_timeout,
	trace_dest t_dst);
int openssl_tls_fix_read_conn(struct tcp_connection *c, int fd,
	int async_timeout, trace_dest t_dst, int lock);
int openssl_tls_read(struct tcp_connection * c,struct tcp_req *r);
int openssl_tls_conn_extra_match(struct tcp_connection *c, void *id);

int openssl_init_tls_dom(struct tls_domain *d, int init_flags);
void openssl_destroy_tls_dom(struct tls_domain *tls_dom);
int openssl_load_priv_key(struct tls_domain *tls_dom, int from_file);
int openssl_reg_sni_cb(tls_sni_cb_f cb);
int openssl_switch_ssl_ctx(struct tls_domain *dom, void *ssl_ctx);

int openssl_tls_var_comp(int ind, void *ssl, str *res);
int openssl_tls_var_version(void *ssl, str *res);
int openssl_tls_var_desc(void *ssl, str *res);
int openssl_tls_var_cipher(void *ssl, str *res);
int openssl_tls_var_bits(void *ssl, str *str_res, int *int_res);
int openssl_tls_var_cert_vers(int ind, void *ssl, str *res);
int openssl_tls_var_sn(int ind, void *ssl, str *str_res, int *int_res);
int openssl_tls_var_alt(int ind, void *ssl, str *res);
int openssl_tls_var_check_cert(int ind, void *ssl, str *str_res, int *int_res);
int openssl_tls_var_validity(int ind, void *ssl, str *res);

void tls_ctx_set_cert_store(void *ctx, void *src_ctx);
int tls_ctx_set_cert_chain(void *ctx, void *src_ctx);
int tls_ctx_set_pkey_file(void *ctx, char *pkey_file);

#ifndef NO_SSL_GLOBAL_LOCK
gen_lock_t *tls_global_lock;
#endif

static cmd_export_t cmds[] = {
	{"load_tls_openssl", (cmd_function)load_tls_openssl,
		{{0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports = {
	"tls_openssl",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	mod_load,	/* load function */
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

static int mod_load(void)
{
	/*
	 * this has to be called before any function calling CRYPTO_malloc,
	 * CRYPTO_malloc will set allow_customize in openssl to 0
	 */

	LM_INFO("openssl version: %s\n", SSLeay_version(SSLEAY_VERSION));
	if (!CRYPTO_set_mem_functions(os_malloc, os_realloc, os_free)) {
		LM_ERR("unable to set the memory allocation functions\n");
		LM_ERR("NOTE: please make sure you are loading tls_mgm module at the"
			"very beginning of your script, before any other module!\n");
		return -1;
	}

	return 0;
}

#ifdef __OPENSSL_ON_EXIT
/* This is used to exit _without_ running the remaining onexit callbacks,
 * we do this because openssl 1.1.x does not properly support multi-process
 * applications, and it tries to release an existing connection from each
 * process, resulting in multiple frees of the same chunk.
 *
 * We are sure that this callback is called _before_ the openssl onexit()
 * because glibc guarantees that the callbacks are called in the reversed
 * order they are armed, and since we are only registering this function in
 * the child init code, we are the last ones that register it.
 */
static void openssl_on_exit(int status, void *param)
{
	_exit(status);
}
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int check_for_krb(void)
{
	SSL_CTX *xx;

	int j;

	xx = SSL_CTX_new(ssl_methods[TLS_USE_SSLv23 - 1]);
	if (xx==NULL)
		return -1;

	for( j=0 ; j<sk_SSL_CIPHER_num(xx->cipher_list) ; j++) {
		SSL_CIPHER *yy = sk_SSL_CIPHER_value(xx->cipher_list,j);
		if ( yy->id>=SSL3_CK_KRB5_DES_64_CBC_SHA &&
			yy->id<=SSL3_CK_KRB5_RC4_40_MD5 ) {
			LM_INFO("KRB5 cipher %s found\n", yy->name);
			SSL_CTX_free(xx);
			return 1;
		}
	}

	SSL_CTX_free(xx);
	return 0;
}
#endif

/*
 * initialize ssl methods
 */
static void
init_ssl_methods(void)
{

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ssl_methods[TLS_USE_TLSv1-1] = (SSL_METHOD*)TLSv1_method();
	ssl_methods[TLS_USE_SSLv23-1] = (SSL_METHOD*)SSLv23_method();

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	ssl_methods[TLS_USE_TLSv1_2-1] = (SSL_METHOD*)TLSv1_2_method();
#endif
#else
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	ssl_versions[TLS_USE_TLSv1_3-1] = TLS1_3_VERSION;
#endif
	ssl_versions[TLS_USE_TLSv1_2-1] = TLS1_2_VERSION;
	ssl_versions[TLS_USE_TLSv1-1] = TLS1_VERSION;
#endif
}

static int mod_init(void)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	int n;
#endif

	LM_INFO("initializing openssl module\n");

#if !defined(OPENSSL_NO_COMP)
	STACK_OF(SSL_COMP)* comp_methods;
	/* disabling compression */
	LM_INFO("disabling compression due ZLIB problems\n");
	comp_methods = SSL_COMP_get_compression_methods();
	if (comp_methods==0) {
		LM_INFO("openssl compression already disabled\n");
	} else {
		sk_SSL_COMP_zero(comp_methods);
	}
#endif
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	if (tls_init_multithread() < 0) {
		LM_ERR("failed to init multi-threading support\n");
		return -1;
	}
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	SSL_library_init();
	SSL_load_error_strings();
#else
	OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT
#if (OPENSSL_VERSION_NUMBER >= 0x1010102fL)
			|OPENSSL_INIT_NO_ATEXIT
#endif
			, NULL);
#endif

#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock = lock_alloc();
	if (!tls_global_lock || !lock_init(tls_global_lock)) {
		LM_ERR("could not initialize global openssl lock!\n");
		return -1;
	}
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	ssl_lock = lock_alloc();
	if (!ssl_lock || !lock_init(ssl_lock)) {
		LM_ERR("could not initialize ssl lock!\n");
		return -1;
	}
	os_ssl_method = RAND_get_rand_method();
	if (!os_ssl_method) {
		LM_ERR("could not get the default ssl rand method!\n");
		return -1;
	}
	RAND_set_rand_method(&opensips_ssl_method);
#endif

	init_ssl_methods();

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	n = check_for_krb();
	if (n==-1) {
		LM_ERR("kerberos check failed\n");
		return -1;
	}

	if ( ( n ^
#ifndef OPENSSL_NO_KRB5
			1
#else
			0
#endif
		 )!=0 ) {
		LM_ERR("compiled agaist an openssl with %s"
				"kerberos, but run with one with %skerberos\n",
				(n!=1)?"":"no ",(n!=1)?"no ":"");
		return -1;
	}
#endif

#ifdef __OPENSSL_ON_EXIT
	on_exit(openssl_on_exit, NULL);
#endif

	return 0;
}

static void mod_destroy(void)
{
	LM_INFO("destroying openssl module\n");

	/* TODO - destroy static locks */

	/* library destroy */
	ERR_free_strings();
	/*SSL_free_comp_methods(); - this function is not on std. openssl*/
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return;

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_destroy(tls_global_lock);
	lock_dealloc(tls_global_lock);
	#endif
}

static int openssl_is_peer_verified(void *ssl)
{
	long ssl_verify;
	X509 *x509_cert;

	ssl_verify = SSL_get_verify_result((SSL *)ssl);
	if ( ssl_verify != X509_V_OK ) {
		LM_INFO("verification of presented certificate failed... return -1\n");
		return -1;
	}

	/* now, we have only valid peer certificates or peers without certificates.
	 * Thus we have to check for the existence of a peer certificate
	 */
	x509_cert = SSL_get_peer_certificate((SSL *)ssl);
	if ( x509_cert == NULL ) {
		LM_INFO("peer did not presented "
				"a certificate. Thus it could not be verified... return -1\n");
		return -1;
	}

	X509_free(x509_cert);

	LM_DBG("peer is successfully verified... done\n");
	return 0;
}

static int load_tls_openssl(struct openssl_binds *binds)
{
	binds->tls_conn_init = openssl_tls_conn_init;
	binds->tls_conn_clean = openssl_tls_conn_clean;
	binds->tls_update_fd = openssl_tls_update_fd;
	binds->tls_async_connect = openssl_tls_async_connect;
	binds->tls_write = openssl_tls_write;
	binds->tls_blocking_write = openssl_tls_blocking_write;
	binds->tls_fix_read_conn = openssl_tls_fix_read_conn;
	binds->tls_read = openssl_tls_read;
	binds->tls_conn_extra_match = openssl_tls_conn_extra_match;

	binds->init_tls_dom = openssl_init_tls_dom;
	binds->destroy_tls_dom = openssl_destroy_tls_dom;
	binds->load_priv_key = openssl_load_priv_key;
	binds->reg_tls_sni_cb = openssl_reg_sni_cb;
	binds->switch_ssl_ctx = openssl_switch_ssl_ctx;

	binds->is_peer_verified = openssl_is_peer_verified;

	binds->get_tls_var_version = openssl_tls_var_version;
	binds->get_tls_var_desc = openssl_tls_var_desc;
	binds->get_tls_var_cipher = openssl_tls_var_cipher;
	binds->get_tls_var_bits = openssl_tls_var_bits;
	binds->get_tls_var_cert_vers = openssl_tls_var_cert_vers;
	binds->get_tls_var_sn = openssl_tls_var_sn;
	binds->get_tls_var_comp = openssl_tls_var_comp;
	binds->get_tls_var_alt = openssl_tls_var_alt;
	binds->get_tls_var_check_cert = openssl_tls_var_check_cert;
	binds->get_tls_var_validity = openssl_tls_var_validity;

	binds->ctx_set_cert_store = tls_ctx_set_cert_store;
	binds->ctx_set_cert_chain = tls_ctx_set_cert_chain;
	binds->ctx_set_pkey_file = tls_ctx_set_pkey_file;

	return 1;
}
