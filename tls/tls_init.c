/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 * Copyright (C) 2006 enum.at
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
 
#include "tls_init.h"
#include "tls_config.h"
#include "../dprint.h"
#include "../mem/shm_mem.h"
#include "../tcp_init.h"
#include "../ut.h"
#include "tls_domain.h"

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

#define SER_SSL_SESS_ID ((unsigned char*)"opensips-tls-1.2.0")
#define SER_SSL_SESS_ID_LEN (sizeof(SER_SSL_SESS_ID)-1)


#if OPENSSL_VERSION_NUMBER < 0x00907000L
	#warning ""
	#warning "=============================================================="
	#warning "Your version of OpenSSL is < 0.9.7."
	#warning " Upgrade for better compatibility, features and security fixes!"
	#warning "============================================================="
	#warning ""
#endif

SSL_METHOD     *ssl_methods[TLS_USE_SSLv23 + 1];

#define VERIFY_DEPTH_S 3

/* This callback is called during each verification process, 
at each step during the chain of certificates (this function
is not the certificate_verification one!). */
int verify_callback(int pre_verify_ok, X509_STORE_CTX *ctx) {
	char buf[256];
	X509 *err_cert;
	int err, depth;

	depth = X509_STORE_CTX_get_error_depth(ctx);
	LM_NOTICE("depth = %d\n",depth);
	if ( depth > VERIFY_DEPTH_S ) {
		LM_NOTICE("cert chain too long ( depth > VERIFY_DEPTH_S)\n");
		pre_verify_ok=0;
	}
	
	if( pre_verify_ok ) {
		LM_NOTICE("preverify is good: verify return: %d\n", pre_verify_ok);
		return pre_verify_ok;
	}
	
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);	
	X509_NAME_oneline(X509_get_subject_name(err_cert),buf,sizeof buf);
	
	LM_NOTICE("subject = %s\n", buf);
	LM_NOTICE("verify error:num=%d:%s\n",
		err, X509_verify_cert_error_string(err));
	LM_NOTICE("error code is %d\n", ctx->error);
	
	switch (ctx->error) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
				buf,sizeof buf);
			LM_NOTICE("issuer= %s\n",buf);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		case X509_V_ERR_CERT_NOT_YET_VALID:
			LM_NOTICE("notBefore\n");
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		case X509_V_ERR_CERT_HAS_EXPIRED:
			LM_NOTICE("notAfter\n");
			break;
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			LM_NOTICE("unable to decrypt cert "
				"signature\n");
			break;
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			LM_NOTICE("unable to decode issuer "
				"public key\n");
			break;
		case X509_V_ERR_OUT_OF_MEM:
			LM_NOTICE("out of memory \n");
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			LM_NOTICE("Self signed certificate "
				"issue\n");
			break;
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			LM_NOTICE("certificate chain too long\n");
			break;
		case X509_V_ERR_INVALID_CA:
			LM_NOTICE("invalid CA\n");
			break;
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			LM_NOTICE("path length exceeded\n");
			break;
		case X509_V_ERR_INVALID_PURPOSE:
			LM_NOTICE("invalid purpose\n");
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
			LM_NOTICE("certificate untrusted\n");
			break;
		case X509_V_ERR_CERT_REJECTED:
			LM_NOTICE("certificate rejected\n");
			break;
		
		default:
			LM_NOTICE("something wrong with the cert"
				" ... error code is %d (check x509_vfy.h)\n", ctx->error);
			break;
	}
	
	LM_NOTICE("verify return:%d\n", pre_verify_ok);
	return(pre_verify_ok);
}


static int
passwd_cb(char *buf, int size, int rwflag, void *filename)
{
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	UI             *ui;
	const char     *prompt;
	
	ui = UI_new();
	if (ui == NULL)
		goto err;

	prompt = UI_construct_prompt(ui, "passphrase", filename);
	UI_add_input_string(ui, prompt, 0, buf, 0, size - 1);
	UI_process(ui);
	UI_free(ui);
	return strlen(buf);

err:
	LM_ERR("passwd_cb failed\n");
	if (ui)
		UI_free(ui);
	return 0;
	
#else
	if( des_read_pw_string(buf, size-1, "Enter Private Key password:", 0) ) {
		LM_ERR("passwd_cb failed\n");
		return 0;
	}
	return strlen( buf );
	
#endif
}


/*
 * Wrappers around SER shared memory functions
 * (which can be macros)
 */

static void    *
ser_malloc(size_t size)
{
	return shm_malloc(size);
}

static void    *
ser_realloc(void *ptr, size_t size)
{
	return shm_realloc(ptr, size);
}

static void
ser_free(void *ptr)
{
	shm_free(ptr);
}


int
tls_init(struct socket_info *si)
{
	LM_DBG("entered\n");
	
	/*
	 * reuse tcp initialization 
	 */
	if (tcp_init(si) < 0) {
		LM_ERR("failed to initialize TCP part\n");
		goto error;
	}

	si->proto = PROTO_TLS;
	return 0;

  error:
	if (si->socket != -1) {
		close(si->socket);
		si->socket = -1;
	}
	return -1;
}

/*
 * load a certificate from a file 
 * (certificate file can be a chain, starting by the user cert, 
 * and ending in the root CA; if not all needed certs are in this
 * file, they are looked up in the caFile or caPATH (see verify
 * function).
 */
static int
load_certificate(SSL_CTX * ctx, char *filename)
{
	LM_DBG("entered\n");
	if (!SSL_CTX_use_certificate_chain_file(ctx, filename)) {
		LM_ERR("unable to load certificate file '%s'\n",
			filename);
		return -1;
	}

	LM_DBG("'%s' successfuly loaded\n", filename);
	return 0;
}


#define NUM_RETRIES 3
/*
 * load a private key from a file 
 */
static int
load_private_key(SSL_CTX * ctx, char *filename)
{
	int idx, ret_pwd;
	LM_DBG("entered\n");
	
	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, filename);

	for(idx = 0, ret_pwd = 0; idx < NUM_RETRIES; idx++ ) {
		ret_pwd = SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM);
		if ( ret_pwd ) {
			break;
		} else {
			LM_ERR("unable to load private key file '%s'. \n"
				"Retry (%d left) (check password case)\n",
				filename, (NUM_RETRIES - idx -1) );
			continue;
		}
	}
	
	if( ! ret_pwd ) {
		LM_ERR("unable to load private key file '%s'\n",
			filename);
		return -1;
	}
	
	if (!SSL_CTX_check_private_key(ctx)) {
		LM_ERR("key '%s' does not match the public key of the certificate\n",
			filename);
		return -1;
	}
	
	LM_DBG("key '%s' successfuly loaded\n", filename);
	return 0;
}

/*  
 * Load a caList, to be used to verify the client's certificate.
 * The list is to be stored in a single file, containing all
 * the acceptable root certificates.
 */
static int
load_ca(SSL_CTX * ctx, char *filename)
{
	LM_DBG("Entered\n");
	if (!SSL_CTX_load_verify_locations(ctx, filename, 0)) {
		LM_ERR("unable to load ca '%s'\n", filename);
		return -1;
	}
	
	LM_DBG("CA '%s' successfuly loaded\n", filename);
	return 0;
}


/*
 * initialize ssl methods 
 */
static void
init_ssl_methods(void)
{
	LM_DBG("entered\n");
	ssl_methods[TLS_USE_SSLv2_cli - 1] = SSLv2_client_method();
	ssl_methods[TLS_USE_SSLv2_srv - 1] = SSLv2_server_method();
	ssl_methods[TLS_USE_SSLv2 - 1] = SSLv2_method();
	
	ssl_methods[TLS_USE_SSLv3_cli - 1] = SSLv3_client_method();
	ssl_methods[TLS_USE_SSLv3_srv - 1] = SSLv3_server_method();
	ssl_methods[TLS_USE_SSLv3 - 1] = SSLv3_method();
	
	ssl_methods[TLS_USE_TLSv1_cli - 1] = TLSv1_client_method();
	ssl_methods[TLS_USE_TLSv1_srv - 1] = TLSv1_server_method();
	ssl_methods[TLS_USE_TLSv1 - 1] = TLSv1_method();
	
	ssl_methods[TLS_USE_SSLv23_cli - 1] = SSLv23_client_method();
	ssl_methods[TLS_USE_SSLv23_srv - 1] = SSLv23_server_method();
	ssl_methods[TLS_USE_SSLv23 - 1] = SSLv23_method();
}


/*
 * Setup default SSL_CTX (and SSL * ) behavior:
 *     verification, cipherlist, acceptable versions, ...
 */
static int
init_ssl_ctx_behavior( struct tls_domain *d ) {
	int verify_mode;
	if( d->ciphers_list != 0 ) {
		if( SSL_CTX_set_cipher_list(d->ctx, d->ciphers_list) == 0 ) {
			LM_ERR("failure to set SSL context "
				"cipher list '%s'\n", d->ciphers_list);
			return -1;
		} else {
			LM_NOTICE("cipher list set to %s\n", d->ciphers_list);
		}
	} else {
		LM_DBG( "cipher list null ... setting default\n");
	}

	/* Set a bunch of options: 
	 *     do not accept SSLv2
	 *     no session resumption
	 *     choose cipher according to server's preference's*/

#if OPENSSL_VERSION_NUMBER >= 0x000907000
	SSL_CTX_set_options(d->ctx, 
		SSL_OP_ALL | SSL_OP_NO_SSLv2 |
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
		SSL_OP_CIPHER_SERVER_PREFERENCE);
#else
	SSL_CTX_set_options(d->ctx,
		SSL_OP_ALL | SSL_OP_NO_SSLv2 );
#endif

	/* Set verification procedure
	 * The verification can be made null with SSL_VERIFY_NONE, or 
	 * at least easier with SSL_VERIFY_CLIENT_ONCE instead of 
	 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
	 * For extra control, instead of 0, we can specify a callback function:
	 *           int (*verify_callback)(int, X509_STORE_CTX *)
	 * Also, depth 2 may be not enough in some scenarios ... though no need
	 * to increase it much further */

	if (d->type & TLS_DOMAIN_SRV) {
		/* Server mode:
		 * SSL_VERIFY_NONE
		 *   the server will not send a client certificate request to the 
		 *   client, so the client  will not send a certificate.
		 * SSL_VERIFY_PEER
		 *   the server sends a client certificate request to the client. 
		 *   The certificate returned (if any) is checked. If the verification 
		 *   process fails, the TLS/SSL handshake is immediately terminated 
		 *   with an alert message containing the reason for the verification 
		 *   failure. The behaviour can be controlled by the additional 
		 *   SSL_VERIFY_FAIL_IF_NO_PEER_CERT and SSL_VERIFY_CLIENT_ONCE flags.
		 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		 *   if the client did not return a certificate, the TLS/SSL handshake 
		 *   is immediately terminated with a ``handshake failure'' alert. 
		 *   This flag must be used together with SSL_VERIFY_PEER.
		 * SSL_VERIFY_CLIENT_ONCE
		 *   only request a client certificate on the initial TLS/SSL 
		 *   handshake. Do not ask for a client certificate again in case of 
		 *   a renegotiation. This flag must be used together with 
		 *   SSL_VERIFY_PEER.
		 */

		if( d->verify_cert ) {
			verify_mode = SSL_VERIFY_PEER;
			if( d->require_client_cert ) {
				LM_WARN("client verification activated. Client "
					"certificates are mandatory.\n");
				verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			} else
				LM_WARN("client verification activated. Client "
					"certificates are NOT mandatory.\n");
		} else {
			verify_mode = SSL_VERIFY_NONE;
			LM_WARN("client verification NOT activated. Weaker security.\n");
		}
	} else {
		/* Client mode:
		 * SSL_VERIFY_NONE
		 *   if not using an anonymous cipher (by default disabled), the 
		 *   server will send a certificate which will be checked. The result 
		 *   of the certificate verification process can be checked after the 
		 *   TLS/SSL handshake using the SSL_get_verify_result(3) function.
		 *   The handshake will be continued regardless of the verification 
		 *   result.
		 * SSL_VERIFY_PEER
		 *   the server certificate is verified. If the verification process 
		 *   fails, the TLS/SSL handshake is immediately terminated with an 
		 *   alert message containing the reason for the verification failure.
		 *   If no server certificate is sent, because an anonymous cipher is 
		 *   used, SSL_VERIFY_PEER is ignored.
		 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		 *   ignored
		 * SSL_VERIFY_CLIENT_ONCE
		 *   ignored
		 */

		if( d->verify_cert ) {
			verify_mode = SSL_VERIFY_PEER;
			LM_WARN("server verification activated.\n");
		} else {
			verify_mode = SSL_VERIFY_NONE;
			LM_WARN("server verification NOT activated. Weaker security.\n");
		}
	}
	
	SSL_CTX_set_verify( d->ctx, verify_mode, verify_callback);
	SSL_CTX_set_verify_depth( d->ctx, VERIFY_DEPTH_S);

	SSL_CTX_set_session_cache_mode( d->ctx, SSL_SESS_CACHE_SERVER );
	SSL_CTX_set_session_id_context( d->ctx, SER_SSL_SESS_ID, 
		SER_SSL_SESS_ID_LEN );

	return 0;
}


static int check_for_krb(void)
{
	SSL_CTX *xx;
	int j;

	xx = SSL_CTX_new(ssl_methods[tls_method - 1]);
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


/*
 * called once from main.c (main process) 
 */
int
init_tls(void)
{
	int i;
#if (OPENSSL_VERSION_NUMBER >= 0x00908000L) && !defined(OPENSSL_NO_COMP)
	STACK_OF(SSL_COMP)* comp_methods;
#endif

	LM_DBG("entered\n");

#if OPENSSL_VERSION_NUMBER < 0x00907000L
	LM_WARN("using an old version of OpenSSL (< 0.9.7). Upgrade!\n");
#endif

	/*
	* this has to be called before any function calling CRYPTO_malloc,
	* CRYPTO_malloc will set allow_customize in openssl to 0 
	*/
	if (!CRYPTO_set_mem_functions(ser_malloc, ser_realloc, ser_free)) {
		LM_ERR("unable to set the memory allocation functions\n");
		return -1;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x00908000L) && !defined(OPENSSL_NO_COMP)
	/* disabling compression */
	LM_WARN("disabling compression due ZLIB problems\n");
	comp_methods = SSL_COMP_get_compression_methods();
	if (comp_methods==0) {
		LM_INFO("openssl compression already disabled\n");
	} else {
		sk_SSL_COMP_zero(comp_methods);
	}
#endif

	SSL_library_init();
	SSL_load_error_strings();
	init_ssl_methods();

	i = check_for_krb();
	if (i==-1) {
		LM_ERR("kerberos check failed\n");
		return -1;
	}

	if ( ( i ^ 
#ifndef OPENSSL_NO_KRB5
	1
#else
	0
#endif
	)!=0 ) {
		LM_ERR("compiled agaist an openssl with %s"
			"kerberos, but run with one with %skerberos\n",
			(i==1)?"":"no ",(i!=1)?"no ":"");
		return -1;
	}

	/*
	 * now initialize tls default domains 
	 */
	if ( (i=init_tls_domains(tls_default_server_domain)) ) {
		return i;
	}
	if ( (i=init_tls_domains(tls_default_client_domain)) ) {
		return i;
	}
	/*
	 * now initialize tls virtual domains 
	 */
	if ( (i=init_tls_domains(tls_server_domains)) ) {
		return i;
	}
	if ( (i=init_tls_domains(tls_client_domains)) ) {
		return i;
	}
	/*
	 * we are all set 
	 */
	return 0;
}

/*
 * initialize tls virtual domains
 */
int
init_tls_domains(struct tls_domain *d)
{
	struct tls_domain *dom;

	dom = d;
	while (d) {
		if (d->name.len) {
			LM_INFO("Processing TLS domain '%.*s'\n",
				d->name.len, ZSW(d->name.s));
		} else {
			LM_INFO("Processing TLS domain [%s:%d]\n",
				ip_addr2a(&d->addr), d->port);
		}

		/*
		* set method 
		*/
		if (d->method == TLS_METHOD_UNSPEC) {
			LM_DBG("no method for tls[%s:%d], using default\n",
				ip_addr2a(&d->addr), d->port);
			d->method = tls_method;
		}
	
		/*
		* create context 
		*/
		d->ctx = SSL_CTX_new(ssl_methods[d->method - 1]);
		if (d->ctx == NULL) {
			LM_ERR("cannot create ssl context for "
				"tls[%s:%d]\n", ip_addr2a(&d->addr), d->port);
			return -1;
		}
		if (init_ssl_ctx_behavior( d ) < 0)
			return -1;

		/*
		* load certificate 
		*/
		if (!d->cert_file) {
			LM_NOTICE("no certificate for tls[%s:%d] defined, using default"
					"'%s'\n", ip_addr2a(&d->addr), d->port,	tls_cert_file);
			d->cert_file = tls_cert_file;
		}
		if (load_certificate(d->ctx, d->cert_file) < 0)
			return -1;
	
		/*
		* load ca 
		*/
		if (!d->ca_file) {
			LM_NOTICE("no CA for tls[%s:%d] defined, "
				"using default '%s'\n", ip_addr2a(&d->addr), d->port,
				tls_ca_file);
			d->ca_file = tls_ca_file;
		}
		if (d->ca_file && load_ca(d->ctx, d->ca_file) < 0)
			return -1;
		d = d->next;
	}

	/*
	* load all private keys as the last step (may prompt for password) 
	*/
	d = dom;
	while (d) {
		if (!d->pkey_file) {
			LM_NOTICE("no private key for tls[%s:%d] defined, using default"
					"'%s'\n", ip_addr2a(&d->addr), d->port, tls_pkey_file);
			d->pkey_file = tls_pkey_file;
		}
		if (load_private_key(d->ctx, d->pkey_file) < 0)
			return -1;
		d = d->next;
	}
	return 0;
}

/*
 * called from main.c when opensips exits (main process) 
 */
void
destroy_tls(void)
{
	struct tls_domain *d;
	LM_DBG("entered\n");
	
	d = tls_server_domains;
	while (d) {
		if (d->ctx)
			SSL_CTX_free(d->ctx);
		d = d->next;
	}
	d = tls_client_domains;
	while (d) {
		if (d->ctx)
			SSL_CTX_free(d->ctx);
		d = d->next;
	}
	if (tls_default_server_domain && tls_default_server_domain->ctx) {
		SSL_CTX_free(tls_default_server_domain->ctx);
	}
	if (tls_default_client_domain && tls_default_client_domain->ctx) {
		SSL_CTX_free(tls_default_client_domain->ctx);
	}
	tls_free_domains();

	/* library destroy */
	ERR_free_strings();
	/*SSL_free_comp_methods(); - this function is not on std. openssl*/
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

/*
 * called once from main.c (main process) before
 * parsing the configuration
 */
int pre_init_tls(void)
{
	LM_DBG("entered\n");

	tls_default_client_domain = tls_new_domain(TLS_DOMAIN_DEF|TLS_DOMAIN_CLI);
	if (tls_default_client_domain==0) {
		LM_ERR("failed to initialize tls_default_client_domain\n");
		return -1;
	}
	tls_default_client_domain->addr.af = AF_INET;

	tls_default_server_domain = tls_new_domain(TLS_DOMAIN_DEF|TLS_DOMAIN_SRV);
	if (tls_default_server_domain==0) {
		LM_ERR("failed to initialize tls_default_server_domain\n");
		return -1;
	}
	tls_default_server_domain->addr.af = AF_INET;

	return 0;
}

