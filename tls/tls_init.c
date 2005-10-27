/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
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
#include "tls_domain.h"

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

#define SER_SSL_SESS_ID ((unsigned char*)"openser-tls-1.0.0")
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

/*
 * default context, also for outgoing connections 
 */
SSL_CTX        *default_ctx;


#define VERIFY_DEPTH_S 3

/* This callback is called during each verification process, 
at each step during the chain of certificates (this function
is not the certificate_verification one!). */
int verify_callback(int pre_verify_ok, X509_STORE_CTX *ctx) {
	char buf[256];
	X509 *err_cert;
	int err, depth;

	depth = X509_STORE_CTX_get_error_depth(ctx);
	LOG( 2, "tls_init: verify_callback: depth = %d\n",depth);
	if ( depth > VERIFY_DEPTH_S ) {
		LOG( 2, "tls_init: verify_callback: cert chain too long ( depth > VERIFY_DEPTH_S)\n");
		pre_verify_ok=0;
	}
	
	if( pre_verify_ok ) {
		LOG( 2, "tls_init: verify_callback: preverify is good: verify return: %d\n", pre_verify_ok);
		return pre_verify_ok;
	}
	
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);	
	X509_NAME_oneline(X509_get_subject_name(err_cert),buf,sizeof buf);
	
	LOG( 2, "tls_init: verify_callback: subject = %s\n", buf);
	LOG( 2, "tls_init: verify_callback: verify error:num=%d:%s\n", err, X509_verify_cert_error_string(err));	
	LOG( 2, "tls_init: verify_callback: error code is %d\n", ctx->error);
	
	switch (ctx->error) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),buf,sizeof buf);
			LOG( 2, "tls_init: verify_callback: issuer= %s\n",buf);
			break;
			
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		case X509_V_ERR_CERT_NOT_YET_VALID:
			LOG( 2, "tls_init: verify_callback: notBefore\n");
			break;
		
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		case X509_V_ERR_CERT_HAS_EXPIRED:
			LOG( 2, "tls_init: verify_callback: notAfter\n");
			break;
			
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			LOG( 2, "tls_init: verify_callback: unable to decrypt cert signature\n");
			break;
			
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			LOG( 2, "tls_init: verify_callback: unable to decode issuer public key\n");
			break;
			
		case X509_V_ERR_OUT_OF_MEM:
			LOG( 2, "tls_init: verify_callback: Out of memory \n");
			break;
			
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			LOG( 2, "tls_init: verify_callback: Self signed certificate issue\n");
			break;

		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			LOG( 2, "tls_init: verify_callback: certificate chain too long\n");
			break;
		case X509_V_ERR_INVALID_CA:
			LOG( 2, "tls_init: verify_callback: invalid CA\n");
			break;
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			LOG( 2, "tls_init: verify_callback: path length exceeded\n");
			break;
		case X509_V_ERR_INVALID_PURPOSE:
			LOG( 2, "tls_init: verify_callback: invalid purpose\n");
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
			LOG( 2, "tls_init: verify_callback: certificate untrusted\n");
			break;
		case X509_V_ERR_CERT_REJECTED:
			LOG( 2, "tls_init: verify_callback: certificate rejected\n");
			break;
		
		default:
			LOG( 2, "tls_init: verify_callback: something wrong with the cert ... error code is %d (check x509_vfy.h)\n", ctx->error);
			break;
	}
	
	LOG( 2, "tls_init: verify_callback: verify return:%d\n", pre_verify_ok);
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
	LOG(L_ERR, "tls: tls_init: passwd_cb: Error in passwd_cb\n");
	if (ui)
		UI_free(ui);
	return 0;
	
#else
	if( des_read_pw_string(buf, size-1, "Enter Private Key password:", 0) ) {
		LOG(L_ERR, "tls: tls_init: passwd_cb: Error in passwd_cb\n");
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
	DBG("tls_init: Entered\n");
	
	/*
	 * reuse tcp initialization 
	 */
	if (tcp_init(si) < 0) {
		LOG(L_ERR, "tls_init: Error while initializing TCP part\n");
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
	DBG("load_certificate: Entered\n");
	if (!SSL_CTX_use_certificate_chain_file(ctx, filename)) {
		LOG(L_ERR,
			"load_certificate: Unable to load certificate file '%s'\n",
			filename);
		return -1;
	}

	DBG("load_certificate: '%s' successfuly loaded\n", filename);
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
	DBG("load_private_key: Entered\n");
	
	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, filename);

	for(idx = 0, ret_pwd = 0; idx < NUM_RETRIES; idx++ ) {
		ret_pwd = SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM);
		if ( ret_pwd ) {
			break;
		} else {
			LOG( L_ERR,
				"load_private_key: Unable to load private key file '%s'. \n"
				"Retry (%d left) (check password case)\n",
				filename, (NUM_RETRIES - idx -1) );
			continue;
		}
	}
	
	if( ! ret_pwd ) {
		LOG(L_ERR,
			"load_private_key: Unable to load private key file '%s'\n",
			filename);
		return -1;
	}
	
	if (!SSL_CTX_check_private_key(ctx)) {
		LOG(L_ERR,
			"load_private_key: Key '%s' does not match the public key of the certificate\n",
			filename);
		return -1;
	}
	
	DBG("load_private_key: Key '%s' successfuly loaded\n", filename);
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
	DBG("load_ca: Entered\n");
	if (!SSL_CTX_load_verify_locations(ctx, filename, 0)) {
		LOG(L_ERR, "load_ca: Unable to load ca '%s'\n", filename);
		return -1;
	}
	
	DBG("load_ca: CA '%s' successfuly loaded\n", filename);
	return 0;
}


/*
 * initialize ssl methods 
 */
static void
init_ssl_methods(void)
{
	DBG("init_methods: Entered\n");
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
static void
init_ssl_ctx_behavior( SSL_CTX *_ctx ) {
	int verify_mode;
	if( tls_ciphers_list != 0 ) {
		if( SSL_CTX_set_cipher_list(_ctx, tls_ciphers_list) == 0 )
			LOG( L_ERR, "init_tls: failure to set SSL context cipher list\n");
		else
			LOG( 2, "TLS: cipher list set to %s\n", tls_ciphers_list);
	} else {
		DBG( "TLS: cipher list null ... setting default\n");
	}

	/* Set a bunch of options: 
	 *     do not accept SSLv2
	 *     no session resumption
	 *     choose cipher according to server's preference's*/

#if OPENSSL_VERSION_NUMBER >= 0x000907000
	SSL_CTX_set_options(_ctx, 
			SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
#else
	SSL_CTX_set_options(_ctx, 
			SSL_OP_ALL | SSL_OP_NO_SSLv2 );
#endif

	/* Set verification procedure
	 * The verification can be made null with SSL_VERIFY_NONE, or 
	 * at least easier with SSL_VERIFY_CLIENT_ONCE instead of SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
	 *   For extra control, instead of 0, we can specify a callback function:
	 *           int (*verify_callback)(int, X509_STORE_CTX *)
	 * Also, depth 2 may be not enough in some scenarios ... though no need
	 * to increase it much further */
	/*SSL_CTX_set_verify( _ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0); */
	//SSL_CTX_set_verify( _ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_callback);
	//SSL_CTX_set_verify( _ctx, SSL_VERIFY_NONE, NULL);
	verify_mode = SSL_VERIFY_NONE;
	if( tls_verify_cert ) {
		verify_mode |= SSL_VERIFY_PEER;
		if( tls_require_cert ) {
			LOG( L_WARN, "TLS: Verification activated. Client certificates are mandatory.\n");
			verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		} else
			LOG( L_WARN, "TLS: Verification activated. Client certificates are NOT mandatory.\n");
	} else 
		LOG( L_WARN, "TLS: Verification NOT activated. Weaker security.\n");
	
	SSL_CTX_set_verify( _ctx, verify_mode, verify_callback);	
	SSL_CTX_set_verify_depth( _ctx, VERIFY_DEPTH_S);
	
	SSL_CTX_set_session_cache_mode( _ctx, SSL_SESS_CACHE_SERVER );
	SSL_CTX_set_session_id_context( _ctx, SER_SSL_SESS_ID, SER_SSL_SESS_ID_LEN );
}

/*
 * called once from main.c (main process) 
 */
int
init_tls(void)
{
	struct tls_domain *d;
	DBG("init_tls: Entered\n");
#if OPENSSL_VERSION_NUMBER < 0x00907000L
	LOG(L_ERR, "WARNING! You are using an old version of OpenSSL (< 0.9.7). Upgrade!\n");
#endif
	/*
	* this has to be called before any function calling CRYPTO_malloc,
	* CRYPTO_malloc will set allow_customize in openssl to 0 
	*/
	if (!CRYPTO_set_mem_functions(ser_malloc, ser_realloc, ser_free)) {
		LOG(L_ERR,
			"init_tls: Unable to set the memory allocation functions\n");
		return -1;
	}
	
	SSL_library_init();
	SSL_load_error_strings();
	init_ssl_methods();

	/*
	 * initialize default context first 
	 */
	default_ctx = SSL_CTX_new(ssl_methods[tls_method - 1]);
	if (default_ctx == NULL) {
		LOG(L_ERR, "init_tls: Cannot create default ssl context\n");
		return -1;
	}
	init_ssl_ctx_behavior( default_ctx );
	if (load_certificate(default_ctx, tls_cert_file) < 0)
		return -1;
	if (tls_ca_file && load_ca(default_ctx, tls_ca_file) < 0)
		return -1;
	if (load_private_key(default_ctx, tls_pkey_file) < 0)
		return -1;

	/*
	 * now initialize tls virtual domains 
	 */
	d = tls_domains;
	while (d) {
		DBG("init_tls: Processing TLS domain [%s:%d]\n",
				ip_addr2a(&d->addr), d->port);
		/*
		* create context 
		*/
		if (d->method == TLS_METHOD_UNSPEC) {
			DBG("init_tls: No method for tls[%s:%d], using default\n",
			ip_addr2a(&d->addr), d->port);
			d->method = tls_method;
		}
	
		d->ctx = SSL_CTX_new(ssl_methods[d->method - 1]);
		if (d->ctx == NULL) {
			LOG(L_ERR,
				"init_tls: Cannot create ssl context for tls[%s:%d]\n",
				ip_addr2a(&d->addr), d->port);
			return -1;
		}
		init_ssl_ctx_behavior( d->ctx );
		/*
		* load certificate 
		*/
		if (!d->cert_file) {
			LOG(L_NOTICE,
				"init_tls: No certificate for tls[%s:%d] defined, using default '%s'\n",
				ip_addr2a(&d->addr), d->port, tls_cert_file);
			d->cert_file = tls_cert_file;
		}
		if (load_certificate(d->ctx, d->cert_file) < 0)
			return -1;
	
		/*
		* load ca 
		*/
		if (!d->ca_file) {
			LOG(L_NOTICE,
				"init_tls: No CA for tls[%s:%d] defined, using default '%s'\n",
				ip_addr2a(&d->addr), d->port, tls_ca_file);
			d->ca_file = tls_ca_file;
		}
		if (d->ca_file && load_ca(d->ctx, d->ca_file) < 0)
			return -1;
		d = d->next;
	}

	/*
		* load all private keys as the last step (may prompt for password) 
		*/
	d = tls_domains;
	while (d) {
		if (!d->pkey_file) {
			LOG(L_NOTICE,
				"init_tls: No private key for tls[%s:%d] defined, using default '%s'\n",
				ip_addr2a(&d->addr), d->port, tls_pkey_file);
			d->pkey_file = tls_pkey_file;
		}
		if (load_private_key(d->ctx, d->pkey_file) < 0)
			return -1;
		d = d->next;
	}
	/*
	 * we are all set 
	 */
	return 0;
}


/*
 * called from main.c when ser exits (main process) 
 */
void
destroy_tls(void)
{
	struct tls_domain *d;
	DBG("destroy_tls: Entered\n");
	
	d = tls_domains;
	while (d) {
		if (d->ctx)
			SSL_CTX_free(d->ctx);
		d = d->next;
	}
	if (default_ctx)
		SSL_CTX_free(default_ctx);
	tls_free_domains();
}
