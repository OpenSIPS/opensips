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

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <dirent.h>

#include "../../pt.h"
#include "../tls_mgm/tls_helper.h"

#include "openssl_api.h"

void tls_dump_cert_info(char* s, X509* cert);
void tls_print_errstack(void);

extern gen_lock_t *tls_global_lock;

tls_sni_cb_f mod_sni_cb;

#define OS_SSL_SESS_ID (NAME "-" VERSION)
#define OS_SSL_SESS_ID_LEN (sizeof(OS_SSL_SESS_ID)-1)

#define VERIFY_DEPTH_S 3

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
extern int ssl_versions[TLS_USE_TLSv1_3 + 1];
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
extern int ssl_versions[TLS_USE_TLSv1_2 + 1];
#else
extern SSL_METHOD     *ssl_methods[TLS_USE_TLSv1_2 + 1];
#endif

static struct {
	char *name;
	char *alias;
	enum tls_method method;
} ssl_versions_struct[] = {
	{ "SSLv23",  "TLSany", TLS_USE_SSLv23  },
	{ "TLSv1",   NULL,     TLS_USE_TLSv1   },
	{ "TLSv1_2", NULL,     TLS_USE_TLSv1_2 },
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ "TLSv1_3", NULL,     TLS_USE_TLSv1_3 },
#endif
};

#define SSL_VERSIONS_SIZE (sizeof(ssl_versions_struct)/sizeof(ssl_versions_struct[0]))

#define MATCH(name, field) ((field) && strncasecmp(field, (name)->s, (name)->len) == 0)

/*
 * dump ssl error stack
 */
void tls_print_errstack(void)
{
	int             code;

	while ((code = ERR_get_error())) {
		LM_ERR("TLS errstack: %s\n", ERR_error_string(code, 0));
	}
}

void tls_dump_cert_info(char* s, X509* cert)
{
	char* subj;
	char* issuer;

	subj   = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	LM_INFO("%s subject: %s, issuer: %s\n", s ? s : "", subj, issuer);
	OPENSSL_free(subj);
	OPENSSL_free(issuer);
}

enum tls_method get_ssl_min_method(void)
{
	return ssl_versions_struct[1].method;  // skip SSLv23/TLSany
}

enum tls_method get_ssl_max_method(void)
{
	return ssl_versions_struct[SSL_VERSIONS_SIZE-1].method;
}

int parse_ssl_method(str *name)
{
	int index;
	for (index = 0; index < SSL_VERSIONS_SIZE; index++)
		if (MATCH(name, ssl_versions_struct[index].name) || MATCH(name, ssl_versions_struct[index].alias))
			return ssl_versions_struct[index].method;
	return -1;
}

int tls_get_method(str *method_str,
	enum tls_method *method, enum tls_method *method_max)
{
	str val = *method_str;
	str val_max;
	int m;
	char *s;

	/* search for a '-' to denote an interval */
	s = q_memchr(val.s, '-', val.len);
	if (s) {
		val_max.s = s + 1;
		val_max.len = val.len - (s - val.s) - 1;
		val.len = s - val.s;
		trim(&val_max);
	}
	trim(&val);
	if (val.len == 0)
		m = get_ssl_min_method();
	else
		m = parse_ssl_method(&val);
	if (m < 0) {
		LM_ERR("unsupported method [%s]\n",val.s);
		return -1;
	}

	*method = m;

	if (s) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (m == TLS_USE_SSLv23)
			LM_WARN("Using SSLv23/TLSany as the lower value for the method range makes no sense\n");

		if (val_max.len == 0)
			m = get_ssl_max_method();
		else
			m = parse_ssl_method(&val_max);
		if (m < 0) {
			LM_ERR("unsupported method [%s]\n",val_max.s);
			return -1;
		}

		if (m == TLS_USE_SSLv23)
			LM_WARN("Using SSLv23/TLSany as the higher value for the method range makes no sense\n");
#else
		LM_WARN("TLS method range not supported for versions lower than 1.1.0\n");
#endif
	}

	*method_max = m;

	return 0;
}

static void get_ssl_ctx_verify_mode(struct tls_domain *d, int *verify_mode)
{
	/* Set verification procedure
	 * The verification can be made null with SSL_VERIFY_NONE, or
	 * at least easier with SSL_VERIFY_CLIENT_ONCE instead of
	 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
	 * For extra control, instead of 0, we can specify a callback function:
	 *           int (*verify_callback)(int, X509_STORE_CTX *)
	 * Also, depth 2 may be not enough in some scenarios ... though no need
	 * to increase it much further */

	if (d->flags & DOM_FLAG_SRV) {
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
			*verify_mode = SSL_VERIFY_PEER;
			if( d->require_client_cert ) {
				LM_INFO("client verification activated. Client "
						"certificates are mandatory.\n");
				*verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			} else
				LM_INFO("client verification activated. Client "
						"certificates are NOT mandatory.\n");
		} else {
			*verify_mode = SSL_VERIFY_NONE;
			LM_INFO("client verification NOT activated. Weaker security.\n");
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
			*verify_mode = SSL_VERIFY_PEER;
			LM_INFO("server verification activated.\n");
		} else {
			*verify_mode = SSL_VERIFY_NONE;
			LM_INFO("server verification NOT activated. Weaker security.\n");
		}
	}
}

/* This callback is called during each verification process,
   at each step during the chain of certificates (this function
   is not the certificate_verification one!). */
int verify_callback(int pre_verify_ok, X509_STORE_CTX *ctx) {
	char buf[256];
	X509 *cert;
	int depth, err;

	depth = X509_STORE_CTX_get_error_depth(ctx);

	if (pre_verify_ok) {
		LM_NOTICE("depth = %d, verify success\n", depth);
	} else {
		LM_NOTICE("depth = %d, verify failure\n", depth);

		cert = X509_STORE_CTX_get_current_cert(ctx);
		err = X509_STORE_CTX_get_error(ctx);

		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof buf);
		LM_NOTICE("subject = %s\n", buf);

		X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof buf);
		LM_NOTICE("issuer  = %s\n", buf);

		LM_NOTICE("verify error: %s [error=%d]\n", X509_verify_cert_error_string(err), err);
	}

	return pre_verify_ok;
}

/* This callback is called during Client Hello processing in order to
 * inspect if a servername extension is present. If the client
 * indicated which hostname is attempting to connect to, we should present
 * the appropriate certificate for that domain.
 */
int ssl_servername_cb(SSL *ssl, int *ad, void *arg)
{
	char *srvname;
	struct tcp_connection *c;
	struct tls_domain *dom;
	int rc;

	if (!ssl || !arg) {
		LM_ERR("Bad parameters in servername callback\n");
		return SSL_TLSEXT_ERR_NOACK;
	}

	dom = (struct tls_domain *)arg;

	srvname = (char *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (srvname && strlen(srvname) == 0) {
		LM_ERR("Empty Servername extension in Client Hello\n");
		return SSL_TLSEXT_ERR_NOACK;
	}

	c = (struct tcp_connection *)SSL_get_ex_data(ssl, SSL_EX_CONN_IDX);
	if (!c) {
		LM_ERR("Failed to get tcp_connection pointer from SSL struct\n");
		return SSL_TLSEXT_ERR_NOACK;
	}

	rc = mod_sni_cb(dom, c, ssl, srvname);
	switch (rc) {
	case 0:
		return SSL_TLSEXT_ERR_OK;
	case -2:
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	case -1:
	default:
		return SSL_TLSEXT_ERR_NOACK;
	}
}

int openssl_reg_sni_cb(tls_sni_cb_f cb)
{
	mod_sni_cb = cb;
	return 0;
}

int openssl_switch_ssl_ctx(struct tls_domain *dom, void *ssl_ctx)
{
	SSL_set_SSL_CTX((SSL *)ssl_ctx, ((void**)dom->ctx)[process_no]);

	if (!SSL_set_ex_data((SSL *)ssl_ctx, SSL_EX_DOM_IDX, dom)) {
		LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
		return -1;
	}

	return 0;
}

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
/*
 * Load and set DH params to be used in ephemeral key exchange from a file.
 */
static int
set_dh_params(SSL_CTX * ctx, char *filename)
{
	BIO *bio = BIO_new_file(filename, "r");
	if (!bio) {
		LM_ERR("unable to open dh params file '%s'\n", filename);
		return -1;
	}

	DH *dh = PEM_read_bio_DHparams(bio, 0, 0, 0);
	BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from '%s'\n", filename);
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("unable to set dh params\n");
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	DH_free(dh);
	LM_DBG("DH params from '%s' successfully set\n", filename);
	return 0;
}

static int set_dh_params_db(SSL_CTX * ctx, str *blob)
{
	BIO *bio;
	DH *dh;

	bio = BIO_new_mem_buf((void*)blob->s,blob->len);
	if (!bio) {
		LM_ERR("unable to create bio \n");
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, 0, 0, 0);
	BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from bio\n");
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("unable to set dh params\n");
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	DH_free(dh);
	LM_DBG("DH params from successfully set\n");
	return 0;
}

/*
 * Set elliptic curve.
 */
static int set_ec_params(SSL_CTX * ctx, const char* curve_name)
{
	int curve = 0;
	if (curve_name) {
		curve = OBJ_txt2nid(curve_name);
	}
	if (curve > 0) {
		EC_KEY *ecdh = EC_KEY_new_by_curve_name (curve);
		if (! ecdh) {
			LM_ERR("unable to create EC curve\n");
			return -1;
		}
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_get(tls_global_lock);
		#endif
		if (1 != SSL_CTX_set_tmp_ecdh (ctx, ecdh)) {
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif
			LM_ERR("unable to set tmp_ecdh\n");
			return -1;
		}
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		EC_KEY_free (ecdh);
	}
	else {
		LM_ERR("unable to find the EC curve\n");
		return -1;
	}
	return 0;
}
#endif

/*
 * load a certificate from a file
 * (certificate file can be a chain, starting by the user cert,
 * and ending in the root CA; if not all needed certs are in this
 * file, they are looked up in the caFile or caPATH (see verify
 * function).
 */
static int load_certificate(SSL_CTX * ctx, char *filename)
{
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	if (!SSL_CTX_use_certificate_chain_file(ctx, filename)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		tls_print_errstack();
		LM_ERR("unable to load certificate file '%s'\n",
				filename);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	LM_DBG("'%s' successfully loaded\n", filename);
	return 0;
}

static int load_certificate_db(SSL_CTX * ctx, str *blob)
{
	X509 *cert = NULL;
	BIO *cbio;

	cbio = BIO_new_mem_buf((void*)blob->s,blob->len);
	if (!cbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	if (!cert) {
		LM_ERR("Unable to load certificate from buffer\n");
		BIO_free(cbio);
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	if (! SSL_CTX_use_certificate(ctx, cert)) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("Unable to use certificate\n");
		X509_free(cert);
		BIO_free(cbio);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif
	tls_dump_cert_info("Certificate loaded: ", cert);
	X509_free(cert);

	while ((cert = PEM_read_bio_X509(cbio, NULL, 0, NULL)) != NULL) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_get(tls_global_lock);
		#endif
		if (!SSL_CTX_add_extra_chain_cert(ctx, cert)){
			tls_print_errstack();
			#ifndef NO_SSL_GLOBAL_LOCK
			lock_release(tls_global_lock);
			#endif
			tls_dump_cert_info("Unable to add chain cert: ", cert);
			X509_free(cert);
			BIO_free(cbio);
			return -1;
		}
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		/* The x509 certificate provided to SSL_CTX_add_extra_chain_cert()
		*	will be freed by the library when the SSL_CTX is destroyed.
		*	An application should not free the x509 object.a*/
		tls_dump_cert_info("Chain certificate loaded: ", cert);
	}

	BIO_free(cbio);
	LM_DBG("Successfully loaded\n");
	return 0;
}

static int load_crl(SSL_CTX * ctx, char *crl_directory, int crl_check_all)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	DIR *d;
	struct dirent *dir;
	int crl_added = 0;
	LM_DBG("Loading CRL from directory\n");

	/*Get X509 store from SSL context*/
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	if(!store) {
		LM_ERR("Unable to get X509 store from ssl context\n");
		return -1;
	}

	/*Parse directory*/
	d = opendir(crl_directory);
	if(!d) {
		LM_ERR("Unable to open crl directory '%s'\n", crl_directory);
		return -1;
	}

	while ((dir = readdir(d)) != NULL) {
		/*Skip if not regular file*/
		if (dir->d_type != DT_REG)
			continue;

		/*Create filename*/
		char* filename = (char*) pkg_malloc(sizeof(char)*(strlen(crl_directory)+strlen(dir->d_name)+2));
		if (!filename) {
			LM_ERR("Unable to allocate crl filename\n");
			closedir(d);
			return -1;
		}
		strcpy(filename,crl_directory);
		if(filename[strlen(filename)-1] != '/')
			strcat(filename,"/");
		strcat(filename,dir->d_name);

		/*Get CRL content*/
		FILE *fp = fopen(filename,"r");
		pkg_free(filename);
		if(!fp)
			continue;

		X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		fclose(fp);
		if(!crl)
			continue;

		/*Add CRL to X509 store*/
		if (X509_STORE_add_crl(store, crl) == 1)
			crl_added++;
		else
			LM_ERR("Unable to add crl to ssl context\n");

		X509_CRL_free(crl);
	}
	closedir(d);

	if (!crl_added) {
		LM_ERR("No suitable CRL files found in directory %s\n", crl_directory);
		return 0;
	}

	/*Enable CRL checking*/
	X509_VERIFY_PARAM *param;
	param = X509_VERIFY_PARAM_new();

	int flags =  X509_V_FLAG_CRL_CHECK;
	if(crl_check_all)
		flags |= X509_V_FLAG_CRL_CHECK_ALL;

	X509_VERIFY_PARAM_set_flags(param, flags);

	SSL_CTX_set1_param(ctx, param);
	X509_VERIFY_PARAM_free(param);

	return 0;
#else
	static int already_warned = 0;
	if (!already_warned) {
		LM_WARN("CRL not supported in %s\n", OPENSSL_VERSION_TEXT);
		already_warned = 1;
	}
	return 0;
#endif
}

/*
 * Load a caList, to be used to verify the client's certificate.
 * The list is to be stored in a single file, containing all
 * the acceptable root certificates.
 */
static int load_ca(SSL_CTX * ctx, char *filename)
{
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	if (!SSL_CTX_load_verify_locations(ctx, filename, 0)) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("unable to load ca '%s'\n", filename);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	LM_DBG("CA '%s' successfully loaded\n", filename);
	return 0;
}

static int load_ca_db(SSL_CTX * ctx, str *blob)
{
	X509_STORE *store;
	X509 *cert = NULL;
	BIO *cbio;

	cbio = BIO_new_mem_buf((void*)blob->s,blob->len);

	if (!cbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	store =  SSL_CTX_get_cert_store(ctx);
	if(!store) {
		BIO_free(cbio);
		LM_ERR("Unable to get X509 store from ssl context\n");
		return -1;
	}

	while ((cert = PEM_read_bio_X509_AUX(cbio, NULL, 0, NULL)) != NULL) {
		tls_dump_cert_info("CA loaded: ", cert);
		if (!X509_STORE_add_cert(store, cert)){
			tls_dump_cert_info("Unable to add ca: ", cert);
			X509_free(cert);
			BIO_free(cbio);
			return -1;
		}
		X509_free(cert);
	}

	BIO_free(cbio);
	LM_DBG("CA successfully loaded\n");
	return 0;
}

/*
 * Load a caList from a directory instead of a single file.
 */
static int load_ca_dir(SSL_CTX * ctx, char *directory)
{
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	if (!SSL_CTX_load_verify_locations(ctx, 0 , directory)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("unable to load ca directory '%s'\n", directory);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	LM_DBG("CA '%s' successfully loaded from directory\n", directory);
	return 0;
}

int openssl_init_tls_dom(struct tls_domain *d, int init_flags)
{
	int verify_mode = 0;
	unsigned i, tcp_procs;

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
	if (!d->tls_ec_curve)
		LM_NOTICE("No EC curve defined\n");
#else
	if (d->dh_param  || tls_tmp_dh_file)
		LM_INFO("DH params file discarded as not supported by your "
			"openSSL version\n");
	if (d->tls_ec_curve)
		LM_INFO("EC params file discarded as not supported by your "
			"openSSL version\n");
#endif

	if (d->method_str.s && tls_get_method(&d->method_str, &d->method,
		&d->method_max) < 0)
		return -1;

	get_ssl_ctx_verify_mode(d, &verify_mode);

	tcp_procs = count_child_processes();

	d->ctx = shm_malloc(tcp_procs * sizeof(SSL_CTX *));
	if (!d->ctx) {
		LM_ERR("cannot allocate ssl ctx per process!\n");
		return -1;
	}
	memset(d->ctx, 0, tcp_procs * sizeof(SSL_CTX *));

	d->ctx_no = tcp_procs;

	for (i = 0; i < tcp_procs; i++) {
		/*
		 * create context
		 */
#ifndef NO_SSL_GLOBAL_LOCK
		lock_get(tls_global_lock);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		((void**)d->ctx)[i] = SSL_CTX_new(TLS_method());
#else
		((void**)d->ctx)[i] = SSL_CTX_new(ssl_methods[d->method - 1]);
#endif
#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
#endif
		if (((void**)d->ctx)[i] == NULL) {
			LM_ERR("cannot create ssl context for tls domain '%.*s'\n",
				d->name.len, ZSW(d->name.s));
			return -1;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (d->method != TLS_USE_SSLv23) {
			if (!SSL_CTX_set_min_proto_version(((void**)d->ctx)[i],
					ssl_versions[d->method - 1]) ||
				!SSL_CTX_set_max_proto_version(((void**)d->ctx)[i],
					ssl_versions[d->method_max - 1])) {
				LM_ERR("cannot enforce ssl version for tls domain '%.*s'\n",
						d->name.len, ZSW(d->name.s));
				return -1;
			}
		}
#endif

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
		if (!(d->flags & DOM_FLAG_DB) || init_flags & TLS_DOM_DH_FILE_FL) {
			if (d->dh_param.s && set_dh_params(((void**)d->ctx)[i], d->dh_param.s) < 0)
				return -1;
		} else {
			set_dh_params_db(((void**)d->ctx)[i], &d->dh_param);
		}
		if (d->tls_ec_curve && set_ec_params(((void**)d->ctx)[i], d->tls_ec_curve) < 0)
			return -1;
#endif

		if (d->ciphers_list != 0 && SSL_CTX_set_cipher_list(((void**)d->ctx)[i],
			d->ciphers_list) == 0 ) {
			LM_ERR("failure to set SSL context "
					"cipher list '%s'\n", d->ciphers_list);
			return -1;
		}

		/* Set a bunch of options:
		 *     do not accept SSLv2 / SSLv3
		 *     no session resumption
		 *     choose cipher according to server's preference's*/

		SSL_CTX_set_options(((void**)d->ctx)[i],
				SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
				SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
				SSL_OP_CIPHER_SERVER_PREFERENCE);


		SSL_CTX_set_verify(((void**)d->ctx)[i], verify_mode, verify_callback);
		SSL_CTX_set_verify_depth(((void**)d->ctx)[i], VERIFY_DEPTH_S);

		//SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER );
		SSL_CTX_set_session_cache_mode(((void**)d->ctx)[i], SSL_SESS_CACHE_OFF );
		SSL_CTX_set_session_id_context(((void**)d->ctx)[i], (unsigned char*)OS_SSL_SESS_ID,
				OS_SSL_SESS_ID_LEN );

		/* install callback for SNI */
		if (mod_sni_cb && d->flags & DOM_FLAG_SRV) {
			SSL_CTX_set_tlsext_servername_callback(((void**)d->ctx)[i], ssl_servername_cb);
			SSL_CTX_set_tlsext_servername_arg(((void**)d->ctx)[i], d);
		}

		/*
		 * load certificate
		 */
		if (!(d->flags & DOM_FLAG_DB) || init_flags & TLS_DOM_CERT_FILE_FL) {
			if (load_certificate(((void**)d->ctx)[i], d->cert.s) < 0)
				return -1;
		} else
			if (load_certificate_db(((void**)d->ctx)[i], &d->cert) < 0)
				return -1;

		/**
		 * load crl from directory
		 */
		if (d->crl_directory && load_crl(((void**)d->ctx)[i], d->crl_directory,
			d->crl_check_all) < 0)
			return -1;

		/*
		 * load ca
		 */
		if (!(d->flags & DOM_FLAG_DB) || init_flags & TLS_DOM_CA_FILE_FL) {
			if (d->ca.s && load_ca(((void**)d->ctx)[i], d->ca.s) < 0)
				return -1;
		} else {
			if (load_ca_db(((void**)d->ctx)[i], &d->ca) < 0)
				return -1;
		}

		if (d->ca_directory && load_ca_dir(((void**)d->ctx)[i], d->ca_directory) < 0)
			return -1;
	}

	return 0;
}

static int passwd_cb(char *buf, int size, int rwflag, void *filename)
{
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
}

/*
 * load a private key from a file
 */
static int load_private_key(SSL_CTX * ctx, char *filename)
{
#define NUM_RETRIES 3
	int idx, ret_pwd;

	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, filename);

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
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
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("unable to load private key file '%s'\n",
				filename);
		return -1;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("key '%s' does not match the public key of the certificate\n",
				filename);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	LM_DBG("key '%s' successfully loaded\n", filename);
	return 0;
}

static int load_private_key_db(SSL_CTX * ctx, str *blob)
{
#define NUM_RETRIES 3
	int idx;
	BIO *kbio;
	EVP_PKEY *key;

	kbio = BIO_new_mem_buf((void*)blob->s, blob->len);

	if (!kbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_get(tls_global_lock);
	#endif
	for(idx = 0; idx < NUM_RETRIES; idx++ ) {
		key = PEM_read_bio_PrivateKey(kbio,NULL, passwd_cb, "database");
		if ( key ) {
			break;
		} else {
			LM_ERR("unable to load private key. \n"
				   "Retry (%d left) (check password case)\n",  (NUM_RETRIES - idx -1) );
			continue;
		}
	}

	BIO_free(kbio);
	if(!key) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		LM_ERR("unable to load private key from buffer\n");
		return -1;
	}

	if (!SSL_CTX_use_PrivateKey(ctx, key)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		lock_release(tls_global_lock);
		#endif
		EVP_PKEY_free(key);
		LM_ERR("key does not match the public key of the certificate\n");
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	lock_release(tls_global_lock);
	#endif

	EVP_PKEY_free(key);
	LM_DBG("key successfully loaded\n");
	return 0;
}

int openssl_load_priv_key(struct tls_domain *tls_dom, int from_file)
{
	int rc = 0;
	int i;

	for (i = 0; i < tls_dom->ctx_no; i++) {
		if (!(tls_dom->flags & DOM_FLAG_DB) || from_file)
			rc = load_private_key(((void**)tls_dom->ctx)[i], tls_dom->pkey.s);
		else
			rc = load_private_key_db(((void**)tls_dom->ctx)[i], &tls_dom->pkey);
		if (rc < 0)
			break;
	}

	return rc;
}

void openssl_destroy_tls_dom(struct tls_domain *tls_dom)
{
	int i;

	if (tls_dom->ctx) {
		for (i = 0; i < tls_dom->ctx_no; i++)
			if (((void**)tls_dom->ctx)[i])
				SSL_CTX_free(((void**)tls_dom->ctx)[i]);
		shm_free(tls_dom->ctx);
	}
}
