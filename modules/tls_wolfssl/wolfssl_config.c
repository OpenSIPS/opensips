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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/openssl/ec.h>

#include <dirent.h>

#include "../../ut.h"
#include "../tls_mgm/tls_helper.h"

#include "wolfssl_api.h"
#include "wolfssl.h"

#define VERIFY_DEPTH_S 3

struct {
	char *name;
	enum tls_method method;
} ssl_versions_struct[SSL_VERSIONS_SIZE] = {
	{ "SSLv23",  TLS_USE_SSLv23  },
	{ "TLSv1",   TLS_USE_TLSv1   },
	{ "TLSv1_2", TLS_USE_TLSv1_2 },
	{ "TLSv1_3", TLS_USE_TLSv1_3 },
};

tls_sni_cb_f mod_sni_cb;

static int tls_get_method(str *method_str,
	enum tls_method *method, enum tls_method *method_max)
{
	int i;
	str val = *method_str;

	if (q_memchr(val.s, '-', val.len)) {
		LM_WARN("wolfSSL does not support method range specification\n");
		return -1;
	}
	trim(&val);
	if (val.len == 0) {
		LM_ERR("Empty TLS method specification\n");
		return -1;
	}

	for (i = 0; i < SSL_VERSIONS_SIZE; i++)
		if (!strncasecmp(ssl_versions_struct[i].name, val.s, val.len))
			break;
	if (i == SSL_VERSIONS_SIZE) {
		LM_ERR("unsupported method [%s]\n", val.s);
		return -1;
	}

	*method = ssl_versions_struct[i].method;
	*method_max = ssl_versions_struct[i].method;

	return 0;
}

static int verify_callback(int pre_verify_ok, WOLFSSL_X509_STORE_CTX *ctx) {
	char buf[256];
	WOLFSSL_X509 *cert;
	int depth, err;

	depth = wolfSSL_X509_STORE_CTX_get_error_depth(ctx);

	if (pre_verify_ok) {
		LM_NOTICE("depth = %d, verify success\n", depth);
	} else {
		LM_NOTICE("depth = %d, verify failure\n", depth);

		cert = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
		err = wolfSSL_X509_STORE_CTX_get_error(ctx);

		wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(cert),
			buf, sizeof buf);
		LM_NOTICE("subject = %s\n", buf);

		wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(cert),
			buf, sizeof buf);
		LM_NOTICE("issuer  = %s\n", buf);

		LM_NOTICE("verify error: %s [error=%d]\n",
			wolfSSL_X509_verify_cert_error_string(err), err);
	}

	return pre_verify_ok;
}

static int ssl_servername_cb(WOLFSSL *ssl, int *ret, void *exArg)
{
	char *srvname;
	struct tcp_connection *c;
	struct tls_domain *dom;
	int rc;

	if (!ssl || !exArg) {
		LM_ERR("Bad parameters in servername callback\n");
		return alert_warning;
	}

	dom = (struct tls_domain *)exArg;

	srvname = (char *)wolfSSL_get_servername(ssl, WOLFSSL_SNI_HOST_NAME);
	if (srvname && strlen(srvname) == 0) {
		LM_ERR("Empty Servername extension in Client Hello\n");
		return alert_warning;
	}

	c = (struct tcp_connection *)wolfSSL_get_ex_data(ssl, SSL_EX_CONN_IDX);
	if (!c) {
		LM_ERR("Failed to get tcp_connection pointer from SSL struct\n");
		return alert_warning;
	}

	rc = mod_sni_cb(dom, c, ssl, srvname);
	switch (rc) {
	case 0:
		return 0;
	case -2:
		return alert_fatal;
	case -1:
	default:
		return alert_warning;
	}
}

int _wolfssl_reg_sni_cb(tls_sni_cb_f cb)
{
	mod_sni_cb = cb;
	return 0;
}

int _wolfssl_switch_ssl_ctx(struct tls_domain *dom, void *ssl_ctx)
{
	wolfSSL_set_SSL_CTX((WOLFSSL *)ssl_ctx, dom->ctx);

	if (!wolfSSL_set_ex_data((WOLFSSL *)ssl_ctx, SSL_EX_DOM_IDX, dom)) {
		LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
		return -1;
	}

	return 0;
}

static int set_dh_params(WOLFSSL_CTX * ctx, char *filename)
{
	WOLFSSL_BIO *bio = wolfSSL_BIO_new_file(filename, "r");
	if (!bio) {
		LM_ERR("unable to open dh params file '%s'\n", filename);
		return -1;
	}

	WOLFSSL_DH *dh = wolfSSL_PEM_read_bio_DHparams(bio, 0, 0, 0);
	wolfSSL_BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from '%s'\n", filename);
		return -1;
	}

	if (wolfSSL_CTX_set_tmp_dh(ctx, dh) != SSL_SUCCESS) {
		LM_ERR("unable to set dh params\n");
		return -1;
	}

	LM_DBG("DH params from '%s' successfully set\n", filename);
	return 0;
}

static int set_dh_params_db(WOLFSSL_CTX * ctx, str *blob)
{
	WOLFSSL_BIO *bio;
	WOLFSSL_DH *dh;

	bio = wolfSSL_BIO_new_mem_buf((void*)blob->s,blob->len);
	if (!bio) {
		LM_ERR("unable to create bio \n");
		return -1;
	}

	dh = wolfSSL_PEM_read_bio_DHparams(bio, 0, 0, 0);
	wolfSSL_BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from bio\n");
		return -1;
	}

	if (wolfSSL_CTX_set_tmp_dh(ctx, dh) != SSL_SUCCESS) {
		LM_ERR("unable to set dh params\n");
		return -1;
	}

	LM_DBG("DH params from successfully set\n");
	return 0;
}

static int set_ec_params(WOLFSSL_CTX * ctx, const char* curve_name)
{
	int curve = 0;
	if (curve_name) {
		curve = wolfSSL_OBJ_txt2nid(curve_name);
	}
	if (curve > 0) {
		WOLFSSL_EC_KEY *ecdh = wolfSSL_EC_KEY_new_by_curve_name(curve);
		if (! ecdh) {
			LM_ERR("unable to create EC curve\n");
			return -1;
		}
		if (1 != wolfSSL_SSL_CTX_set_tmp_ecdh (ctx, ecdh)) {
			LM_ERR("unable to set tmp_ecdh\n");
			return -1;
		}
		wolfSSL_EC_KEY_free(ecdh);
	}
	else {
		LM_ERR("unable to find the EC curve\n");
		return -1;
	}
	return 0;
}

static int load_certificate(WOLFSSL_CTX * ctx, char *filename)
{
	int rc;

	if ((rc = wolfSSL_CTX_use_certificate_chain_file(ctx, filename)) !=
		SSL_SUCCESS) {
		LM_ERR("unable to load certificate file '%s' (ret=%d)\n", filename, rc);
		return -1;
	}

	LM_DBG("'%s' successfully loaded\n", filename);
	return 0;
}

static int load_certificate_db(WOLFSSL_CTX * ctx, str *blob)
{
	int rc;

	if ((rc = wolfSSL_CTX_use_certificate_chain_buffer(ctx,
		(unsigned char*)blob->s, blob->len)) != SSL_SUCCESS) {
		LM_ERR("unable to load certificate from buffer (ret=%d)\n", rc);
		return -1;
	}

	LM_DBG("Successfully loaded\n");
	return 0;
}

static int load_crl(WOLFSSL_CTX * ctx, char *crl_directory, int crl_check_all)
{
	DIR *d;
	struct dirent *dir;
	int crl_added = 0;
	LM_DBG("Loading CRL from directory\n");

	/*Get X509 store from SSL context*/
	WOLFSSL_X509_STORE *store = wolfSSL_CTX_get_cert_store(ctx);
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
		char* filename = pkg_malloc(strlen(crl_directory)+strlen(dir->d_name)+2);
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

		WOLFSSL_X509_CRL *crl = wolfSSL_PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		fclose(fp);
		if(!crl)
			continue;

		/*Add CRL to X509 store*/
		if (wolfSSL_X509_STORE_add_crl(store, crl) == 1)
			crl_added++;
		else
			LM_ERR("Unable to add crl to ssl context\n");

		wolfSSL_X509_CRL_free(crl);
	}
	closedir(d);

	if (!crl_added) {
		LM_ERR("No suitable CRL files found in directory %s\n", crl_directory);
		return 0;
	}

	/*Enable CRL checking*/
	int flags =  WOLFSSL_CRL_CHECK;
	if(crl_check_all)
		flags |= WOLFSSL_CRL_CHECKALL;

	if (wolfSSL_X509_STORE_set_flags(store, flags) != SSL_SUCCESS) {
		LM_ERR("Failed to set CRL verification flag!\n");
		return -1;
	}

	return 0;
}

static int load_ca(WOLFSSL_CTX * ctx, char *filename)
{
	int rc;

	if ((rc = wolfSSL_CTX_load_verify_locations(ctx, filename, 0)) !=
		SSL_SUCCESS) {
		LM_ERR("unable to load ca '%s' (ret=%d)\n", filename, rc);
		return -1;
	}

	LM_DBG("CA '%s' successfully loaded\n", filename);
	return 0;
}

static int load_ca_db(WOLFSSL_CTX * ctx, str *blob)
{
	int rc;

	if ((rc = wolfSSL_CTX_load_verify_buffer(ctx, (unsigned char *)blob->s, blob->len,
		SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
		LM_ERR("unable to load ca from buffer (ret=%d)\n", rc);
		return -1;
	}

	LM_DBG("CA successfully loaded\n");
	return 0;
}

static int load_ca_dir(WOLFSSL_CTX * ctx, char *directory)
{
	int rc;

	if ((rc = wolfSSL_CTX_load_verify_locations(ctx, 0, directory)) !=
		SSL_SUCCESS) {
		LM_WARN("unable to load ca directory '%s' (ret=%d)\n", directory, rc);
		return -1;
	}

	LM_DBG("CA '%s' successfully loaded from directory\n", directory);
	return 0;
}

int _wolfssl_init_tls_dom(struct tls_domain *d, int init_flags)
{
	int verify_mode = 0;
	int rc = -1;

	if (d->method_str.s && tls_get_method(&d->method_str, &d->method,
		&d->method_max) < 0)
		return -1;

	d->ctx = wolfSSL_CTX_new(ssl_methods[d->method - 1]());
	if (!d->ctx) {
		LM_ERR("cannot create ssl context for tls domain '%.*s'\n",
			d->name.len, d->name.s);
		return -1;
	}

	wolfSSL_CTX_set_options(d->ctx,
			SSL_OP_ALL | WOLFSSL_OP_NO_SSLv2 | WOLFSSL_OP_NO_SSLv3 |
			SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
			SSL_OP_CIPHER_SERVER_PREFERENCE);
	wolfSSL_CTX_set_session_cache_mode(d->ctx, WOLFSSL_SESS_CACHE_OFF);

	if (mod_sni_cb && d->flags & DOM_FLAG_SRV) {
		wolfSSL_CTX_set_servername_callback(d->ctx, ssl_servername_cb);
		wolfSSL_CTX_set_servername_arg(d->ctx, d);
	}

	if (d->flags & DOM_FLAG_SRV) {
		if (d->verify_cert ) {
			verify_mode = SSL_VERIFY_PEER;
			if (d->require_client_cert ) {
				LM_INFO("client verification activated. Client "
						"certificates are mandatory.\n");
				verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			} else {
				LM_INFO("client verification activated. Client "
						"certificates are NOT mandatory.\n");
			}
		} else {
			verify_mode = SSL_VERIFY_NONE;
			LM_INFO("client verification NOT activated. Weaker security.\n");
		}
	} else {
		if (d->verify_cert ) {
			/* This is turned on by default in wolfSSL */
			LM_INFO("server verification activated.\n");
		} else {
			verify_mode = SSL_VERIFY_NONE;
			LM_INFO("server verification NOT activated. Weaker security.\n");
		}
	}

	wolfSSL_CTX_set_verify(d->ctx, verify_mode, verify_callback);
	wolfSSL_CTX_set_verify_depth(d->ctx, VERIFY_DEPTH_S);

	if (!(d->flags & DOM_FLAG_DB) || init_flags & TLS_DOM_DH_FILE_FL) {
		if (d->dh_param.s && set_dh_params(d->ctx, d->dh_param.s) < 0)
			return -1;
	} else {
		set_dh_params_db(d->ctx, &d->dh_param);
	}

	if (!d->tls_ec_curve)
		LM_NOTICE("No EC curve defined\n");
	else if (set_ec_params(d->ctx, d->tls_ec_curve) < 0)
		return -1;

	if (d->ciphers_list != 0 &&
		wolfSSL_CTX_set_cipher_list(d->ctx, d->ciphers_list) != SSL_SUCCESS) {
		LM_ERR("failure to set SSL context "
				"cipher list '%s'\n", d->ciphers_list);
		return -1;
	}

	if (!(d->flags & DOM_FLAG_DB) || init_flags & TLS_DOM_CERT_FILE_FL) {
		if (load_certificate(d->ctx, d->cert.s) < 0)
			return -1;
	} else {
		if (load_certificate_db(d->ctx, &d->cert) < 0)
			return -1;
	}

	if (d->crl_directory && load_crl(d->ctx, d->crl_directory,
		d->crl_check_all) < 0)
		return -1;

	if (!(d->flags & DOM_FLAG_DB) || init_flags & TLS_DOM_CA_FILE_FL) {
		if (d->ca.s && (rc = load_ca(d->ctx, d->ca.s)) < 0)
			return -1;
	} else {
		if ((rc = load_ca_db(d->ctx, &d->ca)) < 0)
			return -1;
	}

	if (d->ca_directory && load_ca_dir(d->ctx, d->ca_directory) < 0 &&
		rc == -1) {
		LM_ERR("No CA loaded\n");
		return -1;
	}

	return 0;
}

static int load_private_key(WOLFSSL_CTX * ctx, char *filename)
{
	int rc;

	if ((rc = wolfSSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM)) !=
		SSL_SUCCESS) {
		LM_ERR("unable to load private key file '%s' (ret=%d)\n", filename, rc);
		return -1;
	}

	if (!wolfSSL_CTX_check_private_key(ctx)) {
		LM_ERR("key '%s' does not match the public key of the certificate\n",
			filename);
		return -1;
	}

	LM_DBG("key '%s' successfully loaded\n", filename);
	return 0;
}

static int load_private_key_db(WOLFSSL_CTX * ctx, str *blob)
{
	int rc;

	if ((rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx, (unsigned char *)blob->s,
		blob->len, SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
		LM_ERR("unable to load private key from buffer (ret=%d)\n", rc);
		return -1;
	}

	if (!wolfSSL_CTX_check_private_key(ctx)) {
		LM_ERR("key does not match the public key of the certificate\n");
		return -1;
	}

	LM_DBG("key successfully loaded\n");
	return 0;
}

int _wolfssl_load_priv_key(struct tls_domain *tls_dom, int from_file)
{
	if (!(tls_dom->flags & DOM_FLAG_DB) || from_file)
		return load_private_key(tls_dom->ctx, tls_dom->pkey.s);
	else
		return load_private_key_db(tls_dom->ctx, &tls_dom->pkey);
}

void _wolfssl_destroy_tls_dom(struct tls_domain *tls_dom)
{
	if (tls_dom->ctx)
		wolfSSL_CTX_free(tls_dom->ctx);
}
