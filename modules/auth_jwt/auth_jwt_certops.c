/*
 * JWT Authentication Module
 *
 * Copyright (C) 2020 OpenSIPS Project
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
 * History:
 * --------
 * 2022-02-04 initial release (vlad)
 */

#include "../../usr_avp.h"
#include "../../mod_fix.h"
#include "../../mem/mem.h"
#include "../../ut.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "../tls_mgm/api.h"

static inline int decode_base64url_nopad(str *in, str *out)
{
	char *padded = NULL;
	int i;
	int pad_len, dec_len;

	if (!in || !in->s || in->len <= 0)
		return -1;

	for (i = 0; i < in->len; i++) {
		if ((in->s[i] >= 'A' && in->s[i] <= 'Z') ||
				(in->s[i] >= 'a' && in->s[i] <= 'z') ||
				(in->s[i] >= '0' && in->s[i] <= '9') ||
				in->s[i] == '-' || in->s[i] == '_')
			continue;
		LM_ERR("invalid base64url input\n");
		return -1;
	}

	pad_len = (4 - (in->len % 4)) % 4;
	padded = pkg_malloc(in->len + pad_len);
	if (!padded) {
		LM_ERR("no more pkg memory for padded b64 input\n");
		return -1;
	}

	memcpy(padded, in->s, in->len);
	if (pad_len)
		memset(padded + in->len, '=', pad_len);

	out->len = calc_max_base64_decode_len(in->len + pad_len);
	out->s = pkg_malloc(out->len);
	if (!out->s) {
		LM_ERR("no more pkg memory for b64 output\n");
		pkg_free(padded);
		return -1;
	}

	dec_len = base64urldecode((unsigned char *)out->s,
			(unsigned char *)padded, in->len + pad_len);
	pkg_free(padded);

	if (dec_len <= 0) {
		pkg_free(out->s);
		out->s = NULL;
		out->len = 0;
		return -1;
	}

	out->len = dec_len;
	return 0;
}

int extract_pub_key_from_cert(struct sip_msg* _msg, str* cert, 
		pv_spec_t* pub_key)
{
	BIO *bio=NULL,*bio_priv=NULL;
	X509 *x509cert=NULL;
	EVP_PKEY *pubkey=NULL;
	str out_pub_key= {0,0};
	pv_value_t pv_val;

	/* TODO - if x5c just add beggining & end */

	if (cert == NULL) {
		LM_ERR("Failed to parse certificate\n");
		return -1;
	}

	bio = BIO_new_mem_buf((void*)cert->s,cert->len);
	if (!bio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}
	
	x509cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

	if ((pubkey = X509_get_pubkey(x509cert)) == NULL) {
		LM_ERR("Failed to get pub key from certificate\n");
		goto err_free;
	}

	bio_priv = BIO_new(BIO_s_mem());
	if (bio_priv == NULL) {
		LM_ERR("Failed to allocate mem for pub key out \n");	
		goto err_free;
	}
	
	if (PEM_write_bio_PUBKEY(bio_priv, pubkey) < 0) {
		LM_ERR("Failed to write mem for pub key out \n");	
		goto err_free;
	}
	out_pub_key.len = BIO_get_mem_data(bio_priv, &out_pub_key.s);
	
	if (out_pub_key.len <= 0) {
		LM_ERR("Failed to get mem for pub key out \n");	
		goto err_free;
	}

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = out_pub_key;
	if (pv_set_value(_msg,pub_key,0,&pv_val) != 0) {
		LM_ERR("Failed to set pub key pvar \n");
		goto err_free;
	} 

	BIO_free(bio);
	BIO_free(bio_priv);
	X509_free(x509cert);
	EVP_PKEY_free(pubkey);

	return 1;
err_free:
	if (bio)
		BIO_free(bio);
	if (bio_priv)
		BIO_free(bio_priv);
	if (x509cert)
		X509_free(x509cert);
	if (pubkey)
		EVP_PKEY_free(pubkey);

	return -1;
	
}

int extract_pub_key_from_exp_mod(struct sip_msg* _msg, str* e, str* n,
		pv_spec_t* pub_key)
{
	BIGNUM *e_bn = NULL, *n_bn = NULL;
	BIO *bio_priv = NULL;
	EVP_PKEY *pubkey = NULL;
	RSA *rsa = NULL;
	str dec_e = {0, 0}, dec_n = {0, 0}, out_pub_key = {0, 0};
	pv_value_t pv_val;

	if (!e || !n) {
		LM_ERR("missing exponent/modulus\n");
		goto err_free;
	}

	if (decode_base64url_nopad(e, &dec_e) < 0) {
		LM_ERR("failed to decode exponent\n");
		goto err_free;
	}

	if (decode_base64url_nopad(n, &dec_n) < 0) {
		LM_ERR("failed to decode modulus\n");
		goto err_free;
	}

	e_bn = BN_bin2bn((unsigned char *)dec_e.s, dec_e.len, NULL);
	if (!e_bn) {
		LM_ERR("failed to convert exponent\n");
		goto err_free;
	}

	n_bn = BN_bin2bn((unsigned char *)dec_n.s, dec_n.len, NULL);
	if (!n_bn) {
		LM_ERR("failed to convert modulus\n");
		goto err_free;
	}

	rsa = RSA_new();
	if (!rsa) {
		LM_ERR("failed to allocate RSA key\n");
		goto err_free;
	}

	if (RSA_set0_key(rsa, n_bn, e_bn, NULL) != 1) {
		LM_ERR("failed to set RSA key components\n");
		goto err_free;
	}
	n_bn = NULL;
	e_bn = NULL;

	pubkey = EVP_PKEY_new();
	if (!pubkey) {
		LM_ERR("failed to allocate EVP key\n");
		goto err_free;
	}

	if (EVP_PKEY_assign_RSA(pubkey, rsa) != 1) {
		LM_ERR("failed to assign RSA key to EVP wrapper\n");
		goto err_free;
	}
	rsa = NULL;

	bio_priv = BIO_new(BIO_s_mem());
	if (bio_priv == NULL) {
		LM_ERR("Failed to allocate mem for pub key out\n");
		goto err_free;
	}

	if (PEM_write_bio_PUBKEY(bio_priv, pubkey) < 0) {
		LM_ERR("Failed to write mem for pub key out\n");
		goto err_free;
	}

	out_pub_key.len = BIO_get_mem_data(bio_priv, &out_pub_key.s);
	if (out_pub_key.len <= 0) {
		LM_ERR("Failed to get mem for pub key out\n");
		goto err_free;
	}

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = out_pub_key;
	if (pv_set_value(_msg, pub_key, 0, &pv_val) != 0) {
		LM_ERR("Failed to set pub key pvar\n");
		goto err_free;
	}

	pkg_free(dec_e.s);
	pkg_free(dec_n.s);
	BIO_free(bio_priv);
	EVP_PKEY_free(pubkey);

	return 1;

err_free:
	if (dec_e.s)
		pkg_free(dec_e.s);
	if (dec_n.s)
		pkg_free(dec_n.s);
	if (e_bn)
		BN_free(e_bn);
	if (n_bn)
		BN_free(n_bn);
	if (rsa)
		RSA_free(rsa);
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (bio_priv)
		BIO_free(bio_priv);

	return -1;
}
