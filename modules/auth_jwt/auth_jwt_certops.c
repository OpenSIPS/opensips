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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../tls_mgm/api.h"

int extract_pub_key_from_cert(struct sip_msg* _msg, str* cert, 
		pv_spec_t* pub_key)
{
	BIO *bio=NULL,*bio_priv=NULL;
	X509 *x509cert=NULL;
	EVP_PKEY *pubkey=NULL;
	str out_pub_key= {0,0};
	pv_value_t pv_val;

	/* TODO - if x5c just add beggining & end */

	bio = BIO_new_mem_buf((void*)cert->s,cert->len);
	if (!bio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}
	
	x509cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (cert == NULL) {
		LM_ERR("Failed to parse certificate\n");
		goto err_free;
	}

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
