/*
 * Copyright (C) 2019 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "tls_helper.h"

static int load_pkey(struct cert_holder *holder, str *pkey_buf)
{
	BIO *kbio;

	kbio = BIO_new_mem_buf((void*)pkey_buf->s, pkey_buf->len);
	if (!kbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	holder->pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
	if (!holder->pkey) {
		LM_ERR("Failed to load private key from buffer\n");
		BIO_free(kbio);
		return -1;
	}

	return 0;
}

static int load_cert(struct cert_holder *holder, str *cert_buf)
{
	BIO *cbio;
	STACK_OF(X509) *stack;
	STACK_OF(X509_INFO) *sk;
	X509_INFO *xi;

	cbio = BIO_new_mem_buf((void*)cert_buf->s,cert_buf->len);
	if (!cbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	/* parse end-entity certificate */
	holder->cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	if (!holder->cert) {
		LM_ERR("Unable to load certificate from buffer\n");
		BIO_free(cbio);
		return -1;
	}

	/* parse untrusted certificate chain */
	stack = sk_X509_new_null();
	if (!stack) {
		LM_ERR("Failed to allocate cert stack\n");
		X509_free(holder->cert);
		BIO_free(cbio);
	}

	sk = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);
	if (!sk) {
		LM_ERR("error reading certificate stack\n");
		X509_free(holder->cert);
		BIO_free(cbio);
		sk_X509_free(stack);
	}

	while (sk_X509_INFO_num(sk)) {
		xi = sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL) {
			sk_X509_push(stack, xi->x509);
			xi->x509 = NULL;
		}
		X509_INFO_free(xi);
	}

	if (!sk_X509_num(stack))
		sk_X509_free(stack);
	else
		holder->certchain = stack;

	BIO_free(cbio);
	sk_X509_INFO_free(sk);

	return 0;
}

void free_cert_holder(struct cert_holder *holder)
{
	X509_free(holder->cert);
	if (holder->certchain)
		sk_X509_pop_free(holder->certchain, X509_free);

	if (holder->pkey)
		EVP_PKEY_free(holder->pkey);

	shm_free(holder);
}

struct cert_holder *new_cert_holder(str *cert_buf, str *pkey_buf)
{
	struct cert_holder *new_holder;

	new_holder = shm_malloc(sizeof *new_holder);
	if (!new_holder) {
		LM_ERR("oom!\n");
		return NULL;
	}
	memset(new_holder, 0, sizeof *new_holder);

	if (load_cert(new_holder, cert_buf) < 0) {
		LM_ERR("Failed to load certificate\n");
		shm_free(new_holder);
		return NULL;
	}

	if (pkey_buf) {
		if (load_pkey(new_holder, pkey_buf) < 0) {
			LM_ERR("Failed to load private key\n");
			free_cert_holder(new_holder);
			return NULL;
		}

		if (!X509_check_private_key(new_holder->cert, new_holder->pkey)) {
			LM_ERR("key does not match the public key of the certificate\n");
			free_cert_holder(new_holder);
			return NULL;
		}
	}

	return new_holder;
}
