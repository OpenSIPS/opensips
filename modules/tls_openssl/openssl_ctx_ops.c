/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../dprint.h"

void tls_print_errstack(void);

void tls_ctx_set_cert_store(void *ctx, void *src_ctx)
{
	X509_STORE *store;

	if ((store = SSL_CTX_get_cert_store(src_ctx)))
		SSL_CTX_set_cert_store(ctx, store);
}

int tls_ctx_set_cert_chain(void *ctx, void *src_ctx)
{
	STACK_OF(X509) *sk = NULL;
	X509 *x509;

	ERR_clear_error();

	x509 = SSL_CTX_get0_certificate(src_ctx);
	if (x509 && (SSL_CTX_use_certificate(ctx, x509) != 1)) {
		tls_print_errstack();
		LM_ERR("Failed to load certificate\n");
		return -1;
	}

	if (SSL_CTX_get0_chain_certs(src_ctx, &sk) != 1) {
		LM_ERR("Failed to get certificate chain from context\n");
		return -1;
	}
	if (sk && SSL_CTX_set0_chain(ctx, sk) != 1) {
		LM_ERR("Failed to set certificate chain in context\n");
		return -1;
	}

	return 0;
}

int tls_ctx_set_pkey_file(void *ctx, char *pkey_file)
{
	ERR_clear_error();

	if (SSL_CTX_use_PrivateKey_file(ctx, pkey_file, SSL_FILETYPE_PEM) != 1) {
		tls_print_errstack();
		return -1;
	}

	return 0;
}
