/*
 * Copyright (C) 2015 OpenSIPS Solutions
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

#ifndef TLS_HELPER_H
#define TLS_HELPER_H

#define F_TLS_DO_ACCEPT   (1<<0)
#define F_TLS_DO_CONNECT  (1<<1)
#define F_TLS_TRACE_READY (1<<2)

#define DOM_FLAG_SRV			(1<<0)
#define DOM_FLAG_CLI			(1<<1)
#define DOM_FLAG_DB				(1<<2)

#define TLS_VERIFY_NONE 0
#define TLS_VERIFY_PEER (1<<0)
#define TLS_VERIFY_FAIL_IF_NO_PEER_CERT (1<<1)

#include "tls_config_helper.h"
#include "../../dprint.h"
#include "../../locking.h"

enum {
	VAR_CERT_LOCAL      = 1<<0,   /* Select local certificate */
	VAR_CERT_PEER       = 1<<1,   /* Select peer certificate */
	VAR_CERT_SUBJECT    = 1<<2,   /* Select subject part of certificate */
	VAR_CERT_ISSUER     = 1<<3,   /* Select issuer part of certificate */

	VAR_CERT_VERIFIED   = 1<<4,   /* Test for verified certificate */
	VAR_CERT_REVOKED    = 1<<5,   /* Test for revoked certificate */
	VAR_CERT_EXPIRED    = 1<<6,   /* Expiration certificate test */
	VAR_CERT_SELFSIGNED = 1<<7,   /* self-signed certificate test */
	VAR_CERT_NOTBEFORE  = 1<<8,   /* Select validity end from certificate */
	VAR_CERT_NOTAFTER   = 1<<9,   /* Select validity start from certificate */

	VAR_COMP_CN = 1<<10,          /* Common name */
	VAR_COMP_O  = 1<<11,          /* Organization name */
	VAR_COMP_OU = 1<<12,          /* Organization unit */
	VAR_COMP_C  = 1<<13,          /* Country name */
	VAR_COMP_ST = 1<<14,          /* State */
	VAR_COMP_L  = 1<<15,          /* Locality/town */

	VAR_COMP_HOST = 1<<16,        /* hostname from subject/alternative */
	VAR_COMP_URI  = 1<<17,        /* URI from subject/alternative */
	VAR_COMP_E    = 1<<18,        /* Email address */
	VAR_COMP_IP   = 1<<19,        /* IP from subject/alternative */
	VAR_COMP_SUBJECT_SERIAL = 1<<20    /*Serial name from Subject*/
};

struct tls_domain {
	str name;
	int flags;
	struct _str_list *match_domains;
	struct _str_list *match_addresses;
	void *ctx;  /* openssl's SSL_CTX or wolfSSL's WOLFSSL_CTX */
	int verify_cert;
	int require_client_cert;
	int crl_check_all;
	str cert;
	str pkey;
	char *crl_directory;
	str ca;
	str dh_param;
	char *tls_ec_curve;
	char *ca_directory;
	char *ciphers_list;
	int refs;
	gen_lock_t *lock;
	str method_str;
	enum tls_method method;
	enum tls_method method_max;
	struct tls_domain *next;
};

static inline int get_ssl_ctx_verify_mode(struct tls_domain *d)
{
	int verify_mode;

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

		if (d->verify_cert) {
			verify_mode = TLS_VERIFY_PEER;
			if (d->require_client_cert) {
				LM_INFO("client verification activated. Client "
						"certificates are mandatory.\n");
				verify_mode |= TLS_VERIFY_FAIL_IF_NO_PEER_CERT;
			} else {
				LM_INFO("client verification activated. Client "
						"certificates are NOT mandatory.\n");
			}
		} else {
			verify_mode = TLS_VERIFY_NONE;
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

		if (d->verify_cert) {
			verify_mode = TLS_VERIFY_PEER;
			LM_INFO("server verification activated.\n");
		} else {
			verify_mode = TLS_VERIFY_NONE;
			LM_INFO("server verification NOT activated. Weaker security.\n");
		}
	}

	return verify_mode;
}

#endif /* TLS_HELPER_H */
