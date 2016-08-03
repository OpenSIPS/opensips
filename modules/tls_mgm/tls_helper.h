/*
 * File:   tls_helper.h
 * Author: cristi
 *
 * Created on September 3, 2015, 5:26 PM
 */

#ifndef TLS_HELPER_H
#define TLS_HELPER_H

#define F_TLS_DO_ACCEPT   (1<<0)
#define F_TLS_DO_CONNECT  (1<<1)
#define F_TLS_TRACE_READY (1<<2)

#include "tls_config_helper.h"
#include "../../locking.h"

struct tls_domain {
	str             id;
	int             type;
	struct ip_addr  addr;
	unsigned short  port;
	void           *ctx; /* libssl's SSL_CTX  */
	int             verify_cert;
	int             require_client_cert;
	int             crl_check_all;
	str            cert;
	str            pkey;
	char           *crl_directory;
	str            ca;
	str            dh_param;
	char           *tls_ec_curve;
	char           *ca_directory;
	char           *ciphers_list;
	int             refs;
	gen_lock_t     *lock;
	enum tls_method method;
	struct tls_domain *next;
	str name;
};

#endif /* TLS_HELPER_H */

