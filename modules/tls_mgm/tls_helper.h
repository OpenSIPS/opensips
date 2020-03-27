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

#include "tls_config_helper.h"
#include "../../locking.h"

struct tls_domain {
	str name;
	int flags;
	struct _str_list *match_domains;
	struct _str_list *match_addresses;
	int ssl_ex_index;
	void **ctx;  /* libssl's SSL_CTX  */
	int ctx_no;  /* number of allocated SSL_CTXes */
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
	enum tls_method method;
	enum tls_method method_max;
	struct tls_domain *next;
};

#endif /* TLS_HELPER_H */
