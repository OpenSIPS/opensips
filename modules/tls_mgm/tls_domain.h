/*
 * Copyright (C)  2001-2003 FhG Fokus
 * Copyright (C)  2004,2005 Free Software Foundation, Inc.
 * Copyright (C)  2005,2006 iptelorg GmbH
 * Copyright (C)  2006 enum.at
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
 */

#ifndef TLS_DOMAIN_H
#define TLS_DOMAIN_H

#include "../../str.h"
#include "../../ip_addr.h"
#include <openssl/ssl.h>

#include "tls_config.h"
#include "tls_helper.h"
#include "../../usr_avp.h"
#include "../../ut.h"
#include "../../rw_locking.h"

#define NO_STR_VALS 7

#define STR_VALS_DOMAIN_COL         0
#define STR_VALS_ADDRESS_COL        1
#define STR_VALS_METHOD_COL         2
#define STR_VALS_CRL_DIR_COL        3
#define STR_VALS_CADIR_COL          4
#define STR_VALS_CPLIST_COL         5
#define STR_VALS_ECCURVE_COL        6

#define NO_INT_VALS 5

#define INT_VALS_ID_COL             0
#define INT_VALS_TYPE_COL           1
#define INT_VALS_VERIFY_CERT_COL    2
#define INT_VALS_REQUIRE_CERT_COL   3
#define INT_VALS_CRL_CHECK_COL      4

#define NO_BLOB_VALS 4

#define BLOB_VALS_CERTIFICATE_COL    0
#define BLOB_VALS_PK_COL             1
#define BLOB_VALS_CALIST_COL         2
#define BLOB_VALS_DHPARAMS_COL       3

#define NO_DB_COLS 16

#define DEFAULT_DOM_BOTH    0
#define CLIENT_DOMAIN       1
#define SERVER_DOMAIN       2

#define DEFAULT_DOM_NAME_S "default"
#define DEFAULT_DOM_NAME_LEN 7

/*
 * TLS configuration domain type
 */
enum tls_domain_type {
	TLS_DOMAIN_SRV = (1 << 0), /* Server domain */
	TLS_DOMAIN_CLI = (1 << 1), /* Client domain */
	TLS_DOMAIN_DB  = (1 << 2)  /* DB defined domain */
};

extern struct tls_domain **tls_server_domains;
extern struct tls_domain **tls_client_domains;
extern struct tls_domain **tls_default_server_domain;
extern struct tls_domain **tls_default_client_domain;
extern struct tls_domain *tls_def_srv_dom_orig, *tls_def_cli_dom_orig;

extern rw_lock_t *dom_lock;


/*
 * find domain with given name
 */
struct tls_domain *tls_find_domain_by_name(str *name, struct tls_domain **dom_list);

/*
 * find domain with given ip and port
 */
struct tls_domain *tls_find_server_domain(struct ip_addr *ip,
				   unsigned short port);

/* find client domain */
struct tls_domain *tls_find_client_domain(struct ip_addr *ip,
				   unsigned short port);

/*
 * find client with given ip and port
 */
struct tls_domain *tls_find_client_domain_addr(struct ip_addr *ip,
				   unsigned short port);

/*
 * find domain with given name
 */
struct tls_domain *tls_find_client_domain_name(str name);

/*
 * create a new server domain
 */
int tls_new_server_domain(str *name, struct ip_addr *ip, unsigned short port,
							struct tls_domain **dom);

/*
 * create a new client domain
 */
int tls_new_client_domain(str *name, struct ip_addr *ip, unsigned short port,
							struct tls_domain **dom);

/*
 * allocate memory and set default values for
 * TLS domain structure
 */
struct tls_domain *tls_new_domain(str *id, int type);

/*
 * clean up
 */
void  tls_free_domains(void);

void tls_release_domain(struct tls_domain* dom);

void tls_release_domain_aux(struct tls_domain *dom);

void tls_release_db_domains(struct tls_domain* dom);

struct tls_domain *find_first_script_dom(struct tls_domain *dom);

int set_all_domain_attr(struct tls_domain **dom, char **str_vals, int *int_vals,
							str* blob_vals);

int aloc_default_doms_ptr(void);

int tls_new_default_domain(int type, struct tls_domain **dom);

int db_add_domain(char **str_vals, int *int_vals, str* blob_vals,
			struct tls_domain **serv_dom, struct tls_domain **cli_dom,
			struct tls_domain **def_serv_dom, struct tls_domain **def_cli_dom,
			struct tls_domain *script_srv_doms, struct tls_domain *script_cli_doms);

#endif
