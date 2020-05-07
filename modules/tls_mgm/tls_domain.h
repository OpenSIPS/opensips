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
#include "../../str_list.h"
#include <openssl/ssl.h>

#include "tls_config.h"
#include "tls_helper.h"
#include "../../usr_avp.h"
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../map.h"

#define NO_STR_VALS 8

#define STR_VALS_DOMAIN_COL         0
#define STR_VALS_MATCH_ADDRESS_COL  1
#define STR_VALS_MATCH_DOMAIN_COL   2
#define STR_VALS_METHOD_COL         3
#define STR_VALS_CRL_DIR_COL        4
#define STR_VALS_CADIR_COL          5
#define STR_VALS_CPLIST_COL         6
#define STR_VALS_ECCURVE_COL        7

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

#define NO_DB_COLS 17

#define CLIENT_DOMAIN_TYPE       1
#define SERVER_DOMAIN_TYPE       2

#define MATCH_ANY_VAL		'*'
#define MATCH_NO_SNI_VAL	"none"

#define DOM_FILT_ARR_MAX	64

struct domain_filter {
	str_list *hostname;
	struct tls_domain *dom_link;
};

struct dom_filt_array {
	struct domain_filter arr[DOM_FILT_ARR_MAX];
	int size;
};

#define ref_tls_dom(_d)  \
	do {  \
		if ((_d)->flags & DOM_FLAG_DB) {  \
			lock_get((_d)->lock);  \
			(_d)->refs++;  \
			lock_release((_d)->lock);  \
		}  \
	} while (0)

extern struct tls_domain **tls_server_domains;
extern struct tls_domain **tls_client_domains;

extern map_t server_dom_matching;
extern map_t client_dom_matching;

extern rw_lock_t *dom_lock;

struct tls_domain *tls_find_domain_by_name(str *name, struct tls_domain **dom_list);
struct tls_domain *tls_find_domain_by_filters(struct ip_addr *ip,
							unsigned short port, str *domain_filter, int type);

/*
 * find a server domain with given ip and port
 */
struct tls_domain *tls_find_server_domain(struct ip_addr *ip,
				   unsigned short port);

/* find client domain */
struct tls_domain *tls_find_client_domain(struct ip_addr *ip, unsigned short port);
struct tls_domain *tls_find_client_domain_name(str *name);

/*
 * allocate memory and set default values for
 * TLS domain structure
 */
int tls_new_domain(str *name, int type, struct tls_domain **dom);

void tls_release_domain(struct tls_domain* dom);

void tls_free_domain(struct tls_domain *dom);

void tls_free_db_domains(struct tls_domain* dom);

struct tls_domain *find_first_script_dom(struct tls_domain *dom);

int set_all_domain_attr(struct tls_domain **dom, char **str_vals, int *int_vals,
							str* blob_vals);

int db_add_domain(char **str_vals, int *int_vals, str* blob_vals,
			struct tls_domain **serv_dom, struct tls_domain **cli_dom,
			struct tls_domain *script_srv_doms, struct tls_domain *script_cli_doms);

int parse_match_domains(struct tls_domain *tls_dom, str *domains_s);
int parse_match_addresses(struct tls_domain *tls_dom, str *addresses_s);

int update_matching_map(struct tls_domain *tls_dom);
int sort_map_dom_arrays(map_t matching_map);
void map_free_node(void *val);

#endif
