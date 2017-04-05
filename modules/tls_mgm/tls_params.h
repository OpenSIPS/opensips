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
 * History:
 * -------
 *  2015-02-18  first version (bogdan)
 */


#ifndef _MOD_PROTO_TLS_tls_params_h
#define _MOD_PROTO_TLS_tls_params_h

#include "../../sr_module.h"
#include "tls_domain.h"

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

#define CLIENT_DOMAIN       0
#define SERVER_DOMAIN       1
#define DEFAULT_DOMAIN      2

int tlsp_add_srv_domain(modparam_t type, void *val);

int tlsp_add_cli_domain(modparam_t type, void *val);

int tlsp_set_method(modparam_t type, void *val);

int tlsp_set_verify(modparam_t type, void *val);

int tlsp_set_require(modparam_t type, void *val);

int tlsp_set_crl_check(modparam_t type, void *val);

int tlsp_set_certificate(modparam_t type, void *val);

int tlsp_set_pk(modparam_t type, void *val);

int tlsp_set_crldir(modparam_t type, void *val);

int tlsp_set_calist(modparam_t type, void *val);

int tlsp_set_cadir(modparam_t type, void *val);

int tlsp_set_cplist(modparam_t type, void *val);

int tlsp_set_dhparams(modparam_t type, void *val);

int tlsp_set_eccurve(modparam_t type, void *val);

int tlsp_db_add_domain(char **str_vals, int *int_vals, str* blob_vals,
    struct tls_domain **serv_dom, struct tls_domain **cli_dom);

#endif

