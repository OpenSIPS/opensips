/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 * Copyright (C) 2006 enum.at
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


#include "tls_config.h"
#include "../../config.h"
#include "../../ut.h"

int             tls_default_method = TLS_USE_SSLv23;

/*
 * These are the default values which will be used
 * for default domains AND virtual domains
 */

/* enable certificate validation as default value */
int             tls_verify_client_cert  = 1;
int             tls_verify_server_cert  = 1;
int             tls_require_client_cert = 1;
/* disable CRL validation for all the certificates from the chain */
int crl_check_all = 0;
/* default location of certificates */
char           *tls_cert_file = TLS_CERT_FILE;
char           *tls_pkey_file = TLS_PKEY_FILE;
char           *tls_ca_file   = TLS_CA_FILE;
char 	       *tls_ca_dir    = TLS_CA_DIRECTORY;
char           *tls_tmp_dh_file        = TLS_DH_PARAMS_FILE;
/* defaul cipher=0, this means the DEFAULT ciphers */
char           *tls_ciphers_list = 0;
/* AVPs used to enforce client domain matching from the script */
int             tls_client_domain_avp = -1;
int             sip_client_domain_avp = -1;

str    id_col = str_init("id");
str    domain_col = str_init("domain");
str    type_col = str_init("type");
str    match_address_col = str_init("match_ip_address");
str    match_domain_col = str_init("match_sip_domain");
str    method_col = str_init("method");
str    verify_cert_col = str_init("verify_cert");
str    require_cert_col = str_init("require_cert");
str    certificate_col = str_init("certificate");
str    pk_col = str_init("private_key");
str    crl_check_col = str_init("crl_check_all");
str    crl_dir_col = str_init("crl_dir");
str    calist_col = str_init("ca_list");
str    cadir_col = str_init("ca_dir");
str    cplist_col = str_init("cipher_list");
str    dhparams_col = str_init("dh_params");
str    eccurve_col = str_init("ec_curve");
str    tls_db_table = str_init("tls_mgm");
str    tls_db_url = {NULL, 0};
