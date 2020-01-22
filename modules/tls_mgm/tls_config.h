/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
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

#ifndef tls_config_h
#define tls_config_h

#include "tls_config_helper.h"
#include "../../str.h"

#define TLS_TABLE_VERSION 3

extern int      tls_default_method;

extern int      tls_verify_client_cert;
extern int      tls_verify_server_cert;
extern int      tls_require_client_cert;
extern int	crl_check_all;
extern char    *tls_cert_file;
extern char    *tls_pkey_file;
extern char    *tls_ca_file;
extern char    *tls_ca_dir;
extern char    *tls_tmp_dh_file;
extern char    *tls_ciphers_list;

extern str     tls_db_url; 
extern str     tls_db_table;
extern str     id_col;
extern str     domain_col;
extern str     type_col;
extern str     match_address_col;
extern str     match_domain_col;
extern str     method_col;
extern str     verify_cert_col;
extern str     require_cert_col;
extern str     certificate_col;
extern str     pk_col;
extern str     crl_check_col;
extern str     crl_dir_col;
extern str     calist_col;
extern str     cadir_col;
extern str     cplist_col;
extern str     dhparams_col;
extern str     eccurve_col;

extern int      tls_client_domain_avp;
extern int      sip_client_domain_avp;

#endif
