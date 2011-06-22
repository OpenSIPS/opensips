/*
 * $Id$
 *
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
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "tls_config.h"
#include "../config.h"

int             tls_log;

int             tls_method = TLS_USE_SSLv23;

/*
 * These are the default values which will be used
 * for default domains AND virtual domains
 */

/* enable certificate validation as default value */
int             tls_verify_client_cert  = 1;
int             tls_verify_server_cert  = 1;
int             tls_require_client_cert = 1;
/* default location of certificates */
char           *tls_cert_file = TLS_CERT_FILE;
char           *tls_pkey_file = TLS_PKEY_FILE;
char           *tls_ca_file   = TLS_CA_FILE;
/* defaul cipher=0, this means the DEFAULT ciphers */
char           *tls_ciphers_list = 0;
/* TLS timeouts; should be low to detect problems fast */
int             tls_handshake_timeout = 30;
int             tls_send_timeout      = 30;
/* per default, the TLS domains do not have a name */
int             tls_client_domain_avp = -1;

