/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
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

int             tls_verify_cert = 0;
int             tls_require_cert = 0;
char           *tls_cert_file = TLS_CERT_FILE;
char           *tls_pkey_file = TLS_PKEY_FILE;
char           *tls_ca_file = TLS_CA_FILE;
char           *tls_ciphers_list = 0;
int             tls_handshake_timeout = 120;
int             tls_send_timeout = 120;
