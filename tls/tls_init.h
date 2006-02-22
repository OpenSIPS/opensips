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

#ifndef tls_init_h
#define tls_init_h

#include <openssl/ssl.h>
#include "tls_config.h"
#include "../tcp_conn.h"

extern SSL_CTX *ssl_contexts[TLS_USE_SSLv23 + 1];

extern SSL_CTX *default_client_ctx;
extern SSL_CTX *default_server_ctx;

/*
 * just once before cleanup 
 */
void            destroy_tls(void);

/*
 * for each socket 
 */
int             tls_init(struct socket_info *si);

/*
 * just once, initialize the tls subsystem 
 */
int             init_tls(void);

#endif
