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

#ifndef TLS_DOMAIN_H
#define TLS_DOMAIN_H

#include "../str.h"
#include "../ip_addr.h"
#include "tls_config.h"
#include <openssl/ssl.h>

/*
 * separate configuration per ip:port 
 */
struct tls_domain {
	struct ip_addr  addr;
	unsigned short  port;
	SSL_CTX        *ctx;
	char           *cert_file;
	char           *pkey_file;
	char           *ca_file;
	enum tls_method method;
	struct tls_domain *next;
};

extern struct tls_domain *tls_domains;

/*
 * find domain with given ip and port 
 */
struct tls_domain *tls_find_domain(struct ip_addr *ip,
				   unsigned short port);

/*
 * create a new domain 
 */
int             tls_new_domain(struct ip_addr *ip, unsigned short port);

/*
 * clean up 
 */
void            tls_free_domains(void);

#endif
