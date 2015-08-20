/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * -------
 *  2003-02-13  added proto to struct proxy_l & to *_proxy functions (andrei)
 *  2007-01-25  support for DNS failover added into proxy structure;
 *              unused members removed (bogdan)
 */


#ifndef _core_proxy_h
#define _core_proxy_h

#include <netdb.h>
#include "ip_addr.h"
#include "str.h"

struct dns_node;

#define PROXY_SHM_FLAG  (1<<0)

struct proxy_l{
	str name; /* original name */
	unsigned short flags;
	unsigned short port;
	unsigned short proto;

	unsigned short addr_idx; /* crt. addr. idx. */
	struct hostent host;     /* addresses */

	/* tree with the DNS resolving status
	 * NOTE: this is all the time in SHM */
	struct dns_node *dn;
};

extern struct proxy_l* proxies;

struct proxy_l* mk_proxy( str* name, unsigned short port, unsigned short proto,
		int is_sips);
struct proxy_l* mk_shm_proxy(str* name, unsigned short port, unsigned short proto,
		int is_sips);
struct proxy_l* mk_proxy_from_ip(struct ip_addr* ip, unsigned short port,
		unsigned short proto);

void free_proxy(struct proxy_l* p);
void free_shm_proxy(struct proxy_l* p);

void free_hostent(struct hostent *dst);

int  hostent_cpy(struct hostent *dst, struct hostent* src);

int  hostent_shm_cpy(struct hostent *dst, struct hostent* src);

void free_shm_hostent(struct hostent *dst);

struct proxy_l* clone_proxy(struct proxy_l *sp);

#include "resolve.h"

#endif

