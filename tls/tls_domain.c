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

#include "tls_server.h"
#include "tls_domain.h"
#include <stdlib.h>

struct tls_domain *tls_domains = NULL;

/*
 * find domain with given ip and port 
 */
struct tls_domain *
tls_find_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *p = tls_domains;
	while (p) {
		if ((p->port == port) && ip_addr_cmp(&p->addr, ip))
			return p;
		p = p->next;
    }
    return 0;
}


/*
 * create a new domain 
 */
int
tls_new_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *d;

	d = pkg_malloc(sizeof(struct tls_domain));
	if (d == NULL) {
		LOG(L_ERR, "tls_new_domain: Memory allocation failure\n");
		return -1;
	}
	memset(d, '\0', sizeof(struct tls_domain));
	memcpy(&d->addr, ip, sizeof(struct ip_addr));
	d->port = port;
	d->next = tls_domains;
	tls_domains = d;
	return 0;
}


/*
 * clean up 
 */
void
tls_free_domains(void)
{
	struct tls_domain *p;
	while (tls_domains) {
		p = tls_domains;
		tls_domains = tls_domains->next;
		pkg_free(p);
    }
}
