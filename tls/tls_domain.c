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

#include "tls_server.h"
#include "tls_domain.h"
#include <stdlib.h>

struct tls_domain *tls_server_domains = NULL;
struct tls_domain *tls_client_domains = NULL;
struct tls_domain *tls_default_server_domain = NULL;
struct tls_domain *tls_default_client_domain = NULL;

/*
 * find server domain with given ip and port 
 * return default domain if virtual domain not found
 */
struct tls_domain *
tls_find_server_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *p = tls_server_domains;
	while (p) {
		if ((p->port == port) && ip_addr_cmp(&p->addr, ip)) {
			LM_DBG("virtual TLS server domain found\n");
			return p;
		}
		p = p->next;
	}
	LM_DBG("virtual TLS server domain not found, "
		"Using default TLS server domain settings\n");
	return tls_default_server_domain;
}

/*
 * find client domain with given ip and port,
 * return default domain if virtual domain not found
 */
struct tls_domain *
tls_find_client_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *p = tls_client_domains;
	while (p) {
		if ((p->name.len == 0) && (p->port == port) && ip_addr_cmp(&p->addr, ip)) {
			LM_DBG("virtual TLS client domain found\n");
			return p;
		}
		p = p->next;
	}
	LM_DBG("virtual TLS client domain not found, "
		"Using default TLS client domain settings\n");
	return tls_default_client_domain;
}

/*
 * find client domain with given name,
 * return 0 if name based virtual domain not found
 */
struct tls_domain *
tls_find_client_domain_name(str name)
{
	struct tls_domain *p = tls_client_domains;
	while (p) {
		if ((p->name.len == name.len) && !strncasecmp(p->name.s, name.s, name.len)) {
			LM_DBG("virtual TLS client domain found\n");
			return p;
		}
		p = p->next;
	}
	LM_DBG("virtual TLS client domain not found\n");
	return 0;
}


/*
 * create a new server domain (identified by a socket)
 */
int
tls_new_server_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *d;

	d = tls_new_domain(TLS_DOMAIN_SRV);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return -1;
	}

	/* fill socket data */
	memcpy(&d->addr, ip, sizeof(struct ip_addr));
	d->port = port;

	/* add this new domain to the linked list */
	d->next = tls_server_domains;
	tls_server_domains = d;
	return 0;
}

/*
 * create a new client domain (identified by a socket)
 */
int
tls_new_client_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *d;

	d = tls_new_domain(TLS_DOMAIN_CLI);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return -1;
	}

	/* fill socket data */
	memcpy(&d->addr, ip, sizeof(struct ip_addr));
	d->port = port;

	/* add this new domain to the linked list */
	d->next = tls_client_domains;
	tls_client_domains = d;
	return 0;
}

/*
 * create a new client domain (identified by a string)
 */
int
tls_new_client_domain_name(char *s, int len)
{
	struct tls_domain *d;

	d = tls_new_domain(TLS_DOMAIN_CLI | TLS_DOMAIN_NAME);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return -1;
	}

	/* initialize name data */
	d->name.s = pkg_malloc(len);
	if (d->name.s == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		pkg_free(d);
		return -1;
	}
	memcpy(d->name.s, s, len);
	d->name.len = len;

	/* add this new domain to the linked list */
	d->next = tls_client_domains;
	tls_client_domains = d;
	return 0;
}

/*
 * allocate memory and set default values for
 * TLS domain structure
 */
struct tls_domain *tls_new_domain(int type)
{
	struct tls_domain *d;

	d = pkg_malloc(sizeof(struct tls_domain));
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return 0;
	}
	memset( d, 0, sizeof(struct tls_domain));

	d->type = type;

	if (type & TLS_DOMAIN_SRV) {
		d->verify_cert         = tls_verify_client_cert;
		d->require_client_cert = tls_require_client_cert;
	} else {
		d->verify_cert         = tls_verify_server_cert;
		d->require_client_cert = 0;
	}
	d->method = TLS_METHOD_UNSPEC;

	return d;
}

/*
 * clean up 
 */
void
tls_free_domains(void)
{
	struct tls_domain *p;
	while (tls_server_domains) {
		p = tls_server_domains;
		tls_server_domains = tls_server_domains->next;
		pkg_free(p);
	}
	while (tls_client_domains) {
		p = tls_client_domains;
		tls_client_domains = tls_client_domains->next;
		/* ToDo: If socket based client domains will be implemented, the name may
		   be empty (must be set to NULL manually). Thus no need to free it */
		if (p->name.s) {
			pkg_free(p->name.s);
		}
		pkg_free(p);
	}
	pkg_free(tls_default_client_domain);
	pkg_free(tls_default_server_domain);
}

