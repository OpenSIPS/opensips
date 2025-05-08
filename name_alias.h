/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2009 Voice Sistem SRL
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
 * --------
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-10-21  support for proto added: proto:host:port (andrei)
 *  2009-02-01  added interface to registed additional functions for checking
 *              the aliases (bogdan)
 */

#ifndef NAME_ALIAS_H
#define NAME_ALIAS_H


#include <strings.h>
#include "str.h"
#include "dprint.h"
#include "ip_addr.h"
#include "mem/mem.h"

#define si_alias_accept_subdomain(_flags) (int) _flags & SI_ACCEPT_SUBDOMAIN_ALIAS

struct host_alias{
	str alias;
	unsigned short port;
	unsigned short proto;
	int accept_subdomain;
	struct host_alias* next;
};


extern struct host_alias* aliases;


typedef int (is_alias_fct)(char* name, int len, unsigned short port,
		unsigned short proto);

struct alias_function {
	is_alias_fct *alias_f;
	struct alias_function *next;
};

extern struct alias_function* alias_fcts;

static inline int match_domain(char* alias, int alias_len, char* host, int host_len, int accept_subdomain) {
	int index_offset;

	/* Check if the alias is a subdomain alias and if so calculate the index offset to start the comparison
	 * Given an alias my.domain.com or my.great.domain.com and a subdomain of domain.com the comparison should start at domain.com
	 * a host of domain.com will also match, if the flag is not set then do a strict comparison
	 */
	if (accept_subdomain) {
		index_offset = host_len - alias_len;
		// the host we're checking is a shorter len than the alias so no need to compare
		if (index_offset < 0) return 0;
		// if the offset is greater than 0 we need to ensure the host we're checking has a preceding '.' to ensure it's a subdomain
		else if (index_offset > 0 && !(*((host + index_offset) - 1) == '.')) return 0;

		if (strncasecmp(alias, host + index_offset, alias_len)==0)
			return 1;
	} else if (host_len == alias_len && strncasecmp(alias, host, host_len)==0) {
		return 1;
	}

	return 0;
}

/* returns 1 if  name is in the alias list; if port=0, port no is ignored
 * if proto=0, proto is ignored*/
static inline int grep_aliases(char* name, int len, unsigned short port,
								unsigned short proto)
{
	struct  host_alias* a;
	struct alias_function *af;

	if ((len>2)&&((*name)=='[')&&(name[len-1]==']')){
		/* ipv6 reference, skip [] */
		name++;
		len-=2;
	}

	for(a=aliases;a;a=a->next) {
		if (((a->port==0) || (port==0) || (a->port==port)) &&
		    ((a->proto==0) || (proto==0) || (a->proto==proto))) {
			if (match_domain(a->alias.s, a->alias.len, name, len, a->accept_subdomain))
				return 1;
		}
	}

	for( af=alias_fcts ; af ; af=af->next ) {
		if ( af->alias_f(name,len,port,proto)>0 )
			return 1;
	}
	return 0;
}

/* adds an alias to the list (only if it isn't already there) */
int add_alias(char* name, int len, unsigned short port, unsigned short proto, int accept_subdomain);

/* register a new function for detecting aliases */
int register_alias_fct( is_alias_fct *fct );

#endif /* NAME_ALIAS_H */
