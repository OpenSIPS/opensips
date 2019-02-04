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
#include "mem/mem.h"



struct host_alias{
	str alias;
	unsigned short port;
	unsigned short proto;
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
	for(a=aliases;a;a=a->next)
		if ((a->alias.len==len) && ((a->port==0) || (port==0) ||
				(a->port==port)) && ((a->proto==0) || (proto==0) ||
				(a->proto==proto)) && (strncasecmp(a->alias.s, name, len)==0))
			return 1;

	for( af=alias_fcts ; af ; af=af->next ) {
		if ( af->alias_f(name,len,port,proto)>0 )
			return 1;
	}
	return 0;
}


/* adds an alias to the list (only if it isn't already there) */
int add_alias(char* name, int len, unsigned short port, unsigned short proto);

/* register a new function for detecting aliases */
int register_alias_fct( is_alias_fct *fct );

#endif /* NAME_ALIAS_H */
