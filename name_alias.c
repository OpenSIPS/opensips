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
 *  2009-02-02  splitted from name_alias.h (bogdan)
 *  2009-02-01  added interface to registed additional functions for checking
 *              the aliases (bogdan)
 */

#include <string.h>
#include "name_alias.h"


struct host_alias* aliases=0; /* name aliases list */

struct alias_function* alias_fcts = NULL;



/* adds an alias to the list (only if it isn't already there)
 * if port==0, the alias will match all the ports
 * if proto==0, the alias will match all the protocols
 * returns 1 if a new alias was added, 0 if a matching alias was already on
 * the list and  -1 on error */
int add_alias(char* name, int len, unsigned short port, unsigned short proto)
{
	struct host_alias* a;

	if ((port) && (proto)){
		/* don't add if there is already an alias matching it */
		if (grep_aliases(name,len, port, proto)) return 0;
	}else{
		/* don't add if already in the list with port or proto ==0*/
		for(a=aliases;a;a=a->next)
			if ((a->alias.len==len) && (a->port==port) && (a->proto==proto) &&
					(strncasecmp(a->alias.s, name, len)==0))
				return 0;
	}
	a=(struct host_alias*)pkg_malloc(sizeof(struct host_alias));
	if(a==0) goto error;
	a->alias.s=(char*)pkg_malloc(len+1);
	if (a->alias.s==0) goto error;
	a->alias.len=len;
	memcpy(a->alias.s, name, len);
	a->alias.s[len]=0; /* null terminate for easier printing*/
	a->port=port;
	a->proto=proto;
	a->next=aliases;
	aliases=a;
	return 1;
error:
	LM_ERR("pkg memory allocation error\n");
	if (a) pkg_free(a);
	return -1;
}


int register_alias_fct( is_alias_fct *fct )
{
	struct alias_function *af;

	af = (struct alias_function *)pkg_malloc(sizeof(struct alias_function));
	if (af==NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	af->alias_f = fct;
	af->next = alias_fcts;
	alias_fcts = af;

	return 0;
}


