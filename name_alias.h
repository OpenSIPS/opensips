/*
 * $Id$
 *
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * History:
 * --------
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-10-21  support for proto added: proto:host:port (andrei)
 */



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



/* returns 1 if  name is in the alias list; if port=0, port no is ignored
 * if proto=0, proto is ignored*/
static inline int grep_aliases(char* name, int len, unsigned short port,
								unsigned short proto)
{
	struct  host_alias* a;
	
#ifdef USE_IPV6
	if ((len>2)&&((*name)=='[')&&(name[len-1]==']')){
		/* ipv6 reference, skip [] */
		name++;
		len-=2;
	}
#endif
	for(a=aliases;a;a=a->next)
		if ((a->alias.len==len) && ((a->port==0) || (port==0) || 
				(a->port==port)) && ((a->proto==0) || (proto==0) || 
				(a->proto==proto)) && (strncasecmp(a->alias.s, name, len)==0))
			return 1;
	return 0;
}



/* adds an alias to the list (only if it isn't already there)
 * if port==0, the alias will match all the ports
 * if proto==0, the alias will match all the protocols
 * returns 1 if a new alias was added, 0 if a matching alias was already on
 * the list and  -1 on error */
static inline int add_alias(char* name, int len, unsigned short port, 
								unsigned short proto)
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
	LOG(L_ERR, "ERROR: add_alias: memory allocation error\n");
	if (a) pkg_free(a);
	return -1;
}



