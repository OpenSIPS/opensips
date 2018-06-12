/*
 * $Id$
 *
 *
 * Copyright (C) 2001-2003 Fhg Fokus
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
 */



#include "str.h"
#include "dprint.h"
#include "mem/mem.h"



struct host_alias{
	str alias;
	unsigned short port;
	struct host_alias* next;
};


extern struct host_alias* aliases;



/* returns 1 if  name is in the alias list; if port=0, port no is ignored*/
static inline int grep_aliases(char* name, int len, unsigned short port)
{
	struct  host_alias* a;
	
	for(a=aliases;a;a=a->next)
#ifdef USE_TLS
		if ((a->alias.len==len) && ((a->port==0) || (port==0) || 
					(port==tls_port_no) ||
#else
		if ((a->alias.len==len) && ((a->port==0) || (port==0) || 
#endif
				(a->port==port)) && (strncasecmp(a->alias.s, name, len)==0))
			return 1;
	return 0;
}



/* adds an alias to the list (only if it isn't already there)
 * if port==0, the alias will match all the ports
 * returns 1 if a new alias was added, 0 if the alias was already on the list
 * and  -1 on error */
static inline int add_alias(char* name, int len, unsigned short port)
{
	struct host_alias* a;
	
	if ((port) && grep_aliases(name,len, port)) return 0;
	a=0;
	a=(struct host_alias*)pkg_malloc(sizeof(struct host_alias));
	if(a==0) goto error;
	a->alias.s=(char*)pkg_malloc(len+1);
	if (a->alias.s==0) goto error;
	a->alias.len=len;
	memcpy(a->alias.s, name, len);
	a->alias.s[len]=0; /* null terminate for easier printing*/
	a->port=port;
	a->next=aliases;
	aliases=a;
	return 1;
error:
	LOG(L_ERR, "ERROR: add_alias: memory allocation error\n");
	if (a) pkg_free(a);
	return -1;
}



