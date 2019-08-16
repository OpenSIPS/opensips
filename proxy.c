/*
 * proxy list & assoc. functions
 *
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
 *  2003-02-13  all *proxy functions are now proto aware (andrei)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2007-01-25  support for DNS failover added into proxy structure;
 *              new shm functions for copy/free added (bogdan)
 */



#include "config.h"
#include "globals.h"
#include "proxy.h"
#include "error.h"
#include "dprint.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#ifdef DNS_IP_HACK
#include "ut.h"
#endif

#include "resolve.h"
#include "ip_addr.h"
#include "globals.h"


struct proxy_l* proxies=0;

int disable_dns_failover=0;


int hostent_shm_cpy(struct hostent *dst, struct hostent* src)
{
	int  i;
	char *p;

	for( i=0 ; src->h_addr_list[i] ; i++ );

	dst->h_addr_list = (char**)shm_malloc
		(i * (src->h_length + sizeof(char*)) + sizeof(char*));
	if (dst->h_addr_list==NULL)
		return -1;

	p = ((char*)dst->h_addr_list) + (i+1)*sizeof(char*);
	dst->h_addr_list[i] = 0;

	for( i-- ; i>=0 ; i-- ) {
		dst->h_addr_list[i] = p;
		memcpy( dst->h_addr_list[i], src->h_addr_list[i], src->h_length );
		p += src->h_length;
	}

	dst->h_addr = dst->h_addr_list[0];
	dst->h_addrtype = src->h_addrtype;
	dst->h_length = src->h_length;
	return 0;
}


void free_shm_hostent(struct hostent *dst)
{
	if (dst->h_addr_list)
		shm_free(dst->h_addr_list);
}


/* copies a hostent structure*, returns 0 on success, <0 on error*/
int hostent_cpy(struct hostent *dst, struct hostent* src)
{
	unsigned int len,len2, i, r;
	int ret;

	/* start copying the host entry.. */
	/* copy h_name */
	len=strlen(src->h_name)+1;
	dst->h_name=(char*)pkg_malloc(sizeof(char) * len);
	if (dst->h_name) strncpy(dst->h_name,src->h_name, len);
	else{
		ser_error=ret=E_OUT_OF_MEM;
		goto error;
	}

	/* copy h_aliases */
	len=0;
	if (src->h_aliases)
		for (;src->h_aliases[len];len++);
	dst->h_aliases=(char**)pkg_malloc(sizeof(char*)*(len+1));
	if (dst->h_aliases==0){
		ser_error=ret=E_OUT_OF_MEM;
		pkg_free(dst->h_name);
		goto error;
	}
	memset((void*)dst->h_aliases, 0, sizeof(char*) * (len+1) );
	for (i=0;i<len;i++){
		len2=strlen(src->h_aliases[i])+1;
		dst->h_aliases[i]=(char*)pkg_malloc(sizeof(char)*len2);
		if (dst->h_aliases[i]==0){
			ser_error=ret=E_OUT_OF_MEM;
			pkg_free(dst->h_name);
			for(r=0; r<i; r++)	pkg_free(dst->h_aliases[r]);
			pkg_free(dst->h_aliases);
			goto error;
		}
		strncpy(dst->h_aliases[i], src->h_aliases[i], len2);
	}
	/* copy h_addr_list */
	len=0;
	if (src->h_addr_list)
		for (;src->h_addr_list[len];len++);
	dst->h_addr_list=(char**)pkg_malloc(sizeof(char*)*(len+1));
	if (dst->h_addr_list==0){
		ser_error=ret=E_OUT_OF_MEM;
		pkg_free(dst->h_name);
		for(r=0; dst->h_aliases[r]; r++)	pkg_free(dst->h_aliases[r]);
		pkg_free(dst->h_aliases);
		goto error;
	}
	memset((void*)dst->h_addr_list, 0, sizeof(char*) * (len+1) );
	for (i=0;i<len;i++){
		dst->h_addr_list[i]=(char*)pkg_malloc(sizeof(char)*src->h_length);
		if (dst->h_addr_list[i]==0){
			ser_error=ret=E_OUT_OF_MEM;
			pkg_free(dst->h_name);
			for(r=0; dst->h_aliases[r]; r++)	pkg_free(dst->h_aliases[r]);
			pkg_free(dst->h_aliases);
			for (r=0; r<i;r++) pkg_free(dst->h_addr_list[r]);
			pkg_free(dst->h_addr_list);
			goto error;
		}
		memcpy(dst->h_addr_list[i], src->h_addr_list[i], src->h_length);
	}

	/* copy h_addr_type & length */
	dst->h_addrtype=src->h_addrtype;
	dst->h_length=src->h_length;
	/*finished hostent copy */

	return 0;

error:
	LM_CRIT("pkg memory allocation failure\n");
	return ret;
}



void free_hostent(struct hostent *dst)
{
	int r;
	if (dst->h_name) pkg_free(dst->h_name);
	if (dst->h_aliases){
		for(r=0; dst->h_aliases[r]; r++) {
			pkg_free(dst->h_aliases[r]);
		}
		pkg_free(dst->h_aliases);
	}
	if (dst->h_addr_list){
		for (r=0; dst->h_addr_list[r];r++) {
			pkg_free(dst->h_addr_list[r]);
		}
		pkg_free(dst->h_addr_list);
	}
}



/* Creates a proxy structure out of the host, port and proto
 * uses also SRV if possible & port==0 (quick hack) */

struct proxy_l* mk_proxy(str* name, unsigned short port, unsigned short proto,
		int is_sips)
{
	struct proxy_l* p;
	struct hostent* he;

	p=(struct proxy_l*) pkg_malloc(sizeof(struct proxy_l));
	if (p==0){
		ser_error=E_OUT_OF_MEM;
		LM_CRIT("pkg memory allocation failure\n");
		goto error;
	}
	memset(p,0,sizeof(struct proxy_l));
	p->name=*name;
	p->port=port;
	p->proto=proto;

	LM_DBG("doing DNS lookup...\n");
	he = sip_resolvehost(name, &(p->port), &p->proto, is_sips,
		disable_dns_failover?0:&p->dn );
	if (!he || !he->h_addr_list[0]) {
		ser_error=E_BAD_ADDRESS;
		LM_CRIT("could not resolve hostname: \"%.*s\"%s\n",
		        name->len, name->s, he ? " (0 results)" : "");
		pkg_free(p);
		goto error;
	}
	if (hostent_cpy(&(p->host), he)!=0){
		free_dns_res( p );
		pkg_free(p);
		goto error;
	}
	return p;
error:
	return 0;
}



/* same as mk_proxy, but in shared memory
 * uses also SRV if possible & port==0 (quick hack) */
struct proxy_l* mk_proxy_from_ip(struct ip_addr* ip, unsigned short port,
		unsigned short proto)
{
	struct proxy_l* p;

	p=(struct proxy_l*) pkg_malloc(sizeof(struct proxy_l));
	if (p==0){
		LM_CRIT("pkg memory allocation failure\n");
		goto error;
	}
	memset(p,0,sizeof(struct proxy_l));

	p->port=port;
	p->proto=proto;
	p->host.h_addrtype=ip->af;
	p->host.h_length=ip->len;
	p->host.h_addr_list=pkg_malloc(2*sizeof(char*));
	if (p->host.h_addr_list==0) goto error;
	p->host.h_addr_list[1]=0;
	p->host.h_addr_list[0]=pkg_malloc(ip->len+1);
	if (p->host.h_addr_list[0]==0){
		pkg_free(p->host.h_addr_list);
		goto error;
	}

	memcpy(p->host.h_addr_list[0], ip->u.addr, ip->len);
	p->host.h_addr_list[0][ip->len]=0;

	return p;

error:
	return 0;
}



void free_proxy(struct proxy_l* p)
{
	if (p) {
		free_hostent(&p->host);
		free_dns_res( p );
	}
}


void free_shm_proxy(struct proxy_l* p)
{
	if (p) {
		free_shm_hostent(&p->host);
		free_dns_res(p);
	}
}

/* same as add_proxy, but it doesn't add the proxy to the list
 * uses also SRV if possible & port==0 (quick hack)
   works in shared memory */
struct proxy_l* mk_shm_proxy(str* name, unsigned short port, unsigned short proto,
		int is_sips)
{
	struct proxy_l* p;
	struct hostent* he;

	p=(struct proxy_l*) shm_malloc(sizeof(struct proxy_l));
	if (p==0){
		ser_error=E_OUT_OF_MEM;
		LM_CRIT("shm memory allocation failure\n");
		goto error;
	}
	memset(p,0,sizeof(struct proxy_l));
	p->name=*name;
	p->port=port;
	p->proto=proto;

	LM_DBG("doing DNS lookup...\n");
	he = sip_resolvehost(name, &(p->port), &p->proto, is_sips,
		disable_dns_failover?0:&p->dn );
	if (he==0){
		ser_error=E_BAD_ADDRESS;
		LM_CRIT("could not resolve hostname: \"%.*s\"\n", name->len, name->s);
		shm_free(p);
		goto error;
	}
	if (hostent_shm_cpy(&(p->host), he)!=0){
		free_dns_res( p );
		shm_free(p);
		goto error;
	}
	return p;
error:
	return 0;
}

/* clones a proxy into pkg memory */
struct proxy_l* clone_proxy(struct proxy_l *sp)
{
	struct proxy_l *dp;

	dp = (struct proxy_l*)pkg_malloc(sizeof(struct proxy_l));
	if (dp==NULL) {
		LM_ERR("no more pkg memory\n");
		return 0;
	}
	memset( dp , 0 , sizeof(struct proxy_l));

	dp->port = sp->port;
	dp->proto = sp->proto;
	dp->addr_idx = sp->addr_idx;

	/* clone the hostent */
	if (hostent_cpy( &dp->host, &sp->host)!=0)
		goto error0;

	/* clone the dns resolver */
	if (sp->dn) {
		dp->dn = dns_res_copy(sp->dn);
		if (dp->dn==NULL)
			goto error1;
	}

	return dp;
error1:
	free_hostent(&dp->host);
error0:
	pkg_free(dp);
	return 0;
}


