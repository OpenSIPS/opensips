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
 * --------
 *  2003-04-12  support for resolving ipv6 address references added (andrei)
 *  2004-07-28  darwin needs nameser_compat.h (andrei)
 *  2007-01-25  support for DNS failover added (bogdan)
 */

/*!
 * \file
 * \brief DNS resolver related functions
 */


#ifndef __resolve_h
#define __resolve_h

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/nameser.h>

#ifdef __OS_darwin
#include <arpa/nameser_compat.h>
#endif

#include "mem/shm_mem.h"
#include "ip_addr.h"
#include "proxy.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif


#define MAX_QUERY_SIZE 8192
#define ANS_SIZE       8192
#define DNS_HDR_SIZE     12
#define MAX_DNS_NAME 256
#define MAX_DNS_STRING 255

/*! \brief this is not official yet */
#define T_EBL		65300

typedef void* (fetch_dns_cache_f)(char *name,int r_type,int name_len);
typedef int (put_dns_cache_f)(char *name,int r_type,void *record,int rdata_len,
				int failure,int ttl);

extern fetch_dns_cache_f *dnscache_fetch_func;
extern put_dns_cache_f *dnscache_put_func;

/*! \brief query union*/
union dns_query{
	HEADER hdr;
	unsigned char buff[MAX_QUERY_SIZE];
};


/*! \brief rdata struct*/
struct rdata {
	unsigned short type;
	unsigned short class;
	unsigned int   ttl;
	void* rdata;
	struct rdata* next;
};


/*! \brief srv rec. struct*/
struct srv_rdata {
	unsigned short priority;
	unsigned short weight;
	unsigned short running_sum;
	unsigned short port;
	unsigned int name_len;
	char name[MAX_DNS_NAME];
};

/*! \brief naptr rec. struct*/
struct naptr_rdata {
	unsigned short order;
	unsigned short pref;
	unsigned int flags_len;
	char flags[MAX_DNS_STRING];
	unsigned int services_len;
	char services[MAX_DNS_STRING];
	unsigned int regexp_len;
	char regexp[MAX_DNS_STRING];
	unsigned int repl_len; /* not currently used */
	char repl[MAX_DNS_NAME];
};


/*! \brief A rec. struct */
struct a_rdata {
	unsigned char ip[4];
};

struct aaaa_rdata {
	unsigned char ip6[16];
};

/*! \brief cname rec. struct*/
struct cname_rdata {
	char name[MAX_DNS_NAME];
};

/*! \brief txt rec. struct
\note	This is not strictly correct as TXT records *could* contain multiple strings. */
struct txt_rdata {
	char txt[MAX_DNS_NAME];
};

/*! \brief EBL rec. struct
\note This is an experimental RR for infrastructure ENUM */
struct ebl_rdata {
	unsigned char position;
	unsigned int separator_len;
	char separator[MAX_DNS_NAME];
	unsigned int apex_len;
	char apex[MAX_DNS_NAME];
};

/*! \brief DNS failover related structures */
struct dns_node {
	unsigned short type;
	unsigned short size;
	unsigned short idx;
	unsigned short no;
	struct dns_val *vals;
	struct dns_node *kids;
};


struct rdata* get_record(char* name, int type);
void free_rdata_list(struct rdata* head);


extern int dns_try_ipv6;
extern int dns_try_naptr;


#define get_naptr(_rdata) \
	( ((struct naptr_rdata*)(_rdata)->rdata) )

#define get_srv(_rdata) \
	( ((struct srv_rdata*)(_rdata)->rdata) )


int  check_ip_address(struct ip_addr* ip, str *name,
		unsigned short port, unsigned short proto, int resolver);

struct hostent* sip_resolvehost(str* name, unsigned short* port,
		unsigned short *proto, int is_sips, struct dns_node **dn);

struct hostent* resolvehost(char* name, int no_ip_test);

struct hostent* rev_resolvehost(struct ip_addr *ip);

/*! \brief Generic "ip[:port]" string parsing + resolving */
int resolve_hostport(str *in, unsigned short default_port,
                     union sockaddr_union *dst);

/*! \brief free the DNS resolver state machine */
void free_dns_res( struct proxy_l *p );

/*! \brief make a perfect copy of a resolver state machine */
struct dns_node *dns_res_copy(struct dns_node *s);

/*! \brief taked the next destination from a resolver state machine */
int get_next_su(struct proxy_l *p, union sockaddr_union* su, int add_to_bl);


int resolv_init();

int resolv_blacklist_init();



static inline struct proxy_l* shm_clone_proxy(struct proxy_l *sp,
													unsigned int move_dn)
{
	struct proxy_l *dp;

	dp = (struct proxy_l*)shm_malloc(sizeof(struct proxy_l));
	if (dp==NULL) {
		LM_ERR("no more shm memory\n");
		return 0;
	}
	memset( dp , 0 , sizeof(struct proxy_l));

	dp->port = sp->port;
	dp->proto = sp->proto;
	dp->addr_idx = sp->addr_idx;
	dp->flags = PROXY_SHM_FLAG;

	/* clone the hostent */
	if (hostent_shm_cpy( &dp->host, &sp->host)!=0)
		goto error0;

	/* clone the dns resolver */
	if (sp->dn) {
		if (move_dn) {
			dp->dn = sp->dn;
			sp->dn = 0;
		} else {
			dp->dn = dns_res_copy(sp->dn);
			if (dp->dn==NULL)
				goto error1;
		}
	}

	return dp;
error1:
	free_shm_hostent(&dp->host);
error0:
	shm_free(dp);
	return 0;
}



#endif
