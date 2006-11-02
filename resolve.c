/* $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2005-2006 Voice Sistem S.R.L.
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
 *
 * History:
 * -------
 *  2003-02-13  added proto to sip_resolvehost, for SRV lookups (andrei)
 *  2003-07-03  default port value set according to proto (andrei)
 */ 


#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>

#include "resolve.h"
#include "dprint.h"
#include "mem/mem.h"
#include "ip_addr.h"
#include "globals.h"



/* mallocs for local stuff */
#define local_malloc pkg_malloc
#define local_free   pkg_free

int dns_try_ipv6=1; /* default on */
/* declared in globals.h */
int dns_retr_time=-1;
int dns_retr_no=-1;
int dns_servers_no=-1;
int dns_search_list=-1;
  	 
  	 
/* init. the resolver
 * params: retr_time  - time before retransmitting (must be >0)
 *         retr_no    - retransmissions number
 *         servers_no - how many dns servers will be used
 *                      (from the one listed in /etc/resolv.conf)
 *         search     - if 0 the search list in /etc/resolv.conf will
 *                      be ignored (HINT: even if you don't have a
 *                      search list in resolv.conf, it's still better
 *                      to set search to 0, because an empty seachlist
 *                      means in fact search "" => it takes more time)
 * If any of the parameters <0, the default (system specific) value
 * will be used. See also resolv.conf(5).
 * returns: 0 on success, -1 on error
 */
int resolv_init()
{
	res_init();
#ifdef HAVE_RESOLV_RES
	if (dns_retr_time>0)
		_res.retrans=dns_retr_time;
	if (dns_retr_no>0)
		_res.retry=dns_retr_no;
	if (dns_servers_no>=0)
		_res.nscount=dns_servers_no;
	if (dns_search_list==0)
		_res.options&=~(RES_DEFNAMES|RES_DNSRCH);
#else
#warning "no resolv timeout support"
	LOG(L_WARN, "WARNING: resolv_init: no resolv options support - resolv"
		" options will be ignored\n");
#endif
	return 0;
}


 /*  skips over a domain name in a dns message
 *  (it can be  a sequence of labels ending in \0, a pointer or
 *   a sequence of labels ending in a pointer -- see rfc1035
 *   returns pointer after the domain name or null on error*/
unsigned char* dns_skipname(unsigned char* p, unsigned char* end)
{
	while(p<end){
		/* check if \0 (root label length) */
		if (*p==0){
			p+=1;
			break;
		}
		/* check if we found a pointer */
		if (((*p)&0xc0)==0xc0){
			/* if pointer skip over it (2 bytes) & we found the end */
			p+=2;
			break;
		}
		/* normal label */
		p+=*p+1;
	}
	return (p>=end)?0:p;
}



/* parses the srv record into a srv_rdata structure
 *   msg   - pointer to the dns message
 *   end   - pointer to the end of the message
 *   rdata - pointer  to the rdata part of the srv answer
 * returns 0 on error, or a dyn. alloc'ed srv_rdata structure */
/* SRV rdata format:
 *            111111
 *  0123456789012345
 * +----------------+
 * |     priority   |
 * |----------------|
 * |     weight     |
 * |----------------|
 * |   port number  |
 * |----------------|
 * |                |
 * ~      name      ~
 * |                |
 * +----------------+
 */
struct srv_rdata* dns_srv_parser( unsigned char* msg, unsigned char* end,
								  unsigned char* rdata)
{
	struct srv_rdata* srv;
	int len;
	
	srv=0;
	if ((rdata+6)>=end) goto error;
	srv=(struct srv_rdata*)local_malloc(sizeof(struct srv_rdata));
	if (srv==0){
		LOG(L_ERR, "ERROR: dns_srv_parser: out of memory\n");
		goto error;
	}
	
	memcpy((void*)&srv->priority, rdata, 2);
	memcpy((void*)&srv->weight,   rdata+2, 2);
	memcpy((void*)&srv->port,     rdata+4, 2);
	rdata+=6;
	srv->priority=ntohs(srv->priority);
	srv->weight=ntohs(srv->weight);
	srv->port=ntohs(srv->port);
	if ((len=dn_expand(msg, end, rdata, srv->name, MAX_DNS_NAME-1))==-1)
		goto error;
	/* add terminating 0 ? (warning: len=compressed name len) */
	return srv;
error:
	if (srv) local_free(srv);
	return 0;
}


/* parses the naptr record into a naptr_rdata structure
 *   msg   - pointer to the dns message
 *   end   - pointer to the end of the message
 *   rdata - pointer  to the rdata part of the naptr answer
 * returns 0 on error, or a dyn. alloc'ed naptr_rdata structure */
/* NAPTR rdata format:
 *            111111
 *  0123456789012345
 * +----------------+
 * |      order     |
 * |----------------|
 * |   preference   |
 * |----------------|
 * ~     flags      ~
 * |   (string)     |
 * |----------------|
 * ~    services    ~
 * |   (string)     |
 * |----------------|
 * ~    regexp      ~
 * |   (string)     |
 * |----------------|
 * ~  replacement   ~
   |    (name)      |
 * +----------------+
 */
struct naptr_rdata* dns_naptr_parser( unsigned char* msg, unsigned char* end,
								  unsigned char* rdata)
{
	struct naptr_rdata* naptr;
	
	naptr = 0;
	if ((rdata + 7) >= end) goto error;
	naptr=(struct naptr_rdata*)local_malloc(sizeof(struct naptr_rdata));
	if (naptr == 0){
		LOG(L_ERR, "ERROR: dns_naptr_parser: out of memory\n");
		goto error;
	}
	
	memcpy((void*)&naptr->order, rdata, 2);
	naptr->order=ntohs(naptr->order);
	memcpy((void*)&naptr->pref, rdata + 2, 2);
	naptr->pref=ntohs(naptr->pref);
	naptr->flags_len = (int)rdata[4];
	if ((rdata + 7 +  naptr->flags_len) >= end) goto error;
	memcpy((void*)&naptr->flags, rdata + 5, naptr->flags_len);
	naptr->services_len = (int)rdata[5 + naptr->flags_len];
	if ((rdata + 7 + naptr->flags_len + naptr->services_len) >= end) goto error;
	memcpy((void*)&naptr->services, rdata + 6 + naptr->flags_len, naptr->services_len);
	naptr->regexp_len = (int)rdata[6 + naptr->flags_len + naptr->services_len];
	if ((rdata + 7 + naptr->flags_len + naptr->services_len +
					naptr->regexp_len) >= end) goto error;
	memcpy((void*)&naptr->regexp, rdata + 7 + naptr->flags_len +
				naptr->services_len, naptr->regexp_len);
	rdata = rdata + 7 + naptr->flags_len + naptr->services_len + 
			naptr->regexp_len;
	naptr->repl_len=dn_expand(msg, end, rdata, naptr->repl, MAX_DNS_NAME-1);
	if ( naptr->repl_len==-1 )
		goto error;
	/* add terminating 0 ? (warning: len=compressed name len) */
	return naptr;
error:
	if (naptr) local_free(naptr);
	return 0;
}



/* parses a CNAME record into a cname_rdata structure */
struct cname_rdata* dns_cname_parser( unsigned char* msg, unsigned char* end,
									  unsigned char* rdata)
{
	struct cname_rdata* cname;
	int len;
	
	cname=0;
	cname=(struct cname_rdata*)local_malloc(sizeof(struct cname_rdata));
	if(cname==0){
		LOG(L_ERR, "ERROR: dns_cname_parser: out of memory\n");
		goto error;
	}
	if ((len=dn_expand(msg, end, rdata, cname->name, MAX_DNS_NAME-1))==-1)
		goto error;
	return cname;
error:
	if (cname) local_free(cname);
	return 0;
}



/* parses an A record rdata into an a_rdata structure
 * returns 0 on error or a dyn. alloc'ed a_rdata struct
 */
struct a_rdata* dns_a_parser(unsigned char* rdata, unsigned char* end)
{
	struct a_rdata* a;
	
	if (rdata+4>=end) goto error;
	a=(struct a_rdata*)local_malloc(sizeof(struct a_rdata));
	if (a==0){
		LOG(L_ERR, "ERROR: dns_a_parser: out of memory\n");
		goto error;
	}
	memcpy(a->ip, rdata, 4);
	return a;
error:
	return 0;
}



/* parses an AAAA (ipv6) record rdata into an aaaa_rdata structure
 * returns 0 on error or a dyn. alloc'ed aaaa_rdata struct */
struct aaaa_rdata* dns_aaaa_parser(unsigned char* rdata, unsigned char* end)
{
	struct aaaa_rdata* aaaa;
	
	if (rdata+16>=end) goto error;
	aaaa=(struct aaaa_rdata*)local_malloc(sizeof(struct aaaa_rdata));
	if (aaaa==0){
		LOG(L_ERR, "ERROR: dns_aaaa_parser: out of memory\n");
		goto error;
	}
	memcpy(aaaa->ip6, rdata, 16);
	return aaaa;
error:
	return 0;
}

/* RFC1035:
 *
 * <character-string> is a single length octet followed by that number of characters.
 * TXT-DATA        One or more <character-string>s.
 *
 * We only take the first string here.
 */
/* parses a TXT record into a txt_rdata structure */
struct txt_rdata* dns_txt_parser( unsigned char* msg, unsigned char* end,
									  unsigned char* rdata)
{
	struct txt_rdata* txt;
	int len;
	
	txt=0;
	txt=(struct txt_rdata*)local_malloc(sizeof(struct txt_rdata));
	if(txt==0){
		LOG(L_ERR, "ERROR: dns_txt_parser: out of memory\n");
		goto error;
	}

	len = *rdata;
	if (rdata + 1 + len >= end) goto error;	/*  something fishy in the record */
	if (len >= sizeof(txt->txt)) goto error; /* not enough space? */
	memcpy(txt->txt, rdata+1, len);
	txt->txt[len] = 0;		/* 0-terminate string */
	return txt;

error:
	if (txt) local_free(txt);
	return 0;
}


/* EBL Record
 *
 *    0  1  2  3  4  5  6  7
 *    +--+--+--+--+--+--+--+--+
 *    |       POSITION        |
 *    +--+--+--+--+--+--+--+--+
 *    /       SEPARATOR       /
 *    +--+--+--+--+--+--+--+--+
 *    /         APEX          /
 *    +--+--+--+--+--+--+--+--+
 */
/* parses a EBL record into a ebl_rdata structure */
struct ebl_rdata* dns_ebl_parser( unsigned char* msg, unsigned char* end,
									  unsigned char* rdata)
{
	struct ebl_rdata* ebl;
	int len;
	
	ebl=0;
	ebl=(struct ebl_rdata*)local_malloc(sizeof(struct ebl_rdata));
	if(ebl==0){
		LOG(L_ERR, "ERROR: dns_ebl_parser: out of memory\n");
		goto error;
	}

	len = *rdata;
	if (rdata + 1 + len >= end) goto error;	/*  something fishy in the record */

	ebl->position = *rdata;
	if ( ebl->position > 15 ) goto error; /* doesn't make sense: E.164 numbers can't be longer */

	rdata++;

	ebl->separator_len = (int) *rdata;
	rdata++;
	if ((rdata + 1 +  ebl->separator_len) >= end) goto error;
	memcpy((void*)&ebl->separator, rdata, ebl->separator_len);
	rdata += ebl->separator_len;

	ebl->apex_len=dn_expand(msg, end, rdata, ebl->apex, MAX_DNS_NAME-1);
	if ( ebl->apex_len==-1 )
		goto error;
	ebl->apex[ebl->apex_len] = 0; /* 0-terminate string */
	return ebl;

error:
	if (ebl) local_free(ebl);
	return 0;
}




/* frees completely a struct rdata list */
void free_rdata_list(struct rdata* head)
{
	struct rdata* l;
	for(l=head; l; l=l->next){
		/* free the parsed rdata*/
		if (l->rdata) local_free(l->rdata);
		local_free(l);
	}
}



/* gets the DNS records for name:type
 * returns a dyn. alloc'ed struct rdata linked list with the parsed responses
 * or 0 on error
 * see rfc1035 for the query/response format */
struct rdata* get_record(char* name, int type)
{
	int size;
	int qno, answers_no;
	int r;
	int ans_len;
	static union dns_query buff;
	unsigned char* p;
	unsigned char* t;
	unsigned char* end;
	static unsigned char answer[ANS_SIZE];
	unsigned short rtype, class, rdlength;
	unsigned int ttl;
	struct rdata* head;
	struct rdata** crt;
	struct rdata** last;
	struct rdata* rd;
	struct srv_rdata* srv_rd;
	struct srv_rdata* crt_srv;
	
	size=res_search(name, C_IN, type, buff.buff, sizeof(buff));
	if (size<0) {
		DBG("get_record: lookup(%s, %d) failed\n", name, type);
		goto not_found;
	}
	else if (size > sizeof(buff)) size=sizeof(buff);
	head=rd=0;
	last=crt=&head;
	
	p=buff.buff+DNS_HDR_SIZE;
	end=buff.buff+size;
	if (p>=end) goto error_boundary;
	qno=ntohs((unsigned short)buff.hdr.qdcount);

	for (r=0; r<qno; r++){
		/* skip the name of the question */
		if ((p=dns_skipname(p, end))==0) {
			LOG(L_ERR, "ERROR: get_record: skipname==0\n");
			goto error;
		}
		p+=2+2; /* skip QCODE & QCLASS */
	#if 0
		for (;(p<end && (*p)); p++);
		p+=1+2+2; /* skip the ending  '\0, QCODE and QCLASS */
	#endif
		if (p>=end) {
			LOG(L_ERR, "ERROR: get_record: p>=end\n");
			goto error;
		}
	};
	answers_no=ntohs((unsigned short)buff.hdr.ancount);
	ans_len=ANS_SIZE;
	t=answer;
	for (r=0; (r<answers_no) && (p<end); r++){
		/*  ignore it the default domain name */
		if ((p=dns_skipname(p, end))==0) {
			LOG(L_ERR, "ERROR: get_record: skip_name=0 (#2)\n");
			goto error;
		}
		/*
		skip=dn_expand(buff.buff, end, p, t, ans_len);
		p+=skip;
		*/
		/* check if enough space is left for type, class, ttl & size */
		if ((p+2+2+4+2)>=end) goto error_boundary;
		/* get type */
		memcpy((void*) &rtype, (void*)p, 2);
		rtype=ntohs(rtype);
		p+=2;
		/* get  class */
		memcpy((void*) &class, (void*)p, 2);
		class=ntohs(class);
		p+=2;
		/* get ttl*/
		memcpy((void*) &ttl, (void*)p, 4);
		ttl=ntohl(ttl);
		p+=4;
		/* get size */
		memcpy((void*)&rdlength, (void*)p, 2);
		rdlength=ntohs(rdlength);
		p+=2;
		/* check for type */
		/*
		if (rtype!=type){
			LOG(L_ERR, "WARNING: get_record: wrong type in answer (%d!=%d)\n",
					rtype, type);
			p+=rdlength;
			continue;
		}
		*/
		/* expand the "type" record  (rdata)*/
		
		rd=(struct rdata*) local_malloc(sizeof(struct rdata));
		if (rd==0){
			LOG(L_ERR, "ERROR: get_record: out of memory\n");
			goto error;
		}
		rd->type=rtype;
		rd->class=class;
		rd->ttl=ttl;
		rd->next=0;
		switch(rtype){
			case T_SRV:
				srv_rd= dns_srv_parser(buff.buff, end, p);
				rd->rdata=(void*)srv_rd;
				if (srv_rd==0) goto error_parse;
				
				/* insert sorted into the list */
				for (crt=&head; *crt; crt= &((*crt)->next)){
					crt_srv=(struct srv_rdata*)(*crt)->rdata;
					if ((srv_rd->priority <  crt_srv->priority) ||
					   ( (srv_rd->priority == crt_srv->priority) && 
							 (srv_rd->weight > crt_srv->weight) ) ){
						/* insert here */
						goto skip;
					}
				}
				last=&(rd->next); /*end of for => this will be the last elem*/
			skip:
				/* insert here */
				rd->next=*crt;
				*crt=rd;
				
				break;
			case T_A:
				rd->rdata=(void*) dns_a_parser(p,end);
				if (rd->rdata==0) goto error_parse;
				*last=rd; /* last points to the last "next" or the list head*/
				last=&(rd->next);
				break;
			case T_AAAA:
				rd->rdata=(void*) dns_aaaa_parser(p,end);
				if (rd->rdata==0) goto error_parse;
				*last=rd;
				last=&(rd->next);
				break;
			case T_CNAME:
				rd->rdata=(void*) dns_cname_parser(buff.buff, end, p);
				if(rd->rdata==0) goto error_parse;
				*last=rd;
				last=&(rd->next);
				break;
			case T_NAPTR:
				rd->rdata=(void*) dns_naptr_parser(buff.buff, end, p);
				if(rd->rdata==0) goto error_parse;
				*last=rd;
				last=&(rd->next);
				break;
			case T_TXT:
				rd->rdata=(void*) dns_txt_parser(buff.buff, end, p);
				if(rd->rdata==0) goto error_parse;
				*last=rd;
				last=&(rd->next);
				break;
			case T_EBL:
				rd->rdata=(void*) dns_ebl_parser(buff.buff, end, p);
				if(rd->rdata==0) goto error_parse;
				*last=rd;
				last=&(rd->next);
				break;
			default:
				LOG(L_ERR, "WARNING: get_record: unknown type %d\n", rtype);
				rd->rdata=0;
				*last=rd;
				last=&(rd->next);
		}
		
		p+=rdlength;
		
	}
	return head;
error_boundary:
		LOG(L_ERR, "ERROR: get_record: end of query buff reached\n");
		if(head)
			free_rdata_list(head);
		return 0;
error_parse:
		LOG(L_ERR, "ERROR: get_record: rdata parse error \n");
		if (rd) local_free(rd); /* rd->rdata=0 & rd is not linked yet into
								   the list */
error:
		LOG(L_ERR, "ERROR: get_record \n");
		if (head) free_rdata_list(head);
not_found:
	return 0;
}


#if 0
/* resolves a host name trying SRV lookup if *port==0 or normal A/AAAA lookup
 * if *port!=0.
 * when performing SRV lookup (*port==0) it will use proto to look for
 * tcp or udp hosts, otherwise proto is unused; if proto==0 => no SRV lookup
 * returns: hostent struct & *port filled with the port from the SRV record;
 *  0 on error
 */
struct hostent* sip_resolvehost_old(str* name, unsigned short* port, int proto)
{
	struct hostent* he;
	struct rdata* head;
	struct rdata* l;
	struct srv_rdata* srv;
	struct ip_addr* ip;
	static char tmp[MAX_DNS_NAME]; /* tmp. buff. for SRV lookups */

	/* try SRV if no port specified (draft-ietf-sip-srv-06) */
	if ((port)&&(*port==0)){
		*port=(proto==PROTO_TLS)?SIPS_PORT:SIP_PORT; /* just in case we don't
														find another */
		if ((name->len+SRV_MAX_PREFIX_LEN+1)>MAX_DNS_NAME){
			LOG(L_WARN, "WARNING: sip_resolvehost: domain name too long (%d),"
						" unable to perform SRV lookup\n", name->len);
		}else{
			/* check if it's an ip address */
			if ( ((ip=str2ip(name))!=0)
#ifdef	USE_IPV6
				  || ((ip=str2ip6(name))!=0)
#endif
				){
				/* we are lucky, this is an ip address */
				return ip_addr2he(name,ip);
			}
			
			switch(proto){
				case PROTO_NONE: /* no proto specified, use udp */
					goto skip_srv;
				case PROTO_UDP:
					memcpy(tmp, SRV_UDP_PREFIX, SRV_UDP_PREFIX_LEN);
					memcpy(tmp+SRV_UDP_PREFIX_LEN, name->s, name->len);
					tmp[SRV_UDP_PREFIX_LEN + name->len] = '\0';
					break;
				case PROTO_TCP:
					memcpy(tmp, SRV_TCP_PREFIX, SRV_TCP_PREFIX_LEN);
					memcpy(tmp+SRV_TCP_PREFIX_LEN, name->s, name->len);
					tmp[SRV_TCP_PREFIX_LEN + name->len] = '\0';
					break;
				case PROTO_TLS:
					memcpy(tmp, SRV_TLS_PREFIX, SRV_TLS_PREFIX_LEN);
					memcpy(tmp+SRV_TLS_PREFIX_LEN, name->s, name->len);
					tmp[SRV_TLS_PREFIX_LEN + name->len] = '\0';
					break;
				default:
					LOG(L_CRIT, "BUG: sip_resolvehost: unknown proto %d\n",
							proto);
					return 0;
			}

			head=get_record(tmp, T_SRV);
			for(l=head; l; l=l->next){
				if (l->type!=T_SRV) continue; /*should never happen*/
				srv=(struct srv_rdata*) l->rdata;
				if (srv==0){
					LOG(L_CRIT, "sip_resolvehost: BUG: null rdata\n");
					free_rdata_list(head);
					break;
				}
				he=resolvehost(srv->name);
				if (he!=0){
					/* we found it*/
					DBG("sip_resolvehost: SRV(%s) = %s:%d\n",
							tmp, srv->name, srv->port);
					*port=srv->port;
					free_rdata_list(head); /*clean up*/
					return he;
				}
			}
			if (head) free_rdata_list(head); /*clean up*/
			DBG("sip_resolvehost: no SRV record found for %.*s," 
					" trying 'normal' lookup...\n", name->len, name->s);
		}
	}
skip_srv:
	if (name->len >= MAX_DNS_NAME) {
		LOG(L_ERR, "sip_resolvehost: domain name too long\n");
		return 0;
	}
	memcpy(tmp, name->s, name->len);
	tmp[name->len] = '\0';
	he=resolvehost(tmp);
	return he;
}
#endif



static inline struct hostent* do_srv_lookup(char *name, unsigned short* port)
{
	struct hostent* he;
	struct srv_rdata* srv;
	struct rdata *head;
	struct rdata *rd;

	/* perform SRV lookup */
	head = get_record( name, T_SRV);
	for( rd=head; rd ; rd=rd->next ) {
		if (rd->type!=T_SRV)
			continue; /*should never happen*/
		srv = (struct srv_rdata*) rd->rdata;
		if (srv==0) {
			LOG(L_CRIT, "BUG:do_srv_lookup: null rdata\n");
			free_rdata_list(head);
			return 0;
		}
		he = resolvehost(srv->name, 1);
		if ( he!=0 ) {
			DBG("DEBUG:do_srv_lookup: SRV(%s) = %s:%d\n",
				name, srv->name, srv->port);
			*port=srv->port;
			free_rdata_list(head);
			return he;
		}
	}
	if (head)
		free_rdata_list(head);
	return 0;
}


#define naptr_prio(_naptr) \
	((((_naptr)->order) << 16) + ((_naptr)->pref))

static inline int get_naptr_proto(struct naptr_rdata *n)
{
#ifdef USE_TLS
	if (n->services[3]=='s' || n->services[3]=='S' )
		return PROTO_TLS;
#endif
	switch (n->services[n->services_len-1]) {
		case 'U':
		case 'u':
			return PROTO_UDP;
			break;
#ifdef USE_TCP
		case 'T':
		case 't':
			return PROTO_TCP;
			break;
#endif
	}
	LOG(L_CRIT,"BUG:get_naptr_proto: failed to detect proto\n");
	return PROTO_NONE;
}


static inline void filter_and_sort_naptr( struct rdata** head_p,
									struct rdata** filtered_p, int is_sips)
{
	struct naptr_rdata *naptr;
	struct rdata *head;
	struct rdata *last;
	struct rdata *out;
	struct rdata *l, *ln, *it, *itp;
	unsigned int prio;
	char p;

	head = 0;
	last = 0;
	out = 0;

	for( l=*head_p ; l ; l=ln ) {
		ln = l->next;

		if (l->type != T_NAPTR)
			goto skip0; /*should never happen*/

		naptr = (struct naptr_rdata*)l->rdata;
		if (naptr == 0) {
			LOG(L_CRIT, "BUG:filter_and_sort_naptr: null rdata\n");
			goto skip0;
		}

		/* first filter out by flag and service */
		if (naptr->flags_len!=1 || (naptr->flags[0]!='s'&&naptr->flags[0]!='S'))
			goto skip;
		if (naptr->repl_len==0 || naptr->regexp_len!=0 )
			goto skip;
		if ( (is_sips || naptr->services_len!=7 ||
			strncasecmp(naptr->services,"sip+d2",6) ) &&
		(
#ifdef USE_TLS
		tls_disable ||
#endif
		naptr->services_len!=8 || strncasecmp(naptr->services,"sips+d2",7)))
			goto skip;
		p = naptr->services[naptr->services_len-1];
		/* by default we do not support SCTP */
		if ( p!='U' && p!='u'
#ifdef USE_TCP
		&& (tcp_disable || (p!='T' && p!='t'))
#endif
		)
			goto skip;
		/* is it valid? (SIPS+D2U is not!) */
		if ( naptr->services_len==8 && (p=='U' || p=='u'))
			goto skip;

		DBG("DEBUG:filter_and_sort_naptr: found valid %.*s -> %s\n",
			naptr->services_len,naptr->services, naptr->repl);

		/* this is a supported service -> add it according to order to the 
		 * new head list */
		prio = naptr_prio(get_naptr(l));
		if (head==0) {
			head = last = l;
			l->next = 0;
		} else if ( naptr_prio(get_naptr(head)) >= prio ) {
			l->next = head;
			head = l;
		} else if ( prio >= naptr_prio(get_naptr(last)) ) {
			l->next = 0;
			last->next = l;
			last = l;
		} else {
			for( itp=head,it=head->next ; it && it->next ; itp=it,it=it->next ){
				if ( prio <= naptr_prio(get_naptr(it)))
					break;
			}
			l->next = itp->next;
			itp->next = l;
		}

		continue;
skip:
		DBG("DEBUG:filter_and_sort_naptr: skipping %.*s -> %s\n",
			naptr->services_len, naptr->services, naptr->repl);
skip0:
		l->next = out;
		out = l;
	}

	*head_p = head;
	*filtered_p = out;
}


struct hostent* sip_resolvehost(str* name, unsigned short* port, int *proto,
																int is_sips)
{
	static char tmp[MAX_DNS_NAME];
	struct ip_addr *ip;
	struct rdata *head;
	struct rdata *rd;
	struct hostent* he;

	/* check if it's an ip address */
	if ( ((ip=str2ip(name))!=0)
#ifdef USE_IPV6
	|| ((ip=str2ip6(name))!=0)
#endif
	){
		/* we are lucky, this is an ip address */
		if (proto && *proto==PROTO_NONE)
			*proto = (is_sips)?PROTO_TLS:PROTO_UDP;
		if (port && *port==0)
			*port = (is_sips||((*proto)==PROTO_TLS))?SIPS_PORT:SIP_PORT;
		return ip_addr2he(name,ip);
	}

	/* do we have a port? */
	if ( !port || (*port)!=0 ) {
		/* have port -> no NAPTR, no SRV lookup, just A record lookup */
		DBG("DEBUG:sip_resolvehost2: has port -> do A record lookup!\n");
		/* set default PROTO if not set */
		if (proto && *proto==PROTO_NONE)
			*proto = (is_sips)?PROTO_TLS:PROTO_UDP;
		goto do_a;
	}

	/* no port... what about proto? */
	if ( !proto || (*proto)!=PROTO_NONE ) {
		/* have proto, but no port -> do SRV lookup */
		DBG("DEBUG:sip_resolvehost2: no port, has proto -> do SRV lookup!\n");
		if (is_sips && (*proto)!=PROTO_TLS) {
			LOG(L_ERR, "ERROR:sip_resolvehost2: forced proto %d not matching "
				"sips uri\n", *proto);
			return 0;
		}
		goto do_srv;
	}

	DBG("DEBUG:sip_resolvehost2: no port, no proto -> do NAPTR lookup!\n");
	/* no proto, no port -> do NAPTR lookup */
	if (name->len >= MAX_DNS_NAME) {
		LOG(L_ERR, "ERROR:sip_resolvehost2: domain name too long\n");
		return 0;
	}
	memcpy(tmp, name->s, name->len);
	tmp[name->len] = '\0';
	/* do NAPTR lookup */
	head = get_record( tmp, T_NAPTR);
	if (head) {
		/* filter and sort the records */
		filter_and_sort_naptr( &head, &rd, is_sips);
		/* free what is useless */
		free_rdata_list( rd );
		/* process the NAPTR records */
		for( rd=head ; rd ; rd=rd->next ) {
			he = do_srv_lookup( get_naptr(rd)->repl, port );
			if ( he ) {
				*proto = get_naptr_proto( get_naptr(rd) );
				DBG("DEBUG:sip_resolvehost2: found!\n");
				free_rdata_list(head);
				return he;
			}
		}
		if (head)
			free_rdata_list(head);
	}
	DBG("DEBUG:sip_resolvehost2: no valid NAPTR record found for %.*s," 
		" trying direct SRV lookup...\n", name->len, name->s);
	*proto = (is_sips)?PROTO_TLS:PROTO_UDP;

do_srv:
	if ((name->len+SRV_MAX_PREFIX_LEN+1)>MAX_DNS_NAME) {
		LOG(L_WARN, "WARNING:sip_resolvehost2: domain name too long (%d),"
			" unable to perform SRV lookup\n", name->len);
		/* set defaults */
		*port = (is_sips)?SIPS_PORT:SIP_PORT;
		goto do_a;
	}

	switch (*proto) {
		case PROTO_UDP:
			memcpy(tmp, SRV_UDP_PREFIX, SRV_UDP_PREFIX_LEN);
			memcpy(tmp+SRV_UDP_PREFIX_LEN, name->s, name->len);
			tmp[SRV_UDP_PREFIX_LEN + name->len] = '\0';
			break;
#ifdef USE_TCP
		case PROTO_TCP:
			if (tcp_disable) goto err_proto;
			memcpy(tmp, SRV_TCP_PREFIX, SRV_TCP_PREFIX_LEN);
			memcpy(tmp+SRV_TCP_PREFIX_LEN, name->s, name->len);
			tmp[SRV_TCP_PREFIX_LEN + name->len] = '\0';
			break;
#endif
#ifdef USE_TLS
		case PROTO_TLS:
			if (tls_disable) goto err_proto;
			memcpy(tmp, SRV_TLS_PREFIX, SRV_TLS_PREFIX_LEN);
			memcpy(tmp+SRV_TLS_PREFIX_LEN, name->s, name->len);
			tmp[SRV_TLS_PREFIX_LEN + name->len] = '\0';
			break;
#endif
		default:
			goto err_proto;
	}

	he = do_srv_lookup( tmp, port );
	if (he)
		return he;
	
	DBG("DEBUG:sip_resolvehost2: no valid SRV record found for %s," 
		" trying A record lookup...\n", tmp);
	/* set default port */
	*port = (is_sips||((*proto)==PROTO_TLS))?SIPS_PORT:SIP_PORT;

do_a:
	/* do A record lookup */
	if (name->len >= MAX_DNS_NAME) {
		LOG(L_ERR, "ERROR:sip_resolvehost2: domain name too long\n");
		return 0;
	}
	memcpy(tmp, name->s, name->len);
	tmp[name->len] = '\0';
	he = resolvehost(tmp,1);
	return he;
err_proto:
	LOG(L_ERR, "ERROR:sip_resolvehost: unsupported proto %d\n",
		*proto);
	return 0;
}


