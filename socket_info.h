/* $Id$
 *
 * find & manage listen addresses 
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * along with this program; if not, write to" the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * This file contains code that initializes and handles ser listen addresses
 * lists (struct socket_info). It is used mainly on startup.
 * 
 * History:
 * --------
 *  2003-10-22  created by andrei
 */


#ifndef socket_info_h
#define socket_info_h

#include <stdlib.h>

#include "ip_addr.h" 
#include "dprint.h"
#include "globals.h"
#include "ut.h"
/* struct socket_info is defined in ip_addr.h */

struct socket_info* udp_listen;
#ifdef USE_TCP
struct socket_info* tcp_listen;
#endif
#ifdef USE_TLS
struct socket_info* tls_listen;
#endif
#ifdef USE_SCTP
struct socket_info* sctp_listen;
#endif


int add_listen_iface(char* name, unsigned short port, unsigned short proto,
							enum si_flags flags);
int fix_all_socket_lists();
void print_all_socket_lists();
void print_aliases();

struct socket_info* grep_sock_info(str* host, unsigned short port,
										unsigned short proto);
struct socket_info* find_si(struct ip_addr* ip, unsigned short port,
												unsigned short proto);


static inline struct socket_info** get_sock_info_list(unsigned short proto)
{
	
	switch(proto){
		case PROTO_UDP:
			return &udp_listen;
			break;
#ifdef USE_TCP
		case PROTO_TCP:
			return &tcp_listen;
			break;
#endif
#ifdef USE_TLS
		case PROTO_TLS:
			return &tls_listen;
			break;
#endif
#ifdef USE_SCTP
		case PROTO_SCTP:
			return &sctp_listen;
			break;
#endif
		default:
			LOG(L_CRIT, "BUG: get_sock_info_list: invalid proto %d\n", proto);
	}
	return 0;
}


/* helper function:
 * returns next protocol, if the last one is reached return 0
 * useful for cycling on the supported protocols */
static inline int next_proto(unsigned short proto)
{
	switch(proto){
		case PROTO_NONE:
			return PROTO_UDP;
		case PROTO_UDP: /* UDP -> [TCP | SCTP] */
#ifdef	USE_TCP
			if(!tcp_disable)
				return PROTO_TCP;
#ifdef USE_SCTP
			return (sctp_disable)?0:PROTO_SCTP;
#else
			return 0;
#endif
#else
#ifdef USE_SCTP
			return (sctp_disable)?0:PROTO_SCTP;
#else
			return 0;
#endif
#endif
#ifdef USE_TCP
		case PROTO_TCP: /* TCP -> [TLS | SCTP] */
#ifdef USE_TLS
			if (!tls_disable)
				return PROTO_TLS;
#ifdef USE_SCTP
			return (sctp_disable)?0:PROTO_SCTP;
#else
			return 0;
#endif
#else
#ifdef USE_SCTP
			return (sctp_disable)?0:PROTO_SCTP;
#else
			return 0;
#endif
#endif
#endif
#ifdef USE_TLS
		case PROTO_TLS:
#ifdef USE_SCTP
			return (sctp_disable)?0:PROTO_SCTP;
#else
			return 0;
#endif
#endif
#ifdef USE_SCTP
		case PROTO_SCTP:
			return 0;
#endif
		default:
			LOG(L_ERR, "ERROR: next_proto: unknown proto %d\n", proto);
	}
	return 0;
}



/* gets first non-null socket_info structure
 * (useful if for. e.g we are not listening on any udp sockets )
 */
inline static struct socket_info* get_first_socket()
{
	if (udp_listen) return udp_listen;
#ifdef USE_TCP
	else if (tcp_listen) return tcp_listen;
#ifdef USE_TLS
	else if (tls_listen) return tls_listen;
#endif
#endif
#ifdef USE_SCTP
	else if (sctp_listen) return sctp_listen;
#endif
	return 0;
}


/* returns -1 on error, 0 on success
 * sets proto */
inline static int parse_proto(unsigned char* s, long len, int* proto)
{
#define PROTO2UINT(a, b, c) ((	(((unsigned int)(a))<<16)+ \
								(((unsigned int)(b))<<8)+  \
								((unsigned int)(c)) ) | 0x20202020)
	unsigned int i;
	
	/* must support 3-char arrays for udp, tcp, tls,
	 * must support 4-char arrays for sctp */
	*proto=PROTO_NONE;
	if (len!=3 && len!=4) return -1;

	i=PROTO2UINT(s[0], s[1], s[2]);
	switch(i){
		case PROTO2UINT('u', 'd', 'p'):
			if(len==3) { *proto=PROTO_UDP; return 0; }
			break;
#ifdef USE_TCP
		case PROTO2UINT('t', 'c', 'p'):
			if(len==3) { *proto=PROTO_TCP; return 0; }
			break;
#ifdef USE_TLS
		case PROTO2UINT('t', 'l', 's'):
			if(len==3) { *proto=PROTO_TLS; return 0; }
			break;
#endif
#endif
#ifdef USE_SCTP
		case PROTO2UINT('s', 'c', 't'):
			if(len==4 && (s[3]=='p' || s[3]=='P')) {
				*proto=PROTO_SCTP; return 0;
			}
			break;
#endif

		default:
			return -1;
	}
	return -1;
}



/*
 * parses [proto:]host[:port]
 * where proto= udp|tcp|tls
 * returns 0 on success and -1 on failure
 */
inline static int parse_phostport(char* s, int slen, char** host, int* hlen,
													int* port, int* proto)
{
	char* first; /* first ':' occurrence */
	char* second; /* second ':' occurrence */
	char* p;
	int   bracket;
	str   tmp;
	char* end;
	
	first=second=0;
	bracket=0;
	end = s + slen;
	
	/* find the first 2 ':', ignoring possible ipv6 addresses
	 * (substrings between [])
	 */
	for(p=s; p<end ; p++){
		switch(*p){
			case '[':
				bracket++;
				if (bracket>1) goto error_brackets;
				break;
			case ']':
				bracket--;
				if (bracket<0) goto error_brackets;
				break;
			case ':':
				if (bracket==0){
					if (first==0) first=p;
					else if( second==0) second=p;
					else goto error_colons;
				}
				break;
		}
	}
	if (p==s) return -1;
	if (*(p-1)==':') goto error_colons;
	
	if (first==0){ /* no ':' => only host */
		*host=s;
		*hlen=(int)(p-s);
		*port=0;
		*proto=0;
		return 0;
	}
	if (second){ /* 2 ':' found => check if valid */
		if (parse_proto((unsigned char*)s, first-s, proto)<0)
			goto error_proto;
		tmp.s = second+1;
		tmp.len = end - tmp.s;
		if (str2int( &tmp, (unsigned int*)port )==-1) goto error_port;
		*host=first+1;
		*hlen=(int)(second-*host);
		return 0;
	}
	/* only 1 ':' found => it's either proto:host or host:port */
	tmp.s = first+1;
	tmp.len = end - tmp.s;
	if (str2int( &tmp, (unsigned int*)port )==-1) {
		/* invalid port => it's proto:host */
		if (parse_proto((unsigned char*)s, first-s, proto)<0) goto error_proto;
		*port=0;
		*host=first+1;
		*hlen=(int)(p-*host);
	}else{
		/* valid port => its host:port */
		*proto=0;
		*host=s;
		*hlen=(int)(first-*host);
	}
	return 0;
error_brackets:
	LOG(L_ERR, "ERROR: parse_phostport: too many brackets in %s\n", s);
	return -1;
error_colons:
	LOG(L_ERR, "ERROR: parse_phostport: too many colons in %s\n", s);
	return -1;
error_proto:
	LOG(L_ERR, "ERROR: parse_phostport: bad protocol in %s\n", s);
	return -1;
error_port:
	LOG(L_ERR, "ERROR: parse_phostport: bad port number in %s\n", s);
	return -1;
}


#define MAX_SOCKET_STR ( 4 + 1 + IP_ADDR_MAX_STR_SIZE+1+INT2STR_MAX_LEN+1)
#define sock_str_len(_sock) ( 3 + 1*((_sock)->proto==PROTO_SCTP) + 1 + \
		(_sock)->address_str.len + 1 + (_sock)->port_no_str.len)

static inline char* socket2str(struct socket_info *sock, char *s, int* len)
{
	static char buf[MAX_SOCKET_STR];
	char *p,*p1;

	if (s) {
		/* buffer provided -> check lenght */
		if ( sock_str_len(sock) > *len ) {
			LOG(L_ERR,"ERROR:socket2str: buffer too short\n");
			return 0;
		}
		p = p1 = s;
	} else {
		p = p1 = buf;
	}

	switch (sock->proto) {
		case PROTO_UDP:
			*(p++) = 'u';
			*(p++) = 'd';
			*(p++) = 'p';
			break;
		case PROTO_TCP:
			*(p++) = 't';
			*(p++) = 'c';
			*(p++) = 'p';
			break;
		case PROTO_TLS:
			*(p++) = 't';
			*(p++) = 'l';
			*(p++) = 's';
			break;
		case PROTO_SCTP:
			*(p++) = 's';
			*(p++) = 'c';
			*(p++) = 't';
			*(p++) = 'p';
			break;
		default:
			LOG(L_CRIT,"BUG:socket2str: unsupported proto %d\n", sock->proto);
			return 0;
	}
	*(p++) = ':';
	memcpy( p, sock->address_str.s, sock->address_str.len);
	p += sock->address_str.len;
	*(p++) = ':';
	memcpy( p, sock->port_no_str.s, sock->port_no_str.len);
	p += sock->port_no_str.len;
	*len = (int)(long)(p-p1);
	DBG("DEBUG:socket2str: <%.*s>\n",*len,p1);
	return p1;
}



#endif
