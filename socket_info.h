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
 * along with this program; if not, write to" the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

/*!
 * \file
 * \brief Find & manage listen addresses.
 * Contains code that initializes and handles server listen addresses
 * lists (struct socket_info). It is used mainly on startup.
 */


#ifndef socket_info_h
#define socket_info_h

#include <stdlib.h>

#include "ip_addr.h"
#include "dprint.h"
#include "globals.h"
#include "net/trans.h"
#include "ut.h"
/* struct socket_info is defined in ip_addr.h */

#define NUM_IP_OCTETS	4
#define PROTO_NAME_MAX_SIZE  8 /* CHANGEME if you define a bigger protocol name
						   * currently hep_tcp - biggest proto */

int add_listen_iface(char* name, unsigned short port, unsigned short proto,
							char *adv_name, unsigned short adv_port,
							unsigned short children, enum si_flags flags);
struct socket_info *
new_sock_info(char* name, unsigned short port, unsigned short proto,
							char *adv_name, unsigned short adv_port,
							unsigned short children, enum si_flags flags);

int new_sock2list(char* name, unsigned short port, unsigned short proto,
		char *adv_name, unsigned short adv_port, unsigned short children,
		enum si_flags flags, struct socket_info** list);

int fix_socket_list(struct socket_info **);

/*
 * This function will retrieve a list of all ip addresses and ports that
 * OpenSIPS is listening on, with respect to the transport protocol specified
 * with 'protocol'.
 *
 * The first parameter, ipList, is a pointer to a pointer. It will be assigned
 * new block of memory holding the IP Addresses and ports being listened to
 * with respect to 'protocol'.  The array maps a 2D array into a 1 dimensional
 * space, and is layed out as follows:
 *
 * The first NUM_IP_OCTETS indices will be the IP address, and the next index
 * the port.  So if NUM_IP_OCTETS is equal to 4 and there are two IP addresses
 * found, then:
 *
 *  - ipList[0] will be the first octet of the first ip address
 *  - ipList[3] will be the last octet of the first ip address.
 *  - iplist[4] will be the port of the first ip address
 *  -
 *  - iplist[5] will be the first octet of the first ip address,
 *  - and so on.
 *
 * The function will return the number of sockets which were found.  This can
 * be used to index into ipList.
 *
 * NOTE: This function assigns a block of memory equal to:
 *
 *            returnedValue * (NUM_IP_OCTETS + 1) * sizeof(int);
 *
 *       Therefore it is CRUCIAL that you free ipList when you are done with
 *       its contents, to avoid a nasty memory leak.
 */
int get_socket_list_from_proto(int **ipList, int protocol);

/*
 * Returns the sum of the number of bytes waiting to be consumed on all network
 * interfaces and transports that OpenSIPS is listening on.
 *
 * Note: This currently only works on systems supporting the
 *       /proc/net/[tcp|udp] interface.  On other systems, zero will always
 *       be returned.  Details of why this is so can be found in
 *       network_stats.c
 */
int get_total_bytes_waiting(int only_proto);

void print_aliases();

struct socket_info* grep_sock_info(str* host, unsigned short port,
										unsigned short proto);
struct socket_info* find_si(struct ip_addr* ip, unsigned short port,
												unsigned short proto);

#define set_sip_defaults( _port, _proto) \
	do { \
		if (_proto==PROTO_NONE) _proto = PROTO_UDP; \
		if (_port==0) { \
			if (_proto==PROTO_TLS) _port = SIPS_PORT; else\
			_port = SIP_PORT; \
		} \
	} while(0)



/*! \brief helper function:
 * \return next protocol, if the last one is reached return 0
 * \note useful for cycling on the supported protocols */
static inline int next_proto(unsigned short proto)
{
	for( proto++ ; proto<PROTO_LAST ; proto++ )
		if (protos[proto].id!=PROTO_NONE)
			return proto;
	return PROTO_NONE;
}



/*! \brief gets first non-null socket_info structure
 * (useful if for. e.g we are not listening on any udp sockets )
 */
inline static struct socket_info* get_first_socket(void)
{
	int p;

	for( p=0 ; p<PROTO_LAST ; p++ )
		if (protos[p].listeners)
			return protos[p].listeners;

	return NULL;
}


/*! \brief Sets protocol
 * \return -1 on error, 0 on success
 */
inline static int parse_proto(unsigned char* s, long len, int* proto)
{
#define PROTO2UINT(a, b, c) ((	(((unsigned int)(a))<<16)+ \
								(((unsigned int)(b))<<8)+  \
								((unsigned int)(c)) ) | 0x20202020)
	unsigned int i;
	unsigned int j;

	/* must support 3-char arrays for udp, tcp, tls,
	 * must support 4-char arrays for sctp
	 * must support 7-char arrays for hep_tcp and hep_udp */
	*proto=PROTO_NONE;
	if ((len < 2 || len > 4) && len != 7) return -1;

	i=PROTO2UINT(s[0], s[1], s[2]);
	switch(i){
		case PROTO2UINT('u', 'd', 'p'):
			if(len==3) { *proto=PROTO_UDP; return 0; }
			break;
		case PROTO2UINT('t', 'c', 'p'):
			if(len==3) { *proto=PROTO_TCP; return 0; }
			break;
		case PROTO2UINT('t', 'l', 's'):
			if(len==3) { *proto=PROTO_TLS; return 0; }
			break;
		case PROTO2UINT('s', 'c', 't'):
			if(len==4 && (s[3]=='p' || s[3]=='P')) {
				*proto=PROTO_SCTP; return 0;
			}
			break;
		case PROTO2UINT('w', 's', 's'):
			if(len==3) { *proto=PROTO_WSS; return 0; }
			break;
		case PROTO2UINT('b', 'i', 'n'):
			if(len==3) { *proto=PROTO_BIN; return 0; }
			break;

		case PROTO2UINT('h', 'e', 'p'):
			if (len != 7) return -1;

			j=PROTO2UINT(s[4], s[5], s[6]);
			switch (j) {
				case PROTO2UINT('u','d', 'p'):
					*proto=PROTO_HEP_UDP;
					return 0;
				case PROTO2UINT('t','c', 'p'):
					*proto=PROTO_HEP_TCP;
					return 0;
				default:
					return -1;
			}
			break;
		default:
			if(len==2 && (s[0]|0x20)=='w' && (s[1]|0x20)=='s') {
				*proto=PROTO_WS; return 0;
			}
			return -1;
	}
	return -1;
}



/*! \brief
 * parses [proto:]host[:port] where proto= udp|tcp|tls
 * \return 0 on success and -1 on failure
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
	LM_ERR("too many brackets in %s\n", s);
	return -1;
error_colons:
	LM_ERR(" too many colons in %s\n", s);
	return -1;
error_proto:
	LM_ERR("bad protocol in %s\n", s);
	return -1;
error_port:
	LM_ERR("bad port number in %s\n", s);
	return -1;
}


/* function will write the proto as string, starting from the p pointer. The
   new resulting proto will be returned (where writing ended) */
static inline char* proto2str(int proto, char *p)
{
	switch (proto) {
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
		case PROTO_WS:
			*(p++) = 'w';
			*(p++) = 's';
			break;
		case PROTO_WSS:
			*(p++) = 'w';
			*(p++) = 's';
			*(p++) = 's';
			break;
		case PROTO_BIN:
			*(p++) = 'b';
			*(p++) = 'i';
			*(p++) = 'n';
			break;
		case PROTO_HEP_UDP:
			*(p++) = 'h';
			*(p++) = 'e';
			*(p++) = 'p';
			*(p++) = '_';
			*(p++) = 'u';
			*(p++) = 'd';
			*(p++) = 'p';
			break;
		case PROTO_HEP_TCP:
			*(p++) = 'h';
			*(p++) = 'e';
			*(p++) = 'p';
			*(p++) = '_';
			*(p++) = 't';
			*(p++) = 'c';
			*(p++) = 'p';
			break;

		default:
			LM_CRIT("unsupported proto %d\n", proto);
			return 0;
	}
	return p;
}

#define MAX_SOCKET_STR ( 4 + 1 + IP_ADDR_MAX_STR_SIZE+1+INT2STR_MAX_LEN+1)
#define sock_str_len(_sock) ( 3 + 1*((_sock)->proto==PROTO_SCTP) + 1 + \
		(_sock)->address_str.len + 1 + (_sock)->port_no_str.len)

static inline char* socket2str(struct socket_info *sock, char *s, int* len, int adv)
{
	static char buf[MAX_SOCKET_STR];
	char *p,*p1;

	if (s) {
		/* buffer provided -> check lenght */
		if ( sock_str_len(sock) > *len ) {
			LM_ERR("buffer too short\n");
			return 0;
		}
		p = p1 = s;
	} else {
		p = p1 = buf;
	}

	p = proto2str( sock->proto, p);
	if (p==NULL) return 0;

	*(p++) = ':';
 	if(adv) {
 		memcpy( p, sock->adv_name_str.s, sock->adv_name_str.len);
 		p += sock->adv_name_str.len;
 		*(p++) = ':';
 		memcpy( p, sock->adv_port_str.s, sock->adv_port_str.len);
 		p += sock->adv_port_str.len;
 	} else {
 		memcpy( p, sock->address_str.s, sock->address_str.len);
 		p += sock->address_str.len;
 		*(p++) = ':';
 		memcpy( p, sock->port_no_str.s, sock->port_no_str.len);
 		p += sock->port_no_str.len;
 	}
	*len = (int)(long)(p-p1);
	LM_DBG("<%.*s>\n",*len,p1);
	return p1;
}


#define get_sock_info_list(_proto) \
	((_proto>=PROTO_FIRST && _proto<PROTO_LAST)?&protos[_proto].listeners:0)


int probe_max_sock_buff( int sock, int buff_choice, int buff_max,
		int buff_increment);

#endif
