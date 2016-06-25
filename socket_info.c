/*
 * $Id$
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * This file contains code that initializes and handles ser listen addresses
 * lists (struct socket_info). It is used mainly on startup.
 *
 * History:
 * --------
 *  2003-10-22  created by andrei
 *  2004-10-10  added grep_sock_info (andrei)
 *  2004-11-08  added find_si (andrei)
 *  2007-01-11  auto_aliases option added (bogdan)
 */

/*!
 * \file
 * \brief Find & manage listen addresses
 */


#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <net/if.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#include "globals.h"
#include "socket_info.h"
#include "dprint.h"
#include "mem/mem.h"
#include "ut.h"
#include "resolve.h"
#include "name_alias.h"

#define MAX_PROC_BUFFER	256

/* list manip. functions (internal use only) */


/* append */
#define sock_listadd(head, el) \
	do{\
		if (*(head)==0) *(head)=(el); \
		else{ \
			for((el)->next=*(head); (el)->next->next;\
					(el)->next=(el)->next->next); \
			(el)->next->next=(el); \
			(el)->prev=(el)->next; \
			(el)->next=0; \
		}\
	}while(0)


/* insert after "after" */
#define sock_listins(el, after) \
	do{ \
		if ((after)){\
			(el)->next=(after)->next; \
			if ((after)->next) (after)->next->prev=(el); \
			(after)->next=(el); \
			(el)->prev=(after); \
		}else{ /* after==0 = list head */ \
			(after)=(el); \
			(el)->next=(el)->prev=0; \
		}\
	}while(0)


#define sock_listrm(head, el) \
	do {\
		if (*(head)==(el)) *(head)=(el)->next; \
		if ((el)->next) (el)->next->prev=(el)->prev; \
		if ((el)->prev) (el)->prev->next=(el)->next; \
	}while(0)



/* another helper function, it just creates a socket_info struct */
inline struct socket_info* new_sock_info(	char* name,
								unsigned short port, unsigned short proto,
								char *adv_name, unsigned short adv_port,
								unsigned short children,enum si_flags flags)
{
	struct socket_info* si;

	si=(struct socket_info*) pkg_malloc(sizeof(struct socket_info));
	if (si==0) goto error;
	memset(si, 0, sizeof(struct socket_info));
	si->socket=-1;
	si->name.len=strlen(name);
	si->name.s=(char*)pkg_malloc(si->name.len+1); /* include \0 */
	if (si->name.s==0) goto error;
	memcpy(si->name.s, name, si->name.len+1);
	/* set port & proto */
	si->port_no=port;
	si->proto=proto;
	si->flags=flags;

    /* advertised socket information */
	/* Make sure the adv_sock_string is initialized, because if there is
	 * no adv_sock_name, no other code will initialize it!
	 */
	si->adv_sock_str.s=NULL;
	si->adv_sock_str.len=0;
	if(adv_name) {
		si->adv_name_str.len=strlen(adv_name);
		si->adv_name_str.s=(char *)pkg_malloc(si->adv_name_str.len+1);
		if (si->adv_name_str.s==0) goto error;
		memcpy(si->adv_name_str.s, adv_name, si->adv_name_str.len+1);
	}
	si->adv_port = 0; /* Here to help grep_sock_info along. */
	if(adv_port) {
		si->adv_port_str.s=pkg_malloc(10);
		if (si->adv_port_str.s==0) goto error;
		si->adv_port_str.len=snprintf(si->adv_port_str.s, 10, "%hu", adv_port);
		si->adv_port = adv_port;
	}
	if ( (si->proto==PROTO_TCP || si->proto==PROTO_TLS) && children) {
		LM_WARN("number of children per TCP/TLS listener not supported -> ignoring...\n");
	} else {
		si->children = children;
	}
	return si;
error:
	LM_ERR("pkg memory allocation error\n");
	if (si) pkg_free(si);
	return 0;
}



/*  delete a socket_info struct */
static void free_sock_info(struct socket_info* si)
{
	if(si){
		if(si->name.s) pkg_free(si->name.s);
		if(si->address_str.s) pkg_free(si->address_str.s);
		if(si->port_no_str.s) pkg_free(si->port_no_str.s);
		if(si->adv_name_str.s) pkg_free(si->adv_name_str.s);
		if(si->adv_port_str.s) pkg_free(si->adv_port_str.s);
	}
}


/* checks if the proto: host:port is one of the address we listen on
 * and returns the corresponding socket_info structure.
 * if port==0, the  port number is ignored
 * if proto==0 (PROTO_NONE) the protocol is ignored
 * returns  0 if not found
 * WARNING: uses str2ip6 so it will overwrite any previous
 *  unsaved result of this function (static buffer)
 */
struct socket_info* grep_sock_info(str* host, unsigned short port,
												unsigned short proto)
{
	char* hname;
	int h_len;
	struct socket_info* si;
	struct socket_info** list;
	unsigned short c_proto;
#ifdef USE_IPV6
	struct ip_addr* ip6;
#endif
	h_len=host->len;
	hname=host->s;
#ifdef USE_IPV6
	if ((h_len>2)&&((*hname)=='[')&&(hname[h_len-1]==']')){
		/* ipv6 reference, skip [] */
		hname++;
		h_len-=2;
	}
#endif
	c_proto=proto?proto:PROTO_UDP;
	do{
		/* get the proper sock_list */
		if (c_proto==PROTO_NONE)
			list=&udp_listen;
		else
			list=get_sock_info_list(c_proto);

		if (list==0){
			LM_WARN("unknown proto %d\n", c_proto);
			goto not_found; /* false */
		}
		for (si=*list; si; si=si->next){
			LM_DBG("checking if host==us: %d==%d && "
					" [%.*s] == [%.*s]\n",
						h_len,
						si->name.len,
						h_len, hname,
						si->name.len, si->name.s
				);
			if (port) {
				LM_DBG("checking if port %d matches port %d\n",
						si->port_no, port);
				if (si->port_no!=port && si->adv_port!=port) {
					continue;
				}
			}
			if ( (h_len==si->name.len) &&
				(strncasecmp(hname, si->name.s,
						 si->name.len)==0) /*slower*/)
				/* comp. must be case insensitive, host names
				 * can be written in mixed case, it will also match
				 * ipv6 addresses if we are lucky*/
				goto found;
			/* Check if the adv. name of this socket matches */
			if ( (h_len==si->adv_name_str.len) &&
				(strncasecmp(hname, si->adv_name_str.s,
					si->adv_name_str.len)==0) /*slower*/)
				/* comp. must be case insensitive, host names
				* can be in mixed case, it will also match
				* ipv6 addresses if we are lucky*/
				goto found;
			/* check if host == ip address */
#ifdef USE_IPV6
			/* ipv6 case is uglier, host can be [3ffe::1] */
			ip6=str2ip6(host);
			if (ip6){
				if (ip_addr_cmp(ip6, &si->address))
					goto found; /* match */
				else
					continue; /* no match, but this is an ipv6 address
								 so no point in trying ipv4 */
			}
#endif
			/* ipv4 */
			if ( 	(!(si->flags&SI_IS_IP)) &&
					(h_len==si->address_str.len) &&
				(memcmp(hname, si->address_str.s,
									si->address_str.len)==0)
				)
				goto found;
		}
	}while( (proto==0) && (c_proto=next_proto(c_proto)) );
not_found:
	return 0;
found:
	return si;
}



/* checks if the proto: ip:port is one of the address we listen on
 * and returns the corresponding socket_info structure.
 * (same as grep_socket_info, but use ip addr instead)
 * if port==0, the  port number is ignored
 * if proto==0 (PROTO_NONE) the protocol is ignored
 * returns  0 if not found
 * WARNING: uses str2ip6 so it will overwrite any previous
 *  unsaved result of this function (static buffer)
 */
struct socket_info* find_si(struct ip_addr* ip, unsigned short port,
												unsigned short proto)
{
	struct socket_info* si;
	struct socket_info** list;
	unsigned short c_proto;

	c_proto=proto?proto:PROTO_UDP;
	do{
		/* get the proper sock_list */
		if (c_proto==PROTO_NONE)
			list=&udp_listen;
		else
			list=get_sock_info_list(c_proto);

		if (list==0){
			LM_WARN("unknown proto %d\n", c_proto);
			goto not_found; /* false */
		}
		for (si=*list; si; si=si->next){
			if (port) {
				if (si->port_no!=port) {
					continue;
				}
			}
			if (ip_addr_cmp(ip, &si->address) || ip_addr_cmp(ip, &si->adv_address))
				goto found;
		}
	}while( (proto==0) && (c_proto=next_proto(c_proto)) );
not_found:
	return 0;
found:
	return si;
}



/* adds a new sock_info structure to the corresponding list
 * return  0 on success, -1 on error */
int new_sock2list(char* name, unsigned short port, unsigned short proto,
		char *adv_name, unsigned short adv_port, unsigned short children,
		enum si_flags flags, struct socket_info** list)
{
	struct socket_info* si;

	si=new_sock_info(name, port, proto, adv_name, adv_port, children, flags);
	if (si==0){
		LM_ERR("new_sock_info failed\n");
		goto error;
	}
	sock_listadd(list, si);
	return 0;
error:
	return -1;
}



/* adds a sock_info structure to the corresponding proto list
 * return  0 on success, -1 on error */
int add_listen_iface(char* name, unsigned short port, unsigned short proto,
			char *adv_name, unsigned short adv_port, unsigned short children,
			enum si_flags flags)
{
	struct socket_info** list;
	unsigned short c_proto;

	c_proto=(proto)?proto:PROTO_UDP;
	do{
		list=get_sock_info_list(c_proto);
		if (list==0){
			LM_ERR("get_sock_info_list failed\n");
			goto error;
		}
		if (port==0){ /* use default port */
			port=
#ifdef USE_TLS
				((c_proto)==PROTO_TLS)?tls_port_no:
#endif
				port_no;
		}
#ifdef USE_TLS
		else if ((c_proto==PROTO_TLS) && (proto==0)){
			/* -l  ip:port => on udp:ip:port; tcp:ip:port and tls:ip:port+1? */
				port++;
		}
#endif
		if (new_sock2list(name, port, c_proto, adv_name, adv_port, children,
		flags, list)<0){
			LM_ERR("new_sock2list failed\n");
			goto error;
		}
	}while( (proto==0) && (c_proto=next_proto(c_proto)));
	return 0;
error:
	return -1;
}



/* add all family type addresses of interface if_name to the socket_info array
 * if if_name==0, adds all addresses on all interfaces
 * WARNING: it only works with ipv6 addresses on FreeBSD
 * return: -1 on error, 0 on success
 */
int add_interfaces(char* if_name, int family, unsigned short port,
					unsigned short proto,
					struct socket_info** list)
{
	struct ifconf ifc;
	struct ifreq ifr;
	struct ifreq ifrcopy;
	char*  last;
	char* p;
	int size;
	int lastlen;
	int s;
	char* tmp;
	struct ip_addr addr;
	int ret;
	enum si_flags flags;

#ifdef HAVE_SOCKADDR_SA_LEN
	#ifndef MAX
		#define MAX(a,b) ( ((a)>(b))?(a):(b))
	#endif
#endif
	/* ipv4 or ipv6 only*/
	flags=SI_NONE;
	s=socket(family, SOCK_DGRAM, 0);
	ret=-1;
	lastlen=0;
	ifc.ifc_req=0;
	for (size=100; ; size*=2){
		ifc.ifc_len=size*sizeof(struct ifreq);
		ifc.ifc_req=(struct ifreq*) pkg_malloc(size*sizeof(struct ifreq));
		if (ifc.ifc_req==0){
			LM_ERR("memory allocation failure\n");
			goto error;
		}
		if (ioctl(s, SIOCGIFCONF, &ifc)==-1){
			if(errno==EBADF) return 0; /* invalid descriptor => no such ifs*/
			LM_ERR("ioctl failed: %s\n", strerror(errno));
			goto error;
		}
		if  ((lastlen) && (ifc.ifc_len==lastlen)) break; /*success,
														   len not changed*/
		lastlen=ifc.ifc_len;
		/* try a bigger array*/
		pkg_free(ifc.ifc_req);
	}

	last=(char*)ifc.ifc_req+ifc.ifc_len;
	for(p=(char*)ifc.ifc_req; p<last;
			p+=
			#ifdef __OS_linux
				sizeof(ifr) /* works on x86_64 too */
			#else
				(sizeof(ifr.ifr_name)+
				#ifdef  HAVE_SOCKADDR_SA_LEN
					MAX(ifr.ifr_addr.sa_len, sizeof(struct sockaddr))
				#else
					( (ifr.ifr_addr.sa_family==AF_INET)?
						sizeof(struct sockaddr_in):
						((ifr.ifr_addr.sa_family==AF_INET6)?
						sizeof(struct sockaddr_in6):sizeof(struct sockaddr)) )
				#endif
				)
			#endif
		)
	{
		/* copy contents into ifr structure
		 * warning: it might be longer (e.g. ipv6 address) */
		memcpy(&ifr, p, sizeof(ifr));
		if (ifr.ifr_addr.sa_family!=family){
			/*printf("strange family %d skipping...\n",
					ifr->ifr_addr.sa_family);*/
			continue;
		}

		/*get flags*/
		ifrcopy=ifr;
		if (ioctl(s, SIOCGIFFLAGS,  &ifrcopy)!=-1){ /* ignore errors */
			/* ignore down ifs only if listening on all of them*/
			if (if_name==0){
				/* if if not up, skip it*/
				if (!(ifrcopy.ifr_flags & IFF_UP)) continue;
			}
		}



		if ((if_name==0)||
			(strncmp(if_name, ifr.ifr_name, sizeof(ifr.ifr_name))==0)){

			/*add address*/
			sockaddr2ip_addr(&addr,
					(struct sockaddr*)(p+(long)&((struct ifreq*)0)->ifr_addr));
			if ((tmp=ip_addr2a(&addr))==0) goto error;
			/* check if loopback */
			if (ifrcopy.ifr_flags & IFF_LOOPBACK)
				flags|=SI_IS_LO;
			/* add it to one of the lists */
			if (new_sock2list(tmp, port, proto, 0, 0, 0, flags, list)!=0){
				LM_ERR("new_sock2list failed\n");
				goto error;
			}
			ret=0;
		}
			/*
			printf("%s:\n", ifr->ifr_name);
			printf("        ");
			print_sockaddr(&(ifr->ifr_addr));
			printf("        ");
			ls_ifflags(ifr->ifr_name, family, options);
			printf("\n");*/
	}
	pkg_free(ifc.ifc_req); /*clean up*/
	close(s);
	return  ret;
error:
	if (ifc.ifc_req) pkg_free(ifc.ifc_req);
	close(s);
	return -1;
}


/* fixes a socket list => resolve addresses,
 * interface names, fills missing members, remove duplicates */
int fix_socket_list(struct socket_info **list)
{
	struct socket_info* si;
	struct socket_info* l;
	struct socket_info* next;
	char* tmp;
	int len;
	struct hostent* he;
	char** h;

	/* try to change all the interface names into addresses
	 *  --ugly hack */

	for (si=*list;si;){
		next=si->next;
		if (add_interfaces(si->name.s, AF_INET, si->port_no,
							si->proto, list)!=-1){
			/* success => remove current entry (shift the entire array)*/
			sock_listrm(list, si);
			free_sock_info(si);
		}
		si=next;
	}
	/* get ips & fill the port numbers*/
#ifdef EXTRA_DEBUG
	LM_DBG("listening on \n");
#endif
	for (si=*list;si;si=si->next){
		/* fix the number of processes per interface */
		if (si->children==0 && (si->proto==PROTO_UDP || si->proto==PROTO_SCTP))
			si->children = children_no;
		/* fix port number, port_no should be !=0 here */
		if (si->port_no==0){
#ifdef USE_TLS
			si->port_no= (si->proto==PROTO_TLS)?tls_port_no:port_no;
#else
			si->port_no= port_no;
#endif
		}
		tmp=int2str(si->port_no, &len);
		if (len>=MAX_PORT_LEN){
			LM_ERR("bad port number: %d\n", si->port_no);
			goto error;
		}
		si->port_no_str.s=(char*)pkg_malloc(len+1);
		if (si->port_no_str.s==0){
			LM_ERR("out of pkg memory.\n");
			goto error;
		}
		strncpy(si->port_no_str.s, tmp, len+1);
		si->port_no_str.len=len;
		/* get "official hostnames", all the aliases etc. */
		he=resolvehost(si->name.s,0);
		if (he==0){
			LM_ERR("could not resolve %s\n", si->name.s);
			goto error;
		}
		/* check if we got the official name */
		if (strcasecmp(he->h_name, si->name.s)!=0){
			if (auto_aliases && add_alias(si->name.s, si->name.len,
							si->port_no, si->proto)<0){
				LM_ERR("add_alias failed\n");
			}
			/* change the official name */
			pkg_free(si->name.s);
			si->name.s=(char*)pkg_malloc(strlen(he->h_name)+1);
			if (si->name.s==0){
				LM_ERR("out of pkg memory.\n");
				goto error;
			}
			si->name.len=strlen(he->h_name);
			strncpy(si->name.s, he->h_name, si->name.len+1);
		}
		/* add the aliases*/
		if (auto_aliases) {
			for(h=he->h_aliases; h && *h; h++)
				if (add_alias(*h, strlen(*h), si->port_no, si->proto)<0){
					LM_ERR("add_alias failed\n");
				}
		}
		hostent2ip_addr(&si->address, he, 0); /*convert to ip_addr
														 format*/
		if ((tmp=ip_addr2a(&si->address))==0) goto error;
		if (si->address.af == AF_INET6) {
			si->address_str.s=(char*)pkg_malloc(strlen(tmp)+1+2);
			if (si->address_str.s==0){
				LM_ERR("out of pkg memory.\n");
				goto error;
			}
			si->address_str.s[0] = '[';
			strncpy( si->address_str.s+1 , tmp, strlen(tmp));
			si->address_str.s[1+strlen(tmp)] = ']';
			si->address_str.s[2+strlen(tmp)] = '\0';
			si->address_str.len=strlen(tmp) + 2;
		} else {
			si->address_str.s=(char*)pkg_malloc(strlen(tmp)+1);
			if (si->address_str.s==0){
				LM_ERR("out of pkg memory.\n");
				goto error;
			}
			strncpy(si->address_str.s, tmp, strlen(tmp)+1);
			si->address_str.len=strlen(tmp);
		}
		/* set is_ip (1 if name is an ip address, 0 otherwise) */
		if ( auto_aliases && (si->address_str.len==si->name.len) &&
				(strncasecmp(si->address_str.s, si->name.s,
								si->address_str.len)==0)
			){
				si->flags|=SI_IS_IP;
				/* do rev. DNS on it (for aliases)*/
				he=rev_resolvehost(&si->address);
				if (he==0){
					LM_WARN("could not rev. resolve %s\n", si->name.s);
				}else{
					/* add the aliases*/
					if (add_alias(he->h_name, strlen(he->h_name),
									si->port_no, si->proto)<0){
						LM_ERR("add_alias failed\n");
					}
					for(h=he->h_aliases; h && *h; h++)
						if (add_alias(*h,strlen(*h),si->port_no,si->proto)<0){
							LM_ERR(" add_alias failed\n");
						}
				}
		}

		/* Now build an ip_addr structure for the adv_name, if there is one
		 * so that find_si can find it later easily.  Doing this so that
		 * we can force_send_socket() on an advertised name.  Generally there
		 * is little interest in dealing with an advertised name as anything
		 * other than an opaque string that we blindly put into the SIP
		 * message.
		 */
        if(si->adv_name_str.len) {
			/* If adv_name_str is already an IP, this is kinda foolish cus it
			 * converts it to ip_addr, then to he, then here we go back to
			 * ip_addr, but it's either that, or we duplicate the logic to
			 * check for an ip address here, and still we might have to call
			 * resolvehost().
			 */
			he=resolvehost(si->adv_name_str.s,0);
			if (he==0){
				LM_ERR("ERROR: fix_socket_list: could not resolve "
						"advertised name %s\n", si->adv_name_str.s);
				goto error;
			}
			hostent2ip_addr(&si->adv_address, he, 0); /*convert to ip_addr */

			/* build and set string encoding for the adv socket info
			 * This is usefful for the usrloc module when it's generating
			 * or updating the socket on a location record, so we'll generate
			 * it up front just like the regular sock_str so we don't have
			 * to worry about it later.
			 */
			tmp = socket2str( si, 0, &si->adv_sock_str.len, 1);
			if (tmp==0) {
				LM_ERR("ERROR: fix_socket_list: failed to convert "
					    "socket to string (adv)\n");
				goto error;
			}
			si->adv_sock_str.s=(char*)pkg_malloc(si->adv_sock_str.len);
			if (si->adv_sock_str.s==0) {
				LM_ERR("ERROR: fix_socket_list: out of memory.\n");
				goto error;
			}
			memcpy(si->adv_sock_str.s, tmp, si->adv_sock_str.len);
		}

		/* build and set string encoding for the real socket info */
		tmp = socket2str( si, 0, &si->sock_str.len, 0);
		if (tmp==0) {
			LM_ERR("failed to convert socket to string");
			goto error;
		}
		si->sock_str.s=(char*)pkg_malloc(si->sock_str.len);
		if (si->sock_str.s==0) {
			LM_ERR("out of pkg memory.\n");
			goto error;
		}
		memcpy(si->sock_str.s, tmp, si->sock_str.len);

#ifdef USE_MCAST
		/* Check if it is an multicast address and
		 * set the flag if so
		 */
		if (is_mcast(&si->address)) {
			si->flags |= SI_IS_MCAST;
		}
#endif /* USE_MCAST */

#ifdef EXTRA_DEBUG
		printf("              %.*s [%s]:%s%s\n", si->name.len,
				si->name.s, si->address_str.s, si->port_no_str.s,
		                si->flags & SI_IS_MCAST ? " mcast" : "");
#endif
	}
	/* removing duplicate addresses*/
	for (si=*list;si; si=si->next){
		for (l=si->next;l;){
			next=l->next;
			if ((si->port_no==l->port_no) &&
				(si->address.af==l->address.af) &&
				(memcmp(si->address.u.addr, l->address.u.addr, si->address.len)
					== 0)
				){
#ifdef EXTRA_DEBUG
				printf("removing duplicate %s [%s] ==  %s [%s]\n",
						si->name.s, si->address_str.s,
						 l->name.s, l->address_str.s);
#endif
				/* add the name to the alias list*/
				if ((!(l->flags& SI_IS_IP)) && (
						(l->name.len!=si->name.len)||
						(strncmp(l->name.s, si->name.s, si->name.len)!=0))
					)
					add_alias(l->name.s, l->name.len, l->port_no, l->proto);

				/* remove l*/
				sock_listrm(list, l);
				free_sock_info(l);
			}
			l=next;
		}
	}

#ifdef USE_MCAST
	     /* Remove invalid multicast entries */
	si=*list;
	while(si){
		if ((si->flags & SI_IS_MCAST) &&
		    ((si->proto == PROTO_TCP)
#ifdef USE_TLS
		    || (si->proto == PROTO_TLS)
#endif /* USE_TLS */
#ifdef USE_SCTP
			|| (si->proto == PROTO_SCTP)
#endif
		    )){
			LM_WARN("removing entry %s:%s [%s]:%s\n",
			    get_proto_name(si->proto), si->name.s,
			    si->address_str.s, si->port_no_str.s);
			l = si;
			si=si->next;
			sock_listrm(list, l);
			free_sock_info(l);
		} else {
			si=si->next;
		}
	}
#endif /* USE_MCAST */

	return 0;
error:
	return -1;
}



/* fix all 3 socket lists
 * return 0 on success, -1 on error */
int fix_all_socket_lists(void)
{
	struct utsname myname;

	if ((udp_listen==0)
#ifdef USE_TCP
			&& (tcp_listen==0)
#ifdef USE_TLS
			&& (tls_listen==0)
#endif
#endif
#ifdef USE_SCTP
			&& (sctp_listen==0)
#endif
		){
		/* get all listening ipv4 interfaces */
		if (add_interfaces(0, AF_INET, 0,  PROTO_UDP, &udp_listen)==0){
			/* if ok, try to add the others too */
#ifdef USE_TCP
			if (!tcp_disable){
				if (add_interfaces(0, AF_INET, 0,  PROTO_TCP, &tcp_listen)!=0)
					goto error;
#ifdef USE_TLS
				if (!tls_disable){
					if (add_interfaces(0, AF_INET, 0, PROTO_TLS,
								&tls_listen)!=0)
					goto error;
				}
#endif
			}
#endif
#ifdef USE_SCTP
			if (!sctp_disable){
				if (add_interfaces(0, AF_INET, 0, PROTO_SCTP, &sctp_listen)!=0)
					goto error;
			}
#endif
		}else{
			/* if error fall back to get hostname */
			/* get our address, only the first one */
			if (uname (&myname) <0){
				LM_ERR("cannot determine hostname, try -l address\n");
				goto error;
			}
			if (add_listen_iface(myname.nodename, 0, 0, 0, 0, 0, 0)!=0){
				LM_ERR("add_listen_iface failed \n");
				goto error;
			}
		}
	}
	if (fix_socket_list(&udp_listen)!=0){
		LM_ERR("fix_socket_list udp failed\n");
		goto error;
	}
#ifdef USE_TCP
	if (!tcp_disable && (fix_socket_list(&tcp_listen)!=0)){
		LM_ERR("fix_socket_list tcp failed\n");
		goto error;
	}
#ifdef USE_TLS
	if (!tls_disable && (fix_socket_list(&tls_listen)!=0)){
		LM_ERR("fix_socket_list tls failed\n");
		goto error;
	}
#endif
#endif
#ifdef USE_SCTP
	if (!sctp_disable && (fix_socket_list(&sctp_listen)!=0)){
		LM_ERR("fix_socket_list sctp failed\n");
		goto error;
	}
#endif

	if ((udp_listen==0)
#ifdef USE_TCP
			&& (tcp_listen==0 || tcp_disable)
#ifdef USE_TLS
			&& (tls_listen==0 || tls_disable)
#endif
#endif
#ifdef USE_SCTP
			&& (sctp_listen==0 || sctp_disable)
#endif
	){
		LM_ERR("no listening sockets\n");
		goto error;
	}
	return 0;
error:
	return -1;
}


/*
 * This function will retrieve a list of all ip addresses and ports that OpenSER
 * is listening on, with respect to the transport protocol specified with
 * 'protocol'.
 *
 * The first parameter, ipList, is a pointer to a pointer. It will be assigned a
 * new block of memory holding the IP Addresses and ports being listened to with
 * respect to 'protocol'.  The array maps a 2D array into a 1 dimensional space,
 * and is layed out as follows:
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
 * The function will return the number of sockets which were found.  This can be
 * used to index into ipList.
 *
 * NOTE: This function assigns a block of memory equal to:
 *
 *            returnedValue * (NUM_IP_OCTETS + 1) * sizeof(int);
 *
 *       Therefore it is CRUCIAL that you free ipList when you are done with its
 *       contents, to avoid a nasty memory leak.
 */
int get_socket_list_from_proto(int **ipList, int protocol) {

	struct socket_info  *si;
	struct socket_info** list;

	int num_ip_octets   = 4;
	int numberOfSockets = 0;
	int currentRow      = 0;

	/* I hate to use #ifdefs, but this is necessary because of the way
	 * get_sock_info_list() is defined.  */
#ifndef USE_TCP
	if (protocol == PROTO_TCP)
	{
		return 0;
	}
#endif

#ifndef USE_TLS
	if (protocol == PROTO_TLS)
	{
		return 0;
	}
#endif

	/* Retrieve the list of sockets with respect to the given protocol. */
	list=get_sock_info_list(protocol);

	/* Find out how many sockets are in the list.  We need to know this so
	 * we can malloc an array to assign to ipList. */
	for(si=list?*list:0; si; si=si->next){
		/* We only support IPV4 at this point. */
		if (si->address.af == AF_INET) {
			numberOfSockets++;
		}
	}

	/* There are no open sockets with respect to the given protocol. */
	if (numberOfSockets == 0)
	{
		return 0;
	}

	*ipList = pkg_malloc(numberOfSockets * (num_ip_octets + 1) * sizeof(int));

	/* We couldn't allocate memory for the IP List.  So all we can do is
	 * fail. */
	if (*ipList == NULL) {
		LM_ERR("no more pkg memory");
		return 0;
	}


	/* We need to search the list again.  So find the front of the list. */
	list=get_sock_info_list(protocol);

	/* Extract out the IP Addresses and ports.  */
	for(si=list?*list:0; si; si=si->next){

		/* We currently only support IPV4. */
		if (si->address.af != AF_INET) {
			continue;
		}

		(*ipList)[currentRow*(num_ip_octets + 1)  ] =
			si->address.u.addr[0];
		(*ipList)[currentRow*(num_ip_octets + 1)+1] =
			si->address.u.addr[1];
		(*ipList)[currentRow*(num_ip_octets + 1)+2] =
			si->address.u.addr[2];
		(*ipList)[currentRow*(num_ip_octets + 1)+3] =
			si->address.u.addr[3];
		(*ipList)[currentRow*(num_ip_octets + 1)+4] =
			si->port_no;

		currentRow++;
	}

	return numberOfSockets;
}

/*
 * Takes a 'line' (from the proc file system), parses out the ipAddress,
 * address, and stores the number of bytes waiting in 'rx_queue'
 *
 * Returns 1 on success, and 0 on a failed parse.
 *
 * Note: The format of ipAddress is as defined in the comments of
 * get_socket_list_from_proto() in this file.
 *
 */
static int parse_proc_net_line(char *line, int *ipAddress, int *rx_queue)
{
	int i;

	int ipOctetExtractionMask = 0xFF;

	char *currColonLocation;
	char *nextNonNumericalChar;
	char *currentLocationInLine = line;

	int parsedInteger[4];

	/* Example line from /proc/net/tcp or /proc/net/udp:
	 *
	 *	sl  local_address rem_address   st tx_queue rx_queue
	 *	21: 5A0A0B0A:CAC7 1C016E0A:0016 01 00000000:00000000
	 *
	 * Algorithm:
	 *
	 * 	1) Find the location of the first  ':'
	 * 	2) Parse out the IP Address into an integer
	 * 	3) Find the location of the second ':'
	 * 	4) Parse out the port number.
	 * 	5) Find the location of the fourth ':'
	 * 	6) Parse out the rx_queue.
	 */

	for (i = 0; i < 4; i++) {

		currColonLocation = strchr(currentLocationInLine, ':');

		/* We didn't find all the needed ':', so fail. */
		if (currColonLocation == NULL) {
			return 0;
		}

		/* Parse out the integer, keeping the location of the next
		 * non-numerical character.  */
		parsedInteger[i] =
			(int) strtol(++currColonLocation, &nextNonNumericalChar,
					16);

		/* strtol()'s specifications specify that the second parameter
		 * is set to the first parameter when a number couldn't be
		 * parsed out.  This means the parse was unsuccesful.  */
		if (nextNonNumericalChar == currColonLocation) {
			return 0;
		}

		/* Reset the currentLocationInLine to the last non-numerical
		 * character, so that next iteration of this loop, we can find
		 * the next colon location. */
		currentLocationInLine = nextNonNumericalChar;

	}

	/* Extract out the segments of the IP Address.  They are stored in
	 * reverse network byte order. */
	for (i = 0; i < NUM_IP_OCTETS; i++) {

		ipAddress[i] =
			parsedInteger[0] & (ipOctetExtractionMask << i*8);

		ipAddress[i] >>= i*8;

	}

	ipAddress[NUM_IP_OCTETS] = parsedInteger[1];

	*rx_queue = parsedInteger[3];

	return 1;

}


/*
 * Returns 1 if ipOne was found in ipArray, and 0 otherwise.
 *
 * The format of ipOne and ipArray are described in the comments of
 * get_socket_list_from_proto() in this file.
 *
 * */
static int match_ip_and_port(int *ipOne, int *ipArray, int sizeOf_ipArray)
{
	int curIPAddrIdx;
	int curOctetIdx;
	int ipArrayIndex;

	/* Loop over every IP Address */
	for (curIPAddrIdx = 0; curIPAddrIdx < sizeOf_ipArray; curIPAddrIdx++) {

		/* Check for octets that don't match.  If one is found, skip the
		 * rest.  */
		for (curOctetIdx = 0; curOctetIdx < NUM_IP_OCTETS + 1; curOctetIdx++) {

			/* We've encoded a 2D array as a 1D array.  So find out
			 * our position in the 1D array. */
			ipArrayIndex =
				curIPAddrIdx * (NUM_IP_OCTETS + 1) + curOctetIdx;

			if (ipOne[curOctetIdx] != ipArray[ipArrayIndex]) {
				break;
			}
		}

		/* If the index from the inner loop is equal to NUM_IP_OCTETS
		 * + 1, then that means that every octet (and the port with the
		 * + 1) matched. */
		if (curOctetIdx == NUM_IP_OCTETS + 1) {
			return 1;
		}

	}

	return 0;
}


/*
 * Returns the number of bytes waiting to be consumed on the network interfaces
 * assigned the IP Addresses specified in interfaceList.  The check will be
 * limited to the TCP or UDP transport exclusively.  Specifically:
 *
 * - If forTCP is non-zero, the check involves only the TCP transport.
 * - if forTCP is zero, the check involves only the UDP transport.
 *
 * Note: This only works on linux systems supporting the /proc/net/[tcp|udp]
 *       interface.  On other systems, zero will always be returned.
 */
static int get_used_waiting_queue(
		int forTCP, int *interfaceList, int listSize)
{
	FILE *fp;
	char *fileToOpen;

	char lineBuffer[MAX_PROC_BUFFER];
	int  ipAddress[NUM_IP_OCTETS+1];
	int  rx_queue;
	int  waitingQueueSize = 0;

	if (listSize==0 || interfaceList==NULL)
		return 0;

	/* Set up the file we want to open. */
	if (forTCP) {
		fileToOpen = "/proc/net/tcp";
	} else {
		fileToOpen = "/proc/net/udp";
	}

	fp = fopen(fileToOpen, "r");

	if (fp == NULL) {
		LM_DBG("Could not open %s. openserMsgQueu eDepth and its related"
				" alarms will not be available.\n", fileToOpen);
		return 0;
	}

	/* Read in every line of the file, parse out the ip address, port, and
	 * rx_queue, and compare to our list of interfaces we are listening on.
	 * Add up rx_queue for those lines which match our known interfaces. */
	while (fgets(lineBuffer, MAX_PROC_BUFFER, fp)!=NULL) {

		/* Parse out the ip address, port, and rx_queue. */
		if(parse_proc_net_line(lineBuffer, ipAddress, &rx_queue)) {

			/* Only add rx_queue if the line just parsed corresponds
			 * to an interface we are listening on.  We do this
			 * check because it is possible that this system has
			 * other network interfaces that OpenSER has been told
			 * to ignore. */
			if (match_ip_and_port(ipAddress, interfaceList, listSize)) {
				waitingQueueSize += rx_queue;
			}
		}
	}

	fclose(fp);

	return waitingQueueSize;
}

/*
 * Returns the sum of the number of bytes waiting to be consumed on all network
 * interfaces and transports that OpenSIPS is listening on.
 *
 * Note: This currently only works on systems supporting the /proc/net/[tcp|udp]
 *       interface.  On other systems, zero will always be returned.  To change
 *       this in the future, add an equivalent for get_used_waiting_queue().
 */
int get_total_bytes_waiting(int only_proto)
{
	static int *UDPList  = NULL;
	static int *TCPList  = NULL;
	static int *TLSList  = NULL;

	static int numUDPSockets  = -1;
	static int numTCPSockets  = -1;
	static int numTLSSockets  = -1;

	int bytesWaiting = 0;

	/* Extract out the IP address address for UDP, TCP, and TLS, keeping
	 * track of the number of IP addresses from each transport  */
	if (numUDPSockets==-1)
		numUDPSockets  = get_socket_list_from_proto(&UDPList,  PROTO_UDP);
	if (numTCPSockets==-1)
		numTCPSockets  = get_socket_list_from_proto(&TCPList,  PROTO_TCP);
	if (numTLSSockets==-1)
		numTLSSockets  = get_socket_list_from_proto(&TLSList,  PROTO_TLS);

	/* Find out the number of bytes waiting on our interface list over all
	 * UDP and TCP transports. */
	if (only_proto==PROTO_NONE) {
		bytesWaiting  += get_used_waiting_queue(0, UDPList,  numUDPSockets);
		bytesWaiting  += get_used_waiting_queue(1, TCPList,  numTCPSockets);
		bytesWaiting  += get_used_waiting_queue(1, TLSList,  numTLSSockets);
	} else if (only_proto==PROTO_UDP) {
		bytesWaiting  += get_used_waiting_queue(0, UDPList,  numUDPSockets);
	} else if (only_proto==PROTO_TCP) {
		bytesWaiting  += get_used_waiting_queue(1, TCPList,  numTCPSockets);
	} else if (only_proto==PROTO_TLS) {
		bytesWaiting  += get_used_waiting_queue(1, TLSList,  numTLSSockets);
	}

	return bytesWaiting;
}


void print_all_socket_lists(void)
{
	struct socket_info *si;
	struct socket_info** list;
	unsigned short proto;


	proto=PROTO_UDP;
	do{
		list=get_sock_info_list(proto);
		for(si=list?*list:0; si; si=si->next){
			printf("             %s: %s [%s]:%s%s\n", get_proto_name(proto),
			       si->name.s, si->address_str.s, si->port_no_str.s,
			       si->flags & SI_IS_MCAST ? " mcast" : "");
		}
	}while((proto=next_proto(proto)));
}


void print_aliases(void)
{
	struct host_alias* a;

	for(a=aliases; a; a=a->next)
		if (a->port)
			printf("             %s: %.*s:%d\n", get_proto_name(a->proto),
					a->alias.len, a->alias.s, a->port);
		else
			printf("             %s: %.*s:*\n", get_proto_name(a->proto),
					a->alias.len, a->alias.s);
}

/*
 * Arguments :
 *		sock - socket to have buffer increased
 *		buff_choice - 0 for receive buff, 1 for send buff
 *		buff_max - max size of socket buffer we are looking for
 *		buff_increment - increment nr of bytes after reaching limit
 *
 *	Returns :
 *		0 in case of success
 *		1 in case of failure
*/
int probe_max_sock_buff(int sock,int buff_choice,int buff_max,int buff_increment)
{
	unsigned int optval, ioptval, ioptvallen, foptval, foptvallen, voptval, voptvallen;
	int phase=0;
	int buff_opt;
	char *info;

	if (buff_choice == 0)
	{
		info = "rcv";
		buff_opt = SO_RCVBUF;
	}
	else if (buff_choice == 1)
	{
		info = "snd";
		buff_opt = SO_SNDBUF;
	}
	else
	{
		LM_WARN("Called with unimplemented buff_choice - %d\n",buff_choice);
		return 1;
	}

	/* try to increase buffer size as much as we can */
	ioptvallen=sizeof(ioptval);
	if (getsockopt( sock, SOL_SOCKET, buff_opt, (void*) &ioptval,
		    &ioptvallen) == -1 )
	{
		LM_ERR("getsockopt: %s\n", strerror(errno));
		return -1;
	}
	if ( ioptval==0 )
	{
		LM_DBG(" getsockopt: %s initially set to 0; resetting to %d\n",
			info,buff_increment );
		ioptval=buff_increment;
	} else LM_DBG("getsockopt: %s is initially %d\n",info, ioptval );
	for (optval=ioptval; ;  ) {
		/* increase size; double in initial phase, add linearly later */
		if (phase==0) optval <<= 1; else optval+=buff_increment;
		if (optval > maxbuffer){
			if (phase==1) break;
			else { phase=1; optval >>=1; continue; }
		}
		LM_DBG("trying : %d\n", optval );
		if (setsockopt( sock, SOL_SOCKET, buff_opt,
			(void*)&optval, sizeof(optval)) ==-1){
			/* Solaris returns -1 if asked size too big; Linux ignores */
			LM_DBG("setsockopt: SOL_SOCKET failed"
					" for %d, phase %d: %s\n", optval, phase, strerror(errno));
			/* if setting buffer size failed and still in the aggressive
			   phase, try less aggressively; otherwise give up */
			if (phase==0) { phase=1; optval >>=1 ; continue; }
			else break;
		}
		/* verify if change has taken effect */
		/* Linux note -- otherwise I would never know that; funny thing: Linux
		   doubles size for which we asked in setsockopt */
		voptvallen=sizeof(voptval);
		if (getsockopt( sock, SOL_SOCKET, buff_opt, (void*) &voptval,
		    &voptvallen) == -1 )
		{
			LM_ERR("getsockopt: %s\n", strerror(errno));
			return -1;
		} else {
			LM_DBG("setting %s: set=%d,verify=%d\n",info,
				optval, voptval);
			if (voptval<optval) {
				LM_DBG("setting buf has no effect\n");
				/* if setting buffer size failed and still in the aggressive
				phase, try less aggressively; otherwise give up */
				if (phase==0) { phase=1; optval >>=1 ; continue; }
				else break;
			}
		}

	} /* for ... */
	foptvallen=sizeof(foptval);
	if (getsockopt( sock, SOL_SOCKET, buff_opt, (void*) &foptval,
		    &foptvallen) == -1 )
	{
		LM_ERR("getsockopt: %s\n", strerror(errno));
		return -1;
	}
	LM_INFO("using %s buffer of %d kb\n",info, (foptval/1024));

	return 0;
}
