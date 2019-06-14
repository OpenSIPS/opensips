/*
 * ip address & address family related functions
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
 * --------
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free
 *  2004-10-01  mk_net fixes bad network addresses now (andrei)
 */

/*!
 * \file
 * \brief OpenSIPS IP address & address family related functions
 */

#include <stdlib.h>
#include <stdio.h>

#include "ip_addr.h"
#include "dprint.h"
#include "mem/mem.h"

char _ip_addr_A_buff[IP_ADDR_MAX_STR_SIZE];

struct net* mk_net(struct ip_addr* ip, struct ip_addr* mask)
{
	struct net* n;
	int warning;
	unsigned int r;

	warning=0;
	if ((ip->af != mask->af) || (ip->len != mask->len)){
		LM_CRIT("trying to use a different mask family"
				" (eg. ipv4/ipv6mask or ipv6/ipv4mask)\n");
		goto error;
	}
	n=(struct net*)pkg_malloc(sizeof(struct net));
	if (n==0){
		LM_CRIT("memory allocation failure\n");
		goto error;
	}
	n->ip=*ip;
	n->mask=*mask;
	for (r=0; r<n->ip.len/4; r++) { /*ipv4 & ipv6 addresses are multiple of 4*/
		n->ip.u.addr32[r] &= n->mask.u.addr32[r];
		if (n->ip.u.addr32[r]!=ip->u.addr32[r]) warning=1;
	};
	if (warning){
		LM_WARN("invalid network address/netmask "
					"combination fixed...\n");
		print_ip("original network address:", ip, "/");
		print_ip("", mask, "\n");
		print_ip("fixed    network address:", &(n->ip), "/");
		print_ip("", &(n->mask), "\n");
	};
	return n;
error:
	return 0;
}



struct net* mk_net_bitlen(struct ip_addr* ip, unsigned int bitlen)
{
	struct ip_addr mask;
	unsigned int r;

	if (bitlen>ip->len*8){
		LM_CRIT("bad bitlen number %d\n", bitlen);
		goto error;
	}
	memset(&mask,0, sizeof(mask));
	for (r=0;r<bitlen/8;r++) mask.u.addr[r]=0xff;
	if (bitlen%8) mask.u.addr[r]=  ~((1<<(8-(bitlen%8)))-1);
	mask.af=ip->af;
	mask.len=ip->len;

	return mk_net(ip, &mask);
error:
	return 0;
}



void print_ip(char* p, struct ip_addr* ip, char *s)
{
	switch(ip->af){
		case AF_INET:
			LM_DBG("%s%d.%d.%d.%d%s", (p)?p:"",
								ip->u.addr[0],
								ip->u.addr[1],
								ip->u.addr[2],
								ip->u.addr[3],
								(s)?s:""
								);
			break;
		case AF_INET6:
			LM_DBG("%s%x:%x:%x:%x:%x:%x:%x:%x%s", (p)?p:"",
											htons(ip->u.addr16[0]),
											htons(ip->u.addr16[1]),
											htons(ip->u.addr16[2]),
											htons(ip->u.addr16[3]),
											htons(ip->u.addr16[4]),
											htons(ip->u.addr16[5]),
											htons(ip->u.addr16[6]),
											htons(ip->u.addr16[7]),
											(s)?s:""
				);
			break;
		default:
			LM_DBG("warning unknown address family %d\n", ip->af);
	}
}



void stdout_print_ip(struct ip_addr* ip)
{
	switch(ip->af){
		case AF_INET:
			printf("%d.%d.%d.%d",	ip->u.addr[0],
								ip->u.addr[1],
								ip->u.addr[2],
								ip->u.addr[3]);
			break;
		case AF_INET6:
			printf("%x:%x:%x:%x:%x:%x:%x:%x",	htons(ip->u.addr16[0]),
											htons(ip->u.addr16[1]),
											htons(ip->u.addr16[2]),
											htons(ip->u.addr16[3]),
											htons(ip->u.addr16[4]),
											htons(ip->u.addr16[5]),
											htons(ip->u.addr16[6]),
											htons(ip->u.addr16[7])
				);
			break;
		default:
			LM_DBG("warning unknown address family %d\n", ip->af);
	}
}



void print_net(struct net* net)
{
	if (net==0){
		LM_WARN("null pointer\n");
		return;
	}
	print_ip("", &net->ip, "/"); print_ip("", &net->mask, "");
}


int ip_addr_is_1918(str *s_ip)
{
	static struct {
		uint32_t netaddr;
		uint32_t mask;
	} nets_1918[] = {
		{ 0x0a000000, 0xffffffffu << 24},  /* "10.0.0.0"    RFC 1918 */
		{ 0xac100000, 0xffffffffu << 20},  /* "172.16.0.0"  RFC 1918 */
		{ 0xc0a80000, 0xffffffffu << 16},  /* "192.168.0.0" RFC 1918 */
		{ 0x64400000, 0xffffffffu << 22},  /* "100.64.0.0"  RFC 6598 */
		{ 0, 0}
	};
	struct ip_addr *ip;
	uint32_t netaddr;
	int i;

	/* is it an IPv4 address? */
	if ( (ip=str2ip(s_ip))==NULL )
		return -1;

	netaddr = ntohl(ip->u.addr32[0]);

	for (i = 0; nets_1918[i].netaddr != 0; i++) {
		if ((netaddr & nets_1918[i].mask) == nets_1918[i].netaddr)
			return 1;
	}

	return -1;
}


#ifdef USE_MCAST

/* Returns 1 if the given address is a multicast address */
int is_mcast(struct ip_addr* ip)
{
	if (!ip){
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (ip->af==AF_INET){
		return IN_MULTICAST(htonl(ip->u.addr32[0]));
	} else if (ip->af==AF_INET6){
		return IN6_IS_ADDR_MULTICAST((struct in6_addr *)ip->u.addr);
	} else {
		LM_ERR("unsupported protocol family\n");
		return -1;
	}
}

#endif /* USE_MCAST */
