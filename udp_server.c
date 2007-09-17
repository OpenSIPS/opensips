/*
 * $Id$
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
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * --------
 *  2003-01-28  packet zero-termination moved to receive_msg (jiri)
 *  2003-02-10  undoed the above changes (andrei)
 *  2003-03-19  replaced all the mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-14  set sockopts to TOS low delay (andrei)
 *  2004-05-03  applied multicast support patch from janakj
 *              added set multicast ttl support (andrei)
 *  2004-07-05  udp_rcv_loop: drop packets with 0 src port + error msg.
 *              cleanups (andrei)
 *  2005-03-10  multicast options are now set for all the udp sockets (andrei)
 */


#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <errno.h>
#include <arpa/inet.h>
#ifdef __linux__
	#include <linux/types.h>
	#include <linux/errqueue.h>
#endif


#include "udp_server.h"
#include "globals.h"
#include "config.h"
#include "dprint.h"
#include "receive.h"
#include "mem/mem.h"
#include "ip_addr.h"


#ifdef DBG_MSG_QA
/* message quality assurance -- frequently, bugs in ser have
   been indicated by zero characters or long whitespaces
   in generated messages; this debugging option aborts if
   any such message is sighted
*/
static int dbg_msg_qa(char *buf, int len)
{
#define _DBG_WS_LEN 3
#define _DBG_WS "   "

	char *scan;
	int my_len;
	int space_cnt;
	enum { QA_ANY, QA_SPACE, QA_EOL1 } state;

	my_len=len;
	scan=buf;
	state=QA_ANY;
	space_cnt=0;

	while(my_len) {
		switch(*scan) {
			case ' ':	if (state==QA_SPACE) {
							space_cnt++;
							if (space_cnt==4) {
								LM_CRIT("too many spaces\n");
								return 0;
							}
						} else space_cnt=0;
						state=QA_SPACE; 
						break;

			case '\r':	/* ignore */
						space_cnt=0;
						break;

			case '\n': /* don't proceed to body on EoH */
						if (state==QA_EOL1) goto qa_passed;
						space_cnt=0;
						state=QA_EOL1;
						break;

			default:	space_cnt=0;
						state=QA_ANY;
						break;
		}
		scan++;
		my_len--;
	}


qa_passed:
	return 1;
}

#endif


int probe_max_receive_buffer( int udp_sock )
{
	unsigned int optval;
	unsigned int ioptval;
	unsigned int ioptvallen;
	unsigned int foptval;
	unsigned int foptvallen;
	unsigned int voptval;
	unsigned int voptvallen;
	int phase=0;

	/* jku: try to increase buffer size as much as we can */
	ioptvallen=sizeof(ioptval);
	if (getsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF, (void*) &ioptval,
		    &ioptvallen) == -1 )
	{
		LM_ERR("getsockopt: %s\n", strerror(errno));
		return -1;
	}
	if ( ioptval==0 ) 
	{
		LM_DBG(" getsockopt: SO_RCVBUF initially set to 0; resetting to %d\n",
			BUFFER_INCREMENT );
		ioptval=BUFFER_INCREMENT;
	} else LM_INFO("getsockopt SO_RCVBUF is initially %d\n", ioptval );
	for (optval=ioptval; ;  ) {
		/* increase size; double in initial phase, add linearly later */
		if (phase==0) optval <<= 1; else optval+=BUFFER_INCREMENT;
		if (optval > maxbuffer){
			if (phase==1) break; 
			else { phase=1; optval >>=1; continue; }
		}
		LM_DBG("trying SO_RCVBUF: %d\n", optval );
		if (setsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF,
			(void*)&optval, sizeof(optval)) ==-1){
			/* Solaris returns -1 if asked size too big; Linux ignores */
			LM_DBG("setsockopt: SOL_SOCKET failed"
					" for %d, phase %d: %s\n", optval, phase, strerror(errno));
			/* if setting buffer size failed and still in the aggressive
			   phase, try less aggressively; otherwise give up 
			*/
			if (phase==0) { phase=1; optval >>=1 ; continue; } 
			else break;
		} 
		/* verify if change has taken effect */
		/* Linux note -- otherwise I would never know that; funny thing: Linux
		   doubles size for which we asked in setsockopt
		*/
		voptvallen=sizeof(voptval);
		if (getsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF, (void*) &voptval,
		    &voptvallen) == -1 )
		{
			LM_ERR("getsockopt: %s\n", strerror(errno));
			return -1;
		} else {
			LM_DBG("setting SO_RCVBUF; set=%d,verify=%d\n", 
				optval, voptval);
			if (voptval<optval) {
				LM_DBG("setting SO_RCVBUF has no effect\n");
				/* if setting buffer size failed and still in the aggressive
				phase, try less aggressively; otherwise give up 
				*/
				if (phase==0) { phase=1; optval >>=1 ; continue; } 
				else break;
			} 
		}
	
	} /* for ... */
	foptvallen=sizeof(foptval);
	if (getsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF, (void*) &foptval,
		    &foptvallen) == -1 )
	{
		LM_ERR("getsockopt: %s\n", strerror(errno));
		return -1;
	}
	LM_INFO("option SO_RCVBUF is finally %d\n", foptval );

	return 0;

	/* EoJKU */
}


#ifdef USE_MCAST

/*
 * Setup multicast receiver
 */
static int setup_mcast_rcvr(int sock, union sockaddr_union* addr)
{
	struct ip_mreq mreq;
#ifdef USE_IPV6
	struct ipv6_mreq mreq6;
#endif /* USE_IPV6 */
	
	if (addr->s.sa_family==AF_INET){
		memcpy(&mreq.imr_multiaddr, &addr->sin.sin_addr, 
		       sizeof(struct in_addr));
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,&mreq,
			       sizeof(mreq))==-1){
			LM_ERR("setsockopt: %s\n", strerror(errno));
			return -1;
		}
		
#ifdef USE_IPV6
	} else if (addr->s.sa_family==AF_INET6){
		memcpy(&mreq6.ipv6mr_multiaddr, &addr->sin6.sin6_addr, 
		       sizeof(struct in6_addr));
		mreq6.ipv6mr_interface = 0;
#ifdef __OS_linux
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6,
#else
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
#endif
			       sizeof(mreq6))==-1){
			LM_ERR("setsockopt:%s\n",  strerror(errno));
			return -1;
		}
		
#endif /* USE_IPV6 */
	} else {
		LM_ERR("unsupported protocol family\n");
		return -1;
	}
	return 0;
}

#endif /* USE_MCAST */


int udp_init(struct socket_info* sock_info)
{
	union sockaddr_union* addr;
	int optval;
#ifdef USE_MCAST
	unsigned char m_optval;
#endif

	addr=&sock_info->su;
	sock_info->proto=PROTO_UDP;
	if (init_su(addr, &sock_info->address, sock_info->port_no)<0){
		LM_ERR("could not init sockaddr_union\n");
		goto error;
	}
	
	sock_info->socket = socket(AF2PF(addr->s.sa_family), SOCK_DGRAM, 0);
	if (sock_info->socket==-1){
		LM_ERR("socket: %s\n", strerror(errno));
		goto error;
	}
	/* set sock opts? */
	optval=1;
	if (setsockopt(sock_info->socket, SOL_SOCKET, SO_REUSEADDR ,
					(void*)&optval, sizeof(optval)) ==-1){
		LM_ERR("setsockopt: %s\n", strerror(errno));
		goto error;
	}
	/* tos */
	optval=tos;
	if (setsockopt(sock_info->socket, IPPROTO_IP, IP_TOS, (void*)&optval, 
			sizeof(optval)) ==-1){
		LM_WARN("setsockopt tos: %s\n", strerror(errno));
		/* continue since this is not critical */
	}
#if defined (__linux__) && defined(UDP_ERRORS)
	optval=1;
	/* enable error receiving on unconnected sockets */
	if(setsockopt(sock_info->socket, SOL_IP, IP_RECVERR,
					(void*)&optval, sizeof(optval)) ==-1){
		LM_ERR("setsockopt: %s\n", strerror(errno));
		goto error;
	}
#endif

#ifdef USE_MCAST
	if ((sock_info->flags & SI_IS_MCAST) 
	    && (setup_mcast_rcvr(sock_info->socket, addr)<0)){
			goto error;
	}
	/* set the multicast options */
	if (addr->s.sa_family==AF_INET){
		m_optval = mcast_loopback;
		if (setsockopt(sock_info->socket, IPPROTO_IP, IP_MULTICAST_LOOP, 
						&m_optval, sizeof(m_optval))==-1){
			LM_WARN("setsockopt(IP_MULTICAST_LOOP): %s\n", strerror(errno));
			/* it's only a warning because we might get this error if the
			  network interface doesn't support multicasting -- andrei */
		}
		if (mcast_ttl>=0){
			m_optval = mcast_ttl;
			if (setsockopt(sock_info->socket, IPPROTO_IP, IP_MULTICAST_TTL,
						&m_optval, sizeof(m_optval))==-1){
				LM_ERR("setsockopt (IP_MULTICAST_TTL): %s\n", strerror(errno));
				goto error;
			}
		}
#ifdef USE_IPV6
	} else if (addr->s.sa_family==AF_INET6){
		if (setsockopt(sock_info->socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 
						&mcast_loopback, sizeof(mcast_loopback))==-1){
			LM_WARN("setsockopt (IPV6_MULTICAST_LOOP): %s\n", strerror(errno));
			/* it's only a warning because we might get this error if the
			  network interface doesn't support multicasting -- andrei */
		}
		if (mcast_ttl>=0){
			if (setsockopt(sock_info->socket, IPPROTO_IP, IPV6_MULTICAST_HOPS,
						&mcast_ttl, sizeof(mcast_ttl))==-1){
				LM_ERR("setssckopt (IPV6_MULTICAST_HOPS): %s\n",
						strerror(errno));
				goto error;
			}
		}
#endif /* USE_IPV6*/
	} else {
		LM_ERR("unsupported protocol family %d\n", addr->s.sa_family);
		goto error;
	}
#endif /* USE_MCAST */

	if ( probe_max_receive_buffer(sock_info->socket)==-1) goto error;
	
	if (bind(sock_info->socket,  &addr->s, sockaddru_len(*addr))==-1){
		LM_ERR("bind(%x, %p, %d) on %s: %s\n", sock_info->socket, &addr->s, 
				(unsigned)sockaddru_len(*addr),	sock_info->address_str.s,
				strerror(errno));
	#ifdef USE_IPV6
		if (addr->s.sa_family==AF_INET6)
			LM_ERR("might be caused by using a link "
					" local address, try site local or global\n");
	#endif
		goto error;
	}

/*	pkg_free(addr);*/
	return 0;

error:
/*	if (addr) pkg_free(addr);*/
	return -1;
}



int udp_rcv_loop(void)
{
	int len;
#ifdef DYN_BUF
	char* buf;
#else
	static char buf [BUF_SIZE+1];
#endif
	char *tmp;
	union sockaddr_union* from;
	unsigned int fromlen;
	struct receive_info ri;


	from=(union sockaddr_union*) pkg_malloc(sizeof(union sockaddr_union));
	if (from==0){
		LM_ERR("out of pkg memory\n");
		goto error;
	}
	memset(from, 0 , sizeof(union sockaddr_union));
	ri.bind_address=bind_address; /* this will not change, we do it only once*/
	ri.dst_port=bind_address->port_no;
	ri.dst_ip=bind_address->address;
	ri.proto=PROTO_UDP;
	ri.proto_reserved1=ri.proto_reserved2=0;
	for(;;){
#ifdef DYN_BUF
		buf=pkg_malloc(BUF_SIZE+1);
		if (buf==0){
			LM_ERR("could not allocate receive buffer\n");
			goto error;
		}
#endif
		fromlen=sockaddru_len(bind_address->su);
		len=recvfrom(bind_address->socket, buf, BUF_SIZE, 0, &from->s,
											&fromlen);
		if (len==-1){
			if (errno==EAGAIN){
				LM_DBG("packet with bad checksum received\n");
				continue;
			}
			LM_ERR("recvfrom:[%d] %s\n", errno, strerror(errno));
			if ((errno==EINTR)||(errno==EWOULDBLOCK)|| (errno==ECONNREFUSED))
				continue; /* goto skip;*/
			else goto error;
		}
		/* we must 0-term the messages, receive_msg expects it */
		buf[len]=0; /* no need to save the previous char */

		ri.src_su=*from;
		su2ip_addr(&ri.src_ip, from);
		ri.src_port=su_getport(from);

#ifndef NO_ZERO_CHECKS
		if (len<MIN_UDP_PACKET) {
			tmp=ip_addr2a(&ri.src_ip);
			LM_DBG("probing packet received from %s %d\n",
					tmp, htons(ri.src_port));
			continue;
		}
#endif
#ifdef DBG_MSG_QA
		if (!dbg_msg_qa(buf, len)) {
			LM_WARN("an incoming message didn't pass test,"
						"  drop it: %.*s\n", len, buf );
			continue;
		}
#endif
		if (ri.src_port==0){
			tmp=ip_addr2a(&ri.src_ip);
			LM_INFO("dropping 0 port packet from %s\n", tmp);
			continue;
		}
		
		
		/* receive_msg must free buf too!*/
		receive_msg(buf, len, &ri);
		
	/* skip: do other stuff */
		
	}
	/*
	if (from) pkg_free(from);
	return 0;
	*/
	
error:
	if (from) pkg_free(from);
	return -1;
}




/* which socket to use? main socket or new one? */
int udp_send(struct socket_info *source, char *buf, unsigned len,
										union sockaddr_union*  to)
{

	int n;
	int tolen;

#ifdef DBG_MSG_QA
	/* aborts on error, does nothing otherwise */
	if (!dbg_msg_qa( buf, len )) {
		LM_ERR("dbg_msg_qa failed\n");
		abort();
	}
#endif

	tolen=sockaddru_len(*to);
again:
	n=sendto(source->socket, buf, len, 0, &to->s, tolen);
#ifdef XL_DEBUG
	LM_INFO("status: %d\n", n);
#endif
	if (n==-1){
		LM_ERR("sendto(sock,%p,%d,0,%p,%d): %s(%d)\n", buf,len,to,tolen,
				strerror(errno),errno);
		if (errno==EINTR) goto again;
		if (errno==EINVAL) {
			LM_CRIT("invalid sendtoparameters\n"
			"one possible reason is the server is bound to localhost and\n"
			"attempts to send to the net\n");
		}
	}
	return n;
}
