/*
 * Copyright (C) 2014-2015 OpenSIPS Foundation
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
 *
 * History:
 * -------
 *  2015-02-09  first version (bogdan)
 */


#include <unistd.h>

#include "../ipc.h"
#include "../daemonize.h"
#include "../reactor.h"
#include "../timer.h"
#include "net_udp.h"


#define UDP_SELECT_TIMEOUT  1

/* if the UDP network layer is used or not by some protos */
static int udp_disabled = 1;

extern void handle_sigs(void);

/* initializes the UDP network layer */
int udp_init(void)
{
	unsigned int i;

	/* first we do auto-detection to see if there are any UDP based
	 * protocols loaded */
	for ( i=PROTO_FIRST ; i<PROTO_LAST ; i++ )
		if (is_udp_based_proto(i)) {udp_disabled=0;break;}

	return 0;
}

/* destroys the UDP network layer */
void udp_destroy(void)
{
	return;
}

/* tells how many processes the UDP layer will create */
int udp_count_processes(void)
{
	struct socket_info *si;
	int n, i;

	if (udp_disabled)
		return 0;

	for( i=0,n=0 ; i<PROTO_LAST ; i++)
		if (protos[i].id!=PROTO_NONE && is_udp_based_proto(i))
			for( si=protos[i].listeners ; si; si=si->next)
				n+=si->children;

	return n;
}

#ifdef USE_MCAST
/**
 * Setup a multicast receiver socket, supports IPv4 and IPv6.
 * \param sock socket
 * \param addr receiver address
 * \return zero on success, -1 otherwise
 */
static int setup_mcast_rcvr(int sock, union sockaddr_union* addr)
{
	struct ip_mreq mreq;
	struct ipv6_mreq mreq6;

	if (addr->s.sa_family==AF_INET){
		memcpy(&mreq.imr_multiaddr, &addr->sin.sin_addr,
		       sizeof(struct in_addr));
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,&mreq,
			       sizeof(mreq))==-1){
			LM_ERR("setsockopt: %s\n", strerror(errno));
			return -1;
		}
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
	} else {
		LM_ERR("unsupported protocol family\n");
		return -1;
	}
	return 0;
}

#endif /* USE_MCAST */


/**
 * Initialize a UDP socket, supports multicast, IPv4 and IPv6.
 * \param si socket that should be bind
 * \return zero on success, -1 otherwise
 *
 * @status_flags - extra status flags to be set for the socket fd
 */
int udp_init_listener(struct socket_info *si, int status_flags)
{
	union sockaddr_union* addr;
	int optval;
#ifdef USE_MCAST
	unsigned char m_optval;
#endif

	addr=&si->su;
	if (init_su(addr, &si->address, si->port_no)<0){
		LM_ERR("could not init sockaddr_union\n");
		goto error;
	}

	si->socket = socket(AF2PF(addr->s.sa_family), SOCK_DGRAM, 0);
	if (si->socket==-1){
		LM_ERR("socket: %s\n", strerror(errno));
		goto error;
	}

	/* make socket non-blocking */
	if (status_flags) {
		optval=fcntl(si->socket, F_GETFL);
		if (optval==-1){
			LM_ERR("fcntl failed: (%d) %s\n", errno, strerror(errno));
			goto error;
		}
		if (fcntl(si->socket,F_SETFL,optval|status_flags)==-1){
			LM_ERR("set non-blocking failed: (%d) %s\n",
				errno, strerror(errno));
			goto error;
		}
	}

	/* set sock opts? */
	optval=1;
	if (setsockopt(si->socket, SOL_SOCKET, SO_REUSEADDR ,
					(void*)&optval, sizeof(optval)) ==-1){
		LM_ERR("setsockopt: %s\n", strerror(errno));
		goto error;
	}
	/* tos */
	optval=tos;
	if (setsockopt(si->socket, IPPROTO_IP, IP_TOS, (void*)&optval,
			sizeof(optval)) ==-1){
		LM_WARN("setsockopt tos: %s\n", strerror(errno));
		/* continue since this is not critical */
	}
#if defined (__linux__) && defined(UDP_ERRORS)
	optval=1;
	/* enable error receiving on unconnected sockets */
	if(setsockopt(si->socket, SOL_IP, IP_RECVERR,
					(void*)&optval, sizeof(optval)) ==-1){
		LM_ERR("setsockopt: %s\n", strerror(errno));
		goto error;
	}
#endif

#ifdef USE_MCAST
	if ((si->flags & SI_IS_MCAST)
	    && (setup_mcast_rcvr(si->socket, addr)<0)){
			goto error;
	}
	/* set the multicast options */
	if (addr->s.sa_family==AF_INET){
		m_optval = mcast_loopback;
		if (setsockopt(si->socket, IPPROTO_IP, IP_MULTICAST_LOOP,
						&m_optval, sizeof(m_optval))==-1){
			LM_WARN("setsockopt(IP_MULTICAST_LOOP): %s\n", strerror(errno));
			/* it's only a warning because we might get this error if the
			  network interface doesn't support multicasting */
		}
		if (mcast_ttl>=0){
			m_optval = mcast_ttl;
			if (setsockopt(si->socket, IPPROTO_IP, IP_MULTICAST_TTL,
						&m_optval, sizeof(m_optval))==-1){
				LM_ERR("setsockopt (IP_MULTICAST_TTL): %s\n", strerror(errno));
				goto error;
			}
		}
	} else if (addr->s.sa_family==AF_INET6){
		if (setsockopt(si->socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
						&mcast_loopback, sizeof(mcast_loopback))==-1){
			LM_WARN("setsockopt (IPV6_MULTICAST_LOOP): %s\n", strerror(errno));
			/* it's only a warning because we might get this error if the
			  network interface doesn't support multicasting */
		}
		if (mcast_ttl>=0){
			if (setsockopt(si->socket, IPPROTO_IP, IPV6_MULTICAST_HOPS,
						&mcast_ttl, sizeof(mcast_ttl))==-1){
				LM_ERR("setssckopt (IPV6_MULTICAST_HOPS): %s\n",
						strerror(errno));
				goto error;
			}
		}
	} else {
		LM_ERR("unsupported protocol family %d\n", addr->s.sa_family);
		goto error;
	}
#endif /* USE_MCAST */

	if (probe_max_sock_buff(si->socket,0,MAX_RECV_BUFFER_SIZE,
				BUFFER_INCREMENT)==-1) goto error;

	if (bind(si->socket,  &addr->s, sockaddru_len(*addr))==-1){
		LM_ERR("bind(%x, %p, %d) on %s: %s\n", si->socket, &addr->s,
				(unsigned)sockaddru_len(*addr),	si->address_str.s,
				strerror(errno));
		if (addr->s.sa_family==AF_INET6)
			LM_ERR("might be caused by using a link "
					" local address, try site local or global\n");
		goto error;
	}
	return 0;

error:
	return -1;
}


inline static int handle_io(struct fd_map* fm, int idx,int event_type)
{
	int n,read;

	switch(fm->type){
		case F_UDP_READ:
			update_stat( pt[process_no].load, +1 );
			n = protos[((struct socket_info*)fm->data)->proto].net.
				read( fm->data /*si*/, &read);
			update_stat( pt[process_no].load, -1 );
			return n;
		case F_TIMER_JOB:
			handle_timer_job();
			return 0;
		case F_SCRIPT_ASYNC:
			async_script_resume_f( &fm->fd, fm->data);
			return 0;
		case F_FD_ASYNC:
			async_fd_resume( &fm->fd, fm->data);
			return 0;
		case F_LAUNCH_ASYNC:
			async_launch_resume( &fm->fd, fm->data);
			return 0;
		case F_IPC:
			ipc_handle_job();
			return 0;
		default:
			LM_CRIT("unknown fd type %d in UDP worker\n", fm->type);
			return -1;
	}
	return -1;
}


int udp_proc_reactor_init( struct socket_info *si )
{

	/* create the reactor for UDP proc */
	if ( init_worker_reactor( "UDP_worker", RCT_PRIO_MAX)<0 ) {
		LM_ERR("failed to init reactor\n");
		goto error;
	}

	/* init: start watching for the timer jobs */
	if (reactor_add_reader( timer_fd_out, F_TIMER_JOB, RCT_PRIO_TIMER,NULL)<0){
		LM_CRIT("failed to add timer pipe_out to reactor\n");
		goto error;
	}

	/* init: start watching for the IPC jobs */
	if (reactor_add_reader( IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC,NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor\n");
		goto error;
	}

	/* init: start watching the SIP UDP fd */
	if (reactor_add_reader( si->socket, F_UDP_READ, RCT_PRIO_NET, si)<0) {
		LM_CRIT("failed to add UDP listen socket to reactor\n");
		goto error;
	}

	return 0;
error:
	destroy_worker_reactor();
	return -1;
}


/* starts all UDP related processes */
int udp_start_processes(int *chd_rank, int *startup_done)
{
	struct socket_info *si;
	stat_var *load_p = NULL;
	pid_t pid;
	int i,p;

	if (udp_disabled)
		return 0;

	for( p=PROTO_FIRST ; p<PROTO_LAST ; p++ ) {
		if ( !is_udp_based_proto(p) )
			continue;

		for(si=protos[p].listeners; si ; si=si->next ) {
			if (register_udp_load_stat(&si->sock_str,&load_p,si->children)!=0){
				LM_ERR("failed to init load statistics\n");
				goto error;
			}

			for (i=0;i<si->children;i++) {
				(*chd_rank)++;
				if ( (pid=internal_fork( "UDP receiver"))<0 ) {
					LM_CRIT("cannot fork UDP process\n");
					goto error;
				} else if (pid==0) {
					/* new UDP process */
					/* set a more detailed description */
					set_proc_attrs("SIP receiver %.*s ",
						si->sock_str.len, si->sock_str.s);
					bind_address=si; /* shortcut */
					/* we first need to init the reactor to be able to add fd
					 * into it in child_init routines */
					if (udp_proc_reactor_init(si) < 0 ||
							init_child(*chd_rank) < 0) {
						report_failure_status();
						if (*chd_rank == 1 && startup_done)
							*startup_done = -1;
						exit(-1);
					}

					/* first UDP proc runs statup_route (if defined) */
					if(*chd_rank == 1 && startup_done!=NULL) {
						LM_DBG("running startup for first UDP\n");
						if(run_startup_route()< 0) {
							report_failure_status();
							*startup_done = -1;
							LM_ERR("Startup route processing failed\n");
							exit(-1);
						}
						*startup_done = 1;
					}

					report_conditional_status( (!no_daemon_mode), 0);

					/* all UDP listeners on same interface
					 * have same SHM load pointer */
					pt[process_no].load = load_p;

					/**
					 * Main UDP receiver loop, processes data from the
					 * network, does some error checking and save it in an
					 * allocated buffer. This data is then forwarded to the
					 * receive_msg function. If an dynamic buffer is used, the
					 * buffer must be freed in later steps.
					 * \see receive_msg
					 * \see main_loop
					 */
					reactor_main_loop(UDP_SELECT_TIMEOUT, error, );
					destroy_worker_reactor();
					exit(-1);
				} else {
					/*parent*/
					/* wait for first proc to finish the startup route */
					if (*chd_rank == 1 && startup_done)
						while(!(*startup_done)) {
							usleep(5);
							handle_sigs();
						}
				}
			} /* procs per listener */
		} /* looping through the listeners per proto */
	} /* looping through the available protos */

	return 0;
error:
	return -1;
}

