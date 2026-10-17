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

#include <sys/utsname.h>
#include <sys/ioctl.h>
#include "../ipc.h"
#include "../locking.h"
#include "../mem/shm_mem.h"
#ifdef __OS_linux
#include <linux/filter.h>
#endif
#include "../daemonize.h"
#include "../reactor.h"
#include "../timer.h"
#include "../pt_load.h"
#include "../cfg_reload.h"
#include "../profiling.h"
#include "net_udp.h"


/* if the UDP network layer is used or not by some protos */
static int udp_disabled = 1;

extern void handle_sigs(void);

/* initializes the UDP network layer */
static void udp_rx_mode_resolve(void);

int udp_init(void)
{
	unsigned int i;

	udp_rx_mode_resolve();

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
int udp_count_processes(unsigned int *extra)
{
	struct socket_info_full *sif;
	unsigned int n, e, i;

	if (udp_disabled) {
		if (extra) *extra = 0;
		return 0;
	}

	for( i=0,n=0,e=0 ; i<PROTO_LAST ; i++)
		if (protos[i].id!=PROTO_NONE && is_udp_based_proto(i))
			for( sif=protos[i].listeners ; sif; sif=sif->next) {
				const struct socket_info *si = &sif->socket_info;
				n+=si->workers;
				if (si->s_profile)
					if (si->s_profile->max_procs > si->workers)
						e+=si->s_profile->max_procs-si->workers;
			}

	if (extra) *extra = e;
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
int udp_rx_mode = UDP_RX_AUTO;
/* the mode actually in use, resolved once in udp_init() */
static int udp_rx_mode_eff = UDP_RX_SHARED;

int os_kernel_at_least(int major, int minor)
{
#ifdef __OS_linux
	struct utsname u;
	int ma, mi;

	if (uname(&u) < 0 || sscanf(u.release, "%d.%d", &ma, &mi) != 2)
		return 0;
	return ma > major || (ma == major && mi >= minor);
#else
	return 0;
#endif
}

int parse_udp_rx_mode(const char *s)
{
	if (!strcasecmp(s, "auto")) udp_rx_mode = UDP_RX_AUTO;
	else if (!strcasecmp(s, "shared")) udp_rx_mode = UDP_RX_SHARED;
	else if (!strcasecmp(s, "exclusive")) udp_rx_mode = UDP_RX_EXCLUSIVE;
	else if (!strcasecmp(s, "reuseport")) udp_rx_mode = UDP_RX_REUSEPORT;
	else return -1;
	return 0;
}

/* SO_ATTACH_REUSEPORT_CBPF is 4.5+, EPOLLEXCLUSIVE without the "woken but not
 * running process absorbs the next events" behaviour is 6.0+ (commit
 * "epoll: autoremove wakers even more aggressively") */
#if defined(__OS_linux) && defined(SO_REUSEPORT) && defined(SO_ATTACH_REUSEPORT_CBPF)
#define UDP_RX_HAVE_REUSEPORT (os_kernel_at_least(4, 5))
#else
#define UDP_RX_HAVE_REUSEPORT 0
#endif
#ifdef EPOLLEXCLUSIVE
#define UDP_RX_HAVE_EXCLUSIVE (os_kernel_at_least(6, 0))
#else
#define UDP_RX_HAVE_EXCLUSIVE 0
#endif

static void udp_rx_mode_resolve(void)
{
	static const char *names[] = { "auto", "shared", "exclusive", "reuseport" };

	switch (udp_rx_mode) {
	case UDP_RX_AUTO:
		udp_rx_mode_eff = UDP_RX_HAVE_REUSEPORT ?
			UDP_RX_REUSEPORT : UDP_RX_SHARED;
		break;
	case UDP_RX_EXCLUSIVE:
		if (UDP_RX_HAVE_EXCLUSIVE) {
			udp_rx_mode_eff = UDP_RX_EXCLUSIVE;
		} else {
			LM_WARN("udp_rx_mode=exclusive needs a 6.0+ kernel (older ones "
				"serialize packet bursts on one worker), using 'shared'\n");
			udp_rx_mode_eff = UDP_RX_SHARED;
		}
		break;
	case UDP_RX_REUSEPORT:
		if (UDP_RX_HAVE_REUSEPORT) {
			udp_rx_mode_eff = UDP_RX_REUSEPORT;
		} else {
			LM_WARN("udp_rx_mode=reuseport needs SO_REUSEPORT with a cBPF "
				"selector (Linux 4.5+), using 'shared'\n");
			udp_rx_mode_eff = UDP_RX_SHARED;
		}
		break;
	default:
		udp_rx_mode_eff = UDP_RX_SHARED;
	}
	LM_INFO("UDP receive mode: %s (configured: %s)\n",
		names[udp_rx_mode_eff], names[udp_rx_mode]);
}


/* creates and configures ONE UDP socket for the listener into si->socket */
static int udp_setup_socket(struct socket_info *si, int status_flags,
		int reuseport)
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

	if (reuseport || (si->flags & SI_REUSEPORT)) {
		optval=1;
		if (setsockopt(si->socket, SOL_SOCKET, SO_REUSEPORT ,
						(void*)&optval, sizeof(optval)) ==-1){
			LM_ERR("setsockopt: %s\n", strerror(errno));
			goto error;
		}
	}

	if (si->flags & SI_FRAG) {
		/* no DF */
#if defined(IP_MTU_DISCOVER)
		optval = IP_PMTUDISC_DONT;
		if (setsockopt(si->socket, IPPROTO_IP, IP_MTU_DISCOVER,
				(void*)&optval, sizeof(optval)) == -1) {
			LM_ERR("setsockopt: %s\n", strerror(errno));
			goto error;
		}
#else
#if defined(IP_DONTFRAG)
		optval = 1;
		if (setsockopt(si->socket, IPPROTO_IP, IP_DONTFRAG,
				(void*)&optval, sizeof(optval)) == -1) {
			LM_ERR("setsockopt: %s\n", strerror(errno));
			goto error;
		}
#else
		LM_ERR("DF flag is not supported by your system\n");
		goto error;
#endif
#endif
	}

	/* tos */
	optval = (si->tos > 0) ? si->tos : tos;
	if (optval > 0) {
		if (addr->s.sa_family==AF_INET6){
			if (setsockopt(si->socket,  IPPROTO_IPV6, IPV6_TCLASS, (void*)&optval, sizeof(optval)) ==-1){
				LM_WARN("setsockopt tos for IPV6: %s\n", strerror(errno));
				/* continue since this is not critical */
			}
		} else {
			if (setsockopt(si->socket, IPPROTO_IP, IP_TOS, (void*)&optval, sizeof(optval)) ==-1){
				LM_WARN("setsockopt tos: %s\n", strerror(errno));
				/* continue since this is not critical */
			}
		}
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

	return 0;

error:
	return -1;
}


/* how many sockets this listener gets: 1 (shared) or one per worker */
static inline int udp_listener_socks(struct socket_info *si)
{
	int n = si->workers;

	if (udp_rx_mode_eff != UDP_RX_REUSEPORT)
		return 1;
	if (si->s_profile && si->s_profile->max_procs > n)
		n = si->s_profile->max_procs;
	return n > 1 ? n : 1;
}


/* reuseport + auto-scaling: which socket slot has a reader. Slot i belongs
 * to socket worker_socks[i]; proc[i] is the process-table index of the
 * worker reading it, 0 = no reader. Lives in shm: the attendant assigns a
 * slot when it forks a dynamic worker, the worker frees it when it is
 * ripped, and whoever changes the set re-attaches the selector program. */
struct udp_worker_slots {
	gen_lock_t lock;
	int proc[0];
};


int udp_init_listener(struct socket_info *si, int status_flags)
{
	int n = udp_listener_socks(si), i, fd0;

	if (udp_setup_socket(si, status_flags, n > 1) < 0)
		return -1;
	if (n == 1)
		return 0;

	si->worker_socks = pkg_malloc(n * sizeof(int));
	if (!si->worker_socks) {
		LM_ERR("no more pkg memory for %d worker sockets\n", n);
		return -1;
	}
	fd0 = si->worker_socks[0] = si->socket;
	for (i = 1; i < n; i++) {
		if (udp_setup_socket(si, status_flags, 1) < 0) {
			LM_ERR("failed to create worker socket %d for %.*s\n", i,
				si->sock_str.len, si->sock_str.s);
			return -1;
		}
		si->worker_socks[i] = si->socket;
	}
	si->socket = fd0;
	si->worker_socks_no = n;
	si->worker_slots = shm_malloc(sizeof(struct udp_worker_slots) +
		n * sizeof(int));
	if (!si->worker_slots) {
		LM_ERR("no more shm memory for %d worker slots\n", n);
		return -1;
	}
	memset(si->worker_slots, 0, sizeof(struct udp_worker_slots) +
		n * sizeof(int));
	lock_init(&((struct udp_worker_slots *)si->worker_slots)->lock);
	LM_INFO("listener %.*s: %d per-worker SO_REUSEPORT sockets (%d at start)\n",
		si->sock_str.len, si->sock_str.s, n, (int)si->workers);
	return 0;
}


#if defined(__OS_linux) && defined(SO_ATTACH_REUSEPORT_CBPF)
/* classic BPF program for the SO_REUSEPORT group: pick the socket index
 * uniformly at random per packet (A = prandom; A %= n; return A). The
 * kernel's default is a 4-tuple hash, which for SIP (a handful of fat
 * sources: SBCs, PBXs, trunks) pins whole sources to single workers. */
static int udp_attach_random_select(int fd, const int *slots, int n)
{
	/* A = prandom; A %= n; then map A -> slots[A] (a plain "ret A" when
	 * the active slots are exactly 0..n-1) */
	struct sock_filter *prog;
	struct sock_fprog fprog;
	int i, dense = 1, len;

	if (n < 1) {
		LM_ERR("no active worker slot to select\n");
		return -1;
	}
	for (i = 0; i < n; i++)
		if (slots[i] != i) { dense = 0; break; }
	len = dense ? 3 : 2 + 2 * n + 1;
	prog = pkg_malloc(len * sizeof(*prog));
	if (!prog) {
		LM_ERR("no more pkg memory for the selector program\n");
		return -1;
	}
	prog[0] = (struct sock_filter)
		{ BPF_LD  | BPF_W   | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_RANDOM };
	prog[1] = (struct sock_filter){ BPF_ALU | BPF_MOD | BPF_K, 0, 0, (unsigned)n };
	if (dense) {
		prog[2] = (struct sock_filter){ BPF_RET | BPF_A, 0, 0, 0 };
	} else {
		for (i = 0; i < n; i++) {
			prog[2 + 2 * i] = (struct sock_filter)
				{ BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (unsigned)i };
			prog[3 + 2 * i] = (struct sock_filter)
				{ BPF_RET | BPF_K, 0, 0, (unsigned)slots[i] };
		}
		prog[2 + 2 * n] = (struct sock_filter)
			{ BPF_RET | BPF_K, 0, 0, (unsigned)slots[0] };
	}
	fprog.len = len; fprog.filter = prog;
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
			&fprog, sizeof(fprog)) < 0) {
		LM_ERR("SO_ATTACH_REUSEPORT_CBPF failed: %s\n", strerror(errno));
		pkg_free(prog);
		return -1;
	}
	pkg_free(prog);
	return 0;
}


/* re-attach the selector from the slot table; the lock must be held */
static int udp_reselect_from_slots(const struct socket_info *si)
{
	struct udp_worker_slots *ws = si->worker_slots;
	int *active, i, n = 0, rc;

	active = pkg_malloc(si->worker_socks_no * sizeof(int));
	if (!active) {
		LM_ERR("no more pkg memory for the active slot list\n");
		return -1;
	}
	for (i = 0; i < si->worker_socks_no; i++)
		if (ws->proc[i])
			active[n++] = i;
	rc = udp_attach_random_select(si->worker_socks[0], active, n);
	pkg_free(active);
	return rc;
}


/* attendant: reserve the lowest free slot for a worker about to be forked */
static int udp_slot_reserve(struct socket_info *si)
{
	struct udp_worker_slots *ws = si->worker_slots;
	int i;

	lock_get(&ws->lock);
	for (i = 0; i < si->worker_socks_no; i++)
		if (ws->proc[i] == 0) {
			ws->proc[i] = -1; /* reserved, counts as active */
			break;
		}
	lock_release(&ws->lock);
	return i < si->worker_socks_no ? i : -1;
}


/* attendant: the worker is forked (or the fork failed: proc_idx = 0) */
static void udp_slot_commit(struct socket_info *si, int slot, int proc_idx)
{
	struct udp_worker_slots *ws = si->worker_slots;

	lock_get(&ws->lock);
	ws->proc[slot] = proc_idx;
	if (udp_reselect_from_slots(si) < 0)
		LM_ERR("failed to re-attach the UDP selector after slot %d change\n",
			slot);
	lock_release(&ws->lock);
}


/* ripped worker: leave the group, then drain what already reached its
 * socket so nothing is stranded in a socket without a reader */
static void udp_slot_release(const struct socket_info *si)
{
	struct udp_worker_slots *ws = si->worker_slots;
	int i, n, left = 100000;
	char c;

	lock_get(&ws->lock);
	for (i = 0; i < si->worker_socks_no; i++)
		if (ws->proc[i] == process_no)
			ws->proc[i] = 0;
	if (udp_reselect_from_slots(si) < 0)
		LM_ERR("failed to re-attach the UDP selector on worker exit\n");
	lock_release(&ws->lock);
	while (left-- > 0 &&
	recv(si->socket, &c, 1, MSG_PEEK | MSG_DONTWAIT) > 0)
		protos[si->proto].net.dgram.read(si, &n);
}
#endif


static int udp_bind_fd(struct socket_info *si, int fd)
{
	union sockaddr_union* addr = &si->su;
	if (bind(fd,  &addr->s, sockaddru_len(*addr))==-1){
		LM_ERR("bind(%x, %p, %d) on %s: %s\n", fd, &addr->s,
				(unsigned)sockaddru_len(*addr),	si->address_str.s,
				strerror(errno));
		if (addr->s.sa_family==AF_INET6)
			LM_ERR("might be caused by using a link "
					" local address, try site local or global\n");
		return -1;
	}
	return 0;
}


int udp_bind_listener(struct socket_info *si)
{
	int n = si->worker_socks ? si->worker_socks_no : 1, i;

	for (i = 0; i < n; i++)
		if (udp_bind_fd(si, si->worker_socks ? si->worker_socks[i]
				: si->socket) < 0)
			return -1;
#if defined(__OS_linux) && defined(SO_ATTACH_REUSEPORT_CBPF)
	/* the group exists once the sockets are bound; the program attached to
	 * any member applies to the whole group */
	/* at start only the static workers (slots 0..workers-1) read */
	if (n > 1) {
		int *slots = pkg_malloc(si->workers * sizeof(int));
		if (!slots) {
			LM_ERR("no more pkg memory for the slot list\n");
			return -1;
		}
		for (i = 0; i < si->workers; i++)
			slots[i] = i;
		i = udp_attach_random_select(si->worker_socks[0], slots, si->workers);
		pkg_free(slots);
		if (i < 0)
			return -1;
	}
#endif
	return 0;
}


inline static int handle_io(struct fd_map* fm, int idx,int event_type)
{
	int n = 0;
	int read;

	pt_become_active();

	pre_run_handle_script_reload(fm->app_flags);

	profiling_proc_start( LEVEL_SIP, 1);

	switch(fm->type){
		case F_UDP_READ:
			profiling_proc_enter( LEVEL_SIP,
				ss_merge256(
					protos[((struct socket_info*)fm->data)->proto].name,
					" proto reading"),
				1 );
			n = protos[((struct socket_info*)fm->data)->proto].net.
				dgram.read( fm->data /*si*/, &read);
			profiling_proc_exit( LEVEL_SIP, "reading done", n );
			break;
		case F_TIMER_JOB:
			profiling_proc_enter( LEVEL_FULL, "timer_job", 1 );
			handle_timer_job();
			profiling_proc_exit( LEVEL_FULL, "timer_job", n);
			break;
		case F_SCRIPT_ASYNC:
			profiling_proc_enter( LEVEL_SIP, "async_script", 0 );
			n = async_script_resume_f( fm->fd, fm->data,
				(event_type==IO_WATCH_TIMEOUT)?1:0 );
			profiling_proc_exit( LEVEL_SIP, "async_script", n);
			break;
		case F_FD_ASYNC:
			profiling_proc_enter( LEVEL_SIP, "async_fd", 0 );
			n = async_fd_resume( fm->fd, fm->data);
			profiling_proc_exit( LEVEL_SIP, "async_fd", n);
			break;
		case F_LAUNCH_ASYNC:
			profiling_proc_enter( LEVEL_SIP, "async_launch", 0 );
			n = async_launch_resume( fm->fd, fm->data);
			profiling_proc_exit( LEVEL_SIP, "async_launch", n);
			break;
		case F_IPC:
			profiling_proc_enter( LEVEL_SIP, "ipc_job", 1 );
			ipc_handle_job(fm->fd);
			profiling_proc_exit( LEVEL_SIP, "ipc_job", n);
			break;
		default:
			LM_CRIT("unknown fd type %d in UDP worker\n", fm->type);
			n = -1;
			break;
	}

	if (reactor_is_empty() && _termination_in_progress==1) {
		LM_WARN("reactor got empty while termination in progress\n");
		ipc_handle_all_pending_jobs(IPC_FD_READ_SELF);
		if (reactor_is_empty())
			dynamic_process_final_exit();
	}

	profiling_proc_end( LEVEL_SIP, n );

	post_run_handle_script_reload();

	pt_become_idle();
	return n;
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
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor\n");
		goto error;
	}

	/* init: start watching for IPC "dispatched" jobs */
	if (reactor_add_reader(IPC_FD_READ_SHARED, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC shared pipe to reactor\n");
		return -1;
	}

	/* init: start watching the SIP UDP fd */
	if ((udp_rx_mode_eff == UDP_RX_EXCLUSIVE && !si->worker_socks) ?
	reactor_add_reader_excl( si->socket, F_UDP_READ, RCT_PRIO_NET, si)<0 :
	reactor_add_reader( si->socket, F_UDP_READ, RCT_PRIO_NET, si)<0) {
		LM_CRIT("failed to add UDP listen socket to reactor\n");
		goto error;
	}

	return 0;
error:
	destroy_worker_reactor();
	return -1;
}


static int fork_dynamic_udp_process(void *si_filter)
{
	struct socket_info *si = (struct socket_info*)si_filter;
	int p_id;
	int slot = -1;
	int slot = -1;
	const struct internal_fork_params ifp_udp_rcv = {
		.proc_desc = "UDP receiver",
		.flags = OSS_PROC_DYNAMIC|OSS_PROC_NEEDS_SCRIPT,
		.type = TYPE_UDP,
	};

	if (si->worker_socks && (slot = udp_slot_reserve(si)) < 0) {
		LM_ERR("no free worker socket slot for a new UDP process on %.*s\n",
			si->sock_str.len, si->sock_str.s);
		return -1;
	}

	if ((p_id=internal_fork(&ifp_udp_rcv))<0) {
		LM_CRIT("cannot fork UDP process\n");
		if (slot >= 0)
			udp_slot_commit(si, slot, 0);
		return(-1);
	} else if (p_id==0) {
		/* new UDP process */
		/* set a more detailed description */
		set_proc_attrs("SIP receiver %.*s",
			si->sock_str.len, si->sock_str.s);
		pt[process_no].pg_filter = si;
		bind_address=si; /* shortcut */
		if (slot >= 0)
			si->socket = si->worker_socks[slot];
		/* we first need to init the reactor to be able to add fd
		 * into it in child_init routines */
		if (udp_proc_reactor_init(si) < 0 ||
		init_child(10000/*FIXME*/) < 0 ||
		self_update_routing_script() < 0) {
			goto error;
		}
		report_conditional_status( 1, 0); /*report success*/
		/* the child proc is done read&write) dealing with the status pipe */
		clean_read_pipeend();

		reactor_main_loop( worker_reactor_timeout, error, );
		destroy_worker_reactor();
error:
		report_failure_status();
		LM_ERR("Initializing new process failed, exiting with error \n");
		pt[process_no].flags |= OSS_PROC_SELFEXIT;
		exit( -1);
	} else {
		/*parent/main*/
		if (slot >= 0)
			udp_slot_commit(si, slot, p_id);
		return p_id;
	}
}


static void udp_process_graceful_terminate(int sender, void *param)
{
	/* we accept this only from the main proccess */
	if (sender!=0) {
		LM_BUG("graceful terminate received from a non-main process!!\n");
		return;
	}
	LM_NOTICE("process %d received RPC to terminate from Main\n",process_no);

	/*remove from reactor all the shared fds, so we stop reading from them */

	/*remove timer jobs pipe */
	reactor_del_reader( timer_fd_out, -1, 0);

	/*remove IPC dispatcher pipe */
	reactor_del_reader( IPC_FD_READ_SHARED, -1, 0);

	/*remove network interface - leave the reuseport group first */
#if defined(__OS_linux) && defined(SO_ATTACH_REUSEPORT_CBPF)
	if (bind_address->worker_socks)
		udp_slot_release(bind_address);
#endif
	reactor_del_reader( bind_address->socket, -1, 0);

	/*remove private IPC pipe */
	reactor_del_reader( IPC_FD_READ_SELF, -1, 0);

	/* let's drain the private IPC */
	ipc_handle_all_pending_jobs(IPC_FD_READ_SELF);

	/* what is left now is the reactor are async fd's, so we need to 
	 * wait to complete all of them */
	if (reactor_is_empty())
		dynamic_process_final_exit();

	/* the exit will be triggered by the reactor, when empty */
	_termination_in_progress = 1;
	LM_INFO("reactor not empty, waiting for pending async\n");
}


/* starts all UDP related processes */
int udp_start_processes(int *chd_rank, int *startup_done)
{
	struct socket_info_full *sif;
	int p_id;
	int i,p;
	const struct internal_fork_params ifp_udp_rcv = {
		.proc_desc = "UDP receiver",
		.flags = OSS_PROC_NEEDS_SCRIPT,
		.type = TYPE_UDP,
	};

	if (udp_disabled)
		return 0;

	for( p=PROTO_FIRST ; p<PROTO_LAST ; p++ ) {
		if ( !is_udp_based_proto(p) )
			continue;

		for( sif=protos[p].listeners; sif ; sif=sif->next ) {
			struct socket_info* si = &sif->socket_info;

			if ( auto_scaling_enabled && si->s_profile &&
			create_process_group( TYPE_UDP, si, si->s_profile,
			fork_dynamic_udp_process, udp_process_graceful_terminate)!=0)
				LM_ERR("failed to create group of UDP processes for <%.*s>, "
					"auto forking will not be possible\n",
					si->name.len, si->name.s);

			for (i=0;i<si->workers;i++) {
				(*chd_rank)++;
				if ( (p_id=internal_fork(&ifp_udp_rcv))<0 ) {
					LM_CRIT("cannot fork UDP process\n");
					goto error;
				} else if (p_id==0) {
					/* new UDP process */
					/* set a more detailed description */
					set_proc_attrs("SIP receiver %.*s",
						si->sock_str.len, si->sock_str.s);
					pt[process_no].pg_filter = si;
					bind_address=si; /* shortcut */
					/* per-worker sockets: this worker reads (and sends) on
					 * its own member of the SO_REUSEPORT group; si is pkg
					 * memory, so the swap is private to this process */
					if (si->worker_socks)
						si->socket = si->worker_socks[i];
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

					/**
					 * Main UDP receiver loop, processes data from the
					 * network, does some error checking and save it in an
					 * allocated buffer. This data is then forwarded to the
					 * receive_msg function. If an dynamic buffer is used, the
					 * buffer must be freed in later steps.
					 * \see receive_msg
					 * \see main_loop
					 */
					reactor_main_loop( worker_reactor_timeout, error, );
					destroy_worker_reactor();
					exit(-1);
				} else {
					/*parent*/
					if (si->worker_slots)
						((struct udp_worker_slots *)si->worker_slots)->proc[i] = p_id;
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
