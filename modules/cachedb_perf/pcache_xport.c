/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * The module's own pull transport - see pcache_xport.h for the shape.
 *
 * Why it exists: a pull over the clusterer's bin links is one TCP message
 * each way, and every one of them is handed from the core's TCP main to a
 * receiver and back.  At a few thousand pulls a second that dispatcher is
 * one process at the edge of a core, and every receive-side stall behind
 * it becomes head-of-line blocking for everything else on the link.  Here
 * the sockets are the module's: datagrams go straight from the asking
 * process to the wire and straight from the wire to one transport process
 * that only parses, copies into the slot and wakes the waiter; streams are
 * owned by that process end to end.
 */

/* io_wait.h sets up the GNU fcntl extensions itself - it must come first */
#include "../../io_wait.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "../../dprint.h"
#include "../../locking.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../pt.h"
#include "../../ipc.h"
#include "../../reactor_proc.h"
#include "../clusterer/api.h"
#include "../../ip_addr.h"
#include "pcache_xport.h"

#ifndef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 10
#endif
#ifndef IP_PMTUDISC_DONT
#define IP_PMTUDISC_DONT 0
#endif

char *pcache_pull_bind;
int   pcache_pull_port;

#define XP_MAGIC        "PCP1"
#define XP_HDR          8                  /* magic + src node (BE)         */
#define XP_FRAME_HDR    4                  /* tcp: length of what follows   */
#define XP_MAX_MSG      65535
#define XP_HELLO_S      30                 /* heartbeat announce period     */
#define XP_HELLO_TICK_S 2                  /* the announce timer            */
#define XP_SEND_TMO_MS  200                /* tcp blocking write budget     */
#define XP_CONN_TMO_MS  200                /* tcp connect budget            */
#define XP_SNDBUF       (4 * 1024 * 1024)

enum { ST_TX, ST_TX_FAIL, ST_RX, ST_RX_BAD, ST_TCP_CONNECT, ST_TCP_ACCEPT,
       ST_TCP_ERR };

struct xp_peer {
	int node;                               /* 0 = empty slot               */
	union sockaddr_union su;
	socklen_t sulen;
	int derived;                            /* from pull_port, not a HELLO  */
};

struct xp_shm {
	gen_lock_t lock;
	int proc_no;                            /* the transport process        */
	struct xp_peer peers[CL_MAX_NODE_ID + 1];
	unsigned long st[PCACHE_XPORT_NSTATS];
};

/* a tcp message handed to the transport process by another process */
struct xp_msg {
	int node;
	int len;
	char data[];
};

/* per-connection state, in the transport process only */
struct xp_conn {
	int fd;
	int node;                               /* outgoing: the peer           */
	unsigned int rlen;                      /* incoming: bytes buffered     */
	char *rbuf;
	struct xp_conn *next;
};

static int kind = PCACHE_XPORT_NONE;
static int my_node;
static int max_msg;                         /* largest payload we carry     */
static int udp_fd = -1;                     /* shared, pre-fork             */
static int listen_fd = -1;                  /* tcp, pre-fork                */
static union sockaddr_union bind_su;
static socklen_t bind_len;
static struct xp_shm *xp;
static pcache_xport_recv_f *recv_cb;
/* the transport process's own state */
static struct xp_conn *conns;               /* incoming connections         */
static struct xp_conn *out[CL_MAX_NODE_ID + 1];
static char *rxbuf;

static inline void st_inc(int i)
{
	__sync_fetch_and_add(&xp->st[i], 1);
}

/* ---- addresses --------------------------------------------------------- */

/* "ip:port" / "[ip6]:port" -> sockaddr; 0 on success */
static int parse_addr(const char *s, int len, union sockaddr_union *su,
		socklen_t *sulen)
{
	char host[64], port[8];
	const char *colon, *end = s + len, *hs = s, *he;
	int pl, hl;

	if (len > 0 && s[0] == '[') {
		he = memchr(s, ']', len);
		if (!he || he + 1 >= end || he[1] != ':')
			return -1;
		hs = s + 1; colon = he + 1;
	} else {
		colon = NULL;
		for (he = end - 1; he > s; he--)
			if (*he == ':') { colon = he; break; }
		if (!colon)
			return -1;
		he = colon;
	}
	hl = he - hs; pl = end - colon - 1;
	if (hl <= 0 || hl >= (int)sizeof host || pl <= 0 || pl >= (int)sizeof port)
		return -1;
	memcpy(host, hs, hl); host[hl] = 0;
	memcpy(port, colon + 1, pl); port[pl] = 0;
	memset(su, 0, sizeof *su);
	if (inet_pton(AF_INET, host, &su->sin.sin_addr) == 1) {
		su->sin.sin_family = AF_INET;
		su->sin.sin_port = htons((unsigned short)atoi(port));
		*sulen = sizeof su->sin;
		return 0;
	}
	if (inet_pton(AF_INET6, host, &su->sin6.sin6_addr) == 1) {
		su->sin6.sin6_family = AF_INET6;
		su->sin6.sin6_port = htons((unsigned short)atoi(port));
		*sulen = sizeof su->sin6;
		return 0;
	}
	return -1;
}

static int fmt_addr(const union sockaddr_union *su, char *out, int max)
{
	char ip[INET6_ADDRSTRLEN];

	if (su->s.sa_family == AF_INET6) {
		inet_ntop(AF_INET6, &su->sin6.sin6_addr, ip, sizeof ip);
		return snprintf(out, max, "[%s]:%u", ip, ntohs(su->sin6.sin6_port));
	}
	inet_ntop(AF_INET, &su->sin.sin_addr, ip, sizeof ip);
	return snprintf(out, max, "%s:%u", ip, ntohs(su->sin.sin_port));
}

static int same_addr(const union sockaddr_union *a, const union sockaddr_union *b)
{
	if (a->s.sa_family != b->s.sa_family)
		return 0;
	if (a->s.sa_family == AF_INET6)
		return a->sin6.sin6_port == b->sin6.sin6_port &&
		       !memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, 16);
	return a->sin.sin_port == b->sin.sin_port &&
	       a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr;
}

/* record a peer's address; *is_new = 1 when we did not have this node */
static void peer_set(int node, const union sockaddr_union *su, socklen_t sulen,
		int derived, int *is_new)
{
	struct xp_peer *p;

	if (is_new)
		*is_new = 0;
	if (node <= 0 || node > CL_MAX_NODE_ID)
		return;
	p = &xp->peers[node];
	lock_get(&xp->lock);
	if (p->node && (!derived || p->derived) && same_addr(&p->su, su)) {
		lock_release(&xp->lock);
		return;
	}
	if (p->node && p->derived == 0 && derived) {
		lock_release(&xp->lock);      /* an announced address outranks a guess */
		return;
	}
	if (is_new)
		*is_new = !p->node || p->derived;
	p->node = node;
	p->su = *su;
	p->sulen = sulen;
	p->derived = derived;
	lock_release(&xp->lock);
}

static int peer_get(int node, union sockaddr_union *su, socklen_t *sulen)
{
	struct xp_peer *p;

	if (node <= 0 || node > CL_MAX_NODE_ID)
		return -1;
	p = &xp->peers[node];
	lock_get(&xp->lock);
	if (!p->node) {
		lock_release(&xp->lock);
		return -1;
	}
	*su = p->su;
	*sulen = p->sulen;
	lock_release(&xp->lock);
	return 0;
}

void pcache_xport_learn(int node, const char *addr, int len, int *is_new)
{
	union sockaddr_union su;
	socklen_t sulen;

	if (parse_addr(addr, len, &su, &sulen) < 0) {
		LM_WARN("node %d announced an unusable pull address '%.*s'\n",
			node, len, addr);
		return;
	}
	peer_set(node, &su, sulen, 0, is_new);
	LM_DBG("node %d pulls at %.*s\n", node, len, addr);
}

int pcache_xport_my_addr(char *out, int max)
{
	return fmt_addr(&bind_su, out, max);
}

int pcache_xport_peers_known(void)
{
	int i, n = 0;

	for (i = 1; i <= CL_MAX_NODE_ID; i++)
		if (xp->peers[i].node)
			n++;
	return n;
}

/* ---- sockets ----------------------------------------------------------- */

static int set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL);

	return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int open_udp(void)
{
	int fd, one = 1, sz = XP_SNDBUF, dont = IP_PMTUDISC_DONT;

	fd = socket(bind_su.s.sa_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		LM_ERR("udp socket: %s\n", strerror(errno));
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
	/* payloads above the MTU ride on IP fragmentation: the path is the
	 * operator's (same LAN, or routers known to pass fragments) */
	if (bind_su.s.sa_family == AF_INET)
		setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &dont, sizeof dont);
	if (bind(fd, &bind_su.s, bind_len) < 0) {
		LM_ERR("cannot bind the pull socket to %s: %s\n", pcache_pull_bind,
			strerror(errno));
		close(fd);
		return -1;
	}
	set_nonblock(fd);
	return fd;
}

static int open_listen(void)
{
	int fd, one = 1;

	fd = socket(bind_su.s.sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		LM_ERR("tcp socket: %s\n", strerror(errno));
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(fd, &bind_su.s, bind_len) < 0 || listen(fd, 64) < 0) {
		LM_ERR("cannot listen for pulls on %s: %s\n", pcache_pull_bind,
			strerror(errno));
		close(fd);
		return -1;
	}
	set_nonblock(fd);
	return fd;
}

int pcache_xport_init(int k, int node, pcache_xport_recv_f *cb, int maxp)
{
	kind = k;
	my_node = node;
	recv_cb = cb;
	max_msg = maxp;
	if (kind == PCACHE_XPORT_NONE)
		return 0;
	if (kind == PCACHE_XPORT_TLS) {
		LM_ERR("pull_transport 'tls' is reserved and not implemented yet - "
			"use 'tcp' (or 'bins' for the clusterer's TLS links)\n");
		return -1;
	}
	if (!pcache_pull_bind || !*pcache_pull_bind) {
		LM_ERR("pull_transport '%s' needs pull_bind = \"ip:port\"\n",
			pcache_xport_name());
		return -1;
	}
	if (parse_addr(pcache_pull_bind, strlen(pcache_pull_bind), &bind_su,
	        &bind_len) < 0) {
		LM_ERR("pull_bind '%s' is not ip:port\n", pcache_pull_bind);
		return -1;
	}
	if (maxp + XP_HDR + XP_FRAME_HDR > XP_MAX_MSG) {
		LM_ERR("pull_max_value + key too large for the transport (%d)\n", maxp);
		return -1;
	}
	xp = shm_malloc(sizeof *xp);
	if (!xp) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(xp, 0, sizeof *xp);
	if (!lock_init(&xp->lock)) {
		LM_ERR("cannot init the transport lock\n");
		return -1;
	}
	if (kind == PCACHE_XPORT_UDP) {
		udp_fd = open_udp();
		if (udp_fd < 0)
			return -1;
	} else {
		listen_fd = open_listen();
		if (listen_fd < 0)
			return -1;
	}
	LM_NOTICE("pull transport IN USE: %s on %s - the module's own sockets, "
		"no core TCP dispatcher on the pull path%s\n", pcache_xport_name(),
		pcache_pull_bind, pcache_pull_port > 0 ? "" :
		" (peers learned from HELLO announcements; set pull_port for an "
		"address before the first HELLO)");
	return 0;
}

void pcache_xport_destroy(void)
{
	if (udp_fd >= 0)
		close(udp_fd);
	if (listen_fd >= 0)
		close(listen_fd);
	if (xp) {
		lock_destroy(&xp->lock);
		shm_free(xp);
		xp = NULL;
	}
}

int pcache_xport_kind(void)
{
	return kind;
}

const char *pcache_xport_name(void)
{
	switch (kind) {
	case PCACHE_XPORT_UDP: return "udp";
	case PCACHE_XPORT_TCP: return "tcp";
	case PCACHE_XPORT_TLS: return "tls";
	default: return "none";
	}
}

int pcache_xport_max_payload(void)
{
	return max_msg;
}

int pcache_xport_proc_no(void)
{
	return xp ? xp->proc_no : 0;
}

void pcache_xport_stats(unsigned long o[PCACHE_XPORT_NSTATS])
{
	int i;

	for (i = 0; i < PCACHE_XPORT_NSTATS; i++)
		o[i] = xp ? xp->st[i] : 0;
}

/* a peer we have no address for: derive one from the clusterer's view of
 * the node (its bin address, through the module) and pull_port, if set */
static int peer_derive(int node, union sockaddr_union *su, socklen_t *sulen)
{
	if (pcache_pull_port <= 0 || pcache_pull_node_addr(node, su) < 0)
		return -1;
	if (su->s.sa_family == AF_INET6) {
		su->sin6.sin6_port = htons((unsigned short)pcache_pull_port);
		*sulen = sizeof su->sin6;
	} else {
		su->sin.sin_port = htons((unsigned short)pcache_pull_port);
		*sulen = sizeof su->sin;
	}
	peer_set(node, su, *sulen, 1, NULL);
	return 0;
}

/* ---- sending ------------------------------------------------------------ */

static void put_hdr(char *b)
{
	uint32_t n = htonl((uint32_t)my_node);

	memcpy(b, XP_MAGIC, 4);
	memcpy(b + 4, &n, 4);
}

static void tcp_rpc_send(int sender, void *param);

int pcache_xport_send(int dst_node, const char *payload, int len)
{
	union sockaddr_union su;
	socklen_t sulen;
	struct xp_msg *m;

	if (kind == PCACHE_XPORT_NONE || !xp || len <= 0 || len > max_msg)
		return -1;
	if (peer_get(dst_node, &su, &sulen) < 0 &&
	    peer_derive(dst_node, &su, &sulen) < 0) {
		st_inc(ST_TX_FAIL);
		LM_DBG("no pull address for node %d yet\n", dst_node);
		return -1;
	}
	if (kind == PCACHE_XPORT_UDP) {
		char buf[XP_HDR + XP_MAX_MSG];

		put_hdr(buf);
		memcpy(buf + XP_HDR, payload, len);
		if (sendto(udp_fd, buf, XP_HDR + len, 0, &su.s, sulen) < 0) {
			st_inc(ST_TX_FAIL);
			LM_ERR("pull datagram to node %d failed: %s\n", dst_node,
				strerror(errno));
			return -1;
		}
		st_inc(ST_TX);
		return 0;
	}
	/* tcp: the transport process owns the connections */
	m = shm_malloc(sizeof *m + len);
	if (!m) {
		st_inc(ST_TX_FAIL);
		return -1;
	}
	m->node = dst_node;
	m->len = len;
	memcpy(m->data, payload, len);
	if (xp->proc_no == process_no) {
		tcp_rpc_send(process_no, m);
		return 0;
	}
	if (!xp->proc_no || ipc_send_rpc(xp->proc_no, tcp_rpc_send, m) < 0) {
		shm_free(m);
		st_inc(ST_TX_FAIL);
		return -1;
	}
	return 0;
}

/* ---- the transport process ---------------------------------------------- */

static struct xp_conn *conn_new(int fd, int node)
{
	struct xp_conn *c = pkg_malloc(sizeof *c);

	if (!c)
		return NULL;
	memset(c, 0, sizeof *c);
	c->fd = fd;
	c->node = node;
	return c;
}

static void conn_free(struct xp_conn *c)
{
	if (c->rbuf)
		pkg_free(c->rbuf);
	close(c->fd);
	pkg_free(c);
}

static int tcp_connect(int node)
{
	union sockaddr_union su;
	socklen_t sulen;
	struct timeval tv = { XP_SEND_TMO_MS / 1000, (XP_SEND_TMO_MS % 1000) * 1000 };
	struct pollfd pfd;
	int fd, one = 1, err = 0, sz = XP_SNDBUF;
	socklen_t elen = sizeof err;

	if (peer_get(node, &su, &sulen) < 0 && peer_derive(node, &su, &sulen) < 0)
		return -1;
	fd = socket(su.s.sa_family, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	set_nonblock(fd);
	if (connect(fd, &su.s, sulen) < 0 && errno != EINPROGRESS)
		goto fail;
	pfd.fd = fd; pfd.events = POLLOUT;
	if (poll(&pfd, 1, XP_CONN_TMO_MS) <= 0 ||
	    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err)
		goto fail;
	/* writes block for at most the budget; a peer that cannot take a
	 * message in that time is treated as down for this message */
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	st_inc(ST_TCP_CONNECT);
	return fd;
fail:
	st_inc(ST_TCP_ERR);
	close(fd);
	return -1;
}

static void tcp_rpc_send(int sender, void *param)
{
	struct xp_msg *m = param;
	struct xp_conn *c;
	char hdr[XP_FRAME_HDR + XP_HDR];
	uint32_t flen = htonl((uint32_t)(XP_HDR + m->len));
	struct iovec iov[2];
	ssize_t w;
	int tries;

	if (m->node <= 0 || m->node > CL_MAX_NODE_ID)
		goto out;
	memcpy(hdr, &flen, 4);
	put_hdr(hdr + XP_FRAME_HDR);
	iov[0].iov_base = hdr; iov[0].iov_len = sizeof hdr;
	iov[1].iov_base = m->data; iov[1].iov_len = m->len;
	for (tries = 0; tries < 2; tries++) {
		c = out[m->node];
		if (!c) {
			int fd = tcp_connect(m->node);

			if (fd < 0)
				break;
			c = conn_new(fd, m->node);
			if (!c) {
				close(fd);
				break;
			}
			out[m->node] = c;
		}
		w = writev(c->fd, iov, 2);
		if (w == (ssize_t)(sizeof hdr + m->len)) {
			st_inc(ST_TX);
			shm_free(m);
			return;
		}
		/* short or failed write: the stream is broken, drop the
		 * connection and try once more on a fresh one */
		st_inc(ST_TCP_ERR);
		conn_free(c);
		out[m->node] = NULL;
	}
	st_inc(ST_TX_FAIL);
out:
	shm_free(m);
}

/* deliver one wire message (magic + src + payload) */
static void deliver(const char *b, int len, const union sockaddr_union *from,
		socklen_t fromlen)
{
	uint32_t src;

	if (len < XP_HDR || memcmp(b, XP_MAGIC, 4)) {
		st_inc(ST_RX_BAD);
		return;
	}
	memcpy(&src, b + 4, 4);
	src = ntohl(src);
	if (src == 0 || src > CL_MAX_NODE_ID || (int)src == my_node) {
		st_inc(ST_RX_BAD);
		return;
	}
	/* a datagram's source is the sender's pull socket: learn it */
	if (from)
		peer_set((int)src, from, fromlen, 0, NULL);
	st_inc(ST_RX);
	recv_cb((int)src, b + XP_HDR, len - XP_HDR);
}

static int udp_cb(int fd, void *param, int was_timeout)
{
	union sockaddr_union from;
	socklen_t fromlen;
	ssize_t n;
	int burst;

	for (burst = 0; burst < 256; burst++) {
		fromlen = sizeof from;
		n = recvfrom(fd, rxbuf, XP_HDR + XP_MAX_MSG, 0, &from.s, &fromlen);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				LM_ERR("pull socket read: %s\n", strerror(errno));
			break;
		}
		deliver(rxbuf, (int)n, &from, fromlen);
	}
	return 0;
}

static int tcp_read_cb(int fd, void *param, int was_timeout)
{
	struct xp_conn *c = param, **pp;
	ssize_t n;
	uint32_t flen;

	if (!c->rbuf) {
		c->rbuf = pkg_malloc(XP_FRAME_HDR + XP_HDR + XP_MAX_MSG);
		if (!c->rbuf)
			goto drop;
	}
	n = read(fd, c->rbuf + c->rlen, XP_FRAME_HDR + XP_HDR + XP_MAX_MSG - c->rlen);
	if (n <= 0) {
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			return 0;
		goto drop;
	}
	c->rlen += n;
	for (;;) {
		if (c->rlen < XP_FRAME_HDR)
			return 0;
		memcpy(&flen, c->rbuf, 4);
		flen = ntohl(flen);
		if (flen < XP_HDR || flen > XP_HDR + XP_MAX_MSG) {
			st_inc(ST_RX_BAD);
			goto drop;
		}
		if (c->rlen < XP_FRAME_HDR + flen)
			return 0;
		deliver(c->rbuf + XP_FRAME_HDR, (int)flen, NULL, 0);
		c->rlen -= XP_FRAME_HDR + flen;
		memmove(c->rbuf, c->rbuf + XP_FRAME_HDR + flen, c->rlen);
	}
drop:
	reactor_proc_del_fd(fd, -1, IO_WATCH_READ);
	for (pp = &conns; *pp; pp = &(*pp)->next)
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	conn_free(c);
	return 0;
}

static int tcp_accept_cb(int fd, void *param, int was_timeout)
{
	union sockaddr_union from;
	socklen_t fromlen = sizeof from;
	struct xp_conn *c;
	int cfd;

	while ((cfd = accept(fd, &from.s, &fromlen)) >= 0) {
		set_nonblock(cfd);
		c = conn_new(cfd, 0);
		if (!c || reactor_proc_add_fd(cfd, tcp_read_cb, c) < 0) {
			if (c)
				conn_free(c);
			else
				close(cfd);
			continue;
		}
		c->next = conns;
		conns = c;
		st_inc(ST_TCP_ACCEPT);
		fromlen = sizeof from;
	}
	return 0;
}

/* every XP_HELLO_TICK_S: announce while a cluster member is still unknown
 * or the last announcement did not go out (the links come up after us),
 * otherwise once per XP_HELLO_S as a heartbeat for restarted peers */
static int hello_cb(int fd, void *param, int was_timeout)
{
	static unsigned int ticks;
	static int last_rc = -1;
	uint64_t n;

	while (read(fd, &n, sizeof n) == (ssize_t)sizeof n)
		;
	ticks++;
	if (last_rc < 0 || pcache_xport_peers_known() < pcache_pull_peers_expected()
	        || ticks % (XP_HELLO_S / XP_HELLO_TICK_S) == 0) {
		LM_DBG("announcing our pull address to the cluster\n");
		last_rc = pcache_pull_hello(0);
	}
	return 0;
}

void pcache_xport_proc(int rank)
{
	struct itimerspec its;
	int tfd;

	if (kind == PCACHE_XPORT_NONE)
		return;
	xp->proc_no = process_no;
	rxbuf = pkg_malloc(XP_HDR + XP_MAX_MSG);
	if (!rxbuf || reactor_proc_init("cachedb_perf transport") < 0) {
		LM_ERR("cannot init the transport process\n");
		return;
	}
	if (kind == PCACHE_XPORT_UDP) {
		if (reactor_proc_add_fd(udp_fd, udp_cb, NULL) < 0) {
			LM_ERR("cannot watch the pull socket\n");
			return;
		}
	} else if (reactor_proc_add_fd(listen_fd, tcp_accept_cb, NULL) < 0) {
		LM_ERR("cannot watch the pull listen socket\n");
		return;
	}
	/* announce now and every XP_HELLO_S: peers learn where we pull */
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0) {
		LM_ERR("timerfd: %s - peers will only be learned from their own "
			"announcements\n", strerror(errno));
	} else {
		memset(&its, 0, sizeof its);
		its.it_value.tv_sec = 1;
		its.it_interval.tv_sec = XP_HELLO_TICK_S;
		if (timerfd_settime(tfd, 0, &its, NULL) < 0 ||
		    reactor_proc_add_fd(tfd, hello_cb, NULL) < 0)
			LM_ERR("cannot arm the HELLO timer: %s\n", strerror(errno));
	}
	LM_DBG("transport process up (%s), announcing in 1 s\n", pcache_xport_name());
	reactor_proc_loop();
	LM_CRIT("the transport process's reactor loop ended\n");
}
