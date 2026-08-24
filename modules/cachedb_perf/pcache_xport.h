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
 * The module's own pull transport: controller-free datagrams or streams
 * between the cluster's nodes, carried by sockets this module owns, so no
 * pull message ever passes through the core's TCP dispatcher.
 *
 *   udp   one socket bound at mod_init and inherited by every process:
 *         any process sends on it, the transport process reads it
 *   tcp   one connection per direction per peer, owned by the transport
 *         process; other processes hand their sends over by IPC
 *   tls   reserved (the tcp structure with OpenSSL on the connections)
 *
 * Peers learn each other's address from a HELLO the module sends over its
 * bin capability (cachedb_perf.c) and, for udp, from the source of any
 * datagram; pull_port derives an address from the clusterer's node table
 * until a HELLO arrives.  The payload is the same wire format the clctr
 * plane uses (REQ / RPL); this layer adds a 4-byte magic and the source
 * node id, and for streams a 4-byte length.
 */

#ifndef _PCACHE_XPORT_H_
#define _PCACHE_XPORT_H_

/* the cluster stack's design cap on node ids (also used by cachedb_perf.c) */
#define CL_MAX_NODE_ID 256

enum pcache_xport_kind { PCACHE_XPORT_NONE = 0, PCACHE_XPORT_UDP,
                         PCACHE_XPORT_TCP, PCACHE_XPORT_TLS };

extern char *pcache_pull_bind;      /* modparam pull_bind: "ip:port"      */
extern int   pcache_pull_port;      /* modparam pull_port: peer fallback   */

/* the parser the transport hands every received message to */
typedef void (pcache_xport_recv_f)(int src_node, const char *p, int len);

int  pcache_xport_init(int kind, int my_node, pcache_xport_recv_f *recv,
		int max_msg);                               /* mod_init, pre-fork */
void pcache_xport_destroy(void);
int  pcache_xport_kind(void);
const char *pcache_xport_name(void);
int  pcache_xport_max_payload(void);

/* send one message to a node (any process).  0 = handed to the wire (udp)
 * or to the transport process (tcp); -1 = no address / failure */
int  pcache_xport_send(int dst_node, const char *payload, int len);

/* a peer's announced address, from the bin HELLO ("ip:port") */
void pcache_xport_learn(int node, const char *addr, int len, int *is_new);
/* this node's bound address for the HELLO */
int  pcache_xport_my_addr(char *out, int max);
int  pcache_xport_peers_known(void);

/* the transport process (proc_export function) */
void pcache_xport_proc(int rank);
/* the process number of the transport process, 0 = not started */
int  pcache_xport_proc_no(void);

/* counters: tx, tx_failed, rx, rx_bad, tcp_connects, tcp_accepts, tcp_errors */
#define PCACHE_XPORT_NSTATS 7
void pcache_xport_stats(unsigned long out[PCACHE_XPORT_NSTATS]);

/* announce HELLO over bin: implemented in cachedb_perf.c, called by the
 * transport process at start and on a timer, and by learn() for a peer we
 * did not know (unicast reply) */
int  pcache_pull_hello(int dst_node);        /* 0 = sent, -1 = not (yet) */
/* how many peers the clusterer currently lists (implemented by the module) */
int  pcache_pull_peers_expected(void);
/* the clusterer's address of a node (its bin link), through the module;
 * 0 = filled in, -1 = unknown node */
union sockaddr_union;
int pcache_pull_node_addr(int node, union sockaddr_union *su);

#endif /* _PCACHE_XPORT_H_ */
