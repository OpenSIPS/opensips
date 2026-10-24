/*
 * Copyright (C) 2026 Yury Kirsanov
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
 * Pull transport on module-owned sockets, outside the core TCP layer.
 *   udp: one socket bound pre-fork; any process sends, the transport
 *        process receives
 *   tcp: per-peer connections owned by the transport process; other
 *        processes hand sends over by IPC
 * Peer addresses come from a HELLO over clusterer bin, or from pull_port
 * plus the clusterer's node address until one arrives.
 */

#ifndef _PCACHE_XPORT_H_
#define _PCACHE_XPORT_H_

/* upper bound on clusterer node ids */
#define CL_MAX_NODE_ID 256

enum pcache_xport_kind { PCACHE_XPORT_NONE = 0, PCACHE_XPORT_UDP,
                         PCACHE_XPORT_TCP, PCACHE_XPORT_TLS };

extern char *pcache_pull_bind;
extern int   pcache_pull_port;

typedef void (pcache_xport_recv_f)(int src_node, const char *p, int len);

int  pcache_xport_init(int kind, int my_node, pcache_xport_recv_f *recv,
		int max_msg);
void pcache_xport_destroy(void);
int  pcache_xport_kind(void);
const char *pcache_xport_name(void);
int  pcache_xport_max_payload(void);

/* any process; 0 = sent (udp) or queued to the transport process (tcp),
 * -1 = no address or failure */
int  pcache_xport_send(int dst_node, const char *payload, int len);

/* record a peer's "ip:port" from its HELLO */
void pcache_xport_learn(int node, const char *addr, int len, int *is_new);
int  pcache_xport_my_addr(char *out, int max);
int  pcache_xport_peers_known(void);

void pcache_xport_proc(int rank);
/* 0 = transport process not started */
int  pcache_xport_proc_no(void);

/* counters: tx, tx_failed, rx, rx_bad, tcp_connects, tcp_accepts, tcp_errors */
#define PCACHE_XPORT_NSTATS 7
void pcache_xport_stats(unsigned long out[PCACHE_XPORT_NSTATS]);

/* provided by cachedb_perf.c */
int  pcache_pull_hello(int dst_node);        /* 0 = sent, -1 = not (yet) */
int  pcache_pull_peers_expected(void);
/* 0 = filled in, -1 = unknown node */
union sockaddr_union;
int pcache_pull_node_addr(int node, union sockaddr_union *su);

#endif /* _PCACHE_XPORT_H_ */
