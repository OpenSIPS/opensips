/*
 * clusterer_controller - module broadcasts over multicast
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef CL_CTR_DATA_H
#define CL_CTR_DATA_H

#include "cl_ctr.h"
#include "../../str.h"
#include "../../ip_addr.h"   /* struct receive_info */

/* wire: [magic][tier 0x03][cluster_id BE][key id][nonce] in the clear (the first
 * 8 bytes are the AAD), then sealed [sender][incarnation][seq][type][match][frag i][frag n] */
#define CL_CTR_DATA_TIER        0x03
#define CL_CTR_DATA_KEYID_SZ    4
#define CL_CTR_DATA_AAD_SZ      (CL_CTR_MAGIC_SZ + CL_CTR_CLUSTER_ID_SZ + CL_CTR_DATA_KEYID_SZ)
#define CL_CTR_DATA_HDR_SZ      (CL_CTR_DATA_AAD_SZ + CL_CTR_NONCE_SZ)
#define CL_CTR_DATA_PLAIN_SZ    (2 + 8 + 8 + 1 + 1 + 1 + 1)
#define CL_CTR_DATA_OVERHEAD    (CL_CTR_DATA_HDR_SZ + CL_CTR_DATA_PLAIN_SZ + CL_CTR_TAG_SZ)
#define CL_CTR_DATA_DGRAM_MAX   1472    /* a 1500-byte frame, whatever the MTU above it */
#define CL_CTR_DATA_FRAGS_MAX   255
/* the least mcast_window: two messages of the most fragments stay repairable */
#define CL_CTR_DATA_WINDOW_MIN  512

#define CL_CTR_DATA_T_DATA      1
/* these two carry in seq a number of their own, rising through the sender's life and
 * taken once by the receiver; 0 from a build that does not number them */
#define CL_CTR_DATA_T_NACK      2
#define CL_CTR_DATA_T_GONE      3

#define CL_CTR_DATA_HOLD        1024    /* out-of-order packets held per sender */
#define CL_CTR_DATA_TICK_MS     5
#define CL_CTR_DATA_NACK_AFTER_MS 5     /* reordering allowance before a NACK */
#define CL_CTR_DATA_NACK_IVL_MS 50
#define CL_CTR_DATA_GIVEUP_MS   2000    /* then the gap is skipped and reported */
#define CL_CTR_DATA_NACK_RANGES 16
#define CL_CTR_DATA_RETX_MAX    256     /* packets resent for one NACK */
#define CL_CTR_DATA_REPAIR_RATE 4096    /* packets resent a second to one node */
#define CL_CTR_DATA_RCVBUF      (4 << 20)
#define CL_CTR_DATA_BARRIER_MS  500     /* a TCP message waits this long at most */
/* TCP messages waiting per sender and their bytes: past either all of them go at the
 * readers' next tick, and at twice either no more are kept */
#define CL_CTR_DATA_PARK_MAX    1024
#define CL_CTR_DATA_PARK_BYTES  (4 << 20)
#define CL_CTR_DATA_LATE_WARN_MS 60000  /* one that waited it out: warned of once a minute a node */
#define CL_CTR_DATA_SEND_WARN_MS 60000  /* a refused send: warned of once a minute a cluster */
#define CL_CTR_DATA_FILTER_ROUNDS 10    /* heartbeat rounds per repair-share check */
#define CL_CTR_DATA_SRC_TTL_MS  1000    /* a node's address, cached per reader */
/* in receive_info.proto_reserved2: delivered by the data plane, or released
 * from waiting - the barrier is not checked again */
#define CL_CTR_RI_PASS          0x7a5c11u

extern int mcast_broadcasts;
extern int mcast_workers;
extern int mcast_window;
extern int cl_ctr_data_frag_max;

/* sendto() leaving with my_ip as the source address (IP_PKTINFO): receivers bind a
 * node id to its address, and a host with several may pick another one */
ssize_t cl_ctr_sendto_my_ip(int sock, const void *buf, size_t len,
                            const struct sockaddr *to, socklen_t tolen);

/* main process, after the clusters are parsed and my_ip is known: shared state and
 * the data sockets, inherited by every process; how many clusters have one, or -1 */
int  cl_ctr_data_mod_init(void);
void cl_ctr_data_proc(int rank);
/* every cluster's tick now: repair requests, give-ups, releases. The readers run one
 * each CL_CTR_DATA_TICK_MS, whichever of them is free; this is for the unit tests */
void cl_ctr_data_ticks(void);

/* worker, peers lock held for write: master_salt gave a new session key */
void cl_ctr_data_set_key(cl_ctr_cluster_t *cl);
/* worker, each heartbeat round: may broadcasts go by multicast? */
void cl_ctr_data_round(cl_ctr_cluster_t *cl);
/* the last number this node gave a data packet, carried in its ALIVE */
uint64_t cl_ctr_data_tx_seq(cl_ctr_cluster_t *cl);
/* a member's last data number from its ALIVE: catches a lost tail, and alone starts a life
 * here - until then, and in any other incarnation, its DATA, NACK and GONE are refused */
void cl_ctr_data_note_life(cl_ctr_cluster_t *cl, int node_id, uint64_t inc,
                           uint64_t seq, int after_me, int settled);
void cl_ctr_data_note_seq(cl_ctr_cluster_t *cl, int node_id, uint64_t inc,
                          uint64_t seq);

/* a node left or its id went to another node: its held broadcasts and waiting TCP messages
 * are dropped; the next life starts clean, the same one coming back goes on where it was */
void cl_ctr_data_node_gone(cl_ctr_cluster_t *cl, int node_id);

/* any process, cl_list_lock held for reading: 0 = sent by multicast, -1 = send
 * by TCP (no usable data plane, or too big) */
int  cl_ctr_data_send(int cluster_id, const str *bin, int match_op);
void cl_ctr_data_count_tcp(int cluster_id);
/* the last one is no statistic: how many losses were reported to the modules */
enum { CL_CTR_DST_SENT, CL_CTR_DST_RECEIVED, CL_CTR_DST_REPAIRS, CL_CTR_DST_NACKS,
       CL_CTR_DST_GAPS, CL_CTR_DST_TCP, CL_CTR_DST_BARRIER_WAITS,
       CL_CTR_DST_BARRIER_LATE, CL_CTR_DST_REFUSED, CL_CTR_DST_PARK_DROPPED,
       CL_CTR_DST_SEND_ERRORS, CL_CTR_DST_LOSS_REPORTS };
unsigned long cl_ctr_data_stat(cl_ctr_cluster_t *cl, int which);

/* the low 32 bits of this node's last broadcast number, for the TCP trailer */
unsigned int cl_ctr_data_barrier(int cluster_id);
/* a TCP message from @sender: 1 = it waits (copied) for the broadcasts before it,
 * 0 = dispatch it now; dispatches nothing itself (cl_list_lock may be held) */
int  cl_ctr_data_park(int cluster_id, int sender, unsigned int barrier,
                      const char *bin, int len, const struct receive_info *ri);

/* the shared state alone, without a socket (mod_init, unit tests) */
int  cl_ctr_data_alloc(cl_ctr_cluster_t *cl, int window);
/* an opened DATA packet from @sender: held, dispatched in order, or dropped */
void cl_ctr_data_accept(cl_ctr_cluster_t *cl, int sender, uint64_t inc,
                        uint64_t seq, int match, int fi, int fn,
                        char *body, int blen);
/* one datagram as a broadcast reader takes it from @from (static but for the
 * unit tests) */
void cl_ctr_data_recv(char *buf, int n, const struct sockaddr_in *from);
/* a dispatchable BIN message: its length, and a trailer naming @cluster_id and
 * @sender as its source */
int  cl_ctr_data_bin_ok(int cluster_id, int sender, const char *bin, int len);
/* the check a reassembled broadcast passes before it reaches clusterer: 0 = drop
 * it, counted in mcast_refused (not static for the unit tests) */
int  cl_ctr_data_dispatch_ok(cl_ctr_cluster_t *cl, int sender, const char *bin,
                             int len);
/* the 64-bit number nearest @ref whose low 32 bits are @low */
uint64_t cl_ctr_data_widen(uint64_t ref, uint32_t low);
/* unit tests: deliveries go here instead of to clusterer (match -1: a TCP
 * message released from waiting) */
typedef void (*cl_ctr_data_sink_f)(int sender, int match, const char *bin, int len);
extern cl_ctr_data_sink_f cl_ctr_data_sink;
/* unit tests: added to the clock the incarnation cache reads */
extern long long cl_ctr_data_skew_ms;
/* unit tests: this node's id in every cluster, in place of clusterer's (0: clusterer's) */
extern int cl_ctr_data_self_test;
/* a datagram of @sender in this node's incarnation, sealed with the key of the day of
 * cluster index @idx; @out holds CL_CTR_DATA_DGRAM_MAX; its length, or -1 */
int  cl_ctr_data_seal(cl_ctr_cluster_t *cl, int idx, char *out,
                      uint16_t sender, uint64_t seq, int type, int match,
                      int fi, int fn, const char *body, int blen);
/* opens one in place: the plaintext's length at CL_CTR_DATA_HDR_SZ, or -1 (the two are
 * not static for the unit tests) */
int  cl_ctr_data_open(int idx, char *buf, int n);

#endif /* CL_CTR_DATA_H */
