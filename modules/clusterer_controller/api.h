/*
 * Copyright (C) 2026 VoIPcloud
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

/*
 * Consumer messaging API - lets other modules (and, through them, the
 * script) exchange messages over the controller's encrypted UDP plane
 * instead of building their own transport.  A consumer inherits the
 * XChaCha20-Poly1305 group session key (with its rotation), the
 * per-packet receive gauntlet (magic gate, cluster_id filter, size
 * bound, per-source rate limiting) and the controller's membership,
 * with zero transport code of its own.
 *
 * Usage:
 *     clctr_api_t clctr;
 *     if (load_clctr_api(&clctr) < 0) ...        (mod_init)
 *     clctr.register_channel(&ch, my_cb);        (mod_init - PRE-FORK)
 *     clctr.send_mcast(cluster_id, &ch, &payload, 0);
 *     clctr.send_ucast(cluster_id, node_id, &ch, &payload, 0);
 *
 * Delivery contract:
 *   - the receive callback runs in the CONTROLLER'S WORKER PROCESS for
 *     that cluster, not in the process that called send.  A consumer
 *     that must wake another process brings its own mechanism (shm +
 *     eventfd, ipc_send_rpc, ...).  Keep callbacks short - they run on
 *     the cluster's receive path.
 *   - sends are marshalled to the same worker over IPC, so ordering is
 *     preserved per node and the anti-replay sequence space stays
 *     single-writer.
 *   - CLCTR_SEND_TO_SELF delivers to this node by invoking the local
 *     callback directly - never by hearing our own packet back.  A
 *     unicast addressed to our own node id degenerates to exactly that
 *     local dispatch, with no packet on the wire.
 *   - src_node_id is 0 when the sender had not been assigned an id yet.
 */

#ifndef CL_CTR_API_H
#define CL_CTR_API_H

#include "../../str.h"
#include "../../sr_module.h"

/* deliver to this node too, via local callback dispatch (never off the wire) */
#define CLCTR_SEND_TO_SELF   (1 << 0)
/* Ask for the message to be acknowledged, and resent while it is not.
 *
 * ONLY USE THIS ON A CHANNEL WHERE ONE MESSAGE PER PEER IS IN FLIGHT AT A
 * TIME.  It is not a general-purpose reliability option, and on a channel
 * with concurrent traffic it does not merely cost extra packets - it does
 * not work, and it fails silently.
 *
 * Why: every packet carries a sequence number, and a receiver drops anything
 * whose seq is not strictly greater than the last it accepted from that peer
 * (cl_ctr_check_and_update_seq(), the anti-replay guard).  A retransmit
 * re-sends the cached bytes, so it carries its ORIGINAL seq.  On a serialised
 * 1:1 exchange - the join handshake this was built for - nothing else is in
 * flight from that peer, so the retransmit is still the highest seq and is
 * accepted.  As soon as a second message can overtake it, the retransmit
 * arrives behind a higher seq and is discarded as out of order.  The receive
 * path then re-ACKs it, deliberately, so the sender stops retransmitting and
 * believes it delivered.  Nothing is logged above debug level at either end.
 *
 * Measured, rather than reasoned about: applying this flag to the
 * cross-node cache pull channel (concurrent by nature) made the delivery rate
 * WORSE - 61% -> 49% under 40% reply loss, at two to three times the packet
 * count - and not one retransmitted payload was ever delivered.  See the
 * clusterer_controller notes for the harness.
 *
 * So most consumer traffic is better served by being idempotent and retried
 * by its own logic, which is how the cross-node cache fetch works and why it
 * asks for nothing here.  That was always the recommendation; the point of
 * this note is that for a concurrent channel it is the only thing that works.
 *
 * The cost, where it IS applicable: one ACK per recipient, so a reliable send
 * to the whole cluster is N-1 packets back where a plain one was nothing -
 * hence opt-in, and per send rather than per channel. */
#define CLCTR_SEND_RELIABLE  (1 << 1)

/* limits a consumer can rely on */
#define CLCTR_MAX_CHAN_LEN   31
/* Compile-time lower bound for consumer payload; the actual runtime limit is
 * cc_max_payload, which is derived from the interface MTU at mod_init and may
 * be larger on jumbo-frame links.  Consumers that size local buffers at
 * compile time should use CLCTR_MAX_PAYLOAD; consumers that want to send the
 * largest possible message at runtime should check cc_max_payload instead. */
#define CLCTR_MAX_PAYLOAD    1300
extern int cc_max_payload;

typedef void (*clctr_msg_cb_f)(int cluster_id, int src_node_id,
		str *channel, str *payload);

/* register a named channel; PRE-FORK only (call from mod_init).
 * Returns 0 on success, -1 on bad name / duplicate / table full. */
typedef int (*clctr_register_channel_f)(str *channel, clctr_msg_cb_f cb);

/* send to the cluster's multicast group / to one node by id.
 * Returns 0 = accepted for sending, -1 = bad arguments or unknown
 * cluster, -2 = cluster not ready (no worker / not joined yet).
 * "Accepted" means handed to the cluster worker - UDP gives no
 * delivery guarantee, by design (consumers must be loss-tolerant). */
typedef int (*clctr_send_mcast_f)(int cluster_id, str *channel,
		str *payload, int flags);
typedef int (*clctr_send_ucast_f)(int cluster_id, int node_id,
		str *channel, str *payload, int flags);

/* this node's controller-assigned id in the cluster; 0 = none yet */
/* Send to a named set of nodes.  Deliberately N unicasts rather than one
 * multicast with the receivers filtering: a multicast is decrypted by every
 * member, so "addressed to three of you" would still hand the payload to all
 * of them.  The cost is linear in the size of the list, which is the honest
 * price of addressing a subset.
 *
 * Returns the number of nodes the message was sent to, or -1 on error.  Nodes
 * in the list that are not current members are skipped and counted in
 * @unknown when it is not NULL. */
typedef int (*clctr_send_list_f)(int cluster_id, const int *node_ids, int n,
                                 str *channel, str *payload, int flags,
                                 int *unknown);

typedef int (*clctr_get_my_node_id_f)(int cluster_id);

/*
 * This node's own address on the cluster plane, as RESOLVED at startup - not
 * the raw modparam.  It comes from one of three places (explicit `my_ip`, the
 * IPv4 of an explicit `interface`, or a default-route probe towards the
 * multicast group), and which one won is not otherwise visible to a consumer
 * module.  @src, when non-NULL, receives a short constant describing that
 * origin.  Both outputs point at module-static storage, valid for the process
 * lifetime; neither must be freed.  Returns 0 on success, -1 before mod_init
 * has resolved it.
 *
 * Worth exposing because a wrong answer here is not cosmetic: joining the
 * multicast group on the wrong interface is exactly how a node ends up unable
 * to decrypt its peers' traffic.
 */
typedef int (*clctr_get_my_ip_f)(const char **ip, const char **iface,
		const char **src);

typedef struct clctr_api {
	clctr_register_channel_f  register_channel;
	clctr_send_mcast_f        send_mcast;
	clctr_send_ucast_f        send_ucast;
	clctr_send_list_f         send_list;
	clctr_get_my_node_id_f    get_my_node_id;
	clctr_get_my_ip_f         get_my_ip;
} clctr_api_t;

typedef int (*load_clctr_f)(clctr_api_t *api);

static inline int load_clctr_api(clctr_api_t *api)
{
	load_clctr_f load_clctr;

	load_clctr = (load_clctr_f)(void *)find_export("load_clctr", 0);
	if (!load_clctr)
		return -1;
	return load_clctr(api);
}

#endif /* CL_CTR_API_H */
