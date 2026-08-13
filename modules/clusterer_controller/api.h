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
 * Valid on any channel, including one carrying concurrent messages.  That was
 * NOT true before the receiver grew a replay window, and code or notes
 * predating it may still say the flag is for serialised 1:1 exchanges only.
 *
 * How it behaves.  Every packet carries a sequence number and the receiver
 * accepts each one exactly once.  A retransmit re-sends the cached bytes, so
 * it carries its ORIGINAL seq; the receiver looks that seq up in a window of
 * the last CL_CTR_REPLAY_WIN_BITS it has seen from that peer and can tell the
 * two cases apart - never delivered (accept it now, ACK) versus already
 * delivered (do not deliver twice, but re-ACK, because a duplicate means our
 * previous ACK was lost).  Delivery is therefore at-most-once, and the sender
 * retransmits until acknowledged or its budget runs out.
 *
 * The one limit worth knowing: the window spans a number of MESSAGES, so a
 * peer sending faster than the window divided by the retransmit horizon
 * (consumer_retries x consumer_retry_ms) can outrun it.  A repair arriving
 * that late is dropped and deliberately NOT acknowledged - the sender is told,
 * by silence, that delivery is unconfirmed, and the receiver logs it.  With
 * the defaults that ceiling is ~12,800 msg/s from one peer; mod_init logs the
 * value in force.
 *
 * The cost: one ACK per recipient, so a reliable send to the whole cluster is
 * N-1 packets back where a plain one was nothing - hence opt-in, and per send
 * rather than per channel.  Traffic that can simply be made idempotent and
 * retried by its own logic should still prefer that, which is what the
 * cross-node cache fetch does and why it asks for nothing here.
 *
 * KILL SWITCH.  The flag is honoured unless the deployment sets
 *     modparam("clusterer_controller", "enable_reliable_send", 0)
 * which degrades every reliable send to a plain one - the payload still goes
 * out, it is simply neither acknowledged nor retransmitted - and logs one
 * rate-limited warning.  That exists for fleets that would rather not pay the
 * ACK traffic, not because the mechanism is in doubt. */
#define CLCTR_SEND_RELIABLE  (1 << 1)

/* limits a consumer can rely on */
#define CLCTR_MAX_CHAN_LEN   31
/* A constant to size compile-time buffers with - nothing more.  It is NOT a
 * guaranteed payload size.
 *
 * The runtime limit is cc_max_payload, derived from the interface MTU at
 * mod_init: LARGER on a jumbo-frame link, and SMALLER on a VPN, tunnel or
 * PPPoE link whose MTU is under about 1411.  It used to be padded up to this
 * constant when the link was smaller, which made the constant a promise the
 * network could not keep and fragmented every full-size datagram to pretend
 * otherwise; the module now honours the link and warns at startup instead.
 *
 * So: size a stack buffer with CLCTR_MAX_PAYLOAD - that is always safe, since
 * a buffer can only be too big - but test the length you actually intend to
 * send against cc_max_payload, which is the only bound that will be enforced. */
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
