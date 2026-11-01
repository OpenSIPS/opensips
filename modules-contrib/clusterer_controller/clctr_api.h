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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* consumer messaging API: other modules exchange messages over the controller's
 * encrypted UDP plane, reusing its session key, receive checks and membership */

#ifndef CL_CTR_API_H
#define CL_CTR_API_H

#include "../../str.h"
#include "../../sr_module.h"

/* deliver to this node too, via local callback dispatch (never off the wire);
 * a unicast to our own node id is the same local dispatch */
#define CLCTR_SEND_TO_SELF   (1 << 0)
/* ACKed per recipient and resent until ACKed, delivered at most once (unconfirmed
 * past ~12.8k msg/s from one peer); enable_reliable_send=0 makes it plain */
#define CLCTR_SEND_RELIABLE  (1 << 1)

#define CLCTR_MAX_CHAN_LEN   31
/* buffer sizing only, not a guaranteed size - check get_max_payload(); never
 * extern cc_max_payload (dlopen'd: undefined symbol at startup) */
#define CLCTR_MAX_PAYLOAD    1300

/* runs in the cluster's controller worker, not the sender's process - keep it
 * short; src_node_id is 0 if the sender had no id yet */
typedef void (*clctr_msg_cb_f)(int cluster_id, int src_node_id,
		str *channel, str *payload);

/* PRE-FORK only (mod_init); -1 on a bad name, duplicate or full table */
typedef int (*clctr_register_channel_f)(str *channel, clctr_msg_cb_f cb);

/* 0 = handed to the cluster worker (UDP: no delivery guarantee), -1 = bad args
 * or unknown cluster, -2 = not joined yet; ordered per node */
typedef int (*clctr_send_mcast_f)(int cluster_id, str *channel,
		str *payload, int flags);
typedef int (*clctr_send_ucast_f)(int cluster_id, int node_id,
		str *channel, str *payload, int flags);

/* N unicasts, since a multicast is decrypted by every member; returns the count
 * sent or -1, non-members are skipped and counted in @unknown */
typedef int (*clctr_send_list_f)(int cluster_id, const int *node_ids, int n,
                                 str *channel, str *payload, int flags,
                                 int *unknown);

/* 0 = no id assigned yet */
typedef int (*clctr_get_my_node_id_f)(int cluster_id);

/* from the interface MTU at mod_init: above CLCTR_MAX_PAYLOAD on jumbo links,
 * below it under ~1411 MTU */
typedef int (*clctr_get_max_payload_f)(void);

/* the cluster-plane address as resolved (my_ip, interface or route probe, named
 * in @src); static strings, -1 before mod_init */
typedef int (*clctr_get_my_ip_f)(const char **ip, const char **iface,
		const char **src);

typedef struct clctr_api {
	clctr_register_channel_f  register_channel;
	clctr_send_mcast_f        send_mcast;
	clctr_send_ucast_f        send_ucast;
	clctr_send_list_f         send_list;
	clctr_get_my_node_id_f    get_my_node_id;
	clctr_get_my_ip_f         get_my_ip;
	clctr_get_max_payload_f   get_max_payload;
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
