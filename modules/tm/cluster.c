/*
 * Copyright (C) 2018 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "cluster.h"
#include "../../ut.h"
#include "../../receive.h"
#include "../../socket_info.h"
#include "../../bin_interface.h"

str tm_cid;
int tm_repl_cluster = 0;
str tm_cluster_param = str_init(TM_CLUSTER_DEFAULT_PARAM);
static int tm_node_id = 0;
static str tm_repl_cap = str_init("tm-repl");

struct clusterer_binds cluster_api;

#define TM_BIN_POP(_t, _f, _d) \
	do { \
		if (bin_pop_##_t(packet, _f) < 0) { \
			LM_ERR("cannot pop %s info from packet\n", _d); \
			return; \
		} \
	} while(0)
static void tm_repl_received(bin_packet_t *packet)
{
	int proto;
	int port;
	str tmp;
	struct receive_info ri;

	TM_BIN_POP(int, &proto, "proto");
	TM_BIN_POP(str, &tmp, "dst host");
	TM_BIN_POP(int, &port, "dst port");

	ri.bind_address = grep_sock_info(&tmp, port, proto);
	if (!ri.bind_address) {
		LM_WARN("received replicated message for an interface"
				" we don't know %s:%.*s:%d; discarding...\n",
				proto2a(proto), tmp.len, tmp.s, port);
		return;
	}
	if (!(ri.bind_address->flags & SI_IS_ANYCAST)) {
		LM_WARN("received replicated message for a non-anycast interface"
				" %s:%.*s:%d\n",
				proto2a(proto), tmp.len, tmp.s, port);
	}
	ri.dst_port = ri.bind_address->port_no;
	ri.dst_ip = ri.bind_address->address;
	ri.proto = proto;
	/* XXX: do we care about this? Only UDP should work with anycast */
	ri.proto_reserved1 = ri.proto_reserved2 = 0;

	TM_BIN_POP(str, &tmp, "src host");
	memcpy((char *)&ri.src_ip, tmp.s, tmp.len);
	TM_BIN_POP(int, &ri.src_port, "src port");
	TM_BIN_POP(str, &tmp, "message");

	/* all set up - process it */
	receive_msg(tmp.s, tmp.len, &ri, NULL);
}
#undef TM_BIN_POP

static void receive_tm_repl(bin_packet_t *packet)
{
	LM_DBG("received %d packet from %d in cluster %d\n",
			packet->type, packet->src_id, tm_repl_cluster);
	switch (packet->type) {
		case TM_CLUSTER_REPLY:
		case TM_CLUSTER_REQUEST:
			tm_repl_received(packet);
			break;
		default:
			LM_WARN("Invalid tm binary packet command: %d (from node: %d in cluster: %d)\n",
					packet->type, packet->src_id, tm_repl_cluster);
	}
}

int tm_init_cluster(void)
{
	str cid;

	if (tm_repl_cluster == 0) {
		LM_DBG("tm_replication_cluster not set - not engaging!\n");
		return 0;
	}

	/* fix clusterer param */
	tm_cluster_param.len = strlen(tm_cluster_param.s);

	if (tm_repl_cluster < 0) {
		LM_ERR("Invalid value for tm_replication_cluster must be "
			"a positive cluster id\n");
		return -1;
	}

	if (load_clusterer_api(&cluster_api) < 0) {
		LM_WARN("failed to load clusterer API - is the clusterer module loaded?\n");
		return -1;
	}
	if (cluster_api.register_capability(&tm_repl_cap, receive_tm_repl, NULL,
			tm_repl_cluster) < 0) {
		LM_ERR("cannot register tm bin processing function\n");
		/* overwrite structure to disable clusterer */
		goto cluster_error;
	}
	tm_node_id = cluster_api.get_my_id();

	/* build the via param */
	cid.s = int2str(tm_node_id, &cid.len);
	tm_cid.s = pkg_malloc(1/*;*/ + tm_cluster_param.len + 1/*=*/ + cid.len);
	if (!tm_cid.s) {
		LM_ERR("out of pkg memory!\n");
		goto cluster_error;
	}
	tm_cid.len = 0;
	tm_cid.s[tm_cid.len++] = ';';
	memcpy(tm_cid.s + tm_cid.len, tm_cluster_param.s, tm_cluster_param.len);
	tm_cid.len += tm_cluster_param.len;
	tm_cid.s[tm_cid.len++] = '=';
	memcpy(tm_cid.s + tm_cid.len, cid.s, cid.len);
	tm_cid.len += cid.len;

	return 0;

cluster_error:
	cluster_api.register_capability = 0;
	return -1;
}

#define TM_BIN_PUSH(_t, _f, _d) \
	do { \
		if (bin_push_##_t(&packet, _f) < 0) { \
			LM_ERR("cannot push %s info in packet\n", _d); \
			bin_free_packet(&packet); \
			return NULL; \
		} \
	} while(0)

/**
 * Builds a replicated message, regardless the type
 */
static bin_packet_t *tm_replicate_packet(struct sip_msg *msg)
{
	static bin_packet_t packet;
	str tmp;

	/* XXX: could estimate better here, but let's assume we need msg->len */
	if (bin_init(&packet, &tm_repl_cap, TM_CLUSTER_REPLY, TM_CLUSTER_VERSION,
			msg->len + 128) < 0) {
		LM_ERR("cannot initiate bin reply buffer\n");
		return NULL;
	}

	TM_BIN_PUSH(int, msg->rcv.proto, "proto");
	TM_BIN_PUSH(str, &msg->rcv.bind_address->name, "dst host");
	TM_BIN_PUSH(int, msg->rcv.dst_port, "dst port");
	tmp.s = (char *)&msg->rcv.src_ip;
	tmp.len = sizeof(struct ip_addr);
	TM_BIN_PUSH(str, &tmp, "src host");
	TM_BIN_PUSH(int, msg->rcv.src_port, "src port");
	tmp.s = msg->buf;
	tmp.len = msg->len + 1; /* XXX: add null terminator */
	TM_BIN_PUSH(str, &tmp, "message");

	return &packet;
}
#undef TM_BIN_PUSH
/**
 * Replicates a reply message to the owner of the transaction
 */
static void tm_replicate_reply(struct sip_msg *msg, int cid)
{
	int rc;
	bin_packet_t *packet = tm_replicate_packet(msg);
	if (!packet)
		return;

	rc = cluster_api.send_to(packet, tm_repl_cluster, cid);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n",
				tm_repl_cluster);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("%d node is disabled in cluster: %d\n", cid,
				tm_repl_cluster);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending message to %d in cluster: %d\n", cid,
				tm_repl_cluster);
		break;
	}
	bin_free_packet(packet);
}

/**
 * Replicates a request message to all the member of the cluster
 * hoping that one of them will match the transaction and will act on it
 */
static void tm_replicate_request(struct sip_msg *msg)
{
	int rc;

	bin_packet_t *packet = tm_replicate_packet(msg);
	if (!packet)
		return;

	rc = cluster_api.send_all(packet, tm_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n",
				tm_repl_cluster);
		break;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All nodes are disabled in cluster: %d\n",
				tm_repl_cluster);
		break;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending message to cluster: %d\n",
				tm_repl_cluster);
		break;
	}
	bin_free_packet(packet);
}

/**
 * Retrieves the cluster_id of a message, if present in via
 * Returns:
 *  -2: if param was found, but there was a parsing error
 *  -1: if param was not found
 *  cid: the cluster id, if found and valid
 */
static int tm_get_cid(struct sip_msg *msg)
{
	int cid;
	struct via_param *p;

	if (!msg->via1 || !msg->via1->param_lst)
		goto not_found;
	/* search for the cid parameter */
	for (p = msg->via1->param_lst; p; p = p->next)
		if (p->type == GEN_PARAM && p->name.len == tm_cluster_param.len &&
				memcmp(p->name.s, tm_cluster_param.s, p->name.len) == 0)
			/* found the parameter - get its value */
			return (str2sint(&p->value, &cid) == 0 ? cid : -2);

not_found:
	return -1;
}

/**
 * Checks if a message should be replicated, and if it is, replicates it
 * Returns:
 *  0: if the message should not be replicated
 *  1: if the message was replicated
 */
int tm_reply_replicated(struct sip_msg *msg)
{
	int cid;
	if (!tm_cluster_enabled())
		return 0;

	/* double-check we have received the message on a anycast network */
	if (!(msg->rcv.bind_address->flags & SI_IS_ANYCAST))
		return 0;
	cid = tm_get_cid(msg);
	/* if there was no parameter, or it was, but it was ours, handle it */
	if (cid < 0)
		return 0;
	if (cid == tm_node_id) {
		LM_DBG("reply should be processed by us (%d)\n", cid);
		return 0;
	}
	LM_DBG("reply should get to node %d\n", cid);
	tm_replicate_reply(msg, cid);
	return 0;

}
