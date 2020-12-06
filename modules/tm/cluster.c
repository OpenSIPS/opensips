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
#include "t_lookup.h"
#include "t_fwd.h"
#include "../../ut.h"
#include "../../receive.h"
#include "../../socket_info.h"
#include "../../bin_interface.h"
#include "../../parser/parse_cseq.h"

str tm_cid;
int tm_repl_cluster = 0;
int tm_repl_auto_cancel = 1;
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

static void tm_repl_cancel(bin_packet_t *packet, str *buf, struct receive_info *ri)
{
	int itmp;
	char *tmp;
	str stmp;
	struct cell *t;
	/* build a nice static message, exactly how t_lookupOriginalT() expects */
	struct sip_msg msg;
	struct via_body via;
	struct via_param branch;

	/* cleanup the structure */
	memset(&msg, 0, sizeof(msg));

	branch.value.s = NULL;
	branch.value.len = 0;

	TM_BIN_POP(int, &itmp, "via branch offset");
	if (itmp != 0) {
		TM_BIN_POP(int, &branch.value.len, "via branch length");

		if (branch.value.len > MCOOKIE_LEN &&
			!memcmp(buf->s + itmp, MCOOKIE,MCOOKIE_LEN))
			branch.value.s = buf->s + itmp;
	}

	if (!branch.value.s) {
		/* if there is no RFC3261 magic cookie in the branch param, we do the message
		 * parsing here, as we will need several headers for matching anyway */
		msg.buf = buf->s;
		msg.len = buf->len;
		msg.rcv=*ri;
		msg.ruri_q = Q_UNSPECIFIED;
		msg.id=get_next_msg_no();

		if (parse_msg(buf->s, buf->len, &msg) != 0) {
			tmp = ip_addr2a(&(ri->src_ip));
			LM_ERR("Unable to parse replicated CANCEL received from [%s:%d]\n",
				tmp, ri->src_port);
			return;
		}

		TM_BIN_POP(int, &itmp, "via host offset");
		if (itmp != 0)
			TM_BIN_POP(int, &itmp, "via host length");
		TM_BIN_POP(int, &itmp, "via transport offset");
		if (itmp != 0)
			TM_BIN_POP(int, &msg.via1->transport.len, "via transport length");
		TM_BIN_POP(int, &itmp, "via port");
	} else {
		msg.REQ_METHOD = METHOD_CANCEL;
		msg.via1 = &via;
		msg.via1->branch = &branch;

		TM_BIN_POP(int, &itmp, "via host offset");
		if (itmp != 0) {
			msg.via1->host.s = buf->s + itmp;
			TM_BIN_POP(int, &msg.via1->host.len, "via host length");
		} else
			memset(&msg.via1->host, 0, sizeof(str));
		TM_BIN_POP(int, &itmp, "via transport offset");
		if (itmp != 0) {
			msg.via1->transport.s = buf->s + itmp;
			TM_BIN_POP(int, &msg.via1->transport.len, "via transport length");
		} else
			memset(&msg.via1->transport, 0, sizeof(str));
		TM_BIN_POP(int, &msg.via1->port, "via port");
	}

	TM_BIN_POP(str, &stmp, "cancel reason");
	TM_BIN_POP(int, &msg.hash_index, "hash index");

	LM_DBG("Got CANCEL with branch id=%.*s\n", branch.value.len, branch.value.s);

	/* try to get the transaction */
	set_t(T_UNDEFINED); /* set undefined, because we might have already got a cancel here */
	reset_cancelled_t();
	t = t_lookupOriginalT(&msg);
	/* if transaction is not here, must be somebody else's */
	if (!t) {
		LM_DBG("Original transaction not here!\n");
		return;
	}

	/* transaction is located here - do a proper parsing if not done already */
	if (branch.value.s) {
		/* cleanup new message */
		memset(&msg, 0, sizeof(msg));
		msg.buf = buf->s;
		msg.len = buf->len;
		msg.rcv=*ri;
		msg.ruri_q = Q_UNSPECIFIED;
		msg.id=get_next_msg_no();

		if (parse_msg(buf->s, buf->len, &msg) != 0) {
			tmp = ip_addr2a(&(ri->src_ip));
			LM_ERR("Unable to parse replicated CANCEL received from [%s:%d]\n",
				tmp, ri->src_port);
			goto cleanup;
		}
	}

	t_set_reason(&msg, &stmp);
	if (t_relay_to(&msg, NULL, 0) >= 0)
		LM_DBG("successfully handled auto-CANCEL for %p\n", t);
	else
		LM_ERR("cannot handle auto-CANCEL for %p!\n", t);

cleanup:
	t_unref_cell(t);

	if ((t=get_t()) != NULL && t != T_UNDEFINED)
		t_unref_cell(t);

	free_sip_msg(&msg);
}

static void receive_tm_repl(bin_packet_t *packet)
{
	int proto;
	int port;
	str tmp;
	struct receive_info ri;

	LM_DBG("received %d packet from %d in cluster %d\n",
			packet->type, packet->src_id, tm_repl_cluster);

	if (packet->type != TM_CLUSTER_REPLY &&
			packet->type != TM_CLUSTER_REQUEST &&
			packet->type != TM_CLUSTER_AUTO_CANCEL) {
		LM_WARN("Invalid tm binary packet command: %d (from node: %d in cluster: %d)\n",
				packet->type, packet->src_id, tm_repl_cluster);
		return;
	}

	/* first part is common to all messages */
	TM_BIN_POP(int, &proto, "proto");
	TM_BIN_POP(str, &tmp, "dst host");
	TM_BIN_POP(int, &port, "dst port");

	ri.bind_address = grep_internal_sock_info(&tmp, port, proto);
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

	/* only auto-CANCEL is treated differently */
	if (packet->type == TM_CLUSTER_AUTO_CANCEL) {
		if (tm_repl_auto_cancel) {
			tm_repl_cancel(packet, &tmp, &ri);
			return;
		}
		LM_WARN("auto-CANCEL handling is disabled, but got one auto-CANCEL here!\n");
	}
	receive_msg(tmp.s, tmp.len, &ri, NULL, FL_TM_REPLICATED);
}
#undef TM_BIN_POP

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
			tm_repl_cluster, 0, NODE_CMP_ANY) < 0) {
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
 * Builds a replicated message
 */
static bin_packet_t *tm_replicate_packet(struct sip_msg *msg, int type)
{
	static bin_packet_t packet;
	str tmp;
	int port;

	/* XXX: could estimate better here, but let's assume we need msg->len */
	if (bin_init(&packet, &tm_repl_cap, type, TM_CLUSTER_VERSION,
			msg->len + 128) < 0) {
		LM_ERR("cannot initiate bin reply buffer\n");
		return NULL;
	}

	TM_BIN_PUSH(int, msg->rcv.proto, "proto");
	if (msg->rcv.bind_address->tag.len) {
		/* send interface tag if it exists, instead of hostname and port */
		tmp = msg->rcv.bind_address->tag;
		port = 0;
	} else {
		tmp = msg->rcv.bind_address->name;
		port = msg->rcv.bind_address->port_no;
	}
	TM_BIN_PUSH(str, &tmp, "dst host");
	TM_BIN_PUSH(int, port, "dst port");
	tmp.s = (char *)&msg->rcv.src_ip;
	tmp.len = sizeof(struct ip_addr);
	TM_BIN_PUSH(str, &tmp, "src host");
	TM_BIN_PUSH(int, msg->rcv.src_port, "src port");
	tmp.s = msg->buf;
	tmp.len = msg->len + 1; /* XXX: add null terminator */
	TM_BIN_PUSH(str, &tmp, "message");

	return &packet;
}

/**
 * Replicates an auto-CANCEL message to all nodes
 */
static void *tm_replicate_cancel(struct sip_msg *msg)
{
	int rc;
	str reason;
	static bin_packet_t *pckt, packet;

	/* initially we build a similar packet */
	pckt = tm_replicate_packet(msg, TM_CLUSTER_AUTO_CANCEL);
	if (!pckt)
		return NULL;
	packet = *pckt;

	/* send offset of the via information */
	if (msg->via1->branch) {
		TM_BIN_PUSH(int, msg->via1->branch->value.s - msg->buf, "via branch offset");
		TM_BIN_PUSH(int, msg->via1->branch->value.len, "via branch length");
	} else
		TM_BIN_PUSH(int, 0, "via branch offset");
	if (msg->via1->host.s) {
		TM_BIN_PUSH(int, msg->via1->host.s - msg->buf, "via host offset");
		TM_BIN_PUSH(int, msg->via1->host.len, "via host length");
	} else
		TM_BIN_PUSH(int, 0, "via host offset");
	if (msg->via1->transport.s) {
		TM_BIN_PUSH(int, msg->via1->transport.s - msg->buf, "via transport offset");
		TM_BIN_PUSH(int, msg->via1->transport.len, "via transport length");
	} else
		TM_BIN_PUSH(int, 0, "via transport offset");
	TM_BIN_PUSH(int, msg->via1->port, "via port");
	/* cancel reason */
	get_cancel_reason(msg, T_CANCEL_REASON_FLAG, &reason);
	TM_BIN_PUSH(str, &reason, "cancel reason");
	/* message hash */
	TM_BIN_PUSH(int, msg->hash_index, "hash index");

	rc = cluster_api.send_all(&packet, tm_repl_cluster);
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
	bin_free_packet(&packet);
	return NULL; /* dummy return to comply with TM_BIN_PUSH() */
}
#undef TM_BIN_PUSH
/**
 * Replicates a reply message to the owner of the transaction
 */
static void tm_replicate_reply(struct sip_msg *msg, int cid)
{
	int rc;
	bin_packet_t *packet = tm_replicate_packet(msg, TM_CLUSTER_REPLY);
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
static int tm_replicate_broadcast(struct sip_msg *msg)
{
	int rc;

	bin_packet_t *packet = tm_replicate_packet(msg, TM_CLUSTER_REQUEST);
	if (!packet)
		return -1;

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
	return 0;
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
int tm_reply_replicate(struct sip_msg *msg)
{
	int cid;
	if (!tm_cluster_enabled())
		return 0;

	/* double-check we have received the message on a anycast network */
	if (!is_anycast(msg->rcv.bind_address))
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
	return 1;
}

static int tm_existing_trans(struct sip_msg *msg)
{
	struct cell *t = get_t();
	if (t == T_UNDEFINED) {
		if (t_lookup_request(msg, 0) != -1) {
			LM_DBG("e2e ACK or known CANCEL, do not replicate\n");
			return 1;
		}
		t = get_t(); /* fetch again the transaction */
	}
	if (t) {
		LM_DBG("transaction already present here, no need to replicate\n");
		return 1;
	}
	return 0;
}

/**
 * Replicates a message within a cluster
 * Returns:
 *   1: message was successfully replicated
 *  -1: message should not be replicated
 *  -2: message was already replicated to here - avoid loops
 *  -3: internal error - message was not replicated
 */
int tm_anycast_replicate(struct sip_msg *msg)
{

	if (msg->REQ_METHOD != METHOD_CANCEL && msg->REQ_METHOD != METHOD_ACK) {
		LM_DBG("only CANCEL and ACK can be replicated\n");
		return -1;
	}

	if (!is_anycast(msg->rcv.bind_address)) {
		LM_DBG("request not received on an anycast network\n");
		return -1;
	}

	if (msg->msg_flags & FL_TM_REPLICATED) {
		LM_DBG("message already replicated, shouldn't have got here\n");
		return -2;
	}
	if (tm_existing_trans(msg))
		return -1;

	/* we are currently doing auto-CANCEL only for 3261 transactions */
	if (tm_repl_auto_cancel && msg->REQ_METHOD == METHOD_CANCEL && msg->via1->branch)
		return tm_replicate_cancel(msg)? 1: -3;
	else
		return tm_replicate_broadcast(msg)? 1: -3;
}

/**
 * Handles a CANCEL message received over anycast
 * Returns:
 *  0: message was successfully handled
 * -1: message was not handled
 */
int tm_anycast_cancel(struct sip_msg *msg)
{
	if (!tm_repl_auto_cancel || !tm_repl_cluster)
		return -1;

	if (!tm_existing_trans(msg))
		return tm_replicate_cancel(msg)? 0: -2;
	else if (t_relay_to(msg, NULL, 0) < 0) {
		LM_ERR("cannot handle auto-CANCEL here - send to script!\n");
		return -1;
	}

	return 0;
}
