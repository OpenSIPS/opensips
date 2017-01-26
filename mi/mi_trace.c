/*
 * Copyright (C) 2016 - OpenSIPS Foundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2016-09-19  first version (Ionut Ionita)
 */
#include "../ut.h"

#include "mi_trace.h"

#define TRACE_API_MODULE "proto_hep"
#define MI_ID_S "mi"
#define MI_TRACE_BUF_SIZE (1 << 10)

#define MAX_RPL_CHARS (1 << 7)
#define CORR_BUF_SIZE 64

/* CORR - magic for internally generated correltion id */
#define CORR_MAGIC "\x43\x4F\x52\x52"

trace_proto_t* mi_trace_api=NULL;
int mi_message_id;

static char* correlation_name = "correlation_id";
str correlation_value;
int correlation_id=-1, correlation_vendor=-1;


static char trace_buf[MI_TRACE_BUF_SIZE];


void try_load_trace_api(void)
{
	/* already loaded */
	if ( mi_trace_api )
		return;

	mi_trace_api = pkg_malloc(sizeof(trace_proto_t));
	if (mi_trace_api == NULL)
		return;

	memset(mi_trace_api, 0, sizeof(trace_proto_t));
	if (trace_prot_bind(TRACE_API_MODULE, mi_trace_api) < 0) {
		LM_DBG("No tracing module used!\n");
		return;
	}

	mi_message_id = mi_trace_api->get_message_id(MI_ID_S);
}

#define CHECK_OVERFLOW(_len)								\
	do {													\
		if ( _len >= MI_TRACE_BUF_SIZE ) {					\
			LM_ERR("not enough room in command buffer!\n"); \
			return 0;										\
		}													\
	} while (0);

char* build_mi_trace_request( str* cmd, struct mi_root* mi_req, str* backend)
{
	int len, new;
	struct mi_node* node;

	if ( !cmd || !backend )
		return 0;

	len = snprintf( trace_buf, MI_TRACE_BUF_SIZE,
			"(%.*s) %.*s\n",
			backend->len, backend->s,
			cmd->len, cmd->s);

	CHECK_OVERFLOW(len);

	if ( mi_req ) {
		node = mi_req->node.kids;

		while ( node ) {
			/* FIXME should we also put the name here? */
			new = snprintf( trace_buf+len, MI_TRACE_BUF_SIZE - len,
					"%.*s ", node->value.len, node->value.s);

			len += new;
			CHECK_OVERFLOW(len);

			node = node->next;
		}
	}


	return trace_buf;
}

char* build_mi_trace_reply( int code, str* reason, str* rpl_msg )
{
	int len, new;

	if ( !reason )
		return 0;

	len = snprintf( trace_buf, MI_TRACE_BUF_SIZE,
			"(%d:%.*s)\n",
			code, reason->len, reason->s);
	CHECK_OVERFLOW(len);

	if ( rpl_msg ) {
		new = snprintf( trace_buf+len, MI_TRACE_BUF_SIZE,
				"%.*s...\n",
				rpl_msg->len > MAX_RPL_CHARS ? MAX_RPL_CHARS : rpl_msg->len,
				rpl_msg->s);
		len += new;

		CHECK_OVERFLOW(len);
	}

	return trace_buf;
}

char* generate_correlation_id(int* len)
{
	static char corr_buf[CORR_BUF_SIZE];

	if ( !len )
		return 0;

	*len = snprintf(corr_buf, CORR_BUF_SIZE, "%s%d", CORR_MAGIC, rand());
	if ( *len >= CORR_BUF_SIZE ) {
		LM_ERR("not enough space in correlation buffer!\n");
		return 0;
	}

	return corr_buf;
}


int trace_mi_message(union sockaddr_union* src, union sockaddr_union* dst,
		str* body, str* correlation_value, trace_dest trace_dst)
{
	/* FIXME is this the case for all mi impelementations?? */
	const int proto = IPPROTO_TCP;
	union sockaddr_union tmp, *to_su, *from_su;

	trace_message message;

	if (mi_trace_api->create_trace_message == NULL ||
			mi_trace_api->send_message == NULL) {
		LM_DBG("trace api not loaded!\n");
		return 0;
	}


	if (src == NULL || dst == NULL) {
		tmp.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
		tmp.sin.sin_port = 0;
		tmp.sin.sin_family = AF_INET;
	}

	/* FIXME src and/or dst port might be in htons form */
	if (src)
		from_su = src;
	else
		from_su = &tmp;

	if (dst)
		to_su = dst;
	else
		to_su = &tmp;

	message = mi_trace_api->create_trace_message(from_su, to_su,
			proto, body, mi_message_id, trace_dst);
	if (message == NULL) {
		LM_ERR("failed to create trace message!\n");
		return -1;
	}

	if ( correlation_value ) {
		if ( correlation_id < 0 || correlation_vendor < 0 ) {
			if ( load_correlation_id() < 0 ) {
				LM_ERR("can't load correlation id!\n");
				return -1;
			}
		}

		if ( mi_trace_api->add_trace_data( message, correlation_value->s,
				correlation_value->len, TRACE_TYPE_STR,
					correlation_id, correlation_vendor) < 0 ) {
			LM_ERR("can't set the correlation id!\n");
			return -1;
		}
	}

	if (mi_trace_api->send_message(message, trace_dst, 0) < 0) {
		LM_ERR("failed to send trace message!\n");
		return -1;
	}

	mi_trace_api->free_message(message);

	return 0;
}

int load_correlation_id(void)
{
	/* already looked for them */
	if (correlation_id > 0 && correlation_vendor > 0)
		return 0;

	return mi_trace_api->get_data_id(correlation_name, &correlation_vendor, &correlation_id);
}


