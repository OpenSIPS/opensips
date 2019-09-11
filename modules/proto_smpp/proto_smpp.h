/*
 * Copyright (C) 2019 - OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#ifndef _PROTO_SMPP_H_
#define _PROTO_SMPP_H_

#include "../../lib/list.h"
#include "../../str.h"
#include "smpp.h"

#define DEFAULT_SMPP_SEND_TIMEOUT 100

typedef struct smpp_session {
	uint32_t id;

	str name;

	uint8_t session_status;
	uint8_t session_type;

	gen_lock_t sequence_number_lock;
	uint32_t sequence_number;

	uint8_t chunk_identifier;

	struct ip_addr ip;
	int port;

	int conn_id;

	union {
		smpp_bind_receiver_t receiver;
		smpp_bind_transmitter_t trasmitter;
		smpp_bind_transceiver_t transceiver;
		smpp_outbind_t outbind;
	} bind;

	uint8_t source_addr_ton;
	uint8_t source_addr_npi;
	uint8_t dest_addr_ton;
	uint8_t dest_addr_npi;

	struct list_head list;
} smpp_session_t;

extern struct tm_binds tmb;

/* exposed by proto_smpp.c */
int smpp_sessions_init(void);
struct tcp_connection* smpp_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server, int *fd);

void enquire_link(unsigned int ticks, void *param);
void rpc_bind_sessions(int sender_id, void *param);
void handle_smpp_msg(char *buffer, smpp_session_t *session, struct receive_info *rcv);
int send_submit_or_deliver_request(str *msg, int msg_type, str *src, str *dst,
		smpp_session_t *session,int *delivery_confirmation);
smpp_session_t *smpp_session_new(str *name, struct ip_addr *ip, int port,
		str *system_id, str *password, str *system_type, int src_addr_ton,
		int src_addr_npi, int dst_addr_ton, int dst_addr_npi, int stype);
smpp_session_t *smpp_session_get(str *name);

#endif
