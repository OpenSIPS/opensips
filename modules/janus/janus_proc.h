/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
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
 *
 * History:
 * --------
 * 2024-12-03 initial release (vlad)
 */

#ifndef _JANUS_JANUS_PROC_H_
#define _JANUS_JANUS_PROC_H_

#include "../../str.h"
#include "../../socket_info.h"
#include "../../net/net_tcp.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../str_list.h"
#include "../../lib/list.h"
#include "../../rw_locking.h"
#include "../../ipc.h"
#include "janus_parser.h"
#include "ws_common_defs.h"

typedef struct _janus_ipc_cmd {
	janus_connection *sock;
	str janus_cmd;
	uint64_t janus_transaction_id;
} janus_ipc_cmd;

typedef struct _janus_reply {
	str text;
	uint64_t janus_transaction_id;

	struct list_head list;
} janus_ipc_reply;

int janus_mgr_init(void);
int janus_mgr_wait_init(void);
void janus_worker_loop(int proc_no);
int janus_ipc_init(void);
unsigned long janus_ipc_send_cmd(void);

uint64_t janus_ipc_send_request(janus_connection *sock, cJSON *janus_cmd);


#endif
