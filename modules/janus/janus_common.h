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


#ifndef _PROTO_JANUS_JANUS_COMMON_H_
#define _PROTO_JANUS_JANUS_COMMON_H_

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

typedef struct _janus_connection janus_connection;

struct janus_req{
	/* reading indicators */
	struct tcp_req tcp;

	char *buf;
	int buf_len;

	cJSON* body; /* the JANUS body payload */

	/* control fields */
	/* 1 if one req has been fully read, 0 otherwise*/
	unsigned short complete;
};

struct _janus_connection {
	str janus_id;

	str full_url;
	struct janus_url parsed_url; /* pointers in full_url */

	/* file descriptor towards JANUS */
	int fd;

	/* the JANUS handler id */
	double handler_id;

	/* connection state at TCP level */
	enum tcp_conn_states state;		

	/* tcp req buffer */
	struct janus_ws_req con_req;	

	/* proto data associated to the connection = WS/WSS data */
	void* proto_data;			

	/* TCP profile */
	struct tcp_conn_profile profile;

	int msg_attempts;
	
	rw_lock_t *lists_lk;    /* protects internal lists */

	uint64_t janus_transaction_id;  /* ID/counter for each JANUS cmd */
	double janus_handler_id;  /* handler id, store as double due to JSON lib */
	struct list_head janus_replies;

	/* a socket may concurrently be part of up to 2 lists! */

	struct list_head list;           /* "janus_sockets" - all JANUS sockets */
	struct list_head reconnect_list; /* "janus_sockets_down" - new/failed conns */
};

extern unsigned int *janus_mgr_process_no;
extern struct list_head *janus_sockets;
extern struct list_head *fs_sockets;
extern rw_lock_t *sockets_lock;
extern struct list_head *janus_sockets_down;
extern rw_lock_t *sockets_down_lock;

extern int janusws_send_timeout;
extern int janusws_max_msg_chunks;
extern int janus_cmd_timeout;
extern int janus_cmd_polling_itv;

#define init_janus_req( r, _size) \
	do{ \
		(r)->tcp.parsed=(r)->tcp.start=(r)->tcp.buf; \
		(r)->tcp.pos=(r)->tcp.buf + (_size); \
		(r)->tcp.error=TCP_REQ_OK;\
		(r)->complete=0; \
		(r)->body.len=0;(r)->body.s=NULL; \
	}while(0)


void janus_brief_parse_msg(struct janus_req *r);
janus_connection* janus_add_connection(const str* janus_id, const str* url);
void janus_free_connection(janus_connection *sock);
janus_connection* get_janus_connection_by_id(const str* janus_id); 
int populate_janus_handler_id(janus_connection *conn, cJSON *request); 
void janus_pinger_routine(unsigned int ticks , void * attr);

int janus_register_event(void);
int handle_janus_json_request(janus_connection *conn, cJSON *request);

#endif

