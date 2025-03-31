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

#ifndef _PROTO_JANUSWS_H_
#define _PROTO_JANUSWS_H_

#ifndef trace_api_h
	#include "../../trace_api.h"
#endif

#include "janus_common.h"

#define WS_SUPPORTED_VERSION	13		/*!< WebSocket supported version */

enum ws_conn_state { WS_CON_INIT, WS_CON_HANDSHAKE, WS_CON_HANDSHAKE_DONE,
	WS_CON_BAD_REQ };

enum ws_conn_type { WS_NONE, WS_CLIENT, WS_SERVER };

enum ws_close_code {
	WS_ERR_NONE		= 0,
	WS_ERR_NORMAL	= 1000,
	WS_ERR_CLIENT	= 1001,
	WS_ERR_PROTO	= 1002,
	WS_ERR_INVALID	= 1003,
	WS_ERR_BADDATA	= 1007,
	WS_ERR_POLICY	= 1008,
	WS_ERR_TOO_BIG	= 1009,
	WS_ERR_BADEXT	= 1010,
	WS_ERR_UNEXPECT	= 1011,
	WS_ERR_NOSEND	= 10000
};

/*
 * For now we only need the state stored in the connection
 * Later, we should probably store info about origin, resoruce. versions,
 * protocols supported, etc. - razvanc
 */
struct ws_data {
	TRACE_PROTO_COMMON;

	/* the state of the connection */
	enum ws_conn_state state;

	/* the type of the connection */
	enum ws_conn_type type;

	/* close code */
	enum ws_close_code code;

	/* WebSocket Handshake key */
	str key;
};

#define WS_STATE(_c) \
	(((struct ws_data *)(_c)->proto_data)->state)
#define WS_TYPE(_c) \
	(((struct ws_data *)(_c)->proto_data)->type)
#define WS_CODE(_c) \
	(((struct ws_data *)(_c)->proto_data)->code)
#define WS_KEY(_c) \
	(((struct ws_data *)(_c)->proto_data)->key)

int proto_janusws_conn_init(struct tcp_connection* c);
void proto_janusws_conn_clean(struct tcp_connection* c);

int janusws_read_req(struct tcp_connection* con, int* bytes_read);
int janusws_write_req(janus_connection* con, char *buf, int len);

int janus_ws_connect(janus_connection *sock);
int janus_init_connection(janus_connection *sock);
int janus_handle_data(janus_connection *sock);

#endif /* _PROTO_WS_H_ */
