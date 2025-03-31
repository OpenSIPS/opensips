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

#include "../../trace_api.h"
#include "../../net/net_tcp.h"
#include "../../net/tcp_common.h"
#include "../../net/net_tcp_report.h"
#include "../../net/trans_trace.h"
#include "janus_ws.h"
#include "ws_common_defs.h"
#include "janus_common.h"
#include "ws_tcp.h"
#include "ws_common_defs.h"
#include <poll.h>

extern int is_tcp_main;

int janusws_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;
static int janusws_require_origin = 1;

/* in milliseconds */
int janusws_send_timeout = 1000;

/* in milliseconds */
int janusws_hs_read_tout = 1000;

#define _ws_common_module "janusws"
#define _ws_common_max_msg_chunks janusws_max_msg_chunks
#define _ws_common_read ws_raw_read
#define _ws_common_writev ws_raw_writev
#define _ws_common_read_tout janusws_hs_read_tout
#define _ws_common_write_tout janusws_send_timeout
#define _ws_common_require_origin janusws_require_origin

#include "ws_handshake_common.h"
#include "ws_common.h"

int proto_janusws_conn_init(struct tcp_connection* c)
{
	struct ws_data *d;

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct ws_data *)shm_malloc(sizeof(*d));
	if (d==NULL) {
		LM_ERR("failed to create ws states in shm mem\n");
		return -1;
	}
	memset( d, 0, sizeof( struct ws_data ) );

	d->state = WS_CON_INIT;
	d->type = WS_NONE;
	d->code = WS_ERR_NONE;

	janusws_require_origin = 1;
	c->proto_data = (void*)d;
	return 0;
}

int janusws_write_req(janus_connection *con, char *buf, int len)
{
	return janus_ws_req_write(con,buf,len);
}
