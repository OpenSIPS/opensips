/*
 * Copyright (C) 2015 OpenSIPS Project
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
 *
 *
 * history:
 * ---------
 *  2015-02-xx  created (razvanc)
 */

#ifndef _PROTO_WS_H_
#define _PROTO_WS_H_

#define WS_SUPPORTED_VERSION	13		/*!< WebSocket supported version */
#define WS_DEFAULT_PORT			80		/*!< WebSocket default port */


enum ws_conn_state { WS_CON_INIT, WS_CON_HANDSHAKE, WS_CON_HANDSHAKE_DONE,
	WS_CON_BAD_REQ };

#define WS_STATE(_c) \
	((enum ws_conn_state)(unsigned long)((_c)->proto_data))
#define WS_SET_STATE(_c, _s) \
	(_c)->proto_data = (((void *)(unsigned long)(_s)))

/*
 * For now we only need the state stored in the connection
 * Later, we should probably store info about origin, resoruce. versions,
 * protocols supported, etc. - razvanc
 */
#if 0
#include "ws_handshake.h"

struct ws_data {
	/* the state of the connection */
	enum ws_conn_states state;

	/* we use a pointer here because we want to detach
	 * it after the handshake is completed */
	struct ws_hs *handshake;
};
#endif

#endif /* _PROTO_WS_H_ */
