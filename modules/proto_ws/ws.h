/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 *
 * History:
 * -------
 *  2015-02-xx  first version (razvanc)
 */

#ifndef _WS_H_
#define _WS_H_

/* borrow suff from proto_tcp - but don't use parse and common */
#include "../../net/proto_tcp/tcp_common_defs.h"


extern int ws_max_msg_chunks;
extern int ws_send_timeout;

int ws_process(struct tcp_connection *con);
int ws_handshake(struct tcp_connection *con);
int ws_req_write(struct tcp_connection *con, int fd, char *buf, int len);

#endif /* _WS_H_ */
