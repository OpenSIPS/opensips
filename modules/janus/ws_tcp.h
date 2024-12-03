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

#ifndef _WS_TCP_H_
#define _WS_TCP_H_

#include "../../net/tcp_conn_defs.h"
#include "../../net/tcp_conn_profile.h"
#include "../../net/proto_tcp/tcp_common_defs.h"

#include "janus_common.h"


int janus_ws_raw_read(janus_connection *c, struct tcp_req *r);
int janus_ws_raw_writev(int fd,	const struct iovec *iov, int iovcnt, int tout);

#endif /* _WS_TCP_H_ */
