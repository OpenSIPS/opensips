/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef _PROTO_MSRP_MSRP_PLAIN_H_
#define _PROTO_MSRP_MSRP_PLAIN_H_


#include "msrp_common.h"

int proto_msrp_init_listener(struct socket_info *si);

void msrp_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);

int msrp_read_plain(struct tcp_connection *c, struct msrp_req *r);

#endif
