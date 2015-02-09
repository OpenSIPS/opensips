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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#ifndef _API_PROTO_TI_H_
#define _API_PROTO_TI_H_

#include "../ip_addr.h"
#include "api_proto_net.h"

#define PROTO_PREFIX "proto_"

typedef int (*proto_init_f)(void);
typedef int (*proto_init_listener_f)(struct socket_info *si);
typedef int (*proto_send_f)(struct socket_info *si, char * buf, int len,
		union sockaddr_union* to, int id);

struct api_proto {
	char *					name;
	int						default_port;
	proto_init_f			init;
	proto_init_listener_f	init_listener;
	proto_send_f			send;
};

typedef int (*api_proto_bind)(struct api_proto *ap,
		struct api_proto_net *apn);

#endif /* _api_PROTO_TI_H_ */
