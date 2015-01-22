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

#ifndef _PROTO_TI_H_
#define _PROTO_TI_H_

#include "../ip_addr.h"
#include "proto_net.h"

typedef int (*proto_init_f)(void);
typedef int (*proto_add_listener_f)(char *name, int port);

struct proto {
	int						default_port;
	proto_init_f			init;
	proto_add_listener_f	add_listener;
};

typedef int (*proto_bind_api)(struct proto *proto_binds,
		struct proto_net *net_binds);

#endif /* _PROTO_TI_H_ */
