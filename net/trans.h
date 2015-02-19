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

#ifndef _TRANS_TI_H_
#define _TRANS_TI_H_

#include "../ip_addr.h"
#include "api_proto.h"
#include "api_proto_net.h"

struct proto_info {
	/* proto as ID */
	enum sip_protos id;

	/* the name of the protocol */
	char *name;

	/* the default protocol */
	unsigned short default_port;

	/* bindings for the transport interface */
	struct api_proto tran;

	/* bindings for the net interface */
	struct api_proto_net net;

	/* listeners on this proto */
	struct socket_info *listeners;

	/* default sending interfaces */
	struct socket_info *sendipv4;
	struct socket_info *sendipv6;
};

extern struct proto_info *protos;

/*
 * initializes transport interface structures
 */
int trans_init(void);

/*
 * destroys the transport interface structures
 */
void trans_destroy(void);

/*
 * loads the transport protocol
 */
int trans_load(void);

/*
 * adds a new listener
 */
int add_listener(struct socket_id *sock, enum si_flags flags);

/*
 * adds a temporary listener
 */
int add_cmd_listener(char *name, int port, int proto);

/*
 * fixes temporary listeners
 */
int fix_cmd_listeners(void);

/*
 * fixes all socket lists
 */
int fix_all_socket_lists(void);

/*
 * init all registered listeners
 */
int trans_init_all_listeners(void);

void print_all_socket_lists(void);

static inline char* get_proto_name(unsigned short proto)
{
	if (proto == PROTO_NONE)
		return "*";
	if (proto >= PROTO_LAST || protos[proto].id == PROTO_NONE)
		return "unknown";
	return protos[proto].name;
}

#endif /* _TRANS_TI_H_ */
