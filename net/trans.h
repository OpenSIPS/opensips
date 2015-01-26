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
#include "proto.h"

struct proto_info {
	/* proto as ID */
	enum sip_protos id;

	/* listeners on this proto */
	struct socket_info *listeners;

	/* bindings for this protocol */
	struct proto binds;
};

extern struct proto_info *protos;
extern unsigned int proto_nr;

/*
 * initializes transport interface structures
 */
int init_trans_interface(void);

/*
 * loads the transport protocol
 */
int load_trans_proto(char *name, enum sip_protos proto);

/*
 * adds a new listener
 */
int add_listener(struct socket_id *sock, enum si_flags flags);

/*
 * adds a temporary listener
 */
int add_tmp_listener(char *name, int port, int proto);

/*
 * fixes temporary listeners
 */
int fix_tmp_listeners(void);

/*
 * fixes all socket lists
 */
int fix_all_socket_lists(void);

void print_all_socket_lists(void);

static inline char* get_proto_name(unsigned short proto)
{
	if (proto == PROTO_NONE)
		return "*";
	if (proto >= proto_nr || protos[proto - 1].id == PROTO_NONE)
		return "unknown";
	return protos[proto - 1].binds.name;
}

#endif /* _TRANS_TI_H_ */
