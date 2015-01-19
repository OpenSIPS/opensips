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

	/* functions for this protocol */
	struct proto_funcs funcs;
};

extern struct proto_info *protos;
extern unsigned int proto_nr;

/*
 * initializes transport interface structures
 */
int init_trans_interface(void);

/*
 * returns the ID of the protocol
 */
enum sip_protos get_trans_proto(char *name);

#endif /* _TRANS_TI_H_ */
