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

#include <string.h>
#include "net.h"
#include "../mem/mem.h"

struct api_proto_net *proto_net_binds;

int init_net_interface(int size)
{
	proto_net_binds = pkg_malloc(size * sizeof(struct api_proto_net));
	if (!proto_net_binds) {
		LM_ERR("no more memory to allocate protocol bindings\n");
		return -1;
	}

	memset(proto_net_binds, 0, size * sizeof(struct api_proto_net));

	return 0;
}

