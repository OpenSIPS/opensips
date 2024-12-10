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

#ifndef _JANUSWS_COMMON_DEFS_H_
#define _JANUSWS_COMMON_DEFS_H_

#include "../../net/net_tcp.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "janus_parser.h"
#include "janus_common.h"
#include "../../lib/cJSON.h"

/* wrapper around tcp request to add ws info */
/* keep this in sync with the janus_req, this gets cast to that */
struct janus_ws_req {
	struct tcp_req tcp;

	char * buf;
	int buf_len;

	cJSON* body; /* the JANUS body payload */

	/* control fields */
	/* 1 if one req has been fully read, 0 otherwise*/
	unsigned short complete;

	unsigned int op;
	unsigned int mask;
	unsigned int is_masked;
};


#endif /* _JANUSWS_COMMON_DEFS_H_ */
