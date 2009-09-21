/*
 * $Id: b2b_entities.h $
 *
 * back-to-back entities modules
 *
 * Copyright (C) 2009 Free Software Fundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 */

#ifndef  _B2B_H_
#define  _B2B_H_

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "../tm/tm_load.h"
#include "../signaling/signaling.h"
#include "dlg.h"
#include "client.h"
#include "server.h"

typedef struct b2b_api
{
	b2b_server_new_t          server_new;
	b2b_client_new_t          client_new;

	b2b_send_request_t        send_request;
	b2b_send_reply_t          send_reply;

	b2b_entity_delete_t       entity_delete;
}b2b_api_t;


extern unsigned int server_hsize;
extern unsigned int client_hsize;
extern str server_address;
extern struct sip_uri srv_addr_uri;
extern struct tm_binds tmb;
extern int req_routeid;
extern int reply_routeid;


int b2b_load_api(b2b_api_t* api);
typedef int(*load_b2b_f) (b2b_api_t* api);

static inline int load_b2b_api( struct b2b_api *b2b_api)
{
	load_b2b_f load_b2b;

	/* import the SL auto-loading function */
	if ( !(load_b2b=(load_b2b_f)find_export("load_b2b", 1, 0))) {
		LM_ERR("can't import load_b2b\n");
		return -1;
	}

	/* let the auto-loading function load all TM stuff */
	return load_b2b( b2b_api );
}

#endif
