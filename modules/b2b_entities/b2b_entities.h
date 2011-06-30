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
 *  2011-06-27  added authentication support (Ovidiu Sas)
 */

#ifndef  _B2B_H_
#define  _B2B_H_

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "../uac_auth/uac_auth.h"
#include "../tm/tm_load.h"
#include "../signaling/signaling.h"
#include "dlg.h"
#include "client.h"
#include "server.h"
#include "../../db/db.h"

/* modes to write in db */
#define NO_DB         0
#define WRITE_THROUGH 1
#define WRITE_BACK    2

typedef int (*b2b_restore_linfo_t)(enum b2b_entity_type type, str* key,
		b2b_notify_t cback);

typedef int (*b2b_update_b2bl_param_t)(enum b2b_entity_type type, str* key,
		str* param);
typedef void (*b2b_db_delete_t)(str param);
typedef int (*b2b_get_b2bl_key_t)(str* callid, str* from_tag, str* to_tag,
		str* entity_key, str* tuple_key);

extern int uac_auth_loaded;
extern str b2b_key_prefix;
#define B2B_MAX_PREFIX_LEN    5

typedef struct b2b_api
{
	b2b_server_new_t          server_new;
	b2b_client_new_t          client_new;
	b2b_send_request_t        send_request;
	b2b_send_reply_t          send_reply;
	b2b_entity_delete_t       entity_delete;
	b2b_db_delete_t           entities_db_delete;
	b2b_restore_linfo_t       restore_logic_info;
	b2b_update_b2bl_param_t   update_b2bl_param;
	b2b_get_b2bl_key_t        get_b2bl_key;
}b2b_api_t;


extern unsigned int server_hsize;
extern unsigned int client_hsize;
extern struct tm_binds tmb;
extern uac_auth_api_t uac_auth_api;
extern int req_routeid;
extern int reply_routeid;
extern int replication_mode;
extern db_con_t *b2be_db;
extern db_func_t b2be_dbf;
extern str b2be_dbtable;
extern int b2be_db_mode;

typedef int(*load_b2b_f) (b2b_api_t* api);

static inline int load_b2b_api( struct b2b_api *b2b_api)
{
	load_b2b_f load_b2b;

	/* import the b2b_entities auto-loading function */
	if ( !(load_b2b=(load_b2b_f)find_export("load_b2b", 1, 0))) {
		LM_ERR("can't import load_b2b\n");
		return -1;
	}

	/* let the auto-loading function load all B2B entities stuff */
	return load_b2b( b2b_api );
}

#endif
