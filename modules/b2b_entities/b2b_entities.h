/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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

extern int uac_auth_loaded;
extern str b2b_key_prefix;
#define B2B_MAX_PREFIX_LEN    5

extern unsigned int server_hsize;
extern unsigned int client_hsize;
extern struct tm_binds tmb;
extern uac_auth_api_t uac_auth_api;
extern int req_routeid;
extern int reply_routeid;
extern db_con_t *b2be_db;
extern db_func_t b2be_dbf;
extern str b2be_dbtable;
extern int b2be_db_mode;
extern int serialize_backend;
extern int b2b_ctx_idx;

void *b2b_get_context(void);

#endif
