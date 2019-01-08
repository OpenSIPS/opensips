/*
 * reg_db_handler module
 *
 * Copyright (C) 2011 VoIP Embedded, Inc.
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
 * 2011-12-16  initial version (Ovidiu Sas)
 */

#ifndef REG_DB_HANDLER
#define REG_DB_HANDLER

#include <stdio.h>
#include <stdlib.h>

#include "reg_records.h"


#define REGISTRAR_COL			"registrar"
#define PROXY_COL			"proxy"
#define AOR_COL				"aor"
#define THIRD_PARTY_REGISTRANT_COL	"third_party_registrant"
#define USERNAME_COL			"username"
#define PASSWORD_COL			"password"
#define BINDING_URI_COL			"binding_URI"
#define BINDING_PARAMS_COL		"binding_params"
#define EXPIRY_COL			"expiry"
#define FORCED_SOCKET_COL		"forced_socket"
#define CLUSTER_SHTAG_COL		"cluster_shtag"

#define REG_TABLE_NAME			"registrant"

#define REG_TABLE_VERSION		2

#define REG_TABLE_TOTAL_COL_NO		11

#define REG_FETCH_SIZE			128

extern str registrar_column;
extern str proxy_column;
extern str aor_column;
extern str third_party_registrant_column;
extern str username_column;
extern str password_column;
extern str binding_URI_column;
extern str binding_params_column;
extern str expiry_column;
extern str forced_socket_column;
extern str cluster_shtag_column;

extern str reg_table_name;

extern unsigned int timer_interval;

int init_reg_db(const str *db_url);
int connect_reg_db(const str *db_url);
int load_reg_info_from_db(unsigned int plist);
void destroy_reg_db(void);

#endif
