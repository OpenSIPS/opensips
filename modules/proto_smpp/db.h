/*
 * Copyright (C) 2019 - OpenSIPS Project
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
 */

#ifndef _PROTO_DB_H_
#define _PROTO_DB_H_

#include "../../db/db.h"
#include "../../str.h"

#define SMPP_TABLE_VERSION 1

extern str smpp_table;
extern str smpp_name_col;
extern str smpp_ip_col;
extern str smpp_port_col;
extern str smpp_system_id_col;
extern str smpp_password_col;
extern str smpp_system_type_col;
extern str smpp_src_ton_col;
extern str smpp_src_npi_col;
extern str smpp_dst_ton_col;
extern str smpp_dst_npi_col;
extern str smpp_session_type_col;
extern str smpp_outbound_uri;

int smpp_db_init(const str *db_url);
int smpp_db_connect(const str *db_url);
int load_smpp_sessions_from_db(struct list_head *head);
int smpp_query(const str *smpp_table, db_key_t *cols, int col_nr, db_res_t **res);
void smpp_free_results(db_res_t *res);
void smpp_db_close(void);

#endif
