/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef TCP_DB_H
#define TCP_DB_H

#include "tcp_path.h"
#include "../../db/db.h"

typedef struct db_col {
	str name;
	int type;
	int is_strict_type;
	int allow_null;
} db_col_t;

extern str tcp_db_url;
extern str tcp_db_table;
extern db_col_t tcp_mgm_cols[];

extern db_con_t *db_hdl;
extern db_func_t db;


#define TCPCOL_PROTO        0
#define TCPCOL_REMOTE_ADDR  1
#define TCPCOL_LOCAL_ADDR   2
#define TCPCOL_ATTRS        3
#define NO_STR_VALS         4

#define TCPCOL_ID               0
#define TCPCOL_REMOTE_PORT      1
#define TCPCOL_LOCAL_PORT       2
#define TCPCOL_PRIORITY         3
#define TCPCOL_CONNECT_TIMEOUT  4
#define TCPCOL_CON_LIFETIME     5
#define TCPCOL_MSG_READ_TIMEOUT 6
#define TCPCOL_SEND_THRESHOLD   7
#define TCPCOL_NO_NEW_CONN      8
#define TCPCOL_ALIAS_MODE       9
#define TCPCOL_PARALLEL_READ    10
#define TCPCOL_KEEPALIVE        11
#define TCPCOL_KEEPCOUNT        12
#define TCPCOL_KEEPIDLE         13
#define TCPCOL_KEEPINTERVAL     14
#define NO_INT_VALS             15

#define NO_DB_COLS (NO_STR_VALS + NO_INT_VALS)

int tcp_db_init(void);
int tcp_reload_paths(struct tcp_path **new_paths, int *new_paths_sz);

#endif /* TCP_DB_H */
