/*
 * Copyright (C)  2007-2008 Voice Sistem SRL
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
 *  2007-08-01 initial version (ancuta onofrei)
 */

#ifndef _DP_DB_H_
#define _DP_DB_H_

#include "../../str.h"
#include "../../db/db.h"
#include "dialplan.h"

#define DP_PARTITION 			"default"
#define DP_TABLE_NAME			"dialplan"
#define DPID_COL			"dpid"
#define PR_COL				"pr"
#define MATCH_OP_COL			"match_op"
#define MATCH_EXP_COL			"match_exp"
#define MATCH_FLAGS_COL			"match_flags"
#define SUBST_EXP_COL			"subst_exp"
#define REPL_EXP_COL			"repl_exp"
#define DISABLED_COL			"disabled"
#define ATTRS_COL			"attrs"
#define TIMEREC_COL			"timerec"


#define DP_TABLE_VERSION		5
#define DP_TABLE_COL_NO 		9

typedef struct dp_head{
	str partition;/*Attribute that uniquely identifies head*/
	str dp_db_url;
	str dp_table_name;
	struct dp_head* next;
} dp_head_t, *dp_head_p;


extern dp_head_p dp_hlist;
extern dp_head_p dp_df_head;
extern dp_connection_list_p dp_conns;
extern str default_dp_db_url;
extern str default_dp_table;
extern str dpid_column;
extern str pr_column;
extern str match_op_column;
extern str match_exp_column;
extern str match_flags_column;
extern str subst_exp_column;
extern str repl_exp_column;
extern str attrs_column;
extern str timerec_column;
extern str disabled_column;

struct dp_param_list;

int init_db_data();
//int dp_connect_db(dp_connection_list_p conn, dp_head_p head);
struct dp_connection_list * dp_add_connection(dp_head_p head );
struct dp_connection_list * dp_get_connections(void);
struct dp_connection_list * dp_get_connection(str * partition);
struct dp_connection_list * dp_get_default_connection();
int dp_connect_db(dp_connection_list_p conn);
void dp_disconnect_db();

#endif
