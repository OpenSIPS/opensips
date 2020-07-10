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

#include "../../str.h"
#include "../../resolve.h"
#include "../../lib/list.h"
#include "proto_smpp.h"
#include "../../db/db.h"
#include "db.h"

static db_con_t* smpp_db_handle;
static db_func_t smpp_dbf;

str smpp_table = str_init("smpp"); /* Name of smpp table */
str smpp_name_col = str_init("name"); /* Name of the SMSC table */
str smpp_ip_col = str_init("ip");       /* Name of ip address column */
str smpp_port_col = str_init("port"); /* Name of port column */
str smpp_system_id_col = str_init("system_id");
str smpp_password_col = str_init("password");
str smpp_system_type_col = str_init("system_type");
str smpp_src_ton_col = str_init("src_ton");
str smpp_src_npi_col = str_init("src_npi");
str smpp_dst_ton_col = str_init("dst_ton");
str smpp_dst_npi_col = str_init("dst_npi");
str smpp_session_type_col = str_init("session_type");

int smpp_db_init(const str *db_url)
{
	smpp_table.len = strlen(smpp_table.s);
	smpp_name_col.len = strlen(smpp_name_col.s);
	smpp_ip_col.len = strlen(smpp_ip_col.s);
	smpp_port_col.len = strlen(smpp_port_col.s);
	smpp_system_id_col.len = strlen(smpp_system_id_col.s);
	smpp_password_col.len = strlen(smpp_password_col.s);
	smpp_system_type_col.len = strlen(smpp_system_type_col.s);
	smpp_src_ton_col.len = strlen(smpp_src_ton_col.s);
	smpp_src_npi_col.len = strlen(smpp_src_npi_col.s);
	smpp_dst_ton_col.len = strlen(smpp_dst_ton_col.s);
	smpp_dst_npi_col.len = strlen(smpp_dst_npi_col.s);
	smpp_session_type_col.len = strlen(smpp_session_type_col.s);

	if (db_bind_mod(db_url, &smpp_dbf)) {
		LM_ERR("cannot bind module database\n");
		return -1;
	}

	if (smpp_db_connect(db_url) < 0)
		return -1;

	if(db_check_table_version(&smpp_dbf, smpp_db_handle,
			&smpp_table, SMPP_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}
	return 0;
}

int smpp_db_connect(const str *db_url)
{
	if (smpp_dbf.init == 0) {
		LM_ERR("unbound database module\n");
		return -1;
	}
	smpp_db_handle = smpp_dbf.init(db_url);
	if (smpp_db_handle == 0){
		LM_ERR("cannot initialize database connection\n");
		return -1;
	}

	return 0;
}

int smpp_query(const str *smpp_table, db_key_t *cols, int col_nr, db_res_t **res)
{
	return 0;
}

void smpp_db_close(void)
{
	if (smpp_db_handle && smpp_dbf.close) {
		smpp_dbf.close(smpp_db_handle);
		smpp_db_handle = 0;
	}
}

int load_smpp_sessions_from_db(struct list_head *head)
{
	struct ip_addr *ip;
	db_key_t cols[11];
	db_res_t* res = NULL;
	db_row_t* row;
	db_val_t* val;
	smpp_session_t *session;
	str ip_s, system_s, pass_s, type_s, name_s;

	int i, n = 0;

	cols[0] = &smpp_name_col;
	cols[1] = &smpp_ip_col;
	cols[2] = &smpp_port_col;
	cols[3] = &smpp_system_id_col;
	cols[4] = &smpp_password_col;
	cols[5] = &smpp_system_type_col;
	cols[6] = &smpp_src_ton_col;
	cols[7] = &smpp_src_npi_col;
	cols[8] = &smpp_dst_ton_col;
	cols[9] = &smpp_dst_npi_col;
	cols[10] = &smpp_session_type_col;

	INIT_LIST_HEAD(head);

	if (smpp_dbf.use_table(smpp_db_handle, &smpp_table) < 0) {
		LM_ERR("error while trying to use smpp table\n");
		return -1;
	}

	if (smpp_dbf.query(smpp_db_handle, NULL, 0, NULL, cols, 0, 11, 0, &res) < 0) {
		LM_ERR("error while querying database\n");
		return -1;
	}


	row = RES_ROWS(res);

	LM_DBG("Number of rows in %.*s table: %d\n",
			smpp_table.len, smpp_table.s, RES_ROW_N(res));

	for (i = 0; i < RES_ROW_N(res); i++) {
		val = ROW_VALUES(row + i);

		if (VAL_TYPE(val) == DB_STRING) {
			name_s.s = (char *)VAL_STRING(val);
			name_s.len = strlen(name_s.s);
		} else if (VAL_TYPE(val) == DB_STR) {
			name_s = VAL_STR(val);
		} else {
			LM_ERR("invalid column type %d for name (row %d)\n", VAL_TYPE(val), i);
			continue;
		}
		if (VAL_TYPE(val+ 1) == DB_STRING) {
			ip_s.s = (char *)VAL_STRING(val + 1);
			ip_s.len = strlen(ip_s.s);
		} else if (VAL_TYPE(val + 1) == DB_STR) {
			ip_s = VAL_STR(val + 1);
		} else {
			LM_ERR("invalid column type %d for ip (row %d, %.*s)\n",
					VAL_TYPE(val + 1), i, name_s.len, name_s.s);
			continue;
		}
		ip = str2ip(&ip_s);
		if (!ip) {
			LM_ERR("Invalid IP [%.*s] for row %d, %.*s\n",
					ip_s.len, ip_s.s, i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 2) != DB_INT) {
			LM_ERR("invalid column type %d for port (row %d, %.*s)\n",
					VAL_TYPE(val + 2), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 3) == DB_STRING) {
			system_s.s = (char *)VAL_STRING(val + 3);
			system_s.len = strlen(system_s.s);
		} else if (VAL_TYPE(val + 3) == DB_STR) {
			system_s = VAL_STR(val + 3);
		} else {
			LM_ERR("invalid column type %d for system id (row %d, %.*s)\n",
					VAL_TYPE(val + 3), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 4) == DB_STRING) {
			pass_s.s = (char *)VAL_STRING(val + 4);
			pass_s.len = strlen(pass_s.s);
		} else if (VAL_TYPE(val + 4) == DB_STR) {
			pass_s = VAL_STR(val + 4);
		} else {
			LM_ERR("invalid column type %d for password (row %d, %.*s)\n",
					VAL_TYPE(val + 4), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 5) == DB_STRING) {
			type_s.s = (char *)VAL_STRING(val + 5);
			type_s.len = strlen(type_s.s);
		} else if (VAL_TYPE(val + 5) == DB_STR) {
			type_s = VAL_STR(val + 5);
		} else {
			LM_ERR("invalid column type %d for password (row %d, %.*s)\n",
					VAL_TYPE(val + 5), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 6) != DB_INT) {
			LM_ERR("invalid column type %d for src ton (row %d, %.*s)\n",
					VAL_TYPE(val + 6), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 7) != DB_INT) {
			LM_ERR("invalid column type %d for src npi (row %d, %.*s)\n",
					VAL_TYPE(val + 7), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 8) != DB_INT) {
			LM_ERR("invalid column type %d for dst ton (row %d, %.*s)\n",
					VAL_TYPE(val + 8), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 9) != DB_INT) {
			LM_ERR("invalid column type %d for dst npi (row %d, %.*s)\n",
					VAL_TYPE(val + 9), i, name_s.len, name_s.s);
			continue;
		}
		if (VAL_TYPE(val + 10) != DB_INT) {
			LM_ERR("invalid column type %d for session type (row %d, %.*s)\n",
					VAL_TYPE(val + 10), i, name_s.len, name_s.s);
			continue;
		}
		session = smpp_session_new(&name_s, ip, VAL_INT(val + 2), &system_s,
				&pass_s, &type_s, VAL_INT(val + 6), VAL_INT(val + 7),
				VAL_INT(val + 8), VAL_INT(val + 9), VAL_INT(val + 10));
		if (!session) {
			LM_ERR("cannot add session in row %d, %.*s\n",
					i, name_s.len, name_s.s);
			continue;
		}
		list_add(&session->list, head);
		n++;
	}
	smpp_dbf.free_result(smpp_db_handle, res);
	LM_INFO("Loaded %d SMSc servers\n", n);
	return n;
}
