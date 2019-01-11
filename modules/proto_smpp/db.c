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

#include "../../db/db.h"
#include "../../str.h"
#include "db.h"

static db_con_t* smpp_db_handle;
static db_func_t smpp_dbf;

int smpp_db_bind(const str *db_url)
{
	if (db_bind_mod(db_url, &smpp_dbf)) {
		LM_ERR("cannot bind module database\n");
		return -1;
	}
	return 0;
}

int smpp_db_init(const str *db_url)
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
	if (smpp_dbf.use_table(smpp_db_handle, smpp_table) < 0) {
		LM_ERR("error while trying to use smpp table\n");
		return -1;
	}

	if (smpp_dbf.query(smpp_db_handle, NULL, 0, NULL, cols, 0, col_nr, 0, res) < 0) {
		LM_ERR("error while querying database\n");
		return -1;
	}

	return 0;
}

void smpp_free_results(db_res_t *res)
{
	smpp_dbf.free_result(smpp_db_handle, res);
}

void smpp_db_close(void)
{
	if (smpp_db_handle && smpp_dbf.close) {
		smpp_dbf.close(smpp_db_handle);
		smpp_db_handle = 0;
	}
}
