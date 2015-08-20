/*
 * Copyright (C) 2007 1&1 Internet AG
 *
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

#ifndef DB_PG_RES_H
#define DB_PG_RES_H

#include "../../db/db_row.h"

int db_postgres_convert_result(const db_con_t* _h, db_res_t* _r);

int db_postgres_convert_row(const db_con_t* _h, db_res_t* _res, db_row_t* _r,
	char **row_buf);

int db_postgres_get_columns(const db_con_t* _h, db_res_t* _r);

int db_postgres_convert_rows(const db_con_t* _h, db_res_t* _r);

#endif
