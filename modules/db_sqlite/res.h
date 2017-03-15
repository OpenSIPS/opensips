/**
 *
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 * History
 * -------
 *  2015-03-03  initial version (Ionut Ionita)
*/

#ifndef RES_H
#define RES_H

#include "../../db/db_res.h"
#include "../../db/db_con.h"


/*
 * Fill the structure with data from database
 */
int db_sqlite_convert_result(const db_con_t* _h, db_res_t* _r);

int db_sqlite_get_columns(const db_con_t* _h, db_res_t* _r);

int db_sqlite_allocate_rows(db_res_t* res, const unsigned int rows);
int db_sqlite_realloc_rows(db_res_t* res, const unsigned int rows);
#endif /* RES_H */
