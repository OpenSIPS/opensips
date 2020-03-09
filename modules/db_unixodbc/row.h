/*
 * UNIXODBC module row related functions
 *
 * Copyright (C) 2005-2006 Marco Lorrai
 * Copyright (C) 2008 1&1 Internet AG
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
 *
 * History:
 * --------
 *  2005-12-01  initial commit (chgen)
 */

#ifndef ROW_H
#define ROW_H

#include "../../db/db_con.h"
#include "../../db/db_res.h"
#include "../../db/db_row.h"

#include "db_con.h"

/*
 * Duplicate result columns in pkg memory, stack them linearly
 */
str *db_unixodbc_dup_row(strn *in, int row, int columns);

/*
 * Convert a row from result into db API representation
 */
int db_unixodbc_convert_row(const str *row, const db_res_t *_res, db_row_t *_r);

#endif /* ROW_H */
