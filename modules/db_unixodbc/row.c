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
 *  2006-05-05  passing proper lengths of column data (sgupta)
 */

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../db/db_row.h"
#include "../../db/db_ut.h"
#include "val.h"
#include "row.h"
#include "db_con.h"

/* gradually growing buffer; holds MAX(rows x columns) pointers */
static str *rows;
static int rows_size;

/**
 * duplicate each column in pkg mem
 *
 * row     : index of the given row (0-indexed)
 * columns : total columns in the given row
 */
str *db_unixodbc_dup_row(strn *in, int row, int columns)
{
	int last, i;
	int len;

	i = row * columns + columns;
	if (rows_size < i) {

		if (rows_size == 0)
			rows_size = i;
		else if (rows_size + rows_size >= i)
			rows_size += rows_size;
		else
			rows_size = i;

		rows = pkg_realloc(rows, rows_size * sizeof *rows);
		if (!rows)
			return NULL;
	}

	last = row * columns;
	for (i = 0; i < columns; i++) {
		len = strlen(in[i].s) + 1;

		rows[last + i].s = pkg_malloc(len);
		if (!rows[last + i].s)
			goto out_free;

		memcpy(rows[last + i].s, in[i].s, len);
		rows[last + i].len = len;
	}

	return rows;

out_free:
	for (i = 0; i < last; i++)
		pkg_free(rows[last + i].s);

	pkg_free(rows);
	rows = NULL;
	rows_size = 0;

	return NULL;
}

/*
 * Convert a row from result into db API representation
 */
int db_unixodbc_convert_row(const str *row, const db_res_t *_res, db_row_t *_r)
{
	int i;

	if ((!row) || (!_res) || (!_r)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* Save the number of columns in the ROW structure */
	ROW_N(_r) = RES_COL_N(_res);
	for(i = 0; i < RES_COL_N(_res); i++) {
		if (db_unixodbc_str2val(RES_TYPES(_res)[i], &(ROW_VALUES(_r)[i]),
			row[i].s, row[i].len) < 0) {
			LM_ERR("failed to convert value\n");
			LM_DBG("free row at %p\n", _r);
			db_free_row(_r);
			return -3;
		}
	}

	return 0;
}
