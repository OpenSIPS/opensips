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

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../db/db_row.h"
#include "../../db/db_ut.h"
#include "../../db/db_val.h"
#include "../../db/db_row.h"
#include "my_con.h"
#include "val.h"
#include "row.h"

#define DB_UNDEFINED 1024

/**
 * Convert a row from result into db API representation
 */
int db_sqlite_convert_row(const db_con_t* _h, db_res_t* _res, db_row_t* _r)
{
	int col,len;
	db_val_t* _v;
	const char* db_value;

	if ((!_h) || (!_res) || (!_r)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (!CON_SQLITE_PS(_h)) {
		LM_ERR("conn has no prepared statement! sqlite requires one\n");
		return -1;
	}

	/* Save the number of columns in the ROW structure */
	ROW_N(_r) = RES_COL_N(_res);

	for(col=0; col < RES_COL_N(_res); col++) {
		_v = &(ROW_VALUES(_r)[col]);

		if (sqlite3_column_type(CON_SQLITE_PS(_h), col) == SQLITE_NULL) {
			VAL_NULL(_v) = 1;
			VAL_TYPE(_v) = RES_TYPES(_res)[col];
			continue;
		}

		switch (RES_TYPES(_res)[col]) {
			case DB_BITMAP:
				/* value considered to be int; but stored as bigint;
				 * can be used as VAL_INT() to be called
				 * also can be used as VAL_BIGINT() */
				VAL_BIGINT(_v) = sqlite3_column_int64(CON_SQLITE_PS(_h), col);
				VAL_TYPE(_v) = DB_INT;

				break;
			case DB_INT:
				VAL_BIGINT(_v) =sqlite3_column_int64(CON_SQLITE_PS(_h), col);
				VAL_TYPE(_v) = DB_INT;

				break;
			case DB_BIGINT:
				VAL_BIGINT(_v) = sqlite3_column_int64(CON_SQLITE_PS(_h), col);
				VAL_TYPE(_v) = DB_BIGINT;

				break;
			case DB_DATETIME:
				db_value = (char *)sqlite3_column_text(CON_SQLITE_PS(_h), col);
				if (db_str2time(db_value, &VAL_TIME(_v)) < 0) {
					LM_ERR("error while converting datetime value from string\n");
					return -1;
				}
				VAL_TYPE(_v) = DB_DATETIME;
				break;
			case DB_DOUBLE:
				VAL_DOUBLE(_v) = sqlite3_column_double(CON_SQLITE_PS(_h), col);
				VAL_TYPE(_v) = DB_DOUBLE;

				break;
			case DB_BLOB:
				VAL_BLOB(_v).len = sqlite3_column_bytes(CON_SQLITE_PS(_h), col);
				db_value = sqlite3_column_blob(CON_SQLITE_PS(_h), col);

				VAL_BLOB(_v).s = pkg_malloc(VAL_BLOB(_v).len+1);
				if (VAL_BLOB(_v).s == NULL) {
					LM_ERR("no more pkg mem!\n");
					return -1;
				}
				memcpy(VAL_BLOB(_v).s, db_value, VAL_BLOB(_v).len);

				VAL_BLOB(_v).s[VAL_BLOB(_v).len]='\0';
				VAL_TYPE(_v) = DB_BLOB;
				VAL_FREE(_v) = 1;

				break;
			case DB_STRING:
				len = sqlite3_column_bytes(CON_SQLITE_PS(_h), col);
				db_value = (char *)sqlite3_column_text(CON_SQLITE_PS(_h), col);

				if ((VAL_STRING(_v) = pkg_malloc(len+1)) == NULL) {
					LM_ERR("no more pkg mem!\n");
					return -1;
				}
				memcpy((char*)VAL_STRING(_v), db_value, len+1);

				VAL_TYPE(_v) = DB_STRING;
				VAL_FREE(_v) = 1;

				break;
			default:
				LM_ERR("invalid type for sqlite!\n");
				return -1;
		}
	}
	return 0;
}
