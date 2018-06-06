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
 *  2015-02-18  initial version (Ionut Ionita)
*/

#include "../../dprint.h"
#include "../../db/db_ut.h"
#include "../../db/db_query.h"
#include "val.h"
#include "my_con.h"

#include <string.h>
#include <stdio.h>

/*
 * Used when converting values to be used in a DB query
 */
int db_sqlite_val2str(const db_con_t* _c, const db_val_t* _v, char* _s, int* _len)
{
	int l;

	if (!_c || !_v || !_s || !_len || !*_len) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (VAL_NULL(_v)) {
		if (*_len < sizeof("NULL")) {
			LM_ERR("buffer too small\n");
			return -1;
		}
		*_len = snprintf(_s, *_len, "NULL");
		return 0;
	}

	switch(VAL_TYPE(_v)) {
	case DB_INT:
		if (db_int2str(VAL_INT(_v), _s, _len) < 0) {
			LM_ERR("error while converting string to int\n");
			return -2;
		} else {
			return 0;
		}
		break;

	case DB_BIGINT:
		if (db_bigint2str(VAL_BIGINT(_v), _s, _len) < 0) {
			LM_ERR("error while converting bigint to string\n");
			return -2;
		} else {
			return 0;
		}
		break;


	case DB_BITMAP:
		if (db_int2str(VAL_BITMAP(_v), _s, _len) < 0) {
			LM_ERR("error while converting string to int\n");
			return -3;
		} else {
			return 0;
		}
		break;

	case DB_DOUBLE:
		if (db_double2str(VAL_DOUBLE(_v), _s, _len) < 0) {
			LM_ERR("error while converting string to double\n");
			return -4;
		} else {
			return 0;
		}
		break;

	case DB_STRING:
		l = strlen(VAL_STRING(_v));
		if (*_len < l )
		{
			LM_ERR("destination STRING buffer too short (have %d, need %d)\n",
			       *_len, l);
			return -4;
		}
		else
		{
			sqlite3_snprintf(SQL_BUF_LEN, _s, "'%q'",
						VAL_STRING(_v));
			*_len = strlen(_s);
			_s += strlen(_s);

			return 0;
		}
		break;

	case DB_STR:
		l = VAL_STR(_v).len;
		if (*_len < l)
		{
			LM_ERR("destination STR buffer too short (have %d, need %d)\n",
			       *_len, l);
			return -5;
		}
		else
		{
			sqlite3_snprintf(SQL_BUF_LEN, _s, "'%.*q'",
						VAL_STR(_v).len, VAL_STR(_v).s);
			*_len = strlen(_s);
			_s += strlen(_s);

			return 0;
		}
		break;

	case DB_DATETIME:
		if (db_time2str(VAL_TIME(_v), _s, _len) < 0) {
			LM_ERR("error while converting string to time_t\n");
			return -7;
		} else {
			return 0;
		}
		break;

	case DB_BLOB:
		l = VAL_BLOB(_v).len;
		if (*_len < l)
		{
			LM_ERR("destination BLOB buffer too short (have %d, need %d)\n",
			       *_len, l);
			return -7;
		}
		else
		{
			sqlite3_snprintf(SQL_BUF_LEN, _s, "'%.*q'",
						VAL_BLOB(_v).len, VAL_BLOB(_v).s);
			*_len = strlen(_s);
			_s += strlen(_s);

			return 0;
		}
		break;

	default:
		LM_DBG("unknown data type\n");
		return -9;
	}
}
