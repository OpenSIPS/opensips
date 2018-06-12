/*
 *
 * DBText library
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * DBText library
 *   
 * 2003-02-05 created by Daniel
 * 
 */

#include <string.h>

#include "../../str.h"
#include "../../mem/mem.h"

#include "dbt_res.h"
#include "dbt_api.h"

/*
 * Release memory used by columns
 */
int free_columns(db_res_t* _r)
{
	if (!_r) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:free_columns: Invalid parameter\n");
#endif
		return -1;
	}
	if (RES_NAMES(_r)) 
		pkg_free(RES_NAMES(_r));
	if (RES_TYPES(_r)) 
		pkg_free(RES_TYPES(_r));
	return 0;
}

/*
 * Release memory used by row
 */
int free_row(db_row_t* _r)
{
	if (!_r) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:free_row: Invalid parameter value\n");
#endif
		return -1;
	}
	if(ROW_VALUES(_r))
		pkg_free(ROW_VALUES(_r));
	return 0;
}

/*
 * Release memory used by rows
 */
int free_rows(db_res_t* _r)
{
	int i;
	if (!_r) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:free_rows: Invalid parameter value\n");
#endif
		return -1;
	}
	if (RES_ROWS(_r))
	{
		for(i = 0; i < RES_ROW_N(_r); i++) 
		{
			free_row(&(RES_ROWS(_r)[i]));
		}
		pkg_free(RES_ROWS(_r));
	}
	return 0;
}

/*
 * Release memory used by a result structure
 */
int free_result(db_res_t* _r)
{
	if (!_r) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:free_result: Invalid parameter\n");
#endif
		return -1;
	}
	free_columns(_r);
	free_rows(_r);
	pkg_free(_r);
	return 0;
}


int use_table(db_con_t* _h, const char* _t)
{
	char* ptr;
	int l;
			
	if ((!_h) || (!_t))
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:use_table: Invalid parameter value\n");
#endif
		return -1;
	}

	l = strlen(_t) + 1;
	ptr = (char*)pkg_malloc(l);
	if (!ptr) 
	{
		LOG(L_ERR, "DBT:use_table: No memory left\n");
		return -2;
	}
	memcpy(ptr, _t, l);

	if (CON_TABLE(_h))
		pkg_free(CON_TABLE(_h));
	CON_TABLE(_h) = ptr;
	return 0;
}

/*
 * Create a new result structure and initialize it
 */
db_res_t* new_result(void)
{
	db_res_t* r;
	r = (db_res_t*)pkg_malloc(sizeof(db_res_t));
	if (!r) {
		LOG(L_ERR, "new_result(): No memory left\n");
		return 0;
	}
	RES_NAMES(r) = 0;
	RES_TYPES(r) = 0;
	RES_COL_N(r) = 0;
	RES_ROWS(r) = 0;
	RES_ROW_N(r) = 0;
	return r;
}


/*
 * Retrieve result set
 */
int get_result(db_con_t* _h, db_res_t** _r)
{
	if ((!_h) || (!_r)) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:get_result: Invalid parameter value\n");
#endif
		return -1;
	}

	if (!DBT_CON_RESULT(_h))
	{
		LOG(L_ERR, "DBT:get_result: error getting result\n");
		*_r = 0;
		return -3;
	}

	*_r = new_result();
	if (*_r == 0) 
	{
		LOG(L_ERR, "DBT:get_result: No memory left\n");
		return -2;
	}

	if (convert_result(_h, *_r) < 0) 
	{
		LOG(L_ERR, "DBT:get_result: Error while converting result\n");
		pkg_free(*_r);
		return -4;
	}
	
	return 0;
}

/*
 * Fill the structure with data from database
 */
int convert_result(db_con_t* _h, db_res_t* _r)
{
	if ((!_h) || (!_r)) {
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:convert_result: Invalid parameter\n");
#endif
		return -1;
	}
	if (get_columns(_h, _r) < 0) {
		LOG(L_ERR, "DBT:convert_result: Error while getting column names\n");
		return -2;
	}

	if (convert_rows(_h, _r) < 0) {
		LOG(L_ERR, "DBT:convert_result: Error while converting rows\n");
		free_columns(_r);
		return -3;
	}
	return 0;
}

/*
 * Get and convert columns from a result
 */
int get_columns(db_con_t* _h, db_res_t* _r)
{
	int n, i;
	
	if ((!_h) || (!_r)) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:get_columns: Invalid parameter\n");
#endif
		return -1;
	}
	
	n = DBT_CON_RESULT(_h)->nrcols;
	if (!n) 
	{
		LOG(L_ERR, "DBT:get_columns: No columns\n");
		return -2;
	}
	
	RES_NAMES(_r) = (db_key_t*)pkg_malloc(sizeof(db_key_t) * n);
	if (!RES_NAMES(_r)) 
	{
		LOG(L_ERR, "DBT:get_columns: No memory left\n");
		return -3;
	}

	RES_TYPES(_r) = (db_type_t*)pkg_malloc(sizeof(db_type_t) * n);
	if (!RES_TYPES(_r)) 
	{
		LOG(L_ERR, "DBT:get_columns: No memory left\n");
		pkg_free(RES_NAMES(_r));
		return -4;
	}

	RES_COL_N(_r) = n;

	for(i = 0; i < n; i++) 
	{
		RES_NAMES(_r)[i] = DBT_CON_RESULT(_h)->colv[i].name.s;
		switch( DBT_CON_RESULT(_h)->colv[i].type) 
		{
			case DB_INT:
			case DB_DATETIME:
				RES_TYPES(_r)[i] = DB_INT;
			break;

			case DB_DOUBLE:
				RES_TYPES(_r)[i] = DB_DOUBLE;
			break;

			default:
				RES_TYPES(_r)[i] = DB_STR;
			break;
		}		
	}
	return 0;
}

/*
 * Convert rows from internal to db API representation
 */
int convert_rows(db_con_t* _h, db_res_t* _r)
{
	int n, i;
	dbt_row_p _rp = NULL;
	if ((!_h) || (!_r)) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:convert_rows: Invalid parameter\n");
#endif
		return -1;
	}
	n = DBT_CON_RESULT(_h)->nrrows;
	RES_ROW_N(_r) = n;
	if (!n) 
	{
		RES_ROWS(_r) = 0;
		return 0;
	}
	RES_ROWS(_r) = (struct db_row*)pkg_malloc(sizeof(db_row_t) * n);
	if (!RES_ROWS(_r)) 
	{
		LOG(L_ERR, "DBT:convert_rows: No memory left\n");
		return -2;
	}
	i = 0;
	_rp = DBT_CON_RESULT(_h)->rows;
	while(_rp)
	{
		DBT_CON_ROW(_h) = _rp;
		if (!DBT_CON_ROW(_h)) 
		{
			LOG(L_ERR, "DBT:convert_rows: error getting current row\n");
			RES_ROW_N(_r) = i;
			free_rows(_r);
			return -3;
		}
		if (convert_row(_h, _r, &(RES_ROWS(_r)[i])) < 0) 
		{
			LOG(L_ERR, "DBT:convert_rows: Error while converting row #%d\n", i);
			RES_ROW_N(_r) = i;
			free_rows(_r);
			return -4;
		}
		i++;
		_rp = _rp->next;
	}
	return 0;
}

/*
 * Convert a row from result into db API representation
 */
int convert_row(db_con_t* _h, db_res_t* _res, db_row_t* _r)
{
	int i;
	if ((!_h) || (!_r) || (!_res)) 
	{
#ifdef DBT_EXTRA_DEBUG
		LOG(L_ERR, "DBT:convert_row: Invalid parameter value\n");
#endif
		return -1;
	}

	ROW_VALUES(_r) = (db_val_t*)pkg_malloc(sizeof(db_val_t) * RES_COL_N(_res));
	ROW_N(_r) = RES_COL_N(_res);
	if (!ROW_VALUES(_r)) 
	{
		LOG(L_ERR, "DBT:convert_row: No memory left\n");
		return -1;
	}

	for(i = 0; i < RES_COL_N(_res); i++) 
	{
		(ROW_VALUES(_r)[i]).nul = DBT_CON_ROW(_h)->fields[i].nul;
		switch(RES_TYPES(_res)[i])
		{
			case DB_INT:
				VAL_INT(&(ROW_VALUES(_r)[i])) = 
						DBT_CON_ROW(_h)->fields[i].val.int_val;
				VAL_TYPE(&(ROW_VALUES(_r)[i])) = DB_INT;
			break;
	
			case DB_DOUBLE:
				VAL_DOUBLE(&(ROW_VALUES(_r)[i])) = 
						DBT_CON_ROW(_h)->fields[i].val.double_val;
				VAL_TYPE(&(ROW_VALUES(_r)[i])) = DB_DOUBLE;
			break;
	
			case DB_STRING:
				VAL_STR(&(ROW_VALUES(_r)[i])).s = 
						DBT_CON_ROW(_h)->fields[i].val.str_val.s;
				VAL_STR(&(ROW_VALUES(_r)[i])).len =
						DBT_CON_ROW(_h)->fields[i].val.str_val.len;
				VAL_TYPE(&(ROW_VALUES(_r)[i])) = DB_STR;
			break;
	
			case DB_STR:
				VAL_STR(&(ROW_VALUES(_r)[i])).s = 
						DBT_CON_ROW(_h)->fields[i].val.str_val.s;
				VAL_STR(&(ROW_VALUES(_r)[i])).len =
						DBT_CON_ROW(_h)->fields[i].val.str_val.len;
				VAL_TYPE(&(ROW_VALUES(_r)[i])) = DB_STR;
			break;

			case DB_DATETIME:
				VAL_INT(&(ROW_VALUES(_r)[i])) = 
						DBT_CON_ROW(_h)->fields[i].val.int_val;
				VAL_TYPE(&(ROW_VALUES(_r)[i])) = DB_INT;
			break;

			case DB_BLOB:
				VAL_STR(&(ROW_VALUES(_r)[i])).s =
						DBT_CON_ROW(_h)->fields[i].val.str_val.s;
				VAL_STR(&(ROW_VALUES(_r)[i])).len =
						DBT_CON_ROW(_h)->fields[i].val.str_val.len;
				VAL_TYPE(&(ROW_VALUES(_r)[i])) = DB_STR;
			break;
		}
	}
	return 0;
}


