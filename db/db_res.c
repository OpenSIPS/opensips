/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2007-2008 1&1 Internet AG
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
 */

/**
 * \file db/db_res.c
 * \brief Functions to manage result structures
 *
 * Provides some convenience macros and some memory management
 * functions for result structures.
 */

#include "db_res.h"

#include "db_row.h"
#include "../dprint.h"
#include "../mem/mem.h"

#include <string.h>

/*
 * Release memory used by rows
 */
int db_free_rows(db_res_t* _r)
{
	int i;

	if (!_r) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	LM_DBG("freeing %d rows\n", RES_ROW_N(_r));

	if (RES_ROWS(_r)) {
		for(i = 0; i < RES_ROW_N(_r); i++)
			db_free_row(&(RES_ROWS(_r)[i]));

		LM_DBG("freeing rows at %p\n", RES_ROWS(_r));
		pkg_free(RES_ROWS(_r));
		RES_ROWS(_r) = NULL;
	}

	RES_ROW_N(_r) = 0;

	return 0;
}


/*
 * Release memory used by columns
 */
int db_free_columns(db_res_t* _r)
{
	if (!_r) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	/* free names and types */
	if (RES_NAMES(_r)) {
		LM_DBG("freeing result columns at %p\n", RES_NAMES(_r));
		RES_TYPES(_r) = NULL;
		pkg_free(RES_NAMES(_r));
		RES_NAMES(_r) = NULL;
	}
	return 0;
}

/*
 * Create a new result structure and initialize it
 */
db_res_t* db_new_result(void)
{
	db_res_t* r;

	r = (db_res_t*)pkg_malloc(sizeof(db_res_t));
	if (!r) {
		LM_ERR("no private memory left\n");
		return 0;
	}
	LM_DBG("allocate %d bytes for result set at %p\n",
		(int)sizeof(db_res_t), r);
	memset(r, 0, sizeof(db_res_t));
	return r;
}

/*
 * Release memory used by a result structure
 */
int db_free_result(db_res_t* _r)
{
	if (!_r)
	{
		LM_ERR("invalid parameter\n");
		return -1;
	}

	db_free_columns(_r);
	db_free_rows(_r);
	LM_DBG("freeing result set at %p\n", _r);
	pkg_free(_r);
	return 0;
}

/*
 * Allocate storage for column names and type in existing
 * result structure.
 */
int db_allocate_columns(db_res_t* _r, const unsigned int cols)
{
	unsigned int i;

	RES_NAMES(_r) = (db_key_t*)pkg_malloc
		( cols * (sizeof(db_key_t)+sizeof(db_type_t)+sizeof(str)) );
	if (!RES_NAMES(_r)) {
		LM_ERR("no private memory left\n");
		return -1;
	}
	LM_DBG("allocate %d bytes for result columns at %p\n",
		(int)(cols * (sizeof(db_key_t)+sizeof(db_type_t)+sizeof(str))),
		RES_NAMES(_r));

	for ( i=0 ; i<cols ; i++)
		RES_NAMES(_r)[i] = (str*)(RES_NAMES(_r)+cols)+i;

	RES_TYPES(_r) = (db_type_t*)(RES_NAMES(_r)[0]+cols);

	return 0;
}

/*
 * Allocate storage for rows in existing
 * result structure.
 */
int db_allocate_rows(db_res_t* _res, const unsigned int rows)
{
	unsigned int i;

	RES_ROWS(_res) = (struct db_row*)pkg_malloc
		(rows * (sizeof(db_row_t) + sizeof(db_val_t) * RES_COL_N(_res)) );
	if (!RES_ROWS(_res)) {
		LM_ERR("no memory left\n");
		return -1;
	}
	memset( RES_ROWS(_res), 0 ,
		rows * (sizeof(db_row_t) + sizeof(db_val_t) * RES_COL_N(_res)));

	LM_DBG("allocate %d bytes for result rows and values at %p\n",
		(int)(rows * (sizeof(db_row_t) + sizeof(db_val_t) * RES_COL_N(_res))),
		RES_ROWS(_res));

	for( i=0 ; i<rows ; i++ )
		/* the values of the row i */
		ROW_VALUES( &(RES_ROWS(_res)[i]) ) =
			((db_val_t*)(RES_ROWS(_res)+rows)) + RES_COL_N(_res)*i;

	return 0;
}

/*
 * Extend storage for rows in existing result structure.
 */
int db_realloc_rows(db_res_t *_res, const unsigned int old_rows,
                    const unsigned int rows)
{
	unsigned int i;
	struct db_row *old_buf;

	old_buf = RES_ROWS(_res);

	RES_ROWS(_res) = pkg_malloc(rows * (sizeof(db_row_t) +
	                                    sizeof(db_val_t) * RES_COL_N(_res)) );
	if (!RES_ROWS(_res)) {
		RES_ROWS(_res) = old_buf;
		LM_ERR("no memory left\n");
		return -1;
	}

	memset(RES_ROWS(_res), 0,
	       rows * (sizeof(db_row_t) + sizeof(db_val_t) * RES_COL_N(_res)));

	memcpy(RES_ROWS(_res), old_buf, old_rows * sizeof(db_row_t));
	memcpy(RES_ROWS(_res) + rows,
	       (char *)old_buf + old_rows * sizeof(db_row_t),
	       old_rows * (sizeof(db_val_t) * RES_COL_N(_res)));

	pkg_free(old_buf);

	LM_DBG("allocate %d bytes for result rows and values at %p\n",
		(int)(rows * (sizeof(db_row_t) + sizeof(db_val_t) * RES_COL_N(_res))),
		RES_ROWS(_res));

	for( i=0 ; i<rows ; i++ )
		/* the values of the row i */
		ROW_VALUES( &(RES_ROWS(_res)[i]) ) =
			((db_val_t*)(RES_ROWS(_res)+rows)) + RES_COL_N(_res)*i;

	return 0;
}
