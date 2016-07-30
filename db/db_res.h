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
 * \file db/db_res.h
 * \brief Data structure that represents a result from a query.
 *
 * Data structure that represents a result from a database query,
 * it also provides some convenience macros and some memory management
 * functions for result structures.
 */

#ifndef DB_RES_H
#define DB_RES_H


#include "db_key.h"
#include "db_val.h"

struct db_row;

/**
 * This type represents a result returned by db_query function (see below). The
 * result can consist of zero or more rows (see db_row_t description).
 *
 * Note: A variable of type db_res_t returned by db_query function uses dynamicaly
 * allocated memory, don't forget to call db_free_result if you don't need the
 * variable anymore. You will encounter memory leaks if you fail to do this!
 *
 * In addition to zero or more rows, each db_res_t object contains also an array
 * of db_key_t objects. The objects represent keys (names of columns). *
 */
typedef struct db_res {
	struct {
		db_key_t* names;   /**< Column names                    */
		db_type_t* types;  /**< Column types                    */
		int n;             /**< Number of columns               */
	} col;
	struct db_row* rows;   /**< Rows                            */
	int n;                 /**< Number of rows in current fetch */
	int res_rows;          /**< Number of total rows in query   */
	int last_row;          /**< Last row                        */
} db_res_t;


/** Return the column names */
#define RES_NAMES(re) ((re)->col.names)
/** Return the column types */
#define RES_TYPES(re) ((re)->col.types)
/** Return the number of columns */
#define RES_COL_N(re) ((re)->col.n)
/** Return the result rows */
#define RES_ROWS(re)  ((re)->rows)
/** Return the number of current result rows */
#define RES_ROW_N(re) ((re)->n)
/** Return the last row of the result */
#define RES_LAST_ROW(re)  ((re)->last_row)
/** Return the number of total result rows */
#define RES_NUM_ROWS(re) ((re)->res_rows)


/**
 * Release memory used by rows in a result structure.
 * \param _r the result that should be released
 * \return zero on success, negative on errors
 */
int db_free_rows(db_res_t* _r);


/**
 * Release memory used by columns. This methods assumes that the string values
 * holding the column names are in memory allocated from the database driver,
 * and thus must be not freed here.
 * \param _r the result that should be released
 * \return zero on success, negative on errors
 */
int db_free_columns(db_res_t* _r);


/**
 * Create a new result structure and initialize it.
 * \return a pointer to the new result on success, NULL on errors
 */
db_res_t* db_new_result(void);

/**
 * Release memory used by a result structure.
 * \return zero on success, negative on errors
 */
int db_free_result(db_res_t* _r);

/**
 * Allocate storage for column names and type in existing result structure.
 * If no more memory is available for the allocation of the types then the
 * already allocated memory for the names is freed.
 * \param _r filled result set
 * \param cols number of columns
 * \return zero on success, negative on errors
 */
int db_allocate_columns(db_res_t* _r, const unsigned int cols);


int db_allocate_rows(db_res_t* _res, const unsigned int rows);

#endif /* DB_RES_H */
