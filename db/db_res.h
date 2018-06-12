/* 
 * $Id$ 
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


#ifndef DB_RES_H
#define DB_RES_H

#include "db_row.h"
#include "db_key.h"
#include "db_val.h"
#include "db_con.h"


struct db_row;


typedef struct db_res {
	struct {
		db_key_t* names;   /* Column names */
		db_type_t* types;  /* Column types */
		int n;             /* Number of columns */
	} col;
	struct db_row* rows;       /* Rows */
	int n;                     /* Number of rows */
} db_res_t;


#define RES_NAMES(re) ((re)->col.names)
#define RES_TYPES(re) ((re)->col.types)
#define RES_COL_N(re) ((re)->col.n)
#define RES_ROWS(re)  ((re)->rows)
#define RES_ROW_N(re) ((re)->n)


/*
 * Create a new result structure 
 */
db_res_t* new_result(void);


/*
 * Fill the structure with data from database
 */
int convert_result(db_con_t* _h, db_res_t* _r);


/*
 * Free all memory allocated by the structure
 */
int free_result(db_res_t* _r);


#endif /* DB_RES_H */
