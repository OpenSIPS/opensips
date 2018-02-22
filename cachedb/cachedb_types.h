/*
 * Common NoSQL data abstractions
 *
 * Copyright (C) 2018 OpenSIPS Solutions
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

#ifndef __CACHEDB_TYPES_H__
#define __CACHEDB_TYPES_H__

#include "../ut.h"
#include "../lib/list.h"

typedef enum {
	CDB_INT32, /* signed */
	CDB_INT64, /* signed */
	CDB_STR,
	CDB_DICT,
	CDB_NULL,
} cdb_type_t;

enum cdb_filter_op {
	CDB_OP_EQ,
	CDB_OP_LT,
	CDB_OP_LE,
	CDB_OP_GT,
	CDB_OP_GE,
};

typedef struct {
	str *key;
	str *subkey; /* used to refer to sub-dictionary keys within a row */
} cdb_key_t;

typedef struct _cdb_filter_t {
	str key;
	enum cdb_filter_op op;
	int_str_t val;

	struct _cdb_filter_t *next;
} cdb_filter_t;

typedef struct list_head cdb_dict_t; /* list of cdb_kv_t */

typedef struct {
	cdb_type_t type;
	union cdb_val_u {
		int32_t i32;
		int64_t i64;
		str st;
		cdb_dict_t dict;
	} val;
} cdb_val_t;

typedef struct {
	str key;
	cdb_val_t val;

	struct list_head list;
} cdb_kv_t;

typedef struct {
	cdb_dict_t dict;

	struct list_head list;
} cdb_row_t;

typedef struct {
	struct list_head rows; /* list of cdb_row_t */
	int count;
} cdb_res_t;

static inline void cdb_res_init(cdb_res_t *res)
{
	res->count = 0;
	INIT_LIST_HEAD(&res->rows);
}

void cdb_free_entries(cdb_dict_t *dict);
void cdb_free_rows(cdb_res_t *res);

#endif /* __CACHEDB_TYPES_H__ */
