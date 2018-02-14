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

#ifndef __CACHEDB_DATA_H__
#define __CACHEDB_DATA_H__

#include "../ut.h"
#include "../lib/list.h"

typedef enum {
	CDB_INT, /* signed, 32-bit integer */
	CDB_STR,
	CDB_DICT,
	CDB_NULL,
} cdb_type_t;

enum cdb_filter_ops {
	CDB_OP_LT,
	CDB_OP_GT,
};

typedef struct {
	str *key;
	str *subkey; /* used to refer to sub-dictionary keys within a row */
} cdb_key_t;

typedef struct {
	enum cdb_filter_ops op;
	int val;
} cdb_filter_t;

struct cdb_dict;

typedef struct {
	cdb_type_t type;
	int nul;
	union {
		int int_val;
		str str_val;
		struct cdb_dict *dict_val;
	};
} cdb_val_t;

typedef struct cdb_dict {
	str key;
	cdb_val_t val;

	struct cdb_dict *next;
} cdb_dict_t;

typedef struct {
	cdb_dict_t row;

	struct list_head list;
} cdb_res_t;

#endif /* __CACHEDB_DATA_H__ */
