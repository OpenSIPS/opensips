/*
 * Unified NoSQL data abstractions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __CACHEDB_TYPES_H__
#define __CACHEDB_TYPES_H__

#include "../ut.h"
#include "../lib/list.h"
#include "cachedb_dict.h"

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
	CDB_OP_LTE,
	CDB_OP_GT,
	CDB_OP_GTE,
};

/**
 * This macro can be used to initialize a #cdb_key_t structure on the stack
 */
#define CDB_KEY_INITIALIZER \
   {                        \
      STR_NULL,             \
      0,                    \
   }

typedef struct cdb_key {
	str name;
	char is_pk;
} cdb_key_t;

typedef struct cdb_filter {
	cdb_key_t key;
	enum cdb_filter_op op;
	int_str_t val;

	struct cdb_filter *next;
} cdb_filter_t;

typedef struct cdb_val {
	cdb_type_t type;
	union cdb_val_u {
		int32_t i32;
		int64_t i64;
		str st;
		cdb_dict_t dict;
	} val;
} cdb_val_t;

typedef struct cdb_pair {
	cdb_key_t key;
	/* may be used during an update() to refer to a sub-dictionary key */
	str subkey;
	cdb_val_t val;
	/* seconds; may be set during an update(); 0 means "no ttl set" */
	int ttl;
	/* set to 1 during an update() in order to unset the given key */
	char unset;

	struct list_head list;
} cdb_pair_t;

typedef struct {
	cdb_dict_t dict; /* list of cdb_pair_t */

	struct list_head list;
} cdb_row_t;

typedef struct {
	struct list_head rows; /* list of cdb_row_t */
	int count;
} cdb_res_t;

static inline void cdb_key_init(cdb_key_t *key, const char *name)
{
	init_str(&key->name, name);
	key->is_pk = 0;
}

static inline void cdb_pkey_init(cdb_key_t *key, const char *name)
{
	init_str(&key->name, name);
	key->is_pk = 1;
}

static inline cdb_pair_t *cdb_mk_pair(const cdb_key_t *key, const str *subkey)
{
	cdb_pair_t *pair;

	pair = pkg_malloc(sizeof *pair + key->name.len
	                  + (subkey ? subkey->len : 0));
	if (!pair) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(pair, 0, sizeof *pair);

	pair->key.name.s = (char *)(pair + 1);
	str_cpy(&pair->key.name, &key->name);
	pair->key.is_pk = key->is_pk;

	if (subkey) {
		pair->subkey.s = pair->key.name.s + key->name.len;
		str_cpy(&pair->subkey, subkey);
	}

	pair->val.type = CDB_NULL;
	return pair;
}

/*
 * Create a new row filter or append to existing ones. Multiple filters shall
 * only be linked using a logical AND, due to limitations of some backends
 *
 * Returns NULL in case of an error, without touching existing filters
 */
cdb_filter_t *cdb_append_filter(cdb_filter_t *existing, const cdb_key_t *key,
                                enum cdb_filter_op op, const int_str_t *val);
static inline void cdb_free_filters(cdb_filter_t *filters)
{
	pkg_free_all(filters);
}

static inline void cdb_res_init(cdb_res_t *res)
{
	res->count = 0;
	INIT_LIST_HEAD(&res->rows);
}

void cdb_free_rows(cdb_res_t *res);

#endif /* __CACHEDB_TYPES_H__ */
