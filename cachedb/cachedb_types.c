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

#include "cachedb_types.h"
#include "../lib/osips_malloc.h"

cdb_filter_t *cdb_append_filter(cdb_filter_t *existing, const cdb_key_t *key,
                                enum cdb_filter_op op, const int_str_t *val)
{
	cdb_filter_t *new;

	new = pkg_malloc(sizeof *new + key->name.len
	                 + (val->is_str ? val->s.len : 0));
	if (!new) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(new, 0, sizeof *new);

	new->key.name.s = (char *)(new + 1);
	str_cpy(&new->key.name, &key->name);

	new->key.is_pk = key->is_pk;
	new->op = op;

	if (val->is_str) {
		new->val.is_str = 1;

		new->val.s.s = (char *)(new + 1) + key->name.len;
		str_cpy(&new->val.s, &val->s);
	} else {
		new->val.i = val->i;
	}

	add_last(new, existing);
	return existing;
}

void cdb_free_rows(cdb_res_t *res)
{
	struct list_head *_, *__;
	cdb_row_t *row;

	if (!res)
		return;

	list_for_each_safe (_, __, &res->rows) {
		row = list_entry(_, cdb_row_t, list);
		list_del(&row->list);
		cdb_free_entries(&row->dict, osips_pkg_free);
		pkg_free(row);
	}

	cdb_res_init(res);
}
