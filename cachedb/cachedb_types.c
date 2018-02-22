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

#include "cachedb_types.h"

void cdb_free_entries(cdb_dict_t *dict)
{
	struct list_head *_, *__;
	cdb_kv_t *kv;

	list_for_each_safe(_, __, dict) {
		kv = list_entry(_, cdb_kv_t, list);

		switch (kv->val.type) {
		case CDB_DICT:
			cdb_free_entries(&kv->val.val.dict);
			break;
		case CDB_STR:
			pkg_free(kv->val.val.st.s);
			break;
		default:
			break;
		}

		list_del(&kv->list);

		/* TODO: is it ok to impose alloc linearization like this? */
		pkg_free(kv);
	}
}

void cdb_free_rows(cdb_res_t *res)
{
	struct list_head *_, *__;
	cdb_row_t *row;

	if (!res)
		return;

	list_for_each_safe(_, __, &res->rows) {
		row = list_entry(_, cdb_row_t, list);
		list_del(&row->list);
		cdb_free_entries(&row->dict);
	}

	cdb_res_init(res);
}
