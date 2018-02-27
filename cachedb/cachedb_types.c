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

static int __dbg_cdb_dict(const cdb_dict_t *dict, str *buf,
                          char **head, int *cur_len)
{
	struct list_head *_, *__;
	cdb_kv_t *pair;
	int needed;
	char *ip;
	int ilen;

	list_for_each_safe (_, __, dict) {
		pair = list_entry(_, cdb_kv_t, list);

		needed = 1 + pair->key.name.len + 1 + pair->subkey.len + 3 + 2;
		if (pkg_str_extend(buf, *cur_len + needed) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
		*head = buf->s + *cur_len;

		if (pair->key.is_pk) {
			**head = '*'; (*head)++;
			*cur_len += 1;
		}
		memcpy(*head, pair->key.name.s, pair->key.name.len);
		*head += pair->key.name.len;
		*cur_len += pair->key.name.len;

		if (pair->subkey.len > 0) {
			**head = '.'; (*head)++;
			*cur_len += 1;
			memcpy(*head, pair->subkey.s, pair->subkey.len);
			*head += pair->subkey.len;
			*cur_len += pair->subkey.len;
		}

		memcpy(*head, " : ", 3);
		*head += 3;
		*cur_len += 3;

		if (pkg_str_extend(buf, *cur_len + 20 + 4 +
		        (pair->val.type == CDB_STR ? pair->val.val.st.len : 0)) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
		*head = buf->s + *cur_len;

		if (pair->val.type == CDB_DICT) {
			memcpy(*head, "{ ", 2); (*head) += 2; *cur_len += 2;
			__dbg_cdb_dict(&pair->val.val.dict, buf, head, cur_len);
			memcpy(*head, " }", 2); (*head) += 2; *cur_len += 2;
			goto next_pair;
		}

		switch (pair->val.type) {
		case CDB_NULL:
			memcpy(*head, "null", 4);
			*head += 4;
			*cur_len += 4;
			break;
		case CDB_INT32:
			ip = int2str(pair->val.val.i32, &ilen);
			memcpy(*head, ip, ilen);
			*head += ilen;
			*cur_len += ilen;
			break;
		case CDB_INT64:
			ip = int2str(pair->val.val.i64, &ilen);
			memcpy(*head, ip, ilen);
			*head += ilen;
			*cur_len += ilen;
			break;
		case CDB_STR:
			**head = '"'; (*head)++; *cur_len += 1;
			memcpy(*head, pair->val.val.st.s, pair->val.val.st.len);
			*head += pair->val.val.st.len;
			*cur_len += pair->val.val.st.len;
			**head = '"'; (*head)++; *cur_len += 1;
			break;
		default:
			LM_ERR("unsupported type: %d\n", pair->val.type);
		}

	next_pair:
		if (__ != dict) {
			memcpy(*head, ", ", 2);
			*head += 2;
			*cur_len += 2;
		}
	}

	return 0;
}

void _dbg_cdb_dict(const char *pre_txt, const cdb_dict_t *dict)
{
	static str static_pkg_buf;
	char *head;
	int final_len = 0;

	if (pkg_str_extend(&static_pkg_buf, 32) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	head = static_pkg_buf.s;

	memcpy(head, "{ ", 2);
	head += 2;
	final_len += 2;

	if (__dbg_cdb_dict(dict, &static_pkg_buf, &head, &final_len) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	if (pkg_str_extend(&static_pkg_buf, final_len + 2) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	memcpy(head, " }", 2);
	final_len += 2;

out:
	LM_DBG("%s%.*s\n", pre_txt, final_len, static_pkg_buf.s);
}

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
		pkg_free(row);
	}

	cdb_res_init(res);
}
