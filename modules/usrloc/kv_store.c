/*
 * generic key-value storage support
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

#include "../../ut.h"

#include "kv_store.h"

int_str_t *kv_get(map_t _store, const str* _key)
{
	int_str_t **val;

	val = (int_str_t **)map_find(_store, *_key);
	if (val)
		return *val;

	return NULL;
}

int_str_t *kv_put(map_t _store, const str* _key, const int_str_t* _val)
{
	int_str_t **cur, *new_val;

	LM_DBG("putting %.*s: [ %.*s  / %d ]\n", _key->len, _key->s,
	        _val->is_str ? _val->s.len : 0, _val->is_str ? _val->s.s : NULL,
	        !_val->is_str ? _val->i : -1);

	cur = (int_str_t **)map_get(_store, *_key);
	if (!cur) {
		LM_ERR("oom\n");
		return NULL;
	}

	if (!*cur) {
		*cur = shm_malloc(sizeof **cur);
		if (!*cur) {
			LM_ERR("oom\n");
			return NULL;
		}
		memset(*cur, 0, sizeof **cur);

	}

	new_val = *cur;

	if (!_val->is_str) {
		if (new_val->is_str) {
			new_val->is_str = 0;
			shm_free(new_val->s.s);
		}

		new_val->i = _val->i;
	} else {
		if (!new_val->is_str) {
			memset(new_val, 0, sizeof *new_val);
			new_val->is_str = 1;
		}

		if (shm_str_extend(&new_val->s, _val->s.len + 1) != 0) {
			LM_ERR("oom\n");
			return NULL;
		}

		memcpy(new_val->s.s, _val->s.s, _val->s.len);
		new_val->s.s[_val->s.len] = '\0';
		new_val->s.len--;
	}

	return new_val;
}

static void destroy_kv_store_val(void* _val)
{
	int_str_t *val = (int_str_t *)_val;

	if (val->is_str && !ZSTR(val->s))
		shm_free(val->s.s);

	shm_free(val);
}

void destroy_store(map_t _store)
{
	map_destroy(_store, destroy_kv_store_val);
}
