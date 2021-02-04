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

#include "../../lib/cJSON.h"
#include "../../lib/osips_malloc.h"

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

#ifdef EXTRA_DEBUG
	LM_DBG("putting '%.*s': [ '%.*s' / %d ]\n", _key->len, _key->s,
	        _val->is_str ? _val->s.len : 0, _val->is_str ? _val->s.s : NULL,
	        !_val->is_str ? _val->i : -1);
#endif

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
		new_val->s.len = _val->s.len;
	}

	return new_val;
}

void kv_del(map_t _store, const str* _key)
{
	int_str_t *val;

	val = (int_str_t *)map_remove(_store, *_key);
	if (!val)
		return;

	if (val->is_str)
		shm_free(val->s.s);
}

static int push_kv_to_json(void *param, str key, void *value)
{
	cJSON *flat_map = (cJSON *)param, *val_json;
	int_str_t *val = (int_str_t *)value;

	if (!val->is_str)
		val_json = cJSON_CreateNumber(val->i);
	else
		val_json = cJSON_CreateStr(val->s.s, val->s.len);

	if (!val_json) {
		LM_ERR("oom\n");
		return -1;
	}

	_cJSON_AddItemToObject(flat_map, &key, val_json);

	return 0;
}

static cJSON_Hooks shm_hooks = {
	.malloc_fn = osips_shm_malloc,
	.free_fn   = osips_shm_free,
};

str store_serialize(map_t _store)
{
	cJSON *flat_map;
	str ret = STR_NULL;

	if (map_size(_store) == 0)
		return ret;

	cJSON_InitHooks(&shm_hooks);

	flat_map = cJSON_CreateObject();
	if (!flat_map) {
		LM_ERR("oom\n");
		return ret;
	}

	if (map_for_each(_store, push_kv_to_json, flat_map) != 0)
		LM_ERR("oom - serialized map is incomplete!\n");

	ret.s = cJSON_PrintUnformatted(flat_map);
	if (!ret.s) {
		LM_ERR("oom\n");
		goto out;
	}
	ret.len = strlen(ret.s);

out:
	cJSON_Delete(flat_map);
	cJSON_InitHooks(NULL);
	return ret;
}

void store_free_buffer(str *serialized)
{
	if (serialized->s) {
		cJSON_InitHooks(&shm_hooks);
		cJSON_PurgeString(serialized->s);
		cJSON_InitHooks(NULL);
	}
}

map_t store_deserialize(const str *input)
{
	map_t map;
	cJSON *json_map, *obj;
	str key;
	int_str_t value;

	map = map_create(AVLMAP_SHARED);
	if (!map) {
		LM_ERR("oom\n");
		return NULL;
	}

	cJSON_InitHooks(&shm_hooks);

	json_map = cJSON_Parse(input->s);
	if (!json_map) {
		LM_ERR("bad JSON input or oom\n");
		goto out;
	}

	if (json_map->type != cJSON_Object) {
		LM_BUG("non-cJSON_Object kv_store col type (%d)", json_map->type);
		goto out;
	}

	for (obj = json_map->child; obj; obj = obj->next) {
		init_str(&key, obj->string);

		switch (obj->type) {
		case cJSON_String:
			value.is_str = 1;
			init_str(&value.s, obj->valuestring);
			break;
		case cJSON_Number:
			value.is_str = 0;
			value.i = obj->valueint;
			break;
		default:
			LM_BUG("unknown obj type (%d)", obj->type);
			continue;
		}

		if (!kv_put(map, &key, &value))
			LM_ERR("oom, map will be incomplete\n");
	}

out:
	cJSON_Delete(json_map);
	cJSON_InitHooks(NULL);
	return map;
}

static void destroy_kv_store_val(void* _val)
{
	int_str_t *val = (int_str_t *)_val;

	if (val->is_str && val->s.s)
		shm_free(val->s.s);

	shm_free(val);
}

void store_destroy(map_t _store)
{
	if (_store)
		map_destroy(_store, destroy_kv_store_val);
}
