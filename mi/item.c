/*
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../dprint.h"
#include "item.h"
#include "fmt.h"

static cJSON_Hooks sys_mem_hooks = {
	.malloc_fn = malloc,
	.free_fn   = free,
};
static cJSON_Hooks shm_mem_hooks = {
	.malloc_fn = osips_shm_malloc,
	.free_fn   = osips_shm_free,
};

static mi_response_t *_init_mi_result(mi_item_t **item_out, int type, int ival,
										const char *sval, int sval_len)
{
	mi_response_t *res = NULL;
	mi_item_t *jsonrpc_vers;

	cJSON_InitHooks(sys_mem_hooks);

	res = cJSON_CreateObject();
	if (!res)
		goto out;

	jsonrpc_vers = cJSON_CreateString(JSON_RPC_VERS_S);
	if (!jsonrpc_vers)
		goto error;
	cJSON_AddItemToObject(res, JSON_RPC_JSONRPC_S, *jsonrpc_vers);

	switch (type) {
	case cJSON_Array:
		*item_out = cJSON_CreateArray();
		break;
	case cJSON_Object:
		*item_out = cJSON_CreateObject();
		break;
	case cJSON_String:
		*item_out = cJSON_CreateStr(sval, sval_len);
		break;
	case cJSON_Number:
		*item_out = cJSON_CreateNumber(ival);
		break;
	case cJSON_True:
		*item_out = cJSON_CreateTrue();
		break;
	case cJSON_False:
		*item_out = cJSON_CreateFalse();
		break;
	case cJSON_NULL:
		*item_out = cJSON_CreateNull();
		break;
	default:
		*item_out = NULL;
		LM_BUG("Unknown MI item type: %d\n", type);
		goto out;
	}
	if (!*item_out)
		goto error;

	cJSON_AddItemToObject(res, JSON_RPC_RESULT_S, *item_out);

	cJSON_InitHooks(NULL);
	return res;

error:
	if (res)
		cJSON_Delete(res);
	cJSON_InitHooks(NULL);
	return NULL;
}


mi_response_t *init_mi_result_array(mi_item_t **arr_out)
{
	return _init_mi_result(arr_out, cJSON_Array, 0, NULL, 0);
}

mi_response_t *init_mi_result_object(mi_item_t **obj_out)
{
	return _init_mi_result(arr_out, cJSON_Object, 0, NULL, 0);
}

mi_response_t *init_mi_result_string(const char *value, int value_len)
{
	mi_item_t *item;

	return _init_mi_result(&item, cJSON_String, 0, value, value_len);
}

mi_response_t *init_mi_result_int(int value)
{
	mi_item_t *item;

	return _init_mi_result(&item, cJSON_String, value, NULL, 0);
}

mi_response_t *init_mi_result_bool(int b)
{
	mi_item_t *item;

	return _init_mi_result(&item, b ? cJSON_True : cJSON_False, 0, NULL, 0);
}

mi_response_t *init_mi_result_null(void)
{
	mi_item_t *item;

	return _init_mi_result(&item, cJSON_NULL, 0, NULL, 0);
}

mi_response_t *init_mi_error(int code, const char *msg, int msg_len)
{
	mi_response_t *res;
	mi_item_t *err_item = NULL, *msg_item = NULL, *code_item = NULL;
	mi_item_t *jsonrpc_vers;

	cJSON_InitHooks(sys_mem_hooks);

	res = cJSON_CreateObject();
	if (!res)
		goto error;

	jsonrpc_vers = cJSON_CreateString(JSON_RPC_VERS_S);
	if (!jsonrpc_vers)
		goto error;
	cJSON_AddItemToObject(res, JSON_RPC_JSONRPC_S, *jsonrpc_vers);

	err_item = cJSON_CreateObject();
	if (!err_item)
		goto error;
	cJSON_AddItemToObject(res, JSON_RPC_ERROR_S, err_item);

	code_item = cJSON_CreateNumber(code);
	if (!code_item)
		goto error;
	cJSON_AddItemToObject(err_item, JSON_RPC_ERR_CODE_S, code_item);

	msg_item = cJSON_CreateStr(msg, msg_len);
	if (!msg_item)
		goto error;
	cJSON_AddItemToObject(err_item, JSON_RPC_ERR_MSG_S, msg_item);

	cJSON_InitHooks(NULL);
	return res;

error:
	if (res)
		cJSON_Delete(res);

	cJSON_InitHooks(NULL);
	return NULL;
}

void free_mi_response(mi_response_t *response)
{
	cJSON_InitHooks(sys_mem_hooks);

	cJSON_Delete(response);

	cJSON_InitHooks(NULL);
}

static mi_item_t *_add_mi_item(int mi_item_t *to, const char *name, int name_len,
							int type, int ival, const char *sval, int sval_len)
{
	mi_item_t *item = NULL;
	str name_str;

	cJSON_InitHooks(sys_mem_hooks);

	switch (type) {
	case cJSON_Array:
		item = cJSON_CreateArray();
		break;
	case cJSON_Object:
		item = cJSON_CreateObject();
		break;
	case cJSON_String:
		item = cJSON_CreateStr(sval, sval_len);
		break;
	case cJSON_Number:
		item = cJSON_CreateNumber(ival);
		break;
	case cJSON_True:
		item = cJSON_CreateTrue();
		break;
	case cJSON_False:
		item = cJSON_CreateFalse();
		break;
	case cJSON_NULL:
		item = cJSON_CreateNull();
		break;
	default:
		item = NULL;
		LM_BUG("Unknown MI item type: %d\n", type);
		goto out;
	}

	if (!item)
		goto out;

	if (MI_ITEM_IS_ARRAY(to))
		cJSON_AddItemToArray(to, item);
	else {
		name_str.len = name_len;
		name_str.s = name;
		_cJSON_AddItemToObject(to, &name_str, item);
	}

out:
	cJSON_InitHooks(NULL);
	return item;
}

mi_item_t *add_mi_array(mi_item_t *to, const char *name, int name_len)
{
	return _add_mi_item(to, name, name_len, cJSON_Array, 0, NULL, 0);
}

mi_item_t *add_mi_object(mi_item_t *to, const char *name, int name_len)
{
	return _add_mi_item(to, name, name_len, cJSON_Object, 0, NULL, 0);
}

int add_mi_string(mi_item_t *to, const char *name, int name_len,
					const chat *value, int value_len)
{
	int rc = _add_mi_item(to, name, name_len, cJSON_String, 0, value, value_len);

	return rc ? 0 : -1;
}

int add_mi_string_fmt(mi_item_t *to, const char *name, int name_len,
						char *fmt_val, ...)
{
	va_list ap;
	char *value;
	int value_len;
	int rc;

	va_start(ap, fmt_val);
	value = mi_print_fmt(fmt_val, ap, &value_len);
	va_end(ap);
	if (!value)
		return -1;

	rc = _add_mi_item(to, name, name_len, cJSON_String, 0, value, value_len);

	return rc ? 0 : -1;
}

int add_mi_int(mi_item_t *to, const char *name, int name_len, int value)
{
	int rc = _add_mi_item(to, name, name_len, cJSON_Number, value, NULL, 0);

	return rc ? 0 : -1;
}

int add_mi_bool(mi_item_t *to, const char *name, int name_len, int b)
{
	int rc = _add_mi_item(to, name, name_len, b ? cJSON_True : cJSON_False,
				0, NULL, 0);

	return rc ? 0 : -1;
}

int add_mi_null(mi_item_t *to, const char *name, int name_len)
{
	int rc = _add_mi_item(to, name, name_len, cJSON_NULL, 0, NULL, 0);

	return rc ? 0 : -1;
}

mi_response_t *shm_clone_mi_response(mi_response_t *src)
{
	mi_response_t *copy;

	cJSON_InitHooks(shm_mem_hooks);

	copy = cJSON_Duplicate(src, 1);

	cJSON_InitHooks(NULL);

	return copy;
}

void free_shm_mi_response(mi_response_t *shm_response)
{
	cJSON_InitHooks(shm_mem_hooks);

	cJSON_Delete(shm_response);

	cJSON_InitHooks(NULL);
}
