/*
 * Copyright (C) 2006 Voice Sistem SRL
 * Copyright (C) 2018 OpenSIPS Solutions
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
#include "../ut.h"
#include "item.h"
#include "fmt.h"

#define MI_PARAM_ERR_BUFLEN 255

#define MI_PARAM_ERR_MISSING -1
#define MI_PARAM_ERR_BAD_TYPE -2
#define MI_PARAM_ERR_EMPTY_ARR -3
#define MI_PARAM_ERR_ARR_BAD_TYPE -4

int param_err_type = -2;
char *param_err_pname;

static mi_response_t *_init_mi_result(mi_item_t **item_out, int type, int dval,
										const char *sval, int sval_len)
{
	mi_response_t *res = NULL;
	mi_item_t *jsonrpc_vers;

	_init_mi_sys_mem_hooks();

	res = cJSON_CreateObject();
	if (!res)
		goto error;

	jsonrpc_vers = cJSON_CreateString(JSONRPC_VERS_S);
	if (!jsonrpc_vers)
		goto error;
	cJSON_AddItemToObject(res, JSONRPC_S, jsonrpc_vers);

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
		*item_out = cJSON_CreateNumber(dval);
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
		goto error;
	}
	if (!*item_out)
		goto error;

	cJSON_AddItemToObject(res, JSONRPC_RESULT_S, *item_out);

	_init_mi_pkg_mem_hooks();
	return res;

error:
	if (res)
		cJSON_Delete(res);
	_init_mi_pkg_mem_hooks();
	return NULL;
}


mi_response_t *init_mi_result_array(mi_item_t **arr_out)
{
	return _init_mi_result(arr_out, cJSON_Array, 0, NULL, 0);
}

mi_response_t *init_mi_result_object(mi_item_t **obj_out)
{
	return _init_mi_result(obj_out, cJSON_Object, 0, NULL, 0);
}

mi_response_t *init_mi_result_string(const char *value, int value_len)
{
	mi_item_t *item;

	return _init_mi_result(&item, cJSON_String, 0, value, value_len);
}

mi_response_t *init_mi_result_number(double value)
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

mi_response_t *init_mi_error_extra(int code, const char *msg, int msg_len,
								const char *details, int details_len)
{
	mi_response_t *res;
	mi_item_t *err_item = NULL, *msg_item = NULL, *code_item = NULL, *data_item;
	mi_item_t *jsonrpc_vers;

	_init_mi_sys_mem_hooks();

	res = cJSON_CreateObject();
	if (!res)
		goto error;

	jsonrpc_vers = cJSON_CreateString(JSONRPC_VERS_S);
	if (!jsonrpc_vers)
		goto error;
	cJSON_AddItemToObject(res, JSONRPC_S, jsonrpc_vers);

	err_item = cJSON_CreateObject();
	if (!err_item)
		goto error;
	cJSON_AddItemToObject(res, JSONRPC_ERROR_S, err_item);

	code_item = cJSON_CreateNumber(code);
	if (!code_item)
		goto error;
	cJSON_AddItemToObject(err_item, JSONRPC_ERR_CODE_S, code_item);

	msg_item = cJSON_CreateStr(msg, msg_len);
	if (!msg_item)
		goto error;
	cJSON_AddItemToObject(err_item, JSONRPC_ERR_MSG_S, msg_item);

	if (details && details_len) {
		data_item = cJSON_CreateStr(details, details_len);
		if (!data_item)
			goto error;
		cJSON_AddItemToObject(err_item, JSONRPC_ERR_DATA_S, data_item);
	}

	_init_mi_pkg_mem_hooks();
	return res;

error:
	if (res)
		cJSON_Delete(res);

	_init_mi_pkg_mem_hooks();
	return NULL;
}

void free_mi_response(mi_response_t *response)
{
	_init_mi_sys_mem_hooks();

	cJSON_Delete(response);

	_init_mi_pkg_mem_hooks();
}

static mi_item_t *_add_mi_item(mi_item_t *to, char *name, int name_len,
							int type, double dval, const char *sval, int sval_len)
{
	mi_item_t *item = NULL;
	str name_str;

	_init_mi_sys_mem_hooks();

	switch (type) {
	case cJSON_Array:
		item = cJSON_CreateArray();
		break;
	case cJSON_Object:
		item = cJSON_CreateObject();
		break;
	case cJSON_String:
		if (!sval || sval_len == 0)
			item = cJSON_CreateStr("", 0);
		else
			item = cJSON_CreateStr(sval, sval_len);
		break;
	case cJSON_Number:
		item = cJSON_CreateNumber(dval);
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
	_init_mi_pkg_mem_hooks();
	return item;
}

mi_item_t *add_mi_array(mi_item_t *to, char *name, int name_len)
{
	return _add_mi_item(to, name, name_len, cJSON_Array, 0, NULL, 0);
}

mi_item_t *add_mi_object(mi_item_t *to, char *name, int name_len)
{
	return _add_mi_item(to, name, name_len, cJSON_Object, 0, NULL, 0);
}

int add_mi_string(mi_item_t *to, char *name, int name_len,
					const char *value, int value_len)
{
	return _add_mi_item(to, name, name_len, cJSON_String, 0, value, value_len) ?
		0 : -1;
}

int add_mi_string_fmt(mi_item_t *to, char *name, int name_len,
						char *fmt_val, ...)
{
	va_list ap;
	char *value;
	int value_len;

	va_start(ap, fmt_val);
	value = mi_print_fmt(fmt_val, ap, &value_len);
	va_end(ap);
	if (!value)
		return -1;

	return _add_mi_item(to, name, name_len, cJSON_String, 0, value, value_len) ?
		0 : -1;
}

int add_mi_number(mi_item_t *to, char *name, int name_len, double value)
{
	return _add_mi_item(to, name, name_len, cJSON_Number, value, NULL, 0) ?
		0 : -1;
}

int add_mi_bool(mi_item_t *to, char *name, int name_len, int b)
{
	return _add_mi_item(to, name, name_len, b ? cJSON_True : cJSON_False,
		0, NULL, 0) ? 0 : -1;
}

int add_mi_null(mi_item_t *to, char *name, int name_len)
{
	return _add_mi_item(to, name, name_len, cJSON_NULL, 0, NULL, 0) ?
		0 : -1;
}

mi_response_t *shm_clone_mi_response(mi_response_t *src)
{
	mi_response_t *copy;

	_init_mi_shm_mem_hooks();

	copy = cJSON_Duplicate(src, 1);

	_init_mi_pkg_mem_hooks();

	return copy;
}

void free_shm_mi_response(mi_response_t *shm_response)
{
	/* if there is an id, this is probably in pkg mem, because that's how
	 * add_id_to_response adds it; if we don't release it now, removing it
	 * from shm will result in a memory corruption */
	_init_mi_sys_mem_hooks();
	cJSON_DeleteItemFromObject(shm_response, "id");

	_init_mi_shm_mem_hooks();

	cJSON_Delete(shm_response);

	_init_mi_pkg_mem_hooks();
}

mi_item_t *shm_clone_mi_item(mi_item_t *src)
{
	mi_item_t *copy;

	_init_mi_shm_mem_hooks();

	copy = cJSON_Duplicate(src, 1);

	_init_mi_pkg_mem_hooks();

	return copy;
}

void free_shm_mi_item(mi_item_t *item)
{
	_init_mi_shm_mem_hooks();

	cJSON_Delete(item);

	_init_mi_pkg_mem_hooks();
}

static mi_item_t * _get_mi_param(const mi_params_t *params, char *name)
{
	int i;

	if (!params->item)
		return NULL;

	if (MI_ITEM_IS_ARRAY(params->item)) {
		for (i = 0; params->list[i]; i++)
			if (!strcmp(params->list[i], name))
				break;

		if (!params->list[i])
			return NULL;

		return cJSON_GetArrayItem(params->item, i);
	} else
		return cJSON_GetObjectItem(params->item, name);
}

int try_get_mi_int_param(const mi_params_t *params, char *name, int *value)
{
	mi_item_t *p;
	str st;

	param_err_pname = name;

	p = _get_mi_param(params, name);
	if (!p) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	if (!(p->type & (cJSON_Number|cJSON_String))) {
		param_err_type = MI_PARAM_ERR_BAD_TYPE;
		return MI_PARAM_ERR_BAD_TYPE;
	}

	if (p->type & cJSON_Number) {
		*value = p->valueint;
	} else {
		st.s = p->valuestring;
		st.len = strlen(st.s);
		if (str2sint(&st, value) < 0) {
			param_err_type = MI_PARAM_ERR_BAD_TYPE;
			return MI_PARAM_ERR_BAD_TYPE;
		}
	}

	return 0;
}

int get_mi_int_param(const mi_params_t *params, char *name, int *value)
{
	switch (try_get_mi_int_param(params, name, value))
	{
		case MI_PARAM_ERR_MISSING:
			LM_ERR("Parameter: %s not found\n", name);
			break;
		case MI_PARAM_ERR_BAD_TYPE:
			LM_ERR("Parameter: %s is not an valid integer\n", name);
			break;
		case 0:
			return 0;
	}
	return -1;
}

int try_get_mi_string_param(const mi_params_t *params, char *name,
					char **value, int *value_len)
{
	mi_item_t *p;

	param_err_pname = name;

	p = _get_mi_param(params, name);
	if (!p) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	if (!(p->type & (cJSON_Number|cJSON_String))) {
		param_err_type = MI_PARAM_ERR_BAD_TYPE;
		return MI_PARAM_ERR_BAD_TYPE;
	}

	if (p->type & cJSON_String) {
		*value = p->valuestring;
		*value_len = strlen(p->valuestring);
	} else {
		*value = sint2str(p->valueint, value_len);
	}

	return 0;
}

int get_mi_string_param(const mi_params_t *params, char *name,
					char **value, int *value_len)
{
	switch (try_get_mi_string_param(params, name, value, value_len))
	{
		case MI_PARAM_ERR_MISSING:
			LM_ERR("Parameter: %s not found\n", name);
			break;
		case MI_PARAM_ERR_BAD_TYPE:
			LM_ERR("Bad data type for parameter: %s\n", name);
			break;
		case 0:
			return 0;
	}
	return -1;
}

int try_get_mi_array_param(const mi_params_t *params, char *name,
					mi_item_t **value, int *no_items)
{
	mi_item_t *p;

	param_err_pname = name;

	p = _get_mi_param(params, name);;
	if (!p) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	if (!(p->type & cJSON_Array)) {
		param_err_type = MI_PARAM_ERR_BAD_TYPE;
		return MI_PARAM_ERR_BAD_TYPE;
	}

	*value = p;
	*no_items = cJSON_GetArraySize(p);
	if (*no_items == 0) {
		param_err_type = MI_PARAM_ERR_EMPTY_ARR;
		return MI_PARAM_ERR_EMPTY_ARR;
	}

	return 0;
}

int get_mi_array_param(const mi_params_t *params, char *name,
					mi_item_t **value, int *no_items)
{
	switch (try_get_mi_array_param(params, name, value, no_items))
	{
		case MI_PARAM_ERR_MISSING:
			LM_ERR("Parameter: %s not found\n", name);
			break;
		case MI_PARAM_ERR_BAD_TYPE:
			LM_ERR("Parameter: %s is not an array\n", name);
			break;
		case MI_PARAM_ERR_EMPTY_ARR:
			LM_ERR("Empty array for parameter: %s\n", name);
			break;
		case 0:
			return 0;
	}
	return -1;
}

int try_get_mi_arr_param_string(const mi_item_t *array, int pos,
						char **value, int *value_len)
{
	mi_item_t *s;

	if (!array) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	s = cJSON_GetArrayItem(array, pos);
	if (!s) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	if (!(s->type & (cJSON_Number|cJSON_String))) {
		param_err_type = MI_PARAM_ERR_ARR_BAD_TYPE;
		return MI_PARAM_ERR_ARR_BAD_TYPE;
	}

	if (s->type & cJSON_String) {
		*value = s->valuestring;
		*value_len = strlen(s->valuestring);
	} else {
		*value = sint2str(s->valueint, value_len);
	}

	return 0;
}

int get_mi_arr_param_string(const mi_item_t *array, int pos,
						char **value, int *value_len)
{
	switch (try_get_mi_arr_param_string(array, pos, value, value_len))
	{
		case MI_PARAM_ERR_MISSING:
			LM_ERR("Array index out of bounds\n");
			break;
		case MI_PARAM_ERR_ARR_BAD_TYPE:
			LM_ERR("Bad data type for array item\n");
			break;
		case 0:
			return 0;
	}
	return -1;
}

int try_get_mi_arr_param_int(const mi_item_t *array, int pos, int *value)
{
	mi_item_t *i;
	str st;

	if (!array) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	i = cJSON_GetArrayItem(array, pos);
	if (!i) {
		param_err_type = MI_PARAM_ERR_MISSING;
		return MI_PARAM_ERR_MISSING;
	}

	if (!(i->type & (cJSON_Number|cJSON_String))) {
		param_err_type = MI_PARAM_ERR_ARR_BAD_TYPE;
		return MI_PARAM_ERR_ARR_BAD_TYPE;
	}

	if (i->type & cJSON_Number) {
		*value = i->valueint;
	} else {
		st.s = i->valuestring;
		st.len = strlen(st.s);
		if (str2sint(&st, value) < 0) {
			param_err_type = MI_PARAM_ERR_ARR_BAD_TYPE;
			return MI_PARAM_ERR_ARR_BAD_TYPE;
		}
	}

	return 0;
}

int get_mi_arr_param_int(const mi_item_t *array, int pos, int *value)
{
	switch (try_get_mi_arr_param_int(array, pos, value))
	{
		case MI_PARAM_ERR_MISSING:
			LM_ERR("Array index out of bounds\n");
			break;
		case MI_PARAM_ERR_ARR_BAD_TYPE:
			LM_ERR("Array item is not an integer\n");
			break;
		case 0:
			return 0;
	}
	return -1;
}

mi_response_t *init_mi_param_error(void)
{
	char param_err_buf[MI_PARAM_ERR_BUFLEN];
	int len;

	switch (param_err_type) {
		case MI_PARAM_ERR_BAD_TYPE:
			len = snprintf(param_err_buf, MI_PARAM_ERR_BUFLEN,
				"Bad type for parameter '%s'", param_err_pname);
			if (len)
				return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
					MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), param_err_buf, len);
			break;
		case MI_PARAM_ERR_ARR_BAD_TYPE:
			len = snprintf(param_err_buf, MI_PARAM_ERR_BUFLEN,
				"Bad type for array item in parameter '%s'", param_err_pname);
			if (len)
				return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
					MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), param_err_buf, len);
			break;
		case MI_PARAM_ERR_EMPTY_ARR:
			len = snprintf(param_err_buf, MI_PARAM_ERR_BUFLEN,
				"Empty array in parameter '%s'", param_err_pname);
			if (len)
				return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
					MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), param_err_buf, len);
			break;
		case MI_PARAM_ERR_MISSING:
			/* the call has already been matched with one of the MI recipes so
			 * treat a missing parameter as an unexpected server error (possibly
			 * a bad param name was used by the handler when getting a param) */
			break;
	}

	return init_mi_error_extra(JSONRPC_SERVER_ERR_CODE,
		MI_SSTR(JSONRPC_SERVER_ERR_MSG), MI_SSTR(ERR_DET_PARAM_HANDLE_S));
}
