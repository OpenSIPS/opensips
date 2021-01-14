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
 */


#ifndef _MI_ITEM_H
#define _MI_ITEM_H

#include <stdarg.h>
#include "../str.h"
#include "../lib/cJSON.h"

#define MI_DATE_BUF_LEN 21

#define MI_SSTR(_s) _s,(sizeof(_s)-1)

#define JSONRPC_S "jsonrpc"
#define JSONRPC_VERS_S "2.0"

#define JSONRPC_RESULT_S "result"

#define JSONRPC_ERROR_S "error"
#define JSONRPC_ERR_CODE_S "code"
#define JSONRPC_ERR_MSG_S "message"
#define JSONRPC_ERR_DATA_S "data"

#define MI_OK_S "OK"

#define MI_ITEM_IS_ARRAY(item) ((item)->type & cJSON_Array)

typedef cJSON mi_item_t;

typedef mi_item_t mi_response_t;
typedef flush_fn mi_flush_f;

typedef struct mi_params_ {
	mi_item_t *item;
	char **list;
} mi_params_t;

/* The functions below can be used to build a MI Response
 */

/* Initializes a successful MI Response
 * with an empty array returned in the @arr_out parameter.
 */
mi_response_t *init_mi_result_array(mi_item_t **arr_out);

/* Initializes a successful MI Response
 * with an empty object returned in the @obj_out parameter.
 */
mi_response_t *init_mi_result_object(mi_item_t **obj_out);

/* Initializes a successful MI Response
 * with the provided string.
 */
mi_response_t *init_mi_result_string(const char *value, int value_len);

/* Initializes a successful MI Response
 * with the "OK" string.
 */
#define init_mi_result_ok() init_mi_result_string(MI_SSTR(MI_OK_S))

/* Initializes a successful MI Response
 * with the provided double (as a 'number' json type).
 */
mi_response_t *init_mi_result_number(double value);

/* Initializes a successful MI Response
 * with the provided boolean value.
 */
mi_response_t *init_mi_result_bool(int b);

/* Initializes a successful MI Response
 * with null.
 */
mi_response_t *init_mi_result_null(void);

/* Initializes an error MI Response
 * with the given error code and message.
 * Accepts a string of additional error details.
 */
mi_response_t *init_mi_error_extra(int code, const char *msg, int msg_len,
								const char *details, int details_len);

/* Initializes an error MI Response
 * with the given error code and message.
 */
static inline mi_response_t *init_mi_error(int code, const char *msg, int msg_len)
{
	return init_mi_error_extra(code, msg, msg_len, NULL, 0);
}

/* Frees a MI Reponse
 */
void free_mi_response(mi_response_t *response);

/* Appends a new array to an existing array or to an object at the given name.
 * When appending to an array, @name and @name_len are ignored.
 */
mi_item_t *add_mi_array(mi_item_t *to, char *name, int name_len);

/* Appends a new object to an array or to another object at the given name.
 * When appending to an array, @name and @name_len are ignored.
 */
mi_item_t *add_mi_object(mi_item_t *to, char *name, int name_len);

/* Appends a string to an array or to an object at the given name.
 * When appending to an array, @name and @name_len are ignored.
 */
int add_mi_string(mi_item_t *to, char *name, int name_len,
					const char *value, int value_len);

/* Appends a formated string to an array or to an object at the given name.
 * When appending to an array, @name and @name_len are ignored.
 */
int add_mi_string_fmt(mi_item_t *to, char *name, int name_len,
						char *fmt_val, ...);

/* Appends a double (as a 'number' json type) to an array or to an object at
 * the given name. When appending to an array, @name and @name_len are ignored.
 */
int add_mi_number(mi_item_t *to, char *name, int name_len, double value);

/* Appends a boolean to an array or to an object at the given name.
 * When appending to an array, @name and @name_len are ignored.
 */
int add_mi_bool(mi_item_t *to, char *name, int name_len, int b);

/* Appends null to an array or to an object at the given name.
 * When appending to an array, @name and @name_len are ignored.
 */
int add_mi_null(mi_item_t *to, char *name, int name_len);


/* Clones a MI Response to shm memory
 */
mi_response_t *shm_clone_mi_response(mi_response_t *src);

/* Frees a MI Reponse from shm memory
 */
void free_shm_mi_response(mi_response_t *response);

/* Clones a MI item to shm memory
 */
mi_item_t *shm_clone_mi_item(mi_item_t *src);

/* Frees a MI item from shm memory
 */
void free_shm_mi_item(mi_item_t *response);

/* The string provided in @value will be freed along with the MI request
 * so it should be strdup'ed as necessary
 */
int get_mi_string_param(const mi_params_t *params, char *name,
					char **value, int *value_len);

int get_mi_int_param(const mi_params_t *params, char *name, int *value);

int get_mi_array_param(const mi_params_t *params, char *name,
					mi_item_t **value, int *no_items);

/* get the string item at the index @pos from an array parameter
 * returned by get_mi_array_param()
 */
int get_mi_arr_param_string(const mi_item_t *array, int pos,
						char **value, int *value_len);

/* get the string item at the index @pos from an array parameter
 * returned by get_mi_array_param()
 */
int get_mi_arr_param_int(const mi_item_t *array, int pos, int *value);

/* set of functions for trying to get a parameter, but do not fail if
 * it cannot be found
 */
int try_get_mi_int_param(const mi_params_t *params, char *name,
		int *value);
int try_get_mi_string_param(const mi_params_t *params, char *name,
		char **value, int *value_len);
int try_get_mi_array_param(const mi_params_t *params, char *name,
		mi_item_t **value, int *no_items);
int try_get_mi_arr_param_string(const mi_item_t *array, int pos,
		char **value, int *value_len);
int try_get_mi_arr_param_int(const mi_item_t *array, int pos, int *value);

/* Initializes a standard MI Response with details about the last
 * parameter error produced by a parameter getter function
 */
mi_response_t *init_mi_param_error(void);

#endif
