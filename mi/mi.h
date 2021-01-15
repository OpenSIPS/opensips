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

#ifndef _MI_MI_H_
#define _MI_MI_H_

#include "../str.h"
#include "item.h"

#define MAX_MI_PARAMS  10
#define MAX_MI_RECIPES 10

/* async MI command */
#define MI_ASYNC_RPL_FLAG    (1<<0)
/* command only supports named parameters and will return
 * an error if positional parameters are received */
#define MI_NAMED_PARAMS_ONLY (1<<1)

#define MI_ASYNC_RPL    ((mi_response_t*)-1)
#define MI_NO_RPL 		1

#define JSONRPC_ID_S "id"
#define JSONRPC_METHOD_S "method"
#define JSONRPC_PARAMS_S "params"

#define JSONRPC_PARSE_ERR_CODE     -32700
#define JSONRPC_PARSE_ERR_MSG      "Parse error"
#define JSONRPC_INVAL_REQ_CODE     -32600
#define JSONRPC_INVAL_REQ_MSG      "Invalid Request"
#define JSONRPC_NOT_FOUND_CODE     -32601
#define JSONRPC_NOT_FOUND_MSG      "Method not found"
#define JSONRPC_INVAL_PARAMS_CODE  -32602
#define JSONRPC_INVAL_PARAMS_MSG   "Invalid params"
#define JSONRPC_SERVER_ERR_CODE	   -32000
#define JSONRPC_SERVER_ERR_MSG     "Server error"

#define ERR_DET_POS_PARAMS_S "Command only supports named parameters"
#define ERR_DET_AMBIG_CALL_S "Ambiguous call, use named parameters instead"
#define ERR_DET_NO_PARAMS_S  "Too few or too many parameters"
#define ERR_DET_MATCH_PARAMS_S "Named parameters do not match"
#define ERR_DET_CMD_NULL_S "Command handler returned null"
#define ERR_DET_PARAM_HANDLE_S "Failed to handle parameter"

struct mi_handler;

typedef mi_response_t *(mi_cmd_f)(const mi_params_t *params,
										struct mi_handler *async_hdl);
typedef int (mi_child_init_f)(void);
typedef void (mi_handler_f)(mi_response_t *, struct mi_handler *, int);


struct mi_handler {
	mi_handler_f *handler_f;
	void * param;
};

typedef struct mi_recipe_ {
	mi_cmd_f *cmd;
	char *params[MAX_MI_PARAMS];
} mi_recipe_t;

/* mi_recipe_t array terminator */
#define EMPTY_MI_RECIPE 0, {0}

struct mi_cmd {
	int id;
	str module;
	str name;
	str help;
	mi_child_init_f *init_f;
	unsigned int flags;
	mi_recipe_t *recipes;

	volatile unsigned char* trace_mask;
};

typedef struct mi_export_ {
	char *name;
	char *help;
	unsigned int flags;
	mi_child_init_f *init_f;
	mi_recipe_t recipes[MAX_MI_RECIPES];
} mi_export_t;

/* mi_export_t array terminator */
#define EMPTY_MI_EXPORT 0, 0, 0, 0, {{EMPTY_MI_RECIPE}}

typedef struct mi_request_ {
	mi_item_t *req_obj;
	mi_item_t *id;
	mi_item_t *method;
	mi_item_t *params;
	int invalid;
} mi_request_t;


int register_mi_cmd(char *name, char *help, unsigned int flags,
		mi_child_init_f in, mi_recipe_t *recipes, char* mod_name);

int register_mi_mod(char *mod_name, mi_export_t *mis);

int init_mi_child();

struct mi_cmd *lookup_mi_cmd(char *name, int len);

mi_response_t *w_mi_help(const mi_params_t *params,
					struct mi_handler *async_hdl);
mi_response_t *w_mi_help_1(const mi_params_t *params,
					struct mi_handler *async_hdl);

void get_mi_cmds(struct mi_cmd **cmds, int *size);

void _init_mi_shm_mem_hooks(void);
void _init_mi_pkg_mem_hooks(void);
void _init_mi_sys_mem_hooks(void);  /* stdlib */

/* Parses the MI request provided in the @in string (must be
 * null-terminated) and sets the fields of the @req struct.
 * Returns -1 if unable to parse json text.
 */
int parse_mi_request(const char *in, const char **end_ptr, mi_request_t *req);

/* Get the name of the MI command from the request */
char *mi_get_req_method(mi_request_t *req);

mi_response_t *handle_mi_request(mi_request_t *req, struct mi_cmd *cmd,
							struct mi_handler *async_hdl);

/* If the request is a jsonrpc notification, the function will return MI_NO_RPL
 */
int print_mi_response(mi_response_t *resp, mi_item_t *id, str *buf, int pretty);

/* similar to print_mi_response, but calls a flush function when the buffer
 * gets filled up
 */
int print_mi_response_flush(mi_response_t *resp, mi_item_t *id,
		mi_flush_f *func, void *func_p, str *buf, int pretty);

/* Frees the objects in the struct allocated when parsing the request
 */
void free_mi_request_parsed(mi_request_t *request);

#endif
