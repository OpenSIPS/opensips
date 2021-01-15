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

/*
 * OpenSIPS Management Interface
 *
 * The OpenSIPS management interface (MI) is a plugin architecture with a few different
 * handlers that gives access to the management interface over various transports.
 *
 * The OpenSIPS core and modules register commands to the interface at runtime.
 * Look into the various module documentation files for information of these
 * commands.
 *
 */

#include <string.h>

#include "../dprint.h"
#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../lib/cJSON.h"
#include "../lib/osips_malloc.h"
#include "mi.h"
#include "mi_trace.h"

static struct mi_cmd*  mi_cmds = 0;
static int mi_cmds_no = 0;

static cJSON_Hooks sys_mem_hooks = {
	.malloc_fn = malloc,
	.free_fn   = free,
};
static cJSON_Hooks shm_mem_hooks = {
	.malloc_fn = osips_shm_malloc,
	.free_fn   = osips_shm_free,
};

void _init_mi_sys_mem_hooks(void)
{
	cJSON_InitHooks(&sys_mem_hooks);
}

void _init_mi_shm_mem_hooks(void)
{
	cJSON_InitHooks(&shm_mem_hooks);
}

void _init_mi_pkg_mem_hooks(void)
{
	cJSON_InitHooks(NULL);
}

static inline int get_mi_id( char *name, int len)
{
	int n;
	int i;

	for( n=0,i=0 ; i<len ; n+=name[i] ,i++ );
	return n;
}


static inline struct mi_cmd* lookup_mi_cmd_id(int id,char *name, int len)
{
	int i;

	for( i=0 ; i<mi_cmds_no ; i++ ) {
		if ( id==mi_cmds[i].id && len==mi_cmds[i].name.len &&
		memcmp(mi_cmds[i].name.s,name,len)==0 )
			return &mi_cmds[i];
	}

	return 0;
}


int register_mi_mod( char *mod_name, mi_export_t *mis)
{
	int ret;
	int i;

	if (mis==0)
		return 0;

	for ( i=0 ; mis[i].name ; i++ ) {
		ret = register_mi_cmd(mis[i].name, mis[i].help, mis[i].flags,
				mis[i].init_f, mis[i].recipes, mod_name);
		if (ret!=0) {
			LM_ERR("failed to register cmd <%s> for module %s\n",
					mis[i].name,mod_name);
		}
	}

	return 0;
}


int init_mi_child(void)
{
	int i;

	for ( i=0 ; i<mi_cmds_no ; i++ ) {
		if ( mi_cmds[i].init_f && mi_cmds[i].init_f()!=0 ) {
			LM_ERR("failed to init <%.*s>\n",
					mi_cmds[i].name.len,mi_cmds[i].name.s);
			return -1;
		}
	}
	return 0;
}



int register_mi_cmd(char *name, char *help, unsigned int flags,
		mi_child_init_f in, mi_recipe_t *recipes, char* mod_name)
{
	struct mi_cmd *cmds;
	int id;
	int len;

	if (recipes==0 || name==0) {
		LM_ERR("invalid params recipes=%p, name=%s\n", recipes, name);
		return -1;
	}

	len = strlen(name);
	id = get_mi_id(name,len);

	if (lookup_mi_cmd_id( id, name, len)) {
		LM_ERR("command <%.*s> already registered\n", len, name);
		return -1;
	}

	cmds = (struct mi_cmd*)pkg_realloc( mi_cmds,
			(mi_cmds_no+1)*sizeof(struct mi_cmd) );
	if (cmds==0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	mi_cmds = cmds;
	mi_cmds_no++;

	cmds = &cmds[mi_cmds_no-1];

	cmds->init_f = in;
	cmds->flags = flags;
	cmds->name.s = name;
	cmds->name.len = len;
	cmds->module.s = mod_name;
	cmds->module.len = strlen(mod_name);
	cmds->help.s = help;
	cmds->help.len = help ? strlen(help) : 0;
	cmds->id = id;
	cmds->recipes = recipes;

	/**
	 * FIXME we should check if trace_api is loaded not to lose unnecessary space
	 * but some mi commands might have been already registered before loading the api
	 * an example is the statistics mi commands
	 */
	cmds->trace_mask = shm_malloc(sizeof(volatile unsigned char));
	if ( !cmds->trace_mask ) {
		LM_ERR("no more shm mem!\n");
		return -1;
	}

	/* by default all commands are traced */
	*cmds->trace_mask = (~(volatile unsigned char)0);

	return 0;
}



struct mi_cmd* lookup_mi_cmd( char *name, int len)
{
	int id;

	id = get_mi_id(name,len);
	return lookup_mi_cmd_id( id, name, len);
}


void get_mi_cmds( struct mi_cmd** cmds, int *size)
{
	*cmds = mi_cmds;
	*size = mi_cmds_no;
}

int parse_mi_request(const char *req, const char **end_ptr, mi_request_t *parsed)
{
	mi_item_t *req_jsonrpc;

	_init_mi_sys_mem_hooks();

	parsed->req_obj = cJSON_ParseWithOpts(req, end_ptr, 0);
	if (!parsed->req_obj) {
		_init_mi_pkg_mem_hooks();
		return -1;
	}

	/* check if the request is a valid JSON-RPC Request object */
	/* get request id (if absent -> notification) */
	parsed->id = cJSON_GetObjectItem(parsed->req_obj, JSONRPC_ID_S);
	if (parsed->id && !(parsed->id->type & (cJSON_NULL|cJSON_Number|cJSON_String)))
		parsed->invalid = 1;

	/* check 'jsonrpc' member */
	req_jsonrpc = cJSON_GetObjectItem(parsed->req_obj, JSONRPC_S);
	if (!req_jsonrpc || !(req_jsonrpc->type & cJSON_String) ||
		strcmp(req_jsonrpc->valuestring, JSONRPC_VERS_S))
		parsed->invalid = 1;

	/* check 'method' member */
	parsed->method = cJSON_GetObjectItem(parsed->req_obj, JSONRPC_METHOD_S);
	if (!parsed->method || !(parsed->method->type & cJSON_String)) {
		parsed->method = NULL;
		parsed->invalid = 1;
	}

	/* check 'params' member */
	parsed->params = cJSON_GetObjectItem(parsed->req_obj, JSONRPC_PARAMS_S);
	if (parsed->params) {
		if (!(parsed->params->type & (cJSON_Array|cJSON_Object)))
			parsed->invalid = 1;
		else if (!parsed->params->child) {
			parsed->params = NULL;
		}
	}

	_init_mi_pkg_mem_hooks();

	return 0;
}

char *mi_get_req_method(mi_request_t *req)
{
	if (!req || !req->method)
		return NULL;

	return req->method->valuestring;
}

static int match_named_params(mi_recipe_t *recipe, mi_item_t *req_params)
{
	mi_item_t *param;
	int i;

	for (i = 0; recipe->params[i]; i++) {
		for (param = req_params->child; param; param = param->next)
			if (param->string && !strcmp(recipe->params[i], param->string))
				break;

		if (!param)
			return 0;
	}

	return 1;
}

static int match_no_params(mi_recipe_t *recipe, mi_item_t *req_params)
{
	mi_item_t *param;
	int i, j;

	for (i = 0; recipe->params[i]; i++) ;

	for (param = req_params->child, j = 0; param; param = param->next, j++) ;

	return i == j;
}

static mi_recipe_t *get_cmd_recipe(mi_recipe_t *recipes, mi_item_t *req_params,
								int pos_params, int *params_err)
{
	mi_recipe_t *match = NULL;
	int i;

	for (i = 0; recipes[i].cmd; i++) {
		if (!req_params) {
			if (recipes[i].params[0] == NULL)
				return &recipes[i];
			else
				continue;
		} else {
			if (recipes[i].params[0] == NULL)
				continue;
		}

		if (pos_params) {
			if (match_no_params(&recipes[i], req_params)) {
				if (match) {
					*params_err = -2;
					return NULL;
				} else {
					match = &recipes[i];
				}
			}
		} else {
			if (match_no_params(&recipes[i], req_params))
				*params_err = -3;
			else
				continue;

			if (match_named_params(&recipes[i], req_params))
				return &recipes[i];
		}
	}

	return match;
}

static mi_response_t *build_err_resp(int code, const char *msg, int msg_len,
								const char *details, int details_len)
{
	mi_response_t *err_resp;

	err_resp = init_mi_error_extra(code, msg, msg_len, details, details_len);
	if (!err_resp)
		LM_ERR("Failed to build MI error response object\n");

	return err_resp;
}

mi_response_t *handle_mi_request(mi_request_t *req, struct mi_cmd *cmd,
							struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_recipe_t *cmd_recipe;
	mi_params_t cmd_params;
	int params_err = -1;
	int pos_params;

	if (!req->req_obj) {  /* error parsing the request JSON text */
		LM_ERR("Failed to parse the request JSON text\n");
		return build_err_resp(JSONRPC_PARSE_ERR_CODE,
					MI_SSTR(JSONRPC_PARSE_ERR_MSG), NULL, 0);
	}

	if (req->invalid) {  /* invalid jsonrpc request */
		LM_ERR("Invalid JSON-RPC request\n");
		return build_err_resp(JSONRPC_INVAL_REQ_CODE,
					MI_SSTR(JSONRPC_INVAL_REQ_MSG), NULL, 0);
	}

	if (!cmd) {
		LM_ERR("Command not found\n");
		return build_err_resp(JSONRPC_NOT_FOUND_CODE,
				MI_SSTR(JSONRPC_NOT_FOUND_MSG), NULL, 0);
	}

	pos_params = req->params ? req->params->type & cJSON_Array : 0;
	if (pos_params && (cmd->flags & MI_NAMED_PARAMS_ONLY)) {
		LM_ERR("Command only supports named parameters\n");
		return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
				MI_SSTR(ERR_DET_POS_PARAMS_S));
	}

	/* use the correct 'recipe' of the command based
	 * on the received parameters */
	cmd_recipe = get_cmd_recipe(cmd->recipes, req->params, pos_params,
					&params_err);
	if (!cmd_recipe) {
		LM_ERR("Invalid parameters\n");
		if (params_err == -1)
			return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), MI_SSTR(ERR_DET_NO_PARAMS_S));
		else if (params_err == -2)
			return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
				MI_SSTR(ERR_DET_AMBIG_CALL_S));
		else
			return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
				MI_SSTR(ERR_DET_MATCH_PARAMS_S));
	}

	cmd_params.item = req->params;
	cmd_params.list = cmd_recipe->params;

	resp = cmd_recipe->cmd(&cmd_params, async_hdl);

	if (resp == NULL) {
		LM_ERR("Command failed\n");
		return build_err_resp(JSONRPC_SERVER_ERR_CODE,
				MI_SSTR(JSONRPC_SERVER_ERR_MSG), MI_SSTR(ERR_DET_CMD_NULL_S));
	} else
		return resp;
}

int add_id_to_response(mi_item_t *id, mi_response_t *resp)
{
	if (!id) {
		if (add_mi_null(resp, MI_SSTR(JSONRPC_ID_S)) < 0) {
			LM_ERR("Failed to add null value to MI item\n");
			return -1;
		}

		return 0;
	}

	switch ((id->type) & 0xFF) {
		case cJSON_Number:
			if (add_mi_number(resp, MI_SSTR(JSONRPC_ID_S), id->valueint) < 0) {
				LM_ERR("Failed to add int value to MI item\n");
				return -1;
			}
			break;
		case cJSON_String:
			if (add_mi_string(resp, MI_SSTR(JSONRPC_ID_S), id->valuestring,
				strlen(id->valuestring)) < 0) {
				LM_ERR("Failed to add string value to MI item\n");
				return -1;
			}
			break;
		case cJSON_NULL:
			if (add_mi_null(resp, MI_SSTR(JSONRPC_ID_S)) < 0) {
				LM_ERR("Failed to add null value to MI item\n");
				return -1;
			}
			break;
		default:
			LM_ERR("'id' must be a String, Number or Null value\n");
			return -1;
	}

	return 0;
}

static int prepare_mi_response(mi_response_t *resp, mi_item_t *id)
{
	mi_item_t *res_err, *res_err_code = NULL;

	res_err = cJSON_GetObjectItem(resp, JSONRPC_ERROR_S);
	if (res_err) {
		res_err_code = cJSON_GetObjectItem(res_err, JSONRPC_ERR_CODE_S);
		if (!res_err_code) {
			LM_ERR("no error code for MI error response\n");
			return -1;
		}
	}

	if (!id) {
		/* this is a jsonrpc notification (no id but valid request otherwise)
		 * -> no response */
		if (!res_err)
			return MI_NO_RPL;

		if (res_err_code->valueint != JSONRPC_PARSE_ERR_CODE &&
			res_err_code->valueint != JSONRPC_INVAL_REQ_CODE)
			return MI_NO_RPL;
	}

	if (add_id_to_response(id, resp) < 0)
		return -1;

	return 0;
}

int print_mi_response(mi_response_t *resp, mi_item_t *id, str *buf, int pretty)
{
	int ret = prepare_mi_response(resp, id);

	if (ret != 0)
		return ret;

	if (cJSON_PrintPreallocated(resp, buf->s, buf->len, pretty) == 0) {
		LM_ERR("Failed to print JSON\n");
		return -1;
	}

	return 0;
}

int print_mi_response_flush(mi_response_t *resp, mi_item_t *id,
		mi_flush_f *func, void *func_p, str *buf, int pretty)
{
	int ret = prepare_mi_response(resp, id);

	if (ret != 0)
		return ret;

	if (cJSON_PrintFlushed(resp, buf->s, buf->len, pretty, func, func_p) == 0) {
		LM_ERR("Failed to print JSON\n");
		return -1;
	}

	return 0;
}

void free_mi_request_parsed(mi_request_t *request)
{
	_init_mi_sys_mem_hooks();

	if (request->req_obj)
		cJSON_Delete(request->req_obj);

	_init_mi_pkg_mem_hooks();
}


#define MI_HELP_STR "Usage: help mi_cmd - " \
	"returns information about 'mi_cmd'"
#define MI_UNKNOWN_CMD "unknown MI command"
#define MI_NO_HELP "not available for this command"
#define MI_MODULE_STR "by \"%.*s\" module"

mi_response_t *w_mi_help(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	return init_mi_result_string(MI_SSTR(MI_HELP_STR));
}

mi_response_t *w_mi_help_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct mi_cmd *cmd;
	str cmd_s;

	if (get_mi_string_param(params, "mi_cmd", &cmd_s.s, &cmd_s.len) < 0)
		return init_mi_param_error();

	/* search the command */
	cmd = lookup_mi_cmd(cmd_s.s, cmd_s.len);
	if (!cmd)
		return init_mi_error(404, MI_SSTR(MI_UNKNOWN_CMD));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (cmd->help.s) {
		if (add_mi_string(resp_obj, MI_SSTR("Help"), cmd->help.s, cmd->help.len)
			< 0) {
			LM_ERR("cannot add mi item\n");
			goto error;
		}
	} else {
		if (add_mi_string(resp_obj, MI_SSTR("Help"), MI_SSTR(MI_NO_HELP)) < 0) {
			LM_ERR("cannot add mi item\n");
			goto error;
		}
	}

	if (cmd->module.len && cmd->module.s && add_mi_string(resp_obj,
		MI_SSTR("Exported by"), cmd->module.s, cmd->module.len) < 0) {
		LM_ERR("cannot add mi item\n");
		goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}
