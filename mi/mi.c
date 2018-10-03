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

mi_request_t *parse_mi_request(const char *req, const char **end_ptr)
{
	_init_mi_sys_mem_hooks();

	return cJSON_ParseWithOpts(req, end_ptr, 0);
}

static int match_named_params(mi_recipe_t *recipe, mi_item_t *req_params,
							int *max_params)
{
	mi_item_t *param;
	int i;

	for (i = 0; recipe->params[i]; i++) {
		for (param = req_params->child; param; param = param->next)
			if (!strcmp(recipe->params[i], param->string))
				break;

		if (!param)
			return 0;
	}

	if (i > *max_params) {
		*max_params = i;
		return 1;
	} else if (i == *max_params)
		return -1;
	else
		return 0;
}

static int match_pos_params(mi_recipe_t *recipe, mi_item_t *req_params)
{
	mi_item_t *param;
	int i, j;

	for (i = 0; recipe->params[i]; i++) ;

	for (param = req_params->child, j = 0; param; param = param->next, j++) ;

	return i == j;
}

static mi_recipe_t *get_cmd_recipe(mi_recipe_t *recipes, mi_item_t *req_params,
								int pos_params, int *is_ambiguous)
{
	mi_recipe_t *match = NULL;
	int i, max_params = 0;
	int rc;

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
			if (match_pos_params(&recipes[i], req_params)) {
				if (match) {
					*is_ambiguous = 1;
					return match;
				}
				else
					match = &recipes[i];
			}
		} else {
			rc = match_named_params(&recipes[i], req_params, &max_params);
			if (rc == -1)
				*is_ambiguous = 1;
			else if (rc == 1) {
				*is_ambiguous = 0;
				match = &recipes[i];
			}
		}
	}

	return match;
}

static mi_response_t *build_err_resp(int code, const char *msg, int msg_len,
								const char *details, int details_len)
{
	mi_response_t *err_resp;

	err_resp = init_mi_error(code, msg, msg_len, details, details_len);
	if (!err_resp)
		LM_ERR("Failed to build MI error response object\n");

	return err_resp;
}

mi_response_t *handle_mi_request(mi_request_t *req, struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *req_id, *req_jsonrpc, *req_method, *req_params;
	struct mi_cmd *cmd;
	mi_recipe_t *cmd_recipe;
	mi_params_t cmd_params;
	int is_ambiguous = 0;
	int pos_params = 0;

	if (!req)  /* error parsing the request JSON text */
		return build_err_resp(JSONRPC_PARSE_ERR_CODE,
					MI_SSTR(JSONRPC_PARSE_ERR_MSG), NULL, 0);

	/* check if the request is a valid JSON-RPC Request object */

	/* get request id (if absent -> notification) */
	req_id = cJSON_GetObjectItem(req, JSONRPC_ID_S);
	if (req_id && !(req_id->type & (cJSON_NULL|cJSON_Number|cJSON_String)))
		return build_err_resp(JSONRPC_INVAL_REQ_CODE,
					MI_SSTR(JSONRPC_INVAL_REQ_MSG), NULL, 0);

	/* check 'jsonrpc' member */
	req_jsonrpc = cJSON_GetObjectItem(req, JSONRPC_S);
	if (!req_jsonrpc || !(req_jsonrpc->type & cJSON_String) ||
		strcmp(req_jsonrpc->valuestring, JSONRPC_VERS_S))
		return build_err_resp(JSONRPC_INVAL_REQ_CODE,
					MI_SSTR(JSONRPC_INVAL_REQ_MSG), NULL, 0);

	/* check 'method' member */
	req_method = cJSON_GetObjectItem(req, JSONRPC_METHOD_S);
	if (!req_method || !(req_method->type & cJSON_String))
		return build_err_resp(JSONRPC_INVAL_REQ_CODE,
					MI_SSTR(JSONRPC_INVAL_REQ_MSG), NULL, 0);

	/* check 'params' member */
	req_params = cJSON_GetObjectItem(req, JSONRPC_PARAMS_S);
	if (req_params) {
		if (!(req_params->type & (cJSON_Array|cJSON_Object)) ||
			!req_params->child)
			return build_err_resp(JSONRPC_INVAL_REQ_CODE,
					MI_SSTR(JSONRPC_INVAL_REQ_MSG), NULL, 0);

		pos_params = req_params->type & cJSON_Array;
	}

	cmd_params.item = req_params;

	cmd = lookup_mi_cmd(req_method->valuestring, strlen(req_method->valuestring));
	if (!cmd)
		return build_err_resp(JSONRPC_NOT_FOUND_CODE,
				MI_SSTR(JSONRPC_NOT_FOUND_MSG), NULL, 0);

	if (pos_params && (cmd->flags & MI_NAMED_PARAMS_ONLY))
		return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
				MI_SSTR(ERR_DET_POS_PARAMS_S));

	/* use the correct 'recipe' of the command based
	 * on the received parameters */
	cmd_recipe = get_cmd_recipe(cmd->recipes, req_params, pos_params,
					&is_ambiguous);
	if (!cmd_recipe)
		return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), NULL, 0);
	else if (is_ambiguous)
		return build_err_resp(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
				MI_SSTR(ERR_DET_AMBIG_CALL_S));

	cmd_params.list = cmd_recipe->params;

	resp = cmd_recipe->cmd(&cmd_params, async_hdl);

	if (resp == NULL)
		return build_err_resp(JSONRPC_SERVER_ERR_CODE,
				MI_SSTR(JSONRPC_SERVER_ERR_MSG), NULL, 0);
	else 
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
			if (add_mi_int(resp, MI_SSTR(JSONRPC_ID_S), id->valueint) < 0) {
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

char *print_mi_response(mi_response_t *resp, mi_request_t *req)
{
	char *resp_str;
	mi_item_t *req_id;
	mi_item_t *res_err, *res_err_code = NULL;

	res_err = cJSON_GetObjectItem(resp, JSONRPC_ERROR_S);
	if (res_err) {
		res_err_code = cJSON_GetObjectItem(res_err, JSONRPC_ERROR_S);
		if (!res_err_code) {
			LM_ERR("no error code for MI error response\n");
			return NULL;
		}
	}

	req_id = cJSON_GetObjectItem(req, JSONRPC_ID_S);
	if (!req_id) {
		/* this is a jsonrpc notification (no id but valid request otherwise)
		 * -> no response */
		if (!res_err)
			return MI_NO_RPL;

		if (res_err_code->valueint != JSONRPC_PARSE_ERR_CODE &&
			res_err_code->valueint != JSONRPC_INVAL_REQ_CODE)
			return MI_NO_RPL;
	}

	if (add_id_to_response(req_id, resp) < 0)
		return NULL;

	_init_mi_sys_mem_hooks();
	resp_str = cJSON_Print(resp);
	if (!resp_str)
		LM_ERR("Failed to build JSON\n");
	_init_mi_pkg_mem_hooks();

	return resp_str;
}

void free_mi_request(mi_request_t *request)
{
	_init_mi_sys_mem_hooks();

	cJSON_Delete(request);

	_init_mi_pkg_mem_hooks();
}

void free_mi_response_str(char *resp_str)
{
	_init_mi_sys_mem_hooks();

	cJSON_PurgeString(resp_str);

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
		return init_mi_error(404, MI_SSTR(MI_UNKNOWN_CMD), 0, 0);

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
