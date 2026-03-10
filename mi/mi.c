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

static mi_response_t *build_err_resp(int code, const char *msg, int msg_len,
		const char *details, int details_len);

#define MI_MODULE_SEP ':'
#define MI_DEFAULT_MODULE_NAME "core"

struct mi_mod_group {
	int id;
	str_const module;
	int start;
	int end;
};

static struct mi_mod_group *mi_mod_groups = 0;
static int mi_mod_groups_no = 0;

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

static inline int get_mi_id(const char *name, int len)
{
	int n;
	int i;

	for( n=0,i=0 ; i<len ; n+=name[i] ,i++ );
	return n;
}


static inline struct mi_cmd* lookup_mi_cmd_id(int id, const char *name, int len)
{
	int i;

	for( i=0 ; i<mi_cmds_no ; i++ ) {
		if ( id==mi_cmds[i].id && len==mi_cmds[i].name.len &&
		memcmp(mi_cmds[i].name.s,name,len)==0 )
			return &mi_cmds[i];
	}

	return 0;
}

static void mark_ambiguous_mi_cmd_name(struct mi_cmd *new_cmd)
{
	const char *new_local_name;
	int new_local_len;
	int i;

	new_local_name = new_cmd->name.s + new_cmd->module.len + 1;
	new_local_len = new_cmd->name.len - new_cmd->module.len - 1;

	for (i = 0; i < mi_cmds_no - 1; i++) {
		if (mi_cmds[i].local_id != new_cmd->local_id ||
				mi_cmds[i].name.len - mi_cmds[i].module.len - 1 != new_local_len ||
				memcmp(mi_cmds[i].name.s + mi_cmds[i].module.len + 1,
					new_local_name, new_local_len) != 0)
			continue;

		mi_cmds[i].flags |= MI_LOCAL_NAME_AMBIGUOUS;
		new_cmd->flags |= MI_LOCAL_NAME_AMBIGUOUS;
	}

}

static inline struct mi_cmd* lookup_mi_cmd_local(const char *name, int len)
{
	struct mi_cmd *cmd;
	struct mi_cmd *match = NULL;
	int local_id;
	int i;

	local_id = get_mi_id(name, len);

	for (i = 0; i < mi_cmds_no; i++) {
		cmd = &mi_cmds[i];
		if (cmd->local_id != local_id ||
				cmd->name.len - cmd->module.len - 1 != len ||
				memcmp(cmd->name.s + cmd->module.len + 1, name, len) != 0)
			continue;

		if ((cmd->flags & MI_LOCAL_NAME_AMBIGUOUS) || match)
			return NULL;

		match = cmd;
	}

	return match;
}

static const char *get_mi_mod_name(const char *mod_name)
{
	if (!mod_name || !*mod_name)
		return MI_DEFAULT_MODULE_NAME;

	return mod_name;
}

static mi_response_t *build_ambiguous_mi_cmd_resp(const char *name, int len)
{
	struct mi_cmd *cmd;
	mi_response_t *resp;
	char *details;
	int details_len;
	int local_len;
	int needed;
	int i;
	int n;
	int p;

	if (!name || len <= 0)
		return NULL;

	if (memchr(name, MI_MODULE_SEP, len))
		return NULL;

	n = 0;
	details_len = 0;
	for (i = 0; i < mi_cmds_no; i++) {
		cmd = &mi_cmds[i];
		local_len = cmd->name.len - cmd->module.len - 1;
		if (local_len != len ||
				memcmp(cmd->name.s + cmd->module.len + 1, name, len) != 0)
			continue;

		details_len += cmd->name.len;
		if (n > 0)
			details_len += 2;
		n++;
	}

	if (n < 2)
		return NULL;

	needed = sizeof("supported names: ") - 1 + details_len;
	details = pkg_malloc(needed + 1);
	if (!details) {
		LM_ERR("no more pkg memory\n");
		return build_err_resp(JSONRPC_AMBIG_METHOD_CODE,
				MI_SSTR(JSONRPC_AMBIG_METHOD_MSG),
				MI_SSTR("ambiguous MI command"));
	}

	memcpy(details, "supported names: ", sizeof("supported names: ") - 1);
	p = sizeof("supported names: ") - 1;
	n = 0;

	for (i = 0; i < mi_cmds_no; i++) {
		cmd = &mi_cmds[i];
		local_len = cmd->name.len - cmd->module.len - 1;
		if (local_len != len ||
				memcmp(cmd->name.s + cmd->module.len + 1, name, len) != 0)
			continue;

		if (n > 0) {
			details[p++] = ',';
			details[p++] = ' ';
		}

		memcpy(details + p, cmd->name.s, cmd->name.len);
		p += cmd->name.len;
		n++;
	}

	details[p] = '\0';
	resp = build_err_resp(JSONRPC_AMBIG_METHOD_CODE,
			MI_SSTR(JSONRPC_AMBIG_METHOD_MSG), details, p);
	pkg_free(details);
	return resp;
}

static int add_mi_mod_group(const char *mod_name, int mod_len, int start, int end)
{
	struct mi_mod_group *groups;
	int mod_id;

	if (start >= end)
		return 0;

	mod_id = get_mi_id(mod_name, mod_len);

	if (mi_mod_groups_no > 0 &&
			mi_mod_groups[mi_mod_groups_no - 1].id == mod_id &&
			mi_mod_groups[mi_mod_groups_no - 1].end == start &&
			mi_mod_groups[mi_mod_groups_no - 1].module.len == mod_len &&
			memcmp(mi_mod_groups[mi_mod_groups_no - 1].module.s,
				mod_name, mod_len) == 0) {
		mi_mod_groups[mi_mod_groups_no - 1].end = end;
		return 0;
	}

	groups = (struct mi_mod_group *)pkg_realloc(mi_mod_groups,
			(mi_mod_groups_no + 1) * sizeof(struct mi_mod_group));
	if (!groups) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	mi_mod_groups = groups;
	mi_mod_groups[mi_mod_groups_no].id = mod_id;
	mi_mod_groups[mi_mod_groups_no].module.s = mod_name;
	mi_mod_groups[mi_mod_groups_no].module.len = mod_len;
	mi_mod_groups[mi_mod_groups_no].start = start;
	mi_mod_groups[mi_mod_groups_no].end = end;
	mi_mod_groups_no++;

	return 0;
}

static char *build_mi_cmd_name(const char *mod_name, const char *cmd_name)
{
	int mod_len;
	int cmd_len;
	char *full_name;

	mod_len = strlen(mod_name);
	cmd_len = strlen(cmd_name);

	full_name = pkg_malloc(mod_len + 1 + cmd_len + 1);
	if (!full_name)
		return NULL;

	memcpy(full_name, mod_name, mod_len);
	full_name[mod_len] = MI_MODULE_SEP;
	memcpy(full_name + mod_len + 1, cmd_name, cmd_len);
	full_name[mod_len + 1 + cmd_len] = '\0';

	return full_name;
}


int register_mi_mod(const char *mod_name, const mi_export_t *mis)
{
	const char *module_name;
	char *cmd_name;
	int mod_len;
	int start;
	int ret;
	int i;

	if (mis==0)
		return 0;

	module_name = get_mi_mod_name(mod_name);
	mod_len = strlen(module_name);
	start = mi_cmds_no;

	for ( i=0 ; mis[i].name ; i++ ) {
		if (strchr(mis[i].name, MI_MODULE_SEP)) {
			LM_ERR("invalid MI cmd <%s> for module %s (must not include '%c')\n",
					mis[i].name, module_name, MI_MODULE_SEP);
			return -1;
		}

		cmd_name = build_mi_cmd_name(module_name, mis[i].name);
		if (!cmd_name) {
			LM_ERR("oom while building MI cmd <%s> for module %s\n",
					mis[i].name, module_name);
			return -1;
		}

		ret = register_mi_cmd(cmd_name, mis[i].help, mis[i].flags,
				mis[i].init_f, mis[i].recipes, module_name);
		if (ret!=0) {
			LM_ERR("failed to register cmd <%s> for module %s\n",
					mis[i].name, module_name);
			pkg_free(cmd_name);
		}
	}

	if (add_mi_mod_group(module_name, mod_len, start, mi_cmds_no) < 0)
		return -1;

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
		mi_child_init_f in, const mi_recipe_t *recipes, const char* mod_name)
{
	struct mi_cmd *cmds;
	int mod_len;
	int id;
	int len;

	if (recipes==0 || name==0 || mod_name==0) {
		LM_ERR("invalid params recipes=%p, name=%s\n", recipes, name);
		return -1;
	}

	mod_len = strlen(mod_name);
	len = strlen(name);
	if (len <= mod_len + 1 || memcmp(name, mod_name, mod_len) != 0 ||
			name[mod_len] != MI_MODULE_SEP) {
		LM_ERR("invalid command <%s> for module %s\n", name, mod_name);
		return -1;
	}

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
	cmds->flags = flags & (~MI_LOCAL_NAME_AMBIGUOUS);
	cmds->name.s = name;
	cmds->name.len = len;
	cmds->module.s = mod_name;
	cmds->module.len = strlen(mod_name);
	cmds->local_id = get_mi_id(name + mod_len + 1, len - mod_len - 1);
	cmds->help.s = help;
	cmds->help.len = help ? strlen(help) : 0;
	cmds->id = id;
	cmds->recipes = recipes;

	mark_ambiguous_mi_cmd_name(cmds);

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
	char *cmd_name;
	struct mi_cmd *cmd;
	int mod_len;
	int mod_id;
	int id;
	int i;
	int j;

	cmd_name = memchr(name, MI_MODULE_SEP, len);
	if (!cmd_name)
		return lookup_mi_cmd_local(name, len);
	if (cmd_name == name || cmd_name == name + len - 1)
		return NULL;

	mod_len = cmd_name - name;
	mod_id = get_mi_id(name, mod_len);
	id = get_mi_id(name, len);

	for (i = 0; i < mi_mod_groups_no; i++) {
		if (mi_mod_groups[i].id != mod_id ||
				mi_mod_groups[i].module.len != mod_len ||
				memcmp(mi_mod_groups[i].module.s, name, mod_len) != 0)
			continue;

		for (j = mi_mod_groups[i].start; j < mi_mod_groups[i].end; j++) {
			cmd = &mi_cmds[j];
			if (id == cmd->id && len == cmd->name.len &&
					memcmp(cmd->name.s, name, len) == 0)
				return cmd;
		}
	}

	return NULL;
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

static int match_named_params(const mi_recipe_t *recipe, mi_item_t *req_params)
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

static int match_no_params(const mi_recipe_t *recipe, mi_item_t *req_params)
{
	mi_item_t *param;
	int i, j;

	for (i = 0; recipe->params[i]; i++) ;

	for (param = req_params->child, j = 0; param; param = param->next, j++) ;

	return i == j;
}

static const mi_recipe_t *get_cmd_recipe(const mi_recipe_t *recipes, mi_item_t *req_params,
								int pos_params, int *params_err)
{
	const mi_recipe_t *match = NULL;
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
	const mi_recipe_t *cmd_recipe;
	char *method;
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
		method = mi_get_req_method(req);
		resp = build_ambiguous_mi_cmd_resp(method, strlen(method));
		if (resp)
			return resp;

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
