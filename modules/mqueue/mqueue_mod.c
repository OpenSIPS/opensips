/**
 * Copyright (C) 2010 Elena-Ramona Modroiu (asipto.com)
 *
 * This file is part of opensips, a free SIP server.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../../parser/parse_param.h"
#include "../../mem/mem.h"

#include "mqueue_api.h"
#include "mqueue_db.h"
#include "api.h"


static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

static int w_mq_add(struct sip_msg *msg, str *mq, str *key, str *val);
static int w_mq_fetch(struct sip_msg *msg, str *mq);
static int w_mq_size(struct sip_msg *msg, str *mq_val);
static int w_mq_pv_free(struct sip_msg *msg, str *mq);
int mq_param(modparam_t type, void *val);
static int bind_mq(mq_api_t *api);
mi_response_t *mi_get_sizes(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_get_size(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_fetch(const mi_params_t *params,
								struct mi_handler *async_hdl);

static pv_export_t mod_pvs[] = {
	{ {"mqk",     sizeof("mqk") - 1},     1090, pv_get_mqk,     0,
		pv_parse_mq_name, 0, 0, 0},
	{ {"mqv",     sizeof("mqv") - 1},     1090, pv_get_mqv,     0,
		pv_parse_mq_name, 0, 0, 0},
	{ {"mq_size", sizeof("mq_size") - 1}, 1090, pv_get_mq_size, 0,
		pv_parse_mq_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

static cmd_export_t cmds[] = {
		{"mq_add",     (cmd_function)w_mq_add,     {
			{CMD_PARAM_STR,0,0},
			{CMD_PARAM_STR,0,0},
			{CMD_PARAM_STR,0,0}, {0,0,0}},
			ALL_ROUTES},
		{"mq_fetch",   (cmd_function)w_mq_fetch,   {
			{CMD_PARAM_STR,0,0}, {0,0,0}},
			ALL_ROUTES},
		{"mq_size",    (cmd_function)w_mq_size,    {
			{CMD_PARAM_STR,0,0}, {0,0,0}},
			ALL_ROUTES},
		{"mq_pv_free", (cmd_function)w_mq_pv_free, {
			{CMD_PARAM_STR,0,0}, {0,0,0}},
			ALL_ROUTES},
		{"bind_mq",    (cmd_function)bind_mq,      {
			{0,0,0}},
			0},
		{0,0,{{0,0,0}},0}
};

static param_export_t params[] = {
		{"db_url",         STR_PARAM,                &mqueue_db_url.s},
		{"mqueue",         STR_PARAM|USE_FUNC_PARAM, (void *)&mq_param},
		{0, 0, 0}
};

static const stat_export_t mod_stats[] = {
	{0,0,0}
};

#define MQH1 "Params: none ; Get the size of all memory queues."
#define MQH2 "Params: [mqueue] ; Get the size of a memory queue."
#define MQH3 "Params: [mqueue] ; Fetch a key-value pair from a memory queue."

static const mi_export_t mi_cmds[] = {
	{"mq_get_sizes", MQH1, 0, 0, {
		{mi_get_sizes, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"mq_get_size",  MQH2, 0, 0, {
		{mi_get_size,  {"name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"mq_fetch",     MQH3, 0, 0, {
		{mi_fetch,     {"name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url},
		{ NULL, NULL },
	},
};

struct module_exports exports = {
		"mqueue",        /* module's name */
		MOD_TYPE_DEFAULT,/* class of this module */
		MODULE_VERSION,
		DEFAULT_DLFLAGS, /* dlopen flags */
		0,               /* load function */
		&deps,           /* OpenSIPS module dependencies */
		cmds,            /* exported functions */
		0,               /* exported async functions */
		params,          /* param exports */
		mod_stats,       /* exported statistics */
		mi_cmds,         /* exported MI functions */
		mod_pvs,         /* exported pseudo-variables */
		0,               /* exported transformations */
		0,               /* extra processes */
		0,               /* module pre-initialization function */
		mod_init,        /* module initialization function */
		0,               /* reply processing function */
		mod_destroy,     /* destroy function */
		child_init,      /* per-child init function */
		0                /* reload confirm function */
};

extern mq_head_t *_mq_head_list;

/**
 * init module function
 */
static int mod_init(void)
{
	mq_head_t *mh = NULL;

	LM_DBG("initializing...\n");

	init_db_url( mqueue_db_url , 1 /*can be null*/);

	if(!mq_head_defined())
		LM_WARN("no mqueue defined\n");
	else {
		mh = _mq_head_list;
		while(mh != NULL) {
			if (mh->dbmode == 1 || mh->dbmode == 2) {
				LM_DBG("queue=[%.*s]\n", mh->name.len, mh->name.s);
				if(mqueue_db_load_queue(&mh->name) < 0) {
					LM_ERR("error loading mqueue: %.*s from DB\n", mh->name.len, mh->name.s);
					return -1;
				}
			}
			mh = mh->next;
		}
	}

	return 0;
}

static int child_init(int rank)
{
	return 0;
}

/**
 * destroy module function
 */
static void mod_destroy(void)
{
	mq_destroy();
}

static int w_mq_fetch(struct sip_msg *msg, str *mq)
{
	int ret;

	ret = mq_head_fetch(mq);
	if(ret < 0)
		return ret;
	return 1;
}

static int w_mq_size(struct sip_msg *msg, str *mq_val)
{
	int ret;

	ret = _mq_get_csize(mq_val);

	if(ret < 0)
		LM_ERR("mqueue %.*s not found\n", mq_val->len, mq_val->s);
	if(ret <= 0)
		ret--;

	return ret;
}

static int w_mq_add(struct sip_msg *msg, str *mq, str *key, str *val)
{
	if(mq_item_add(mq, key, val) < 0)
		return -1;
	return 1;
}

static int w_mq_pv_free(struct sip_msg *msg, str *mq)
{
	mq_pv_free(mq);
	return 1;
}

int mq_param(modparam_t type, void *val)
{
	str mqs;
	param_t *params_list = NULL;
	param_hooks_t phooks;
	param_t *pit = NULL;
	str qname = {0, 0};
	int msize = 0;
	int dbmode = 0;
	int addmode = 0;

	if(val == NULL)
		return -1;

	mqs.s = (char *)val;
	mqs.len = strlen(mqs.s);
	if(mqs.s[mqs.len - 1] == ';')
		mqs.len--;
	if(parse_params(&mqs, CLASS_ANY, &phooks, &params_list) < 0)
		return -1;
	for(pit = params_list; pit; pit = pit->next) {
		if(pit->name.len == 4 && strncasecmp(pit->name.s, "name", 4) == 0) {
			qname = pit->body;
		} else if(pit->name.len == 4
				  && strncasecmp(pit->name.s, "size", 4) == 0) {
			if (str2sint(&pit->body, &msize) < 0)
				goto out_error;
		} else if(pit->name.len == 6
				  && strncasecmp(pit->name.s, "dbmode", 6) == 0) {
			if (str2sint(&pit->body, &dbmode) < 0)
				goto out_error;
		} else if(pit->name.len == 7
				  && strncasecmp(pit->name.s, "addmode", 7) == 0) {
			if (str2sint(&pit->body, &addmode) < 0)
				goto out_error;
		} else {
			LM_ERR("unknown param: %.*s\n", pit->name.len, pit->name.s);
			goto out_error;
		}
	}
	if(qname.len <= 0) {
		LM_ERR("mqueue name not defined: %.*s\n", mqs.len, mqs.s);
		goto out_error;
	}
	if(mq_head_add(&qname, msize, addmode) < 0) {
		LM_ERR("cannot add mqueue: %.*s\n", mqs.len, mqs.s);
		goto out_error;
	}
	LM_INFO("mqueue param: [%.*s|%d|%d|%d]\n", qname.len, qname.s, dbmode,
			addmode, msize);
	mq_set_dbmode(&qname, dbmode);
	free_params(params_list);
	return 0;

out_error:
	free_params(params_list);
	return -1;
}

static int bind_mq(mq_api_t *api)
{
	if(!api)
		return -1;
	api->add = mq_item_add;
	return 0;
}

mi_response_t *mi_get_size(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *mq_obj;
	str mqueue_name;
	int mqueue_sz = 0;

	if (get_mi_string_param(params, "name", &mqueue_name.s, &mqueue_name.len) < 0)
		return init_mi_param_error();

	mqueue_sz = _mq_get_csize(&mqueue_name);
	if(mqueue_sz < 0)
		return init_mi_error(404, MI_SSTR("No such queue"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	mq_obj = add_mi_object(resp_obj, MI_SSTR("Queue"));
	if (!mq_obj)
		goto error;

	if (add_mi_string_fmt(mq_obj, MI_SSTR("name"), mqueue_name.s, mqueue_name.len) < 0)
		goto error;
	if (add_mi_number(mq_obj, MI_SSTR("size"), mqueue_sz) < 0)
		goto error;

	return resp;

error:
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return NULL;
}

mi_response_t *mi_get_sizes(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *mq_array, *mq_item;
	mq_head_t *mh = mq_head_get(NULL);
	int size;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	mq_array = add_mi_array(resp_obj, MI_SSTR("Queue"));
	if (!mq_array)
		goto error;

	while(mh != NULL) {
		lock_get(&mh->lock);
		size = mh->csize;
		lock_release(&mh->lock);
		mq_item = add_mi_object(mq_array, MI_SSTR(""));
		if (!mq_item)
			goto error;
		if (add_mi_string_fmt(mq_item, MI_SSTR("name"), mh->name.s, mh->name.len) < 0)
			goto error;
		if (add_mi_number(mq_item, MI_SSTR("size"), size) < 0)
			goto error;
		mh = mh->next;
	}

	return resp;

error:
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return NULL;
}

mi_response_t *mi_fetch(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *mq_item;
	str mqueue_name;
	int mqueue_sz = 0;
	int ret = 0;
	str *key = NULL;
	str *val = NULL;

	if (get_mi_string_param(params, "name", &mqueue_name.s, &mqueue_name.len) < 0)
		return init_mi_param_error();

	mqueue_sz = _mq_get_csize(&mqueue_name);
	if(mqueue_sz < 0)
		return init_mi_error(404, MI_SSTR("No such queue"));

	ret = mq_head_fetch(&mqueue_name);
	if(ret == -2)
		return init_mi_error(404, MI_SSTR("Empty queue"));
	else if(ret < 0)
		return init_mi_error(404, MI_SSTR("Unexpected error (fetch)"));
	
	key = get_mqk(&mqueue_name);
	val = get_mqv(&mqueue_name);

	if(!val || !key)
		return init_mi_error(404, MI_SSTR("Unexpected error (result)"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	mq_item = add_mi_object(resp_obj, MI_SSTR("Item"));
	if (!mq_item)
		goto error;
	if (add_mi_string_fmt(mq_item, MI_SSTR("key"), key->s, key->len) < 0)
		goto error;
	if (add_mi_string_fmt(mq_item, MI_SSTR("value"), val->s, val->len) < 0)
		goto error;

	return resp;

error:
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return NULL;
}

