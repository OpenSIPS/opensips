/*
 * back-to-back entities module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 *  2011-01-04  new mi function: mi_b2be_list (Ovidiu Sas)
 *  2011-06-27  added authentication support (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../db/db.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../script_cb.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../uac_auth/uac_auth.h"
#include "b2be_db.h"

#include "b2b_entities.h"
#include "server.h"
#include "dlg.h"
#include "b2be_clustering.h"

#define TABLE_VERSION 2

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
int b2b_entities_bind(b2b_api_t* api);
static mi_response_t *mi_b2be_list(const mi_params_t *params,
								struct mi_handler *async_hdl);

/** Global variables */
unsigned int server_hsize = 9;
unsigned int client_hsize = 9;
static char* script_req_route;
static char* script_reply_route;
int req_routeid  = -1;
int reply_routeid = -1;
static str db_url;
db_con_t *b2be_db;
db_func_t b2be_dbf;
str b2be_dbtable= str_init("b2b_entities");
static int b2b_update_period = 100;
int uac_auth_loaded;
str b2b_key_prefix = str_init("B2B");
int b2be_db_mode = WRITE_BACK;
b2b_table server_htable;
b2b_table client_htable;

int b2be_cluster;
int serialize_backend;

int b2b_ctx_idx =-1;

#define DB_COLS_NO  26

/* TM bind */
struct tm_binds tmb;

/* UAC_AUTH bind */
uac_auth_api_t uac_auth_api;

/** Exported functions */
static cmd_export_t cmds[] = {
	{"load_b2b",  (cmd_function)b2b_entities_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/** Exported parameters */
static param_export_t params[]={
	{ "server_hsize",          INT_PARAM,    &server_hsize       },
	{ "client_hsize",          INT_PARAM,    &client_hsize       },
	{ "script_req_route",      STR_PARAM,    &script_req_route   },
	{ "script_reply_route",    STR_PARAM,    &script_reply_route },
	{ "db_url",                STR_PARAM,    &db_url.s           },
	{ "db_table",              STR_PARAM,    &b2be_dbtable.s     },
	{ "db_mode",               INT_PARAM,    &b2be_db_mode       },
	{ "update_period",         INT_PARAM,    &b2b_update_period  },
	{ "b2b_key_prefix",        STR_PARAM,    &b2b_key_prefix.s   },
	{ "cluster_id",            INT_PARAM,    &b2be_cluster		 },
	{ 0,                       0,            0                   }
};

static mi_export_t mi_cmds[] = {
	{ "b2be_list", 0,0,0,{
		{mi_b2be_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",       DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "uac_auth", DEP_WARN  },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ "cluster_id", get_deps_clusterer },
		{ NULL, NULL },
	},
};

/** Module interface */
struct module_exports exports= {
	"b2b_entities",                 /* module name */
	MOD_TYPE_DEFAULT,               /* class of this module */
	MODULE_VERSION,                 /* module version */
	DEFAULT_DLFLAGS,                /* dlopen flags */
	0,				                /* load function */
	&deps,                          /* OpenSIPS module dependencies */
	cmds,                           /* exported functions */
	NULL,                           /* exported async functions */
	params,                         /* exported parameters */
	0,                              /* exported statistics */
	mi_cmds,                        /* exported MI functions */
	0,                              /* exported pseudo-variables */
	0,								/* exported transformations */
	0,                              /* extra processes */
	0,                              /* module pre-initialization function */
	mod_init,                       /* module initialization function */
	(response_function) 0,          /* response handling function */
	(destroy_function) mod_destroy, /* destroy function */
	child_init,                     /* per-child init function */
	0                               /* reload confirm function */
};

void b2be_db_timer_update(unsigned int ticks, void* param)
{
	b2b_entities_dump(0);
}

static void b2b_ctx_free(void *param)
{
	struct b2b_context *ctx = (struct b2b_context *)param;

	if (ctx->b2bl_key.s)
		pkg_free(ctx->b2bl_key.s);
	pkg_free(param);
}

/** Module initialize function */
static int mod_init(void)
{
	/* inspect the parameters */
	if(server_hsize< 1 || server_hsize> 20 ||
			client_hsize< 1 || client_hsize> 20)
	{
		LM_ERR("Wrong hash size. Needs to be greater than 1"
				" and smaller than 20. Be aware that you should set the log 2"
				" value of the real size\n");
		return -1;
	}
	server_hsize = 1<<server_hsize;
	client_hsize = 1<<client_hsize;

	if(b2b_key_prefix.s)
	{
		b2b_key_prefix.len = strlen(b2b_key_prefix.s);
		if(b2b_key_prefix.len > B2B_MAX_PREFIX_LEN)
		{
			LM_ERR("b2b_key_prefix [%s] too long. Maximum size %d\n",
					b2b_key_prefix.s, B2B_MAX_PREFIX_LEN);
			return -1;
		}
	}

	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	/* load the UAC_AUTH API - FIXME it should be loaded only
	 * if authentication is required */
	if(load_uac_auth_api(&uac_auth_api)<0)
	{
		LM_INFO("authentication functionality disabled:"
				" load uac_auth first to enable it\n");
		uac_auth_loaded = 0;
	}
	else
	{
		uac_auth_loaded = 1;
	}

	/* initialize the hash tables; they will be allocated in shared memory
	 * to be accesible by all processes */
	if(init_b2b_htables()< 0)
	{
		LM_ERR("Failed to initialize b2b table\n");
		return -1;
	}
	memset(&b2be_dbf, 0, sizeof(db_func_t));

	if(b2be_db_mode)
		init_db_url(db_url, 1);

	if(b2be_db_mode && db_url.s)
	{
		b2be_dbtable.len = strlen(b2be_dbtable.s);

		/* binding to database module  */
		if (db_bind_mod(&db_url, &b2be_dbf))
		{
			LM_ERR("Database module not found\n");
			return -1;
		}

		if (!DB_CAPABILITY(b2be_dbf, DB_CAP_ALL))
		{
			LM_ERR("Database module does not implement all functions"
					" needed by b2b_entities module\n");
			return -1;
		}

		b2be_db = b2be_dbf.init(&db_url);
		if(!b2be_db)
		{
			LM_ERR("connecting to database failed\n");
			return -1;
		}

		/*verify table versions */
		if(db_check_table_version(&b2be_dbf, b2be_db, &b2be_dbtable, TABLE_VERSION) < 0)
		{
			LM_ERR("error during table version check\n");
			return -1;
		}

		b2be_initialize();

		/* reload data */
		if(b2b_entities_restore() < 0)
		{
			LM_ERR("Failed to restore data from database\n");
			return -1;
		}

		if(b2be_db)
			b2be_dbf.close(b2be_db);
		b2be_db = NULL;
	}
	else
		b2be_db_mode = 0;

	if(register_script_cb( b2b_prescript_f, PRE_SCRIPT_CB|REQ_TYPE_CB, 0 ) < 0)
	{
		LM_ERR("Failed to register prescript function\n");
		return -1;
	}

	if (script_req_route)
	{
		req_routeid = get_script_route_ID_by_name( script_req_route,
			sroutes->request, RT_NO);
		if (req_routeid < 1)
		{
			LM_ERR("route <%s> does not exist\n",script_req_route);
			return -1;
		}
	}

	if (script_reply_route)
	{
		reply_routeid = get_script_route_ID_by_name( script_reply_route,
			sroutes->request, RT_NO);
		if (reply_routeid < 1)
		{
			LM_ERR("route <%s> does not exist\n",script_reply_route);
			return -1;
		}
	}
	if(b2b_update_period < 0)
	{
		LM_ERR("Wrong parameter - b2b_update_period [%d]\n", b2b_update_period);
		return -1;
	}
	if(b2be_db_mode == WRITE_BACK)
		register_timer("b2be-dbupdate", b2be_db_timer_update, 0,
			b2b_update_period, TIMER_FLAG_SKIP_ON_DELAY);
	//register_timer("b2b2-clean", b2be_clean,  0, b2b_update_period);

	if (b2be_init_clustering() < 0) {
		LM_ERR("Failed to init clustering support\n");
		return -1;
	}

	if (b2be_db_mode != NO_DB)
		serialize_backend |= B2BCB_BACKEND_DB;
	if (b2be_cluster)
		serialize_backend |= B2BCB_BACKEND_CLUSTER;

	b2b_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, b2b_ctx_free);

	return 0;
}

void check_htable(b2b_table table, int hsize)
{
	int i;
	b2b_dlg_t* dlg, *dlg_next;

	for(i= 0; i< hsize; i++)
	{
		lock_get(&table[i].lock);
		dlg = table[i].first;
		while(dlg)
		{
			dlg_next = dlg->next;
			if(dlg->b2b_cback == 0)
			{
				LM_ERR("Found entity not linked to any logic\n");
				b2b_delete_record(dlg, table, i);
			}
			dlg = dlg_next;
		}
		lock_release(&table[i].lock);
	}
	table->checked = 1;
}

void check_htables(void)
{
	if(server_htable->checked && client_htable->checked)
		return;
	if(!server_htable->checked)
		check_htable(server_htable, server_hsize);
	if(!client_htable->checked)
		check_htable(client_htable, client_hsize);
}

/** Module child initialize function */
static int child_init(int rank)
{
	/* if database is needed */
	if (b2be_db_mode && db_url.s)
	{
		if (b2be_dbf.init==0)
		{
			LM_CRIT("child_init: database not bound\n");
			return -1;
		}

		b2be_db = b2be_dbf.init(&db_url);
		if(!b2be_db)
		{
			LM_ERR("connecting to database failed\n");
			return -1;
		}
		LM_DBG("child %d: Database connection opened successfully\n", rank);
	}
	check_htables();
	return 0;
}

/** Module destroy function */
static void mod_destroy(void)
{
	if (b2be_dbf.init && b2be_db_mode==WRITE_BACK) {
		b2be_db = b2be_dbf.init(&db_url);
		if(!b2be_db) {
			LM_ERR("connecting to database failed, unable to flush\n");
		} else {
			b2b_entities_dump(1);
			b2be_dbf.close(b2be_db);
		}
	}
	destroy_b2b_htables();
}

int b2b_restore_logic_info(enum b2b_entity_type type, str* key,
		b2b_notify_t cback)
{
	b2b_dlg_t* dlg;
	b2b_table table;
	unsigned int hash_index, local_index;

	if(server_htable== NULL)
	{
		LM_ERR("You have to load b2b_entities module before b2b_logic module\n");
		return -1;
	}

	if(type == B2B_SERVER)
	{
		table = server_htable;
	}
	else
	{
		table = client_htable;
	}
	if(b2b_parse_key(key, &hash_index, &local_index, NULL) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", key->len, key->s);
		return -1;
	}
	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg == NULL)
	{
		LM_ERR("No dialog found for key [%.*s]\n", key->len, key->s);
		return -1;
	}
	dlg->b2b_cback = cback;
	return 0;
}

int b2b_update_b2bl_param(enum b2b_entity_type type, str* key,
		str* param, int replicate)
{
	b2b_dlg_t* dlg;
	b2b_table table;
	unsigned int hash_index, local_index;
	int unlock = 1;

	if(!param)
	{
		LM_ERR("NULL param\n");
		return -1;
	}
	if(param->len > B2BL_MAX_KEY_LEN)
	{
		LM_ERR("parameter too long, received [%d], maximum [%d]\n",
				param->len, B2BL_MAX_KEY_LEN);
		return -1;
	}

	if(type == B2B_SERVER)
	{
		table = server_htable;
	}
	else
	{
		table = client_htable;
	}
	if(b2b_parse_key(key, &hash_index, &local_index, NULL) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", key->len, key->s);
		return -1;
	}
	if (table[hash_index].locked_by != process_no)
		lock_get(&table[hash_index].lock);
	else
		unlock = 0;

	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg == NULL)
	{
		LM_ERR("No dialog found\n");
		if (unlock)
			lock_release(&table[hash_index].lock);
		return -1;
	}
	memcpy(dlg->param.s, param->s, param->len);
	dlg->param.len = param->len;
	if (unlock)
		lock_release(&table[hash_index].lock);

	if (b2be_cluster && replicate)
		replicate_entity_update(dlg, type, hash_index, param, -1, NULL);

	return 0;
}

int b2b_get_b2bl_key(str* callid, str* from_tag, str* to_tag, str* entity_key, str* tuple_key)
{
	b2b_dlg_t* dlg;
	unsigned int hash_index, local_index;
	b2b_table table;
	int ret;

	if(!callid || !callid->s || !callid->len){
		LM_ERR("Wrong callid param\n");
		return -1;
	}
	if(!from_tag || !from_tag->s || !from_tag->len){
		LM_ERR("Wrong from_tag param\n");
		return -1;
	}
	if(!to_tag){
		LM_ERR("Wrong to_tag param\n");
		return -1;
	}
	if(!tuple_key || !tuple_key->s || tuple_key->len<B2BL_MAX_KEY_LEN) {
		LM_ERR("Wrong tuple param\n");
		return -1;
	}
	/* check if the to tag has the b2b key format
	 * -> meaning that it is a server request */
	if(b2b_parse_key(to_tag, &hash_index, &local_index, NULL)>=0)
		table = server_htable;
	else if (b2b_parse_key(callid, &hash_index, &local_index, NULL)>=0)
		table = client_htable;
	else
		return -1; /* to tag and/or callid are not part of this B2B */
	lock_get(&table[hash_index].lock);
	dlg=b2b_search_htable_dlg(table, hash_index, local_index,
					to_tag, from_tag, callid);
	if(dlg){
		memcpy(tuple_key->s, dlg->param.s, dlg->param.len);
		tuple_key->len = dlg->param.len;
		if (entity_key) {
			if (table == server_htable) {
				entity_key->s = to_tag->s;
				entity_key->len = to_tag->len;
			} else {
				entity_key->s = callid->s;
				entity_key->len = callid->len;
			}
		}
		LM_DBG("got tuple [%.*s] for entity [%.*s]\n",
			tuple_key->len, tuple_key->s,
			(entity_key?entity_key->len:0),
			(entity_key?entity_key->s:NULL));
		ret = 0;
	} else {
		ret = -1;
	}
	lock_release(&table[hash_index].lock);
	return ret;
}

void *b2b_get_context(void)
{
	struct b2b_context *ctx;

	if (!current_processing_ctx) {
		LM_ERR("no processing ctx found!\n");
		return NULL;
	}

	ctx = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx,
		b2b_ctx_idx);
	if (!ctx) {
		ctx = pkg_malloc(sizeof *ctx);
		if (!ctx) {
			LM_ERR("oom!\n");
			return NULL;
		}
		memset(ctx, 0, sizeof *ctx);

		context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, b2b_ctx_idx,
			ctx);
	}

	return ctx;
}

int b2b_entities_bind(b2b_api_t* api)
{
	if (!api)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}
	api->server_new         = server_new;
	api->client_new         = client_new;
	api->send_request       = b2b_send_request;
	api->send_reply         = b2b_send_reply;
	api->entity_delete      = b2b_entity_delete;
	api->restore_logic_info = b2b_restore_logic_info;
	api->register_cb 		= b2b_register_cb;
	api->update_b2bl_param  = b2b_update_b2bl_param;
	api->entities_db_delete = b2b_db_delete;
	api->get_b2bl_key       = b2b_get_b2bl_key;
	api->apply_lumps        = b2b_apply_lumps;
	api->get_context		= b2b_get_context;

	return 0;
}


static inline int mi_print_b2be_dlg(mi_item_t *resp_arr, b2b_table htable, unsigned int hsize)
{
	int i;
	str param;
	b2b_dlg_t* dlg;
	dlg_leg_t* leg;
	mi_item_t *arr_item, *cseq_item, *rs_item, *ct_item, *legs_arr, *leg_item;

	for(i = 0; i< hsize; i++)
	{
		lock_get(&htable[i].lock);
		dlg = htable[i].first;
		while(dlg)
		{
			arr_item = add_mi_object(resp_arr, NULL, 0);
			if (!arr_item)
				goto error;

			if (add_mi_number(arr_item, MI_SSTR("dlg"), dlg->id) < 0)
				goto error;
			/* check if param is printable */
			param = dlg->param;
			if (!str_check_token(&param))
				init_str(&param, "");
			if (add_mi_string(arr_item, MI_SSTR("param"),
				param.s, param.len) < 0)
				goto error;
			if (add_mi_string(arr_item, MI_SSTR("mod_name"),
				dlg->mod_name.s, dlg->mod_name.len) < 0)
				goto error;
			if (add_mi_number(arr_item, MI_SSTR("state"), dlg->state) < 0)
				goto error;
			if (add_mi_number(arr_item, MI_SSTR("last_invite_cseq"),
				dlg->last_invite_cseq) < 0)
				goto error;
			if (add_mi_number(arr_item, MI_SSTR("last_method"),
				dlg->last_method) < 0)
				goto error;

			if (dlg->last_reply_code)
				if (add_mi_number(arr_item, MI_SSTR("last_reply_code"),
					dlg->last_reply_code) < 0)
					goto error;

			if (add_mi_number(arr_item, MI_SSTR("db_flag"), dlg->db_flag) < 0)
				goto error;

			if (dlg->ruri.len)
				if (add_mi_string(arr_item, MI_SSTR("ruri"),
					dlg->ruri.s, dlg->ruri.len) < 0)
					goto error;
			if (add_mi_string(arr_item, MI_SSTR("callid"),
				dlg->callid.s, dlg->callid.len) < 0)
				goto error;
			if (add_mi_string(arr_item, MI_SSTR("from"),
				dlg->from_dname.s, dlg->from_dname.len) < 0)
				goto error;
			if (add_mi_string(arr_item, MI_SSTR("from_uri"),
				dlg->from_uri.s, dlg->from_uri.len) < 0)
				goto error;
			if (add_mi_string(arr_item, MI_SSTR("from_tag"),
				dlg->tag[0].s, dlg->tag[0].len) < 0)
				goto error;

			if (add_mi_string(arr_item, MI_SSTR("to"),
				dlg->to_dname.s, dlg->to_dname.len) < 0)
				goto error;
			if (add_mi_string(arr_item, MI_SSTR("to_uri"),
				dlg->to_uri.s, dlg->to_uri.len) < 0)
				goto error;
			if (add_mi_string(arr_item, MI_SSTR("to_tag"),
				dlg->tag[1].s, dlg->tag[1].len) < 0)
				goto error;

			cseq_item = add_mi_object(arr_item, MI_SSTR("cseq"));
			if (!cseq_item)
				goto error;
			if (add_mi_number(cseq_item, MI_SSTR("caller"), dlg->cseq[0]) < 0)
				goto error;
			if (add_mi_number(cseq_item, MI_SSTR("callee"), dlg->cseq[1]) < 0)
				goto error;

			if (dlg->route_set[0].len||dlg->route_set[1].len)
			{
				rs_item = add_mi_object(arr_item, MI_SSTR("route_set"));
				if (!rs_item)
					goto error;

				if (dlg->route_set[0].len)
					if (add_mi_string(rs_item, MI_SSTR("caller"),
						dlg->route_set[0].s, dlg->route_set[0].len) < 0)
						goto error;

				if (dlg->route_set[1].len)
					if (add_mi_string(rs_item, MI_SSTR("callee"),
						dlg->route_set[1].s, dlg->route_set[1].len) < 0)
						goto error;
			}

			ct_item = add_mi_object(arr_item, MI_SSTR("contact"));
			if (!ct_item)
				goto error;
			if (add_mi_string(ct_item, MI_SSTR("caller"),
				dlg->contact[0].s, dlg->contact[0].len) < 0)
				goto error;
			if (add_mi_string(ct_item, MI_SSTR("callee"),
				dlg->contact[1].s, dlg->contact[1].len) < 0)
				goto error;

			if (dlg->send_sock)
				if (add_mi_string(arr_item, MI_SSTR("send_sock"),
					dlg->send_sock->name.s, dlg->send_sock->name.len) < 0)
					goto error;

			if(dlg->uac_tran||dlg->uas_tran||dlg->update_tran||dlg->cancel_tm_tran)
			{
				if(dlg->uac_tran)
					if (add_mi_string(arr_item, MI_SSTR("tm_tran"),
						MI_SSTR("uac")) < 0)
						goto error;
				if(dlg->uas_tran)
					if (add_mi_string(arr_item, MI_SSTR("tm_tran"),
						MI_SSTR("uas")) < 0)
						goto error;
				if(dlg->update_tran)
					if (add_mi_string(arr_item, MI_SSTR("tm_tran"),
						MI_SSTR("update")) < 0)
						goto error;
				if(dlg->cancel_tm_tran)
					if (add_mi_string(arr_item, MI_SSTR("tm_tran"),
						MI_SSTR("cancel_tm")) < 0)
						goto error;
			}

			if ( (leg=dlg->legs)!=NULL ) {
				legs_arr = add_mi_array(arr_item, MI_SSTR("LEGS"));
				if (!legs_arr)
					goto error;

				while(leg)
				{
					leg_item = add_mi_object(legs_arr, NULL, 0);
					if (!leg_item)
						goto error;

					if (add_mi_number(leg_item, MI_SSTR("id"), leg->id) < 0)
						goto error;
					if (add_mi_string(leg_item, MI_SSTR("tag"),
						leg->tag.s, leg->tag.len) < 0)
						goto error;
					if (add_mi_number(leg_item, MI_SSTR("cseq"), leg->cseq) < 0)
						goto error;
					if (add_mi_string(leg_item, MI_SSTR("contact"),
						leg->contact.s, leg->contact.len) < 0)
						goto error;
					if(leg->route_set.len)
						if (add_mi_string(leg_item, MI_SSTR("route_set"),
							leg->route_set.s, leg->route_set.len) < 0)
							goto error;

					leg=leg->next;
				}
			}

			dlg = dlg->next;
		}
		lock_release(&htable[i].lock);
	}
	return 0;
error:
	lock_release(&htable[i].lock);
	LM_ERR("failed to add node\n");
	return -1;
}

static mi_response_t *mi_b2be_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_arr;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	if (server_htable)
		if (mi_print_b2be_dlg(resp_arr, server_htable, server_hsize)!=0)
			goto error;
	if (client_htable)
		if (mi_print_b2be_dlg(resp_arr, client_htable, client_hsize)!=0)
			goto error;

	return resp;
error:
	LM_ERR("Unable to create response\n");
	free_mi_response(resp);
	return NULL;
}

