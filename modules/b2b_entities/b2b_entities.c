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
#include "ua_api.h"

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
struct script_route_ref *req_route_ref  = NULL;
struct script_route_ref *reply_route_ref = NULL;
str db_url;
str b2be_cdb_url;
str cdb_key_prefix = str_init("b2be$");
db_con_t *b2be_db;
db_func_t b2be_dbf;
str b2be_dbtable= str_init("b2b_entities");
static int b2b_update_period = 100;
int uac_auth_loaded;
str b2b_key_prefix = str_init("B2B");
int b2be_db_mode = WRITE_BACK;
b2b_table server_htable;
b2b_table client_htable;
int passthru_prack = 0;

cachedb_funcs b2be_cdbf;
cachedb_con *b2be_cdb;

int b2be_cluster;
int serialize_backend;

int b2b_ctx_idx =-1;

#define DB_COLS_NO  26

/* TM bind */
struct tm_binds tmb;

/* UAC_AUTH bind */
uac_auth_api_t uac_auth_api;

/** Exported functions */
static const cmd_export_t cmds[] = {
	{"ua_session_server_init", (cmd_function)b2b_ua_server_init, {
		{CMD_PARAM_VAR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL,
			fixup_ua_flags, fixup_free_ua_flags},
		{0,0,0}},
		REQUEST_ROUTE},
	{"ua_session_update", (cmd_function)b2b_ua_update, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE|EVENT_ROUTE},
	{"ua_session_reply", (cmd_function)b2b_ua_reply, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE|EVENT_ROUTE},
	{"ua_session_terminate", (cmd_function)b2b_ua_terminate, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE},
	{"load_b2b",  (cmd_function)b2b_entities_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/** Exported parameters */
static const param_export_t params[]={
	{ "server_hsize",          INT_PARAM,    &server_hsize       },
	{ "client_hsize",          INT_PARAM,    &client_hsize       },
	{ "script_req_route",      STR_PARAM,    &script_req_route   },
	{ "script_reply_route",    STR_PARAM,    &script_reply_route },
	{ "db_url",                STR_PARAM,    &db_url.s           },
	{ "cachedb_url",           STR_PARAM, 	 &b2be_cdb_url.s     },
	{ "cachedb_key_prefix",    STR_PARAM, 	 &cdb_key_prefix.s   },
	{ "db_table",              STR_PARAM,    &b2be_dbtable.s     },
	{ "db_mode",               INT_PARAM,    &b2be_db_mode       },
	{ "update_period",         INT_PARAM,    &b2b_update_period  },
	{ "b2b_key_prefix",        STR_PARAM,    &b2b_key_prefix.s   },
	{ "cluster_id",            INT_PARAM,    &b2be_cluster		 },
	{ "passthru_prack",        INT_PARAM,    &passthru_prack     },
	{ "advertised_contact",    STR_PARAM,    &adv_contact.s      },
	{ "ua_default_timeout",    INT_PARAM,    &ua_default_timeout },
	{ 0,                       0,            0                   }
};

/* mandatory parameters */
#define UA_START_MI_PARAMS "ruri", "to", "from"
#define UA_UPDATE_MI_PARAMS "key", "method"
#define UA_REPLY_MI_PARAMS "key", "method", "code", "reason"

static const mi_export_t mi_cmds[] = {
	{ "b2be_list", 0,0,0,{
		{mi_b2be_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "ua_session_client_start", 0, 0, 0, {
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "extra_headers", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "extra_headers", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "extra_headers", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "extra_headers", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "extra_headers", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"extra_headers", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "extra_headers",
			"flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "extra_headers",
			"socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"extra_headers", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "extra_headers",
			"flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "extra_headers",
			"socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "extra_headers", "flags",
			"socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "extra_headers", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"extra_headers", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"extra_headers", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "extra_headers",
			"flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"extra_headers", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"extra_headers", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "extra_headers",
			"flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "extra_headers", "flags", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "extra_headers", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"extra_headers", "flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "body", "content_type",
			"extra_headers", "flags", "socket", 0}},
		{b2b_ua_session_client_start, {UA_START_MI_PARAMS, "proxy", "body",
			"content_type", "extra_headers", "flags", "socket", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "ua_session_update", 0, 0, 0, {
		{b2b_ua_mi_update, {UA_UPDATE_MI_PARAMS, 0}},
		{b2b_ua_mi_update, {UA_UPDATE_MI_PARAMS, "body", 0}},
		{b2b_ua_mi_update, {UA_UPDATE_MI_PARAMS, "extra_headers", 0}},
		{b2b_ua_mi_update, {UA_UPDATE_MI_PARAMS, "body", "content_type", 0}},
		{b2b_ua_mi_update, {UA_UPDATE_MI_PARAMS, "body", "extra_headers", 0}},
		{b2b_ua_mi_update, {UA_UPDATE_MI_PARAMS, "body", "content_type",
			"extra_headers", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "ua_session_reply", 0, 0, 0, {
		{b2b_ua_mi_reply, {UA_REPLY_MI_PARAMS, 0}},
		{b2b_ua_mi_reply, {UA_REPLY_MI_PARAMS, "body", 0}},
		{b2b_ua_mi_reply, {UA_REPLY_MI_PARAMS, "extra_headers", 0}},
		{b2b_ua_mi_reply, {UA_REPLY_MI_PARAMS, "body", "content_type", 0}},
		{b2b_ua_mi_reply, {UA_REPLY_MI_PARAMS, "body", "extra_headers", 0}},
		{b2b_ua_mi_reply, {UA_REPLY_MI_PARAMS, "body", "content_type",
			"extra_headers", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "ua_session_terminate", 0, 0, 0, {
		{b2b_ua_mi_terminate, {"key", 0}},
		{b2b_ua_mi_terminate, {"key", "extra_headers", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "ua_session_list", 0,0,0,{
		{b2b_ua_session_list, {0}},
		{b2b_ua_session_list, {"key", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
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

	if (adv_contact.s)
		adv_contact.len = strlen(adv_contact.s);

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

	if(b2be_db_mode) {
		if (!b2be_cdb_url.s) {
			init_db_url(db_url, 1);
			if (!db_url.s)
				b2be_db_mode = NO_DB;
		} else if (db_url.s) {
			LM_ERR("Both 'db_url' and 'cachedb_url' defined\n");
			return -1;
		} else {
			b2be_cdb_url.len = strlen(b2be_cdb_url.s);
		}
	}

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
	} else if (b2be_db_mode && b2be_cdb_url.s) {
		if (cachedb_bind_mod(&b2be_cdb_url, &b2be_cdbf) < 0) {
			LM_ERR("cannot bind functions for cachedb_url %.*s\n",
			       b2be_cdb_url.len, b2be_cdb_url.s);
			return -1;
		}

		if (!CACHEDB_CAPABILITY(&b2be_cdbf, CACHEDB_CAP_MAP)) {
			LM_ERR("not enough capabilities for cachedb_url %.*s\n",
			       b2be_cdb_url.len, b2be_cdb_url.s);
			return -1;
		}

		b2be_cdb = b2be_cdbf.init(&b2be_cdb_url);
		if (!b2be_cdb) {
			LM_ERR("connecting to database failed\n");
			return -1;
		}

		cdb_key_prefix.len = strlen(cdb_key_prefix.s);

		b2be_initialize();

		/* reload data */
		if(b2b_entities_restore() < 0)
		{
			LM_ERR("Failed to restore data from database\n");
			return -1;
		}

		if(b2be_cdb)
			b2be_cdbf.destroy(b2be_cdb);
		b2be_cdb = NULL;
	}

	if(register_script_cb( b2b_prescript_f, PRE_SCRIPT_CB|REQ_TYPE_CB, 0 ) < 0)
	{
		LM_ERR("Failed to register prescript function\n");
		return -1;
	}

	if (script_req_route)
	{
		req_route_ref = ref_script_route_by_name( script_req_route,
			sroutes->request, RT_NO, REQUEST_ROUTE, 0);
		if (!ref_script_route_is_valid(req_route_ref))
		{
			LM_ERR("route <%s> does not exist\n",script_req_route);
			return -1;
		}
	}

	if (script_reply_route)
	{
		reply_route_ref = ref_script_route_by_name( script_reply_route,
			sroutes->request, RT_NO, REQUEST_ROUTE, 0);
		if (!ref_script_route_is_valid(reply_route_ref))
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

	register_timer("b2be-ua-dlg-timer", ua_dlg_timer_routine, 0, 1,
		TIMER_FLAG_DELAY_ON_DELAY);

	if (init_ua_sess_timer() < 0) {
		LM_ERR("Failed to init ua dlg timer\n");
		return -1;
	}

	if (ua_evi_init() < 0) {
		LM_ERR("Failed to init UA session event\n");
		return 0-1;
	}

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
		B2BE_LOCK_GET(table, i);
		dlg = table[i].first;
		while(dlg)
		{
			dlg_next = dlg->next;
			if((dlg->ua_flags&UA_FL_IS_UA_ENTITY) && dlg->b2b_cback == 0)
			{
				LM_ERR("Found entity callid=%.*s ftag=%.*s ttag=%.*s "
						"not linked to any logic\n",
						dlg->callid.len, dlg->callid.s, dlg->tag[0].len,
						dlg->tag[0].s, dlg->tag[1].len, dlg->tag[1].s);
				b2b_delete_record(dlg, table, i);
			}
			dlg = dlg_next;
		}
		B2BE_LOCK_RELEASE(table, i);
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
	if (b2be_db_mode) {
		if (db_url.s) {
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
		} else {
			if (!b2be_cdbf.init) {
				LM_ERR("cachedb functions not initialized\n");
				return -1;
			}

			b2be_cdb = b2be_cdbf.init(&b2be_cdb_url);
			if (!b2be_cdb) {
				LM_ERR("connecting to database failed\n");
				return -1;
			}

			LM_DBG("child %d: cachedb connection opened successfully\n", rank);
		}
	}
	check_htables();
	return 0;
}

/** Module destroy function */
static void mod_destroy(void)
{
	destroy_ua_sess_timer();

	if (b2be_db_mode==WRITE_BACK) {
		if (b2be_dbf.init) {
			b2be_db = b2be_dbf.init(&db_url);
			if(!b2be_db) {
				LM_ERR("connecting to database failed, unable to flush\n");
			} else {
				b2b_entities_dump(1);
				b2be_dbf.close(b2be_db);
			}
		} else if (b2be_cdbf.init) {
			b2be_cdb = b2be_cdbf.init(&b2be_cdb_url);
			if (!b2be_cdb) {
				LM_ERR("connecting to database failed\n");
			} else {
				b2b_entities_dump(1);
				b2be_cdbf.destroy(b2be_cdb);
			}
		}
	}
	destroy_b2b_htables();
}

int b2b_restore_logic_info(enum b2b_entity_type type, str* key,
		b2b_notify_t cback, void *param, b2b_param_free_cb free_param)
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
	if(b2b_parse_key(key, &hash_index, &local_index) < 0)
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
	dlg->param = param;
	dlg->free_param = free_param;
	return 0;
}

int b2b_update_b2bl_param(enum b2b_entity_type type, str* key,
		str* logic_key, int replicate)
{
	b2b_dlg_t* dlg;
	b2b_table table;
	unsigned int hash_index, local_index;
	int unlock = 1;

	if(!logic_key)
	{
		LM_ERR("NULL logic_key\n");
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
	if(b2b_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", key->len, key->s);
		return -1;
	}
	if (table[hash_index].locked_by != process_no)
		B2BE_LOCK_GET(table, hash_index);
	else
		unlock = 0;

	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg == NULL)
	{
		LM_ERR("No dialog found\n");
		if (unlock)
			B2BE_LOCK_RELEASE(table, hash_index);
		return -1;
	}
	shm_str_sync(&dlg->logic_key, logic_key);
	if (unlock)
		B2BE_LOCK_RELEASE(table, hash_index);

	if (b2be_cluster && replicate)
		replicate_entity_update(dlg, type, hash_index, logic_key, -1, NULL);

	return 0;
}

str *b2b_get_b2bl_key(str* callid, str* from_tag, str* to_tag, str* entity_key)
{
	b2b_dlg_t* dlg;
	unsigned int hash_index, local_index;
	b2b_table table;
	str *tuple_key = NULL;

	if(!callid || !callid->s || !callid->len){
		LM_ERR("Wrong callid param\n");
		return NULL;
	}
	if(!from_tag || !from_tag->s || !from_tag->len){
		LM_ERR("Wrong from_tag param\n");
		return NULL;
	}
	if(!to_tag){
		LM_ERR("Wrong to_tag param\n");
		return NULL;
	}
	/* check if the to tag has the b2b key format
	 * -> meaning that it is a server request */
	if(b2b_parse_key(to_tag, &hash_index, &local_index)>=0)
		table = server_htable;
	else if (b2b_parse_key(callid, &hash_index, &local_index)>=0)
		table = client_htable;
	else
		return NULL; /* to tag and/or callid are not part of this B2B */
	B2BE_LOCK_GET(table, hash_index);
	dlg=b2b_search_htable_dlg(table, hash_index, local_index,
					to_tag, from_tag, callid);
	if(dlg){
		tuple_key = pkg_malloc(sizeof(str) + dlg->logic_key.len);
		if (!tuple_key) {
			LM_ERR("cannot duplicate logic\n");
			return NULL;
		}
		tuple_key->s = (char *)(tuple_key + 1);
		memcpy(tuple_key->s, dlg->logic_key.s, dlg->logic_key.len);
		tuple_key->len = dlg->logic_key.len;
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
	}
	B2BE_LOCK_RELEASE(table, hash_index);
	return tuple_key;
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
	api->entity_exists      = b2b_entity_exists;
	api->restore_logic_info = b2b_restore_logic_info;
	api->register_cb 		= b2b_register_cb;
	api->update_b2bl_param  = b2b_update_b2bl_param;
	api->entities_db_delete = b2b_db_delete;
	api->get_b2bl_key       = b2b_get_b2bl_key;
	api->apply_lumps        = b2b_apply_lumps;
	api->get_context		= b2b_get_context;

	return 0;
}

int mi_print_b2be_dlg(b2b_dlg_t* dlg, mi_item_t *to)
{
	str param;
	dlg_leg_t* leg;
	mi_item_t *cseq_item, *rs_item, *ct_item, *legs_arr, *leg_item;

	if (add_mi_number(to, MI_SSTR("dlg"), dlg->id) < 0)
		goto error;
	/* check if param is printable */
	param = dlg->logic_key;
	if (!str_check_token(&param))
		init_str(&param, "");
	if (add_mi_string(to, MI_SSTR("logic_key"),
		param.s, param.len) < 0)
		goto error;
	if (add_mi_string(to, MI_SSTR("mod_name"),
		dlg->mod_name.s, dlg->mod_name.len) < 0)
		goto error;
	if (add_mi_number(to, MI_SSTR("state"), dlg->state) < 0)
		goto error;
	if (add_mi_number(to, MI_SSTR("last_invite_cseq"),
		dlg->last_invite_cseq) < 0)
		goto error;
	if (add_mi_number(to, MI_SSTR("last_method"),
		dlg->last_method) < 0)
		goto error;

	if (dlg->last_reply_code)
		if (add_mi_number(to, MI_SSTR("last_reply_code"),
			dlg->last_reply_code) < 0)
			goto error;

	if (add_mi_number(to, MI_SSTR("db_flag"), dlg->db_flag) < 0)
		goto error;

	if (dlg->ruri.len)
		if (add_mi_string(to, MI_SSTR("ruri"),
			dlg->ruri.s, dlg->ruri.len) < 0)
			goto error;
	if (add_mi_string(to, MI_SSTR("callid"),
		dlg->callid.s, dlg->callid.len) < 0)
		goto error;
	if (add_mi_string(to, MI_SSTR("from"),
		dlg->from_dname.s, dlg->from_dname.len) < 0)
		goto error;
	if (add_mi_string(to, MI_SSTR("from_uri"),
		dlg->from_uri.s, dlg->from_uri.len) < 0)
		goto error;
	if (add_mi_string(to, MI_SSTR("from_tag"),
		dlg->tag[0].s, dlg->tag[0].len) < 0)
		goto error;

	if (add_mi_string(to, MI_SSTR("to"),
		dlg->to_dname.s, dlg->to_dname.len) < 0)
		goto error;
	if (add_mi_string(to, MI_SSTR("to_uri"),
		dlg->to_uri.s, dlg->to_uri.len) < 0)
		goto error;
	if (add_mi_string(to, MI_SSTR("to_tag"),
		dlg->tag[1].s, dlg->tag[1].len) < 0)
		goto error;

	cseq_item = add_mi_object(to, MI_SSTR("cseq"));
	if (!cseq_item)
		goto error;
	if (add_mi_number(cseq_item, MI_SSTR("caller"), dlg->cseq[0]) < 0)
		goto error;
	if (add_mi_number(cseq_item, MI_SSTR("callee"), dlg->cseq[1]) < 0)
		goto error;

	if (dlg->route_set[0].len||dlg->route_set[1].len)
	{
		rs_item = add_mi_object(to, MI_SSTR("route_set"));
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

	ct_item = add_mi_object(to, MI_SSTR("contact"));
	if (!ct_item)
		goto error;
	if (add_mi_string(ct_item, MI_SSTR("caller"),
		dlg->contact[0].s, dlg->contact[0].len) < 0)
		goto error;
	if (add_mi_string(ct_item, MI_SSTR("callee"),
		dlg->contact[1].s, dlg->contact[1].len) < 0)
		goto error;

	if (dlg->send_sock)
		if (add_mi_string(to, MI_SSTR("send_sock"),
			dlg->send_sock->name.s, dlg->send_sock->name.len) < 0)
			goto error;

	if(dlg->uac_tran||dlg->uas_tran||dlg->update_tran||dlg->cancel_tm_tran)
	{
		if(dlg->uac_tran)
			if (add_mi_string(to, MI_SSTR("tm_tran"),
				MI_SSTR("uac")) < 0)
				goto error;
		if(dlg->uas_tran)
			if (add_mi_string(to, MI_SSTR("tm_tran"),
				MI_SSTR("uas")) < 0)
				goto error;
		if(dlg->update_tran)
			if (add_mi_string(to, MI_SSTR("tm_tran"),
				MI_SSTR("update")) < 0)
				goto error;
		if(dlg->cancel_tm_tran)
			if (add_mi_string(to, MI_SSTR("tm_tran"),
				MI_SSTR("cancel_tm")) < 0)
				goto error;
	}

	if ( (leg=dlg->legs)!=NULL ) {
		legs_arr = add_mi_array(to, MI_SSTR("LEGS"));
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

	return 0;
error:
	LM_ERR("Failed to add MI item\n");
	return -1;
}

int mi_print_b2be_all_dlgs(mi_item_t *resp_arr, b2b_table htable,
	unsigned int hsize, int ua_sessions)
{
	int i;
	b2b_dlg_t* dlg;
	mi_item_t *arr_item;

	for(i = 0; i< hsize; i++)
	{
		B2BE_LOCK_GET(htable, i);
		dlg = htable[i].first;
		while(dlg)
		{
			if (ua_sessions && !(dlg->ua_flags&UA_FL_IS_UA_ENTITY)) {
				dlg = dlg->next;
				continue;
			}

			arr_item = add_mi_object(resp_arr, NULL, 0);
			if (!arr_item)
				goto error;

			if (mi_print_b2be_dlg(dlg, arr_item) < 0)
				goto error;

			dlg = dlg->next;
		}
		B2BE_LOCK_RELEASE(htable, i);
	}
	return 0;
error:
	B2BE_LOCK_RELEASE(htable, i);
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
		if (mi_print_b2be_all_dlgs(resp_arr, server_htable, server_hsize, 0)!=0)
			goto error;
	if (client_htable)
		if (mi_print_b2be_all_dlgs(resp_arr, client_htable, client_hsize, 0)!=0)
			goto error;

	return resp;
error:
	LM_ERR("Unable to create response\n");
	free_mi_response(resp);
	return NULL;
}

