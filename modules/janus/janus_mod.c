/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
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
 * History:
 * --------
 * 2024-12-03 initial release (vlad)
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../net/tcp_common.h"
#include "../../mi/mi.h"
#include "../../db/db.h"
#include "../tls_mgm/api.h"
#include "janus_common.h"
#include "janus_ws.h"
#include "janus_proc.h"

#include "../../resolve.h"
#include "../../forward.h"

static int  mod_init(void);
static int  child_init(int);
static void mod_destroy(void);
static int janus_ping_interval = 5; /* we default to pinging every 5 seconds */

static str janus_db_url;
static str janus_db_table = str_init("janus"); 
static str janus_id_col = str_init("janus_id");
static str janus_url_col = str_init("janus_url");
static int janus_db_init(void);
static db_func_t db;
static db_con_t *db_handle;

#define JANUS_TABLE_VERSION 1

static int w_janus_send_request(struct sip_msg *msg, str *janus_id,str *request, pv_spec_t *reply);

static cmd_export_t cmds[] = {
	{"janus_send_request", (cmd_function)w_janus_send_request, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},{0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};


static param_export_t params[] = {
	{"janus_send_timeout",		INT_PARAM, &janusws_send_timeout       },
	{"janus_max_msg_chunks",	INT_PARAM, &janusws_max_msg_chunks },
	{"janus_cmd_timeout",          	INT_PARAM, &janus_cmd_timeout},
	{"janus_cmd_polling_itv",      	INT_PARAM, &janus_cmd_polling_itv},
	{"janus_ping_interval",      	INT_PARAM, &janus_ping_interval},
	{"janus_db_url",      		STR_PARAM, &janus_db_url.s},
	{"janus_db_table",     		STR_PARAM, &janus_db_table.s},

	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{EMPTY_MI_EXPORT}
};

/* module dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 }
	},
	{ /* modparam dependencies */
		{ "db_url",           get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

/* sending process */
static proc_export_t procs[] = {
	{"JANUS Manager",  0, janus_mgr_wait_init , janus_worker_loop, 1, PROC_FLAG_HAS_IPC},
	{0,0,0,0,0,0}
};

struct module_exports exports = {
	"janus",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	procs,      /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	child_init, /* per-child init function */
	0           /* reload confirm function */
};

static int mod_init(void)
{
	cJSON_Hooks hooks;

	LM_INFO("initializing JANUS protocol\n");

	if (janus_ipc_init() != 0) {
		LM_ERR("Failed to init JANUS manager IPC \n");
		return -1;
	}

	if (janus_mgr_init() != 0) {
		LM_ERR("Failed to init JANUS manager process no \n");
		return -1;
	}

	hooks.malloc_fn = osips_pkg_malloc;
	hooks.free_fn = osips_pkg_free;
	cJSON_InitHooks(&hooks);

	if (janus_db_init() < 0) {
		LM_ERR("Failed to load Janus DB entries\n");
		return -1;
	}

	if ( register_timer( "janus-pinger", janus_pinger_routine, NULL,
	janus_ping_interval, TIMER_FLAG_DELAY_ON_DELAY)<0) {
		LM_ERR("failed to register timer\n");
		return -1;
	}

	if ( janus_register_event() < 0) {
		LM_ERR("Failed to register janus event\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	return 0;
}

static void mod_destroy(void)
{
	/* TODO - destroy */
}

static int w_janus_send_request(struct sip_msg *msg, str *janus_id,str *request, pv_spec_t *reply_spec)
{
	janus_connection* conn;
	uint64_t reply_id;
	cJSON *j_request;
	unsigned int total_us;
	janus_ipc_reply *reply = NULL;
	struct list_head *_, *__;
	pv_value_t pv_val;

	if (ZSTRP(request)) {
		LM_ERR("refusing to run a NULL or empty command!\n");
		return -1;
	}

	j_request = cJSON_Parse(request->s);
	if (j_request == NULL) {
		LM_ERR("refusing to run invalid JSON command %.*s!\n",
		request->len,request->s);
		return -1;
	}

	if ((conn = get_janus_connection_by_id(janus_id)) == NULL) {
		LM_ERR("Unknown JANUS ID %.*s\n",janus_id->len,janus_id->s);
		return -1;
	}

	LM_DBG("Found our conn, prep to send out %.*s !! \n",request->len,request->s);

	reply_id = janus_ipc_send_request(conn,j_request);
	if (reply_id == 0) {
		LM_ERR("Failed to queue request %.*s towards %.*s\n",
		request->len,request->s,
		janus_id->len,janus_id->s);
		return -2;
	}

	if (reply_spec == NULL) {
		/* script said they don't care about reply, no need to wait */
		/* for now, assuming there will be no reply at all ( ie. only ACK ),
		 * so there is nothing to cleanup */
		LM_DBG("No janus reply expected - just exiting \n");
		return 1;
	}

	LM_DBG("Expecting reply for transaction %lu\n",reply_id);

	for (total_us = 0; total_us < janus_cmd_timeout * 1000;
	     total_us += janus_cmd_polling_itv) {
		lock_start_write(conn->lists_lk);
		list_for_each_safe(_, __, &conn->janus_replies) {
			reply = list_entry(_, janus_ipc_reply, list);

			if (reply->janus_transaction_id == reply_id) {
				list_del(&reply->list);
				lock_stop_write(conn->lists_lk);
				LM_DBG("got reply after %dms: [%.*s]!\n", total_us / 1000,
				       reply->text.len, reply->text.s);

				pv_val.flags = PV_VAL_STR;
				pv_val.rs = reply->text;

				if (pv_set_value(msg, reply_spec, 0, &pv_val) != 0)
					LM_ERR("Failed to set value for janus reply \n");


				shm_free(reply->text.s);
				shm_free(reply);
				return 1;
			}
		}
		lock_stop_write(conn->lists_lk);

		usleep(janus_cmd_polling_itv);
	}

	LM_ERR("Failed to get janus answer !!! :( \n");
	return -1;
}

int janus_db_init(void) 
{
	db_key_t query_cols[2] = { &janus_id_col, &janus_url_col };
	db_res_t *res = NULL;
	db_val_t *values;
	str janus_id,janus_url;
	int i;

	init_db_url(janus_db_url, 1);

	if (janus_db_url.s == NULL) {
		LM_ERR("No DB_URL configured \n");
		return -1;
	}

	if (db_bind_mod(&janus_db_url, &db) < 0) {
		LM_ERR("failed to load DB API\n");
		return -1;
	}

	db_handle = db.init(&janus_db_url);
	if (!db_handle){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if (db_check_table_version(&db, db_handle, &janus_db_table,
	                           JANUS_TABLE_VERSION) < 0) {
		LM_ERR("table version check failed\n");
		return -1;
	}

	if (db.use_table(db_handle, &janus_db_table) != 0) {
		LM_ERR("failed to use table\n");
		return -1;
	}

	if (db.query(db_handle, 0, 0, 0, query_cols, 0, 2, 0, &res) < 0) {
		LM_ERR("failed to query\n");
		return -1;
	}

	if (RES_ROW_N(res) == 0)
		LM_WARN("table %.*s is empty\n",
		janus_db_table.len, janus_db_table.s);

	for (i = 0; i < RES_ROW_N(res); i++) {
		values = ROW_VALUES(RES_ROWS(res) + i);

		get_str_from_dbval("username", values, 1, 1, janus_id, out_err);
		get_str_from_dbval("password", values+1, 1, 1, janus_url, out_err);

		if (!janus_add_connection(&janus_id,&janus_url)) {
			LM_ERR("Failed to add Janus connection \n");
			goto out_err;
		}
	}

	db.free_result(db_handle, res);
	if (db_handle && db.close)
		db.close(db_handle);

	db_handle = NULL;
	return 0;

out_err:
	db.free_result(db_handle, res);
	if (db_handle && db.close)
		db.close(db_handle);

	db_handle = NULL;

	return -1;
}
