/*
 * Copyright (C) 2006 Voice Sistem SRL
 * Copyright (C) 2011-2018 OpenSIPS Solutions
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


/*!
 * \file
 * \brief MI :: Core
 * \ingroup mi
 */



#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

#include "../dprint.h"
#include "../globals.h"
#include "../ut.h"
#include "../pt.h"
#include "../net/net_tcp.h"
#include "../mem/mem.h"
#include "../mem/rpm_mem.h"
#include "../cachedb/cachedb.h"
#include "../evi/event_interface.h"
#include "../ipc.h"
#include "../xlog.h"
#include "../cfg_reload.h"
#include "mi.h"
#include "mi_trace.h"


static str    up_since_ctime;

static int init_mi_uptime(void)
{
	up_since_ctime.s = (char*)pkg_malloc(26);
	if (up_since_ctime.s==0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	ctime_r(&startup_time, up_since_ctime.s);
	up_since_ctime.len = strlen(up_since_ctime.s)-1;
	return 0;
}

static mi_response_t *mi_uptime(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	time_t now;
	char buf[26];

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	time(&now);
	ctime_r(&now, buf);
	if (add_mi_string(resp_obj, MI_SSTR("Now"), buf, strlen(buf)-1) < 0)
		goto error;

	if (add_mi_string(resp_obj, MI_SSTR("Up since"),
		up_since_ctime.s, up_since_ctime.len) < 0)
		goto error;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("Up time"), "%lu [sec]",
		(unsigned long)difftime(now, startup_time)) < 0)
		goto error;

	return resp;

error:
	LM_ERR("failed to add mi item\n");
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_version(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("Server"), (char *)SERVER_HDR+8,
		SERVER_HDR_LEN-8) < 0) {
		LM_ERR("failed to add mi item\n");
		free_mi_response(resp);
		return 0;
	}

	return resp;
}

static mi_response_t *mi_version_1(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string(resp_obj, MI_SSTR("Server"), (char *)SERVER_HDR+8,
		SERVER_HDR_LEN-8) < 0) {
		LM_ERR("failed to add mi item\n");
		free_mi_response(resp);
		return 0;
	}

#ifdef VERSIONTYPE
	if (add_mi_string(resp_obj, MI_SSTR(VERSIONTYPE), MI_SSTR(THISREVISION))<0) {
		LM_ERR("failed to add mi item\n");
		free_mi_response(resp);
		return 0;
	}
#endif

	return resp;
}

static mi_response_t *mi_pwd(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	static int max_len = 0;
	static char *cwd_buf = 0;
	mi_response_t *resp;
	mi_item_t *resp_obj;

	if (cwd_buf==NULL) {
		max_len = pathmax();
		cwd_buf = pkg_malloc(max_len);
		if (cwd_buf==NULL) {
			LM_ERR("no more pkg mem\n");
			return 0;
		}
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (getcwd(cwd_buf, max_len)==0) {
		LM_ERR("getcwd failed = %s\n",strerror(errno));
		goto error;
	}

	if (add_mi_string(resp_obj, MI_SSTR("WD"), cwd_buf, strlen(cwd_buf)) < 0) {
		LM_ERR("failed to mi item\n");
		goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}


static mi_response_t *mi_arg(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_arr;
	int n;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	for ( n=0; n<my_argc ; n++ ) {
		if (add_mi_string(resp_arr, 0, 0, my_argv[n], strlen(my_argv[n])) < 0) {
			LM_ERR("failed to add mi item\n");
			free_mi_response(resp);
			return 0;
		}
	}

	return resp;
}

static mi_response_t *mi_which_cmd(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	mi_item_t *resp_arr, *cmd_arr;
	mi_response_t *resp;
	struct mi_cmd *cmd;
	str cmd_str;
	int i, j;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	if (get_mi_string_param(params, "command", &cmd_str.s, &cmd_str.len) < 0)
		return init_mi_param_error();

	cmd = lookup_mi_cmd(cmd_str.s, cmd_str.len);
	if (!cmd)
		return init_mi_error(404, MI_SSTR("unknown MI command"));
	for (i = 0; i < MAX_MI_RECIPES && cmd->recipes[i].cmd; i++) {
		cmd_arr = add_mi_array(resp_arr, NULL, 0);
		if (! cmd_arr) {
			LM_ERR("failed to add mi array\n");
			free_mi_response(resp);
			return 0;
		}
		for (j = 0; j < MAX_MI_PARAMS && cmd->recipes[i].params[j]; j++) {
			if (add_mi_string(cmd_arr, 0, 0,
					cmd->recipes[i].params[j],
					strlen(cmd->recipes[i].params[j])) < 0) {
				LM_ERR("failed to add mi item\n");
				free_mi_response(resp);
				return 0;
			}
		}
	}

	return resp;
}

static mi_response_t *mi_which(const mi_params_t *params, struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_arr;
	struct mi_cmd  *cmds;
	int size;
	int i;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	get_mi_cmds( &cmds, &size);
	for ( i=0 ; i<size ; i++ ) {
		if (add_mi_string(resp_arr, 0, 0,
			cmds[i].name.s, cmds[i].name.len) < 0) {
			LM_ERR("failed to add mi item\n");
			free_mi_response(resp);
			return 0;
		}
	}

	return resp;
}


static mi_response_t *mi_ps(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *procs_arr, *proc_item;
	int i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	procs_arr = add_mi_array(resp_obj, MI_SSTR("Processes"));
	if (!procs_arr) {
		free_mi_response(resp);
		return 0;
	}

	for ( i=0 ; i<counted_max_processes ; i++ ) {
		if (!is_process_running(i))
			continue;
		proc_item = add_mi_object(procs_arr, 0, 0);
		if (!proc_item)
			goto error;

		if (add_mi_number(proc_item, MI_SSTR("ID"), i) < 0)
			goto error;

		if (add_mi_number(proc_item, MI_SSTR("PID"), pt[i].pid) < 0)
			goto error;

		if (add_mi_string(proc_item, MI_SSTR("Type"),
			pt[i].desc, strlen(pt[i].desc)) < 0)
			goto error;
	}

	return resp;

error:
	LM_ERR("failed to add mi item\n");
	free_mi_response(resp);
	return 0;
}


static mi_response_t *mi_kill(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	kill(0, SIGTERM);

	return init_mi_result_ok();
}


mi_response_t *mi_log_level(const mi_params_t *params, pid_t pid)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int i;
	int new_level;

	if (get_mi_int_param(params, "level", &new_level) < 0)
		return init_mi_param_error();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (pid) {
		if (add_mi_number(resp_obj, MI_SSTR("Log level"), new_level) < 0)
			goto error;
	} else {
		if (add_mi_number(resp_obj, MI_SSTR("New global log level"), new_level) < 0)
			goto error;
	}

	if (pid) {
		/* convert pid to OpenSIPS id */
		i = get_process_ID_by_PID(pid);
		if (i == -1) {
			free_mi_response(resp);
			return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), MI_SSTR("Bad PID"));
		}

		__set_proc_default_log_level(i, new_level);
		__set_proc_log_level(i, new_level);
	} else
		set_global_log_level(new_level);

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *w_log_level(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *procs_arr, *proc_item;
	int i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	procs_arr = add_mi_array(resp_obj, MI_SSTR("Processes"));
	if (!procs_arr) {
		free_mi_response(resp);
		return 0;
	}

	for (i = 0; i < counted_max_processes; i++) {
		if (!is_process_running(i))
			continue;
		proc_item = add_mi_object(procs_arr, NULL, 0);
		if (!proc_item)
			goto error;

		if (add_mi_number(proc_item, MI_SSTR("PID"), pt[i].pid) < 0)
			goto error;

		if (add_mi_number(proc_item, MI_SSTR("Log level"), pt[i].log_level) < 0)
			goto error;

		if (add_mi_string(proc_item, MI_SSTR("Type"),
			pt[i].desc, strlen(pt[i].desc)) < 0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *w_log_level_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_log_level(params, 0);
}

static mi_response_t *w_log_level_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int pid;

	if (get_mi_int_param(params, "pid", &pid) < 0)
		return init_mi_param_error();

	return mi_log_level(params, pid);
}

static mi_response_t *w_xlog_level(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("xLog Level"), *xlog_level) < 0) {
		LM_ERR("failed to add mi item\n");
		free_mi_response(resp);
		return 0;
	}

	return resp;
}


static mi_response_t *w_xlog_level_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int new_level;

	if (get_mi_int_param(params, "level", &new_level) < 0)
		return init_mi_param_error();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("New xLog level"), new_level) < 0) {
		free_mi_response(resp);
		return 0;
	}

	set_shared_xlog_level(new_level);

	return resp;
}



static mi_response_t *mi_cachestore(const 	mi_params_t *params, unsigned int expire)
{
	str mc_system;
	str attr;
	str value;

	if (get_mi_string_param(params, "system", &mc_system.s, &mc_system.len) < 0)
		return init_mi_param_error();

	if (!mc_system.s || mc_system.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty memory cache id"));

	if (get_mi_string_param(params, "attr", &attr.s, &attr.len) < 0)
		return init_mi_param_error();

	if (!attr.s || attr.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty attribute name"));

	if (get_mi_string_param(params, "value", &value.s, &value.len) < 0)
		return init_mi_param_error();

	if (!value.s || value.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty value"));

	if (cachedb_store(&mc_system, &attr, &value, expire) < 0) {
		LM_ERR("cachedb_store command failed\n");
		return init_mi_error(500, MI_SSTR("Cache store command failed"));
	}

	return init_mi_result_ok();
}

static mi_response_t *w_cachestore(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_cachestore(params, 0);
}

static mi_response_t *w_cachestore_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int expire;

	if (get_mi_int_param(params, "expire", &expire) < 0)
		return init_mi_param_error();

	if (expire < 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Negative expire value"));

	return mi_cachestore(params, expire);
}


static mi_response_t *mi_cachefetch(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	str mc_system;
	str attr;
	str value;
	int ret;

	if (get_mi_string_param(params, "system", &mc_system.s, &mc_system.len) < 0)
		return init_mi_param_error();

	if (!mc_system.s || mc_system.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty memory cache id"));

	if (get_mi_string_param(params, "attr", &attr.s, &attr.len) < 0)
		return init_mi_param_error();

	if (!attr.s || attr.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty attribute name"));

	ret = cachedb_fetch(&mc_system, &attr, &value);
	if(ret== -1)
	{
		LM_ERR("cachedb_fetch command failed\n");
		return init_mi_error(500, MI_SSTR("Cache fetch command failed"));
	}

	if(ret == -2 || value.s == 0 || value.len == 0)
		return init_mi_error(400, MI_SSTR("Value not found"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp) {
		pkg_free(value.s);
		return 0;
	}

	if (add_mi_string(resp_obj, MI_SSTR("key"), attr.s, attr.len) < 0)
		goto error;

	if (add_mi_string(resp_obj, MI_SSTR("value"), value.s, value.len) < 0)
		goto error;

	pkg_free(value.s);

	return resp;

error:
	pkg_free(value.s);
	free_mi_response(resp);
	return 0;
}


static mi_response_t *mi_cacheremove(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str mc_system;
	str attr;

	if (get_mi_string_param(params, "system", &mc_system.s, &mc_system.len) < 0)
		return init_mi_param_error();

	if (!mc_system.s || mc_system.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty memory cache id"));

	if (get_mi_string_param(params, "attr", &attr.s, &attr.len) < 0)
		return init_mi_param_error();

	if (!attr.s || attr.len == 0)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Empty attribute name"));

	if(cachedb_remove(&mc_system, &attr)< 0)
	{
		LM_ERR("cachedb_remove command failed\n");
		return init_mi_error(500, MI_SSTR("Cache remove command failed"));
	}

	return init_mi_result_ok();
}


/* RPC function send by an MI process to force a pkg mem dump into
 * a certain process
 */
static void rpc_do_pkg_dump(int sender_id, void *llevel)
{
	#ifdef PKG_MALLOC
	int bk;

	bk = memdump;
	if ( llevel!=0)
		memdump = (int)(long)llevel;
	LM_GEN1(memdump, "Memory status (pkg):\n");
	pkg_status();
	memdump = bk;
	#endif

	return;
}

static mi_response_t *mi_mem_pkg_dump(const mi_params_t *params, int llevel)
{
	int i;
	pid_t pid = 0;

	if (get_mi_int_param(params, "pid", &pid) < 0)
		return init_mi_param_error();

	/* convert pid to OpenSIPS id */
	i = get_process_ID_by_PID(pid);
	if (i == -1)
		return init_mi_error(404, MI_SSTR("Process not found"));

	if (IPC_FD_WRITE(i)<=0)
		return init_mi_error(500, MI_SSTR("Process does not support mem dump"));

	if (ipc_send_rpc( i, rpc_do_pkg_dump, (void*)(long)llevel)<0) {
		LM_ERR("failed to trigger pkg dump for process %d\n", i);
		return init_mi_error(500, MI_SSTR("Internal error"));
	}

	return init_mi_result_ok();
}

static mi_response_t *w_mem_pkg_dump_1(const mi_params_t *params,
									struct mi_handler *async_hdl)
{
	return mi_mem_pkg_dump(params, 0);
}

static mi_response_t *w_mem_pkg_dump_2(const mi_params_t *params,
									struct mi_handler *async_hdl)
{
	int llevel;

	if (get_mi_int_param(params, "log_level", &llevel) < 0)
		return init_mi_param_error();

	return mi_mem_pkg_dump(params, llevel);
}


static mi_response_t *mi_mem_shm_dump(int llevel)
{
	int bk;

	bk = memdump;
	if (llevel!=0)
		memdump = llevel;
	LM_GEN1(memdump, "Memory status (shm):\n");
	shm_status();
	memdump = bk;

	return init_mi_result_ok();
}

static mi_response_t *w_mem_shm_dump(const mi_params_t *params,
									struct mi_handler *async_hdl)
{
	return mi_mem_shm_dump(0);
}

static mi_response_t *w_mem_shm_dump_1(const mi_params_t *params,
									struct mi_handler *async_hdl)
{
	int llevel;

	if (get_mi_int_param(params, "log_level", &llevel) < 0)
		return init_mi_param_error();

	return mi_mem_shm_dump(llevel);
}

static mi_response_t *mi_mem_rpm_dump(int llevel)
{
	int bk;

	bk = memdump;
	if (llevel!=0)
		memdump = llevel;
	LM_GEN1(memdump, "Memory status (rpm):\n");
	rpm_status();
	memdump = bk;

	return init_mi_result_ok();
}

static mi_response_t *w_mem_rpm_dump(const mi_params_t *params,
									struct mi_handler *async_hdl)
{
	return mi_mem_rpm_dump(0);
}

static mi_response_t *w_mem_rpm_dump_1(const mi_params_t *params,
									struct mi_handler *async_hdl)
{
	int llevel;

	if (get_mi_int_param(params, "log_level", &llevel) < 0)
		return init_mi_param_error();

	return mi_mem_rpm_dump(llevel);
}

static mi_response_t *w_reload_routes(const mi_params_t *params,
							struct mi_handler *async_hdl)
{
	if (reload_routing_script()==0)
		return init_mi_result_ok();
	return init_mi_error( 500, MI_SSTR("reload failed"));
}



static mi_export_t mi_core_cmds[] = {
	{ "uptime", "prints various time information about OpenSIPS - "
		"when it started to run, for how long it runs", 0, init_mi_uptime, {
		{mi_uptime, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "version", "prints the version string of a runningOpenSIPS", 0, 0, {
		{mi_version, {0}},
		{mi_version_1, {"revision", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "pwd", "prints the working directory of OpenSIPS", 0, 0, {
		{mi_pwd, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "arg", "returns the full list of arguments used at startup", 0, 0, {
		{mi_arg, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "which", "lists all available MI commands", 0, 0, {
		{mi_which, {0}},
		{mi_which_cmd, {"command", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "ps", "lists all processes used by OpenSIPS", 0, 0, {
		{mi_ps, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "kill", "terminates OpenSIPS", 0, 0, {
		{mi_kill, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "log_level", "gets/sets the per process or global log level in OpenSIPS",
		0, 0, {
		{w_log_level, 	{0}},
		{w_log_level_1, {"level", 0}},
		{w_log_level_2, {"level", "pid", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "xlog_level", "gets/sets the per process or global xlog level in OpenSIPS",
		0, 0, {
		{w_xlog_level, 	{0}},
		{w_xlog_level_1, {"level", 0}},
		{EMPTY_MI_RECIPE}
		}
	},

#if defined(Q_MALLOC) && defined(DBG_MALLOC)
	{ "shm_check", "complete scan of the shared memory pool "
		"(if any error is found, OpenSIPS will abort!)", 0, 0, {
		{mi_shm_check, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
#endif
	{ "cache_store", "stores in a cache system a string value", 0, 0, {
		{w_cachestore, {"system", "attr", "value", 0}},
		{w_cachestore_1, {"system", "attr", "value", "expire", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "cache_fetch", "queries for a cache stored value", 0, 0, {
		{mi_cachefetch, {"system", "attr", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "cache_remove", "removes a record from the cache system", 0, 0, {
		{mi_cacheremove, {"system", "attr", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "event_subscribe", "subscribes an event to the Event Interface", 0, 0, {
		{w_mi_event_subscribe, {"event", "socket", 0}},
		{w_mi_event_subscribe_1, {"event", "socket", "expire", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "events_list", "lists all the events advertised through the "
		"Event Interface", 0, 0, {
		{mi_events_list, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "subscribers_list", "lists all the Event Interface subscribers; "
		"Params: [ event [ subscriber ]]", 0, 0, {
		{w_mi_subscribers_list, {0}},
		{w_mi_subscribers_list_1, {"event", 0}},
		{w_mi_subscribers_list_2, {"event", "socket", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "raise_event", "raises an event through the Event Interface; "
		"Params: event [ params ]", 0, 0, {
		{w_mi_raise_event, {"event", 0}},
		{w_mi_raise_event, {"event", "params", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "list_tcp_conns", "list all ongoing TCP based connections", 0, 0, {
		{mi_tcp_list_conns, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "mem_pkg_dump", "forces a status dump of the pkg memory (per process)", 0, 0, {
		{w_mem_pkg_dump_1, {"pid", 0}},
		{w_mem_pkg_dump_2, {"pid", "log_level", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "mem_shm_dump", "forces a status dump of the shm memory", 0, 0, {
		{w_mem_shm_dump, {0}},
		{w_mem_shm_dump_1, {"log_level", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "mem_rpm_dump", "forces a status dump of the restart persistent memory", 0, 0, {
		{w_mem_rpm_dump, {0}},
		{w_mem_rpm_dump_1, {"log_level", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "reload_routes", "triggers the script (routes only) reload", 0, 0, {
		{w_reload_routes, {0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "help", "prints information about MI commands usage", 0, 0, {
		{w_mi_help, {0}},
		{w_mi_help_1, {"mi_cmd", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};



int init_mi_core(void)
{
	if (register_mi_mod( "core", mi_core_cmds)<0) {
		LM_ERR("unable to register core MI cmds\n");
		return -1;
	}

	try_load_trace_api();

	return 0;
}
