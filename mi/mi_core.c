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
#ifdef HG_MALLOC
#include "../mem/shm_mem.h"
#include "../mem/hg_malloc.h"
#include "../core_stats.h"   /* hg_pkg_peak_all: the per-process pkg high-water */
#endif
#include "../cachedb/cachedb.h"
#include "../evi/event_interface.h"
#include "../ipc.h"
#include "../xlog.h"
#include "../cfg_reload.h"
#include "../status_report.h"
#include "../db/db_pi.h"
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

	if (add_mi_string(resp_obj, MI_SSTR(VERSIONTYPE), MI_SSTR(THISREVISION))<0) {
		LM_ERR("failed to add mi item\n");
		free_mi_response(resp);
		return 0;
	}

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
	struct mi_cmd *cmds;
	struct mi_cmd *cmd;
	str cmd_str;
	int found;
	int size;
	int i, j;

	if (get_mi_string_param(params, "command", &cmd_str.s, &cmd_str.len) < 0)
		return init_mi_param_error();

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	if (cmd_str.len > 0 && cmd_str.s[cmd_str.len - 1] == ':') {
		found = 0;
		get_mi_cmds(&cmds, &size);
		for (i = 0; i < size; i++) {
			if (cmds[i].name.len < cmd_str.len ||
					memcmp(cmds[i].name.s, cmd_str.s, cmd_str.len) != 0)
				continue;
			found = 1;
			if (add_mi_string(resp_arr, 0, 0,
					cmds[i].name.s, cmds[i].name.len) < 0) {
				LM_ERR("failed to add mi item\n");
				free_mi_response(resp);
				return 0;
			}
		}

		if (found)
			return resp;

		free_mi_response(resp);
		return init_mi_error(404, MI_SSTR("unknown MI command"));
	}

	cmd = lookup_mi_cmd(cmd_str.s, cmd_str.len);
	if (!cmd) {
		free_mi_response(resp);
		return init_mi_error(404, MI_SSTR("unknown MI command"));
	}
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

		/* -1 = never pinned (no pin_workers / no matching group) */
		if (add_mi_number(proc_item, MI_SSTR("PinnedCPU"),
			pt[i].pinned_cpu) < 0)
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

static int mi_add_profiling_proc_item(mi_item_t *procs_arr, int i)
{
	mi_item_t *proc_item;

	proc_item = add_mi_object(procs_arr, NULL, 0);
	if (!proc_item)
		return -1;

	if (add_mi_number(proc_item, MI_SSTR("ID"), i) < 0)
		return -1;

	if (add_mi_number(proc_item, MI_SSTR("PID"), pt[i].pid) < 0)
		return -1;

	if (add_mi_number(proc_item, MI_SSTR("Profiling level"),
		pt[i].profiling_proc_level) < 0)
		return -1;

	if (add_mi_string(proc_item, MI_SSTR("Type"),
		pt[i].desc, strlen(pt[i].desc)) < 0)
		return -1;

	return 0;
}

static mi_response_t *w_profiling_proc(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int id;
	int pid;
	int level;
	int have_id;
	int have_pid;
	int have_level;
	int target_idx = -1;
	int i;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *procs_arr;

	have_id = (try_get_mi_int_param(params, "id", &id) == 0);
	have_pid = (try_get_mi_int_param(params, "pid", &pid) == 0);
	have_level = (try_get_mi_int_param(params, "level", &level) == 0);

	if (have_id && have_pid)
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("Only one of 'id' or 'pid' is allowed"));

	if (have_id) {
		if (id < 0 || id >= counted_max_processes)
			return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
				MI_SSTR("Bad process ID"));
		target_idx = id;
	} else if (have_pid) {
		target_idx = get_process_ID_by_PID(pid);
		if (target_idx < 0)
			return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
				MI_SSTR(JSONRPC_INVAL_PARAMS_MSG), MI_SSTR("Bad PID"));
	}

	if (have_level) {
		if (level < LEVEL_OFF)
			level = LEVEL_OFF;
		else if (level > LEVEL_FULL)
			level = LEVEL_FULL;

		if (target_idx >= 0) {
			pt[target_idx].profiling_proc_level = level;
		} else {
			for (i = 0; i < counted_max_processes; i++)
				pt[i].profiling_proc_level = level;
		}
		return init_mi_result_ok();
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	procs_arr = add_mi_array(resp_obj, MI_SSTR("Processes"));
	if (!procs_arr) {
		free_mi_response(resp);
		return 0;
	}

	if (target_idx >= 0) {
		if (mi_add_profiling_proc_item(procs_arr, target_idx) < 0) {
			free_mi_response(resp);
			return 0;
		}
	} else {
		for (i = 0; i < counted_max_processes; i++)
			if (mi_add_profiling_proc_item(procs_arr, i) < 0) {
				free_mi_response(resp);
				return 0;
			}
	}

	return resp;
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

static mi_response_t *w_log_level_filter_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	str consumer;
	int level_filter;

	if (get_mi_string_param(params, "consumer", &consumer.s, &consumer.len) < 0)
		return init_mi_param_error();

	if (get_log_consumer_level_filter(&consumer, &level_filter) < 0)
		return init_mi_error(404, MI_SSTR("Unknown log consumer"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("Log level filter"), level_filter) < 0)
		goto error;

	return resp;
error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *w_log_level_filter_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str consumer;
	int level_filter;

	if (get_mi_string_param(params, "consumer", &consumer.s, &consumer.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "level_filter", &level_filter) < 0)
		return init_mi_param_error();

	if (set_log_consumer_level_filter(&consumer, level_filter))
		return init_mi_error(404, MI_SSTR("Unknown log consumer"));

	return init_mi_result_ok();
}

static mi_response_t *w_log_mute_state_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	str consumer;
	int mute_state;

	if (get_mi_string_param(params, "consumer", &consumer.s, &consumer.len) < 0)
		return init_mi_param_error();

	if (get_log_consumer_mute_state(&consumer, &mute_state) < 0)
		return init_mi_error(404, MI_SSTR("Unknown log consumer"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("mute state"), mute_state) < 0)
		goto error;

	return resp;
error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *w_log_mute_state_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str consumer;
	int mute_state;

	if (get_mi_string_param(params, "consumer", &consumer.s, &consumer.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "mute_state", &mute_state) < 0)
		return init_mi_param_error();

	if (set_log_consumer_mute_state(&consumer, mute_state))
		return init_mi_error(404, MI_SSTR("Unknown log consumer"));

	return init_mi_result_ok();
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



#ifdef HG_MALLOC
/*
 * HG_MALLOC keeps state the shared shmem:/pkgmem: statistics cannot express.
 * Those six figures were designed for a free-list allocator, where freed
 * memory returns to one general pool; HG_MALLOC instead CARVES the arena into
 * fixed size-class chunks that are never given back, so "how much is
 * committed", "how much is live" and "how much can still be handed out" stop
 * being the same question. Rather than overload the shared names further,
 * report the allocator's own view here.
 */
/* @per_process: this arena is private to the answering process (pkg), so stamp
 * whose it is into the payload - see the call site for why that matters */
static int hg_stats_one(mi_item_t *parent, char *name, struct hg_block *hb,
                        int per_process)
{
	mi_item_t *o, *cls_arr, *cls_item;
	struct hg_chunk *ch;
	unsigned int chunks_of[HG_NCLASSES], cell_size_of[HG_NCLASSES];
	unsigned long cells_of[HG_NCLASSES];
	unsigned long carved, live_committed;
	const char *tier;
	int c;

	if (!hb)
		return 0;

	o = add_mi_object(parent, name, strlen(name));
	if (!o)
		return -1;

	if (per_process) {
		const char *d = (process_no >= 0 && pt) ? pt[process_no].desc : "?";

		if (add_mi_number(o, MI_SSTR("pid"), my_pid()) < 0)
			return -1;
		if (add_mi_string(o, MI_SSTR("process"), (char *)d, strlen(d)) < 0)
			return -1;
		if (add_mi_string(o, MI_SSTR("scope"),
			MI_SSTR("this process only - see pkmem: for every process")) < 0)
			return -1;
	}

	carved = hb->real_used;
	tier = hg_mem_tier_str(hb->tier);
	/* call this before reading max_live_used: the high-water mark is
	 * refreshed on read, so sampling it here keeps live_peak in step with
	 * shmem:max_used_size instead of reporting a stale 0 until something
	 * else happens to query the statistics */
	live_committed = hg_get_real_used(hb);

	if (add_mi_string(o, MI_SSTR("tier"), (char *)tier, strlen(tier)) < 0)
		return -1;
	/*
	 * "tier" above is what INIT achieved. Growth deltas negotiate their
	 * backing separately and may land lower, so a grown arena is described
	 * by the byte split, not by one label - the label alone would be the
	 * "outcome reported as an attribute" mistake. Emitted only when a
	 * second tier actually holds bytes, so the common case stays terse.
	 */
	{
		int nt = 0, t;
		for (t = HG_MEM_HUGETLB; t <= HG_MEM_4K; t++)
			if (hb->tier_bytes[t])
				nt++;
		if (nt > 1) {
			mi_item_t *ta = add_mi_object(o, MI_SSTR("tier_bytes"));

			if (!ta)
				return -1;
			for (t = HG_MEM_HUGETLB; t <= HG_MEM_4K; t++) {
				/* add_mi_number() takes a non-const name; the tier
				 * strings are literals it only reads */
				char *ts = (char *)hg_mem_tier_str((enum hg_mem_tier)t);

				if (hb->tier_bytes[t] &&
				    add_mi_number(ta, ts, strlen(ts),
				                  hb->tier_bytes[t]) < 0)
					return -1;
			}
		}
	}
	if (add_mi_number(o, MI_SSTR("total_size"), hb->size) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("pinned_mb"), hb->locked_mb) < 0)
		return -1;
	/* v3: committed vs reserved, and whether growth has happened or been
	 * refused. committed == cap means fixed (v2 semantics, the default). */
	if (add_mi_number(o, MI_SSTR("committed"), hb->hsize) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("cap"), hb->hcap) < 0)
		return -1;
	if (hb->hcap > hb->hsize &&
	    add_mi_number(o, MI_SSTR("grow_headroom"), hb->hcap - hb->hsize) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grows"), hb->grows) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_bytes"), hb->grow_bytes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_refused"), hb->grow_refused) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("grow_blocked"), hb->grow_blocked) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("shrinks"), hb->shrinks) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("shrink_bytes"), hb->shrink_bytes) < 0)
		return -1;

	/* carved: bytes taken from the arena and cut into size-class chunks.
	 * Never returned - this is the figure that only ever grows, and the one
	 * that free_size counts down from. */
	if (add_mi_number(o, MI_SSTR("carved"), carved) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("carved_peak"), hb->max_real_used) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("chunks"), hb->nchunks) < 0)
		return -1;
	/* what shmem:free_size reports: arena never yet carved */
	if (add_mi_number(o, MI_SSTR("free_to_carve"), hb->size - carved) < 0)
		return -1;

	/* live: what is actually handed out right now. live_committed and
	 * live_peak are what shmem:real_used_size and shmem:max_used_size
	 * report; payload and cells are shmem:used_size and shmem:fragments. */
	if (add_mi_number(o, MI_SSTR("live_committed"), live_committed) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("live_peak"), hb->max_live_used) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("live_payload"), hg_used(hb)) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("live_cells"), hg_fragments(hb)) < 0)
		return -1;
	/* SLAB ONLY - large allocations (> the top size class) are served by
	 * the boundary-tag tier and never appear here, so this is deliberately
	 * NOT comparable with live_payload above, which counts both. */
	if (add_mi_number(o, MI_SSTR("slab_cell_bytes_live"),
		hg_cell_live(hb)) < 0)
		return -1;

	/* carved but idle: on a private free stack or in the global pool.
	 * Reusable, but ONLY for its own size class - which is why it is not
	 * counted as free_to_carve. */
	/*
	 * v2 reclaim. blocks_carved counts every block ever cut and
	 * blocks_returned every one handed back, so the difference is the live
	 * block count and the ratio is how well reclaim keeps up. Watch
	 * carved against carved_peak too: under v1 carve was monotonic and the
	 * two were always equal, so carved BELOW its peak is itself the proof
	 * that memory is being given back.
	 */
	if (add_mi_number(o, MI_SSTR("blocks_carved"), hb->blocks_carved) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("blocks_returned"), hb->gc_blocks_returned) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("gc_passes"), hb->gc_passes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("cache_flushes"), hb->cache_flushes) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("cells_flushed"), hb->cells_flushed) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_splits"), hb->buddy_splits) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_merges"), hb->buddy_merges) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_merges_init"), hb->buddy_merges_init) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("buddy_free_leaves"), hb->buddy_free_leaves) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("slab_recycled"), hg_slab_recycled(hb)) < 0)
		return -1;

	/*
	 * Corruption detections. Zero is the only acceptable value: every site
	 * that bumps one of these has already refused an operation or leaked a
	 * cell. Broken out by kind because a recurrence of one defect looks very
	 * different from several unrelated rare ones, and the nfree_underflow
	 * kind in particular is the signature of the __thread palloc_slots bug
	 * family. Until now the ONLY detector was a log grep.
	 */
	{
		static const char * const kind[HG_CORRUPT_KINDS] = {
			"class_mismatch", "double_free", "nfree_underflow",
			"bad_class", "foreign_ptr", "buddy_bad_free", "internal"
		};
		mi_item_t *co;
		int k;

		co = add_mi_object(o, MI_SSTR("corruption"));
		if (!co)
			return -1;
		if (add_mi_number(co, MI_SSTR("total"), hg_corrupt_total(hb)) < 0)
			return -1;
		for (k = 0; k < HG_CORRUPT_KINDS; k++)
			if (add_mi_number(co, (char *)kind[k], strlen(kind[k]),
					hb->corrupt[k]) < 0)
				return -1;
	}
	/* the large tier's own footprint, so the split between the two tiers
	 * inside carved is readable rather than inferred by subtraction */
	if (add_mi_number(o, MI_SSTR("large_backing"), hb->large_backing) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_live"), hb->large_live) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_recycled"), hg_large_recycled(hb)) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_chunks_carved"),
			hb->large_chunks_carved) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("large_chunks_returned"),
			hb->large_chunks_returned) < 0)
		return -1;
	/*
	 * Reserve-floor state.  Without these the floor is unobservable in
	 * production: crossing it only emits one LM_WARN and bumps a sweep
	 * generation that is indistinguishable from the periodic sweep.
	 */
	if (add_mi_number(o, MI_SSTR("reserve_floor"), hb->reserve_floor) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("below_floor"), hb->below_floor) < 0)
		return -1;
	if (add_mi_number(o, MI_SSTR("floor_crossings"), hb->floor_crossings) < 0)
		return -1;

	/*
	 * Per-order buddy free lists.  buddy_free_leaves alone cannot say
	 * whether the free space is one contiguous run or the same number of
	 * leaves scattered at order 0 - which is the difference between an
	 * arena that can still serve a large chunk and one that cannot.
	 */
	{
		mi_item_t *ord_arr, *ord_item;
		unsigned int ord;

		ord_arr = add_mi_array(o, MI_SSTR("buddy_free_orders"));
		if (!ord_arr)
			return -1;
		for (ord = 0; ord <= hb->buddy_top && ord <= HG_MAX_ORDERS; ord++) {
			if (!hb->nfree[ord])
				continue;
			ord_item = add_mi_object(ord_arr, 0, 0);
			if (!ord_item)
				return -1;
			if (add_mi_number(ord_item, MI_SSTR("order"), ord) < 0)
				return -1;
			if (add_mi_number(ord_item, MI_SSTR("bytes"),
				(unsigned long)HG_LEAF_SIZE << ord) < 0)
				return -1;
			if (add_mi_number(ord_item, MI_SSTR("blocks"), hb->nfree[ord]) < 0)
				return -1;
		}
	}

	memset(chunks_of, 0, sizeof chunks_of);
	memset(cell_size_of, 0, sizeof cell_size_of);
	memset(cells_of, 0, sizeof cells_of);
	for (ch = hb->chunks; ch; ch = ch->next) {
		if (ch->cls >= HG_NCLASSES)
			continue;
		chunks_of[ch->cls]++;
		cell_size_of[ch->cls] = ch->cell_size;
		cells_of[ch->cls] += ch->cells;
	}

	cls_arr = add_mi_array(o, MI_SSTR("classes"));
	if (!cls_arr)
		return -1;
	for (c = 0; c < HG_NCLASSES; c++) {
		if (!chunks_of[c])
			continue;
		cls_item = add_mi_object(cls_arr, 0, 0);
		if (!cls_item)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("cell_size"),
			cell_size_of[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("chunks"), chunks_of[c]) < 0)
			return -1;
		if (add_mi_number(cls_item, MI_SSTR("cells"), cells_of[c]) < 0)
			return -1;
		/*
		 * Free cells of this class in the SHARED pool.  Cells sitting in
		 * a thread's private cache are not counted - they are unreachable
		 * from here by construction - so this is a lower bound on what is
		 * reusable.  It is still the missing half of the picture: "cells"
		 * alone is capacity, and capacity cannot distinguish a class that
		 * is fully occupied from one that carved a lot and then went idle,
		 * which is precisely the shape of the 2026-08-10 wrong-class
		 * exhaustion on the staging SBCs.
		 */
		if (add_mi_number(cls_item, MI_SSTR("free_shared"),
			hb->gpool_n[c]) < 0)
			return -1;
	}

	return 0;
}

/*
 * Sizing advice for -m / -M, from what the arenas have actually reached.
 *
 * Both margins are multipliers on the observed HIGH-WATER, not on current
 * use: an arena that is 90% idle right now may still have peaked at 90% full
 * during the busy hour, and it is the peak that has to fit.  They differ
 * because the two failure modes differ - shm exhaustion makes an allocation
 * fail and a call drop, pkg exhaustion kills the process outright, so pkg
 * gets the wider margin.
 */
#define HG_ADVISE_SHM_MARGIN   2
#define HG_ADVISE_PKG_MARGIN   3
/*
 * Floors, deliberately low. An earlier 64 MB shm floor swallowed the answer:
 * peak x margin came to ~13 MB on every workload tried, always below it, so
 * the command replied "64" whatever it was asked and the arithmetic was never
 * visible. A floor should stop a silly recommendation, not become the
 * recommendation.
 */
#define HG_ADVISE_SHM_FLOOR_MB 8
#define HG_ADVISE_PKG_FLOOR_MB 2

/* Bands. 80% was too late to be a warning: an arena at 77% of peak reported
 * "reasonable" while being one busy hour from failing an allocation. */
#define HG_ADVISE_TIGHT_PCT    70
#define HG_ADVISE_WATCH_PCT    50
#define HG_ADVISE_LOOSE_PCT    20

/* peak x margin, in MB, never below @floor, rounded up to a whole huge page
 * so the arena does not map a partial one */
static unsigned long hg_advise_mb(unsigned long peak, unsigned int margin,
                                  unsigned long floor_mb, unsigned long hps)
{
	unsigned long mb = ((peak * margin) + (1UL << 20) - 1) >> 20;
	unsigned long step = (hps >= (1UL << 20)) ? (hps >> 20) : 1;

	if (mb < floor_mb)
		mb = floor_mb;
	if (step > 1)
		mb = ((mb + step - 1) / step) * step;
	return mb;
}

static const char *hg_advise_verdict(unsigned long peak, unsigned long size)
{
	unsigned long pct = size ? (peak * 100 / size) : 0;

	if (pct > HG_ADVISE_TIGHT_PCT)
		return "TIGHT - raise it before the next busy period";
	if (pct > HG_ADVISE_WATCH_PCT)
		return "watch - fine now, no room for a bad day";
	if (pct < HG_ADVISE_LOOSE_PCT)
		return "oversized - the surplus is pinned and unusable elsewhere";
	return "reasonable";
}

static int hg_advise_one(mi_item_t *parent, const char *name,
		struct hg_block *hb, unsigned long peak, unsigned int margin,
		unsigned long floor_mb, int nproc)
{
	mi_item_t *o;
	unsigned long rec;

	o = add_mi_object(parent, (char *)name, strlen(name));
	if (!o)
		return -1;

	rec = hg_advise_mb(peak, margin, floor_mb, hb->hps);

	if (add_mi_number(o, MI_SSTR("configured_mb"), hb->size >> 20) < 0 ||
	    add_mi_number(o, MI_SSTR("peak_bytes"), peak) < 0 ||
	    add_mi_number(o, MI_SSTR("peak_pct_of_configured"),
	        hb->size ? (peak * 100 / hb->size) : 0) < 0 ||
	    add_mi_number(o, MI_SSTR("margin_applied"), margin) < 0 ||
	    add_mi_number(o, MI_SSTR("recommended_mb"), rec) < 0 ||
	    add_mi_string(o, MI_SSTR("verdict"),
	        (char *)hg_advise_verdict(peak, hb->size),
	        strlen(hg_advise_verdict(peak, hb->size))) < 0)
		return -1;

	/*
	 * Split the live figure into the part that is a property of the
	 * WORKLOAD and the part that is a property of the ARENA SIZE, because
	 * the second one makes any "shrink to N x observed" advice circular.
	 *
	 * Measured on an idle pkg arena across -M 32/16/8/4: slab live stayed
	 * at exactly 6,560 bytes while the large tier halved with every halving
	 * of -M. The cause is in reactor.c:85 -
	 *     reactor_size = mem_size / n * FD_MEM_PERCENT / 100;
	 * the reactor's fd table is a PERCENTAGE of pkg memory, so it shrinks
	 * when the arena does. Apply a recommendation derived from total live
	 * and the next reading is smaller again, all the way to the floor.
	 *
	 * Reporting both halves is honest; guessing which large allocations are
	 * size-proportional and which are real workload is not, so no attempt
	 * is made to net it out automatically.
	 */
	{
		unsigned long slab_live  = hg_cell_live(hb);
		unsigned long large_live = hb->large_live;
		unsigned long live       = slab_live + large_live;
		unsigned long share      = live ? (large_live * 100 / live) : 0;

		if (add_mi_number(o, MI_SSTR("live_slab_bytes"), slab_live) < 0 ||
		    add_mi_number(o, MI_SSTR("live_large_bytes"), large_live) < 0 ||
		    add_mi_number(o, MI_SSTR("large_share_pct"), share) < 0)
			return -1;

		if (share > 50 && add_mi_string(o, MI_SSTR("caveat"), MI_SSTR(
			"most of this arena's live bytes are in the large tier, and at "
			"least some large consumers size themselves as a fraction of the "
			"arena - so this recommendation is an upper bound, not a fixed "
			"point. Apply it once, restart, and re-read rather than "
			"iterating.")) < 0)
			return -1;
	}

	/* pkg is per-process, so the interesting number is the whole fleet of
	 * arenas, not one of them - that is what is pinned out of the hugepage
	 * pool and cannot be used by anything else */
	if (nproc > 0) {
		if (add_mi_number(o, MI_SSTR("processes"), nproc) < 0 ||
		    add_mi_number(o, MI_SSTR("pinned_total_mb"),
		        (unsigned long)nproc * (hb->size >> 20)) < 0 ||
		    add_mi_number(o, MI_SSTR("recommended_total_mb"),
		        (unsigned long)nproc * rec) < 0)
			return -1;
	}
	return 0;
}

static mi_response_t *mi_hg_advise(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *notes;
	struct hg_block *hb;
	unsigned long uptime = (unsigned long)(time(NULL) - startup_time);
	int reported = 0;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_number(resp_obj, MI_SSTR("uptime_s"), uptime) < 0)
		goto error;

	if (mem_allocator_shm == MM_HG_MALLOC ||
	    mem_allocator_shm == MM_HG_MALLOC_DBG) {
		hb = (struct hg_block *)shm_block;
		/* the CARVE high-water, not the live one: carve is what has to
		 * fit in the arena, and in v2 it can sit well above live */
		if (hg_advise_one(resp_obj, "shm", hb, hb->max_real_used,
				HG_ADVISE_SHM_MARGIN, HG_ADVISE_SHM_FLOOR_MB, 0) < 0)
			goto error;
		reported++;
	}

	if (mem_allocator_pkg == MM_HG_MALLOC ||
	    mem_allocator_pkg == MM_HG_MALLOC_DBG) {
		unsigned long peak = 0, sum = 0;
		int nproc = 0;

		hb = (struct hg_block *)mem_block;
#ifdef PKG_MALLOC
		if (hg_pkg_peak_all(&peak, &sum, &nproc) < 0)
			nproc = 0;
#endif
		/* fall back to this process's own arena if the shared array is
		 * not populated - better a narrow answer than none, but say so
		 * in the notes below */
		if (!nproc)
			peak = hb->max_real_used;

		if (hg_advise_one(resp_obj, "pkg", hb, peak,
				HG_ADVISE_PKG_MARGIN, HG_ADVISE_PKG_FLOOR_MB, nproc) < 0)
			goto error;
		reported++;
	}

	if (!reported) {
		free_mi_response(resp);
		return init_mi_error(400,
			MI_SSTR("HG_MALLOC is not the active allocator"));
	}

	notes = add_mi_array(resp_obj, MI_SSTR("notes"));
	if (!notes)
		goto error;
	if (add_mi_string(notes, 0, 0, MI_SSTR(
		"advice is based on the high-water reached SO FAR; a longer or "
		"heavier window can only raise it")) < 0)
		goto error;
	if (uptime < 7200 && add_mi_string(notes, 0, 0, MI_SSTR(
		"uptime is under 2 hours - too short to have seen a busy period, "
		"treat the numbers as provisional")) < 0)
		goto error;
	if (add_mi_string(notes, 0, 0, MI_SSTR(
		"pkg peak is the worst single process, which is the one -M has to "
		"cover; every process gets its own arena of that size")) < 0)
		goto error;

	return resp;

error:
	LM_ERR("failed to add mi item\n");
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_hg_stats(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int reported = 0;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (mem_allocator_shm == MM_HG_MALLOC ||
	    mem_allocator_shm == MM_HG_MALLOC_DBG) {
		if (hg_stats_one(resp_obj, "shm", (struct hg_block *)shm_block, 0) < 0)
			goto error;
		reported++;
	}

	if (mem_allocator_pkg == MM_HG_MALLOC ||
	    mem_allocator_pkg == MM_HG_MALLOC_DBG) {
		/*
		 * pkg arenas are per-process, and the payload now says so rather
		 * than leaving it to a comment here. Over mi_fifo the answering
		 * process is the FIFO listener, which does no SIP work at all -
		 * reading its arena as "the" pkg arena is exactly how a worker
		 * running out of pkg stays invisible. The all-process picture is
		 * in the generic pkmem: statistics group.
		 */
		if (hg_stats_one(resp_obj, "pkg", (struct hg_block *)mem_block, 1) < 0)
			goto error;
		reported++;
	}

	if (!reported) {
		free_mi_response(resp);
		return init_mi_error(400,
			MI_SSTR("HG_MALLOC is not the active allocator"));
	}

	/*
	 * Per-process, like the pkg figures above: frees this process handed
	 * back to an arena other than the one named by the caller. The name
	 * says so, because read over mi_fifo this only ever samples the FIFO
	 * listener and will sit at 0 no matter what the SIP workers do - a
	 * zero here is not evidence of anything.
	 */
	if (add_mi_number(resp_obj, MI_SSTR("cross_arena_frees_this_proc"),
			hg_xarena_frees) < 0)
		goto error;

	return resp;

error:
	LM_ERR("failed to add mi item\n");
	free_mi_response(resp);
	return 0;
}
#endif /* HG_MALLOC */

static const mi_export_t mi_core_cmds[] = {
	{ "pi_list", "lists the provisioning framework", 0, 0, {
		{w_mi_pi_list, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "pi_reload", "reloads the provisioning framework", 0, 0, {
		{w_mi_pi_reload, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "uptime", "prints various time information about OpenSIPS - "
		"when it started to run, for how long it runs", 0, init_mi_uptime, {
		{mi_uptime, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "version", "prints the version string of a runningOpenSIPS", 0, 0, {
		{mi_version, {0}},
		{mi_version_1, {"revision", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "pwd", "prints the working directory of OpenSIPS", 0, 0, {
		{mi_pwd, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
#ifdef HG_MALLOC
	{ "hg_stats", "HG_MALLOC arena internals: how much of the arena is "
		"carved into size-class chunks, how much of that is live versus "
		"recycled, and the per-class chunk breakdown", 0, 0, {
		{mi_hg_stats, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "hg_advise", "what -m and -M should be set to, derived from the "
		"high-water each arena has actually reached; pkg advice covers the "
		"worst single process, not the one answering", 0, 0, {
		{mi_hg_advise, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
#endif
	{ "arg", "returns the full list of arguments used at startup", 0, 0, {
		{mi_arg, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "which", "lists all available MI commands", 0, 0, {
		{mi_which, {0}},
		{mi_which_cmd, {"command", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "ps", "lists all processes used by OpenSIPS", 0, 0, {
		{mi_ps, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "kill", "terminates OpenSIPS", 0, 0, {
		{mi_kill, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "log_level", "gets/sets the per process or global log level in OpenSIPS",
		0, 0, {
		{w_log_level, 	{0}},
		{w_log_level_1, {"level", 0}},
		{w_log_level_2, {"level", "pid", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "xlog_level", "gets/sets the per process or global xlog level in OpenSIPS",
		0, 0, {
		{w_xlog_level, 	{0}},
		{w_xlog_level_1, {"level", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "profiling_proc", "get/set profiling by process id, pid or all", 0, 0, {
		{w_profiling_proc, {0}},
		{w_profiling_proc, {"id", 0}},
		{w_profiling_proc, {"pid", 0}},
		{w_profiling_proc, {"level", 0}},
		{w_profiling_proc, {"id", "level", 0}},
		{w_profiling_proc, {"pid", "level", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "log_level_filter", "gets/sets the per consumer log level filter",
		0, 0, {
		{w_log_level_filter_1, {"consumer", 0}},
		{w_log_level_filter_2, {"consumer", "level_filter", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "log_mute_state", "mute/unmute a log consumer",
		0, 0, {
		{w_log_mute_state_1, {"consumer", 0}},
		{w_log_mute_state_2, {"consumer", "mute_state", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "reload_routes", "triggers the script (routes only) reload", 0, 0, {
		{w_reload_routes, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "help", "prints information about MI commands usage", 0, 0, {
		{w_mi_help, {0}},
		{w_mi_help_1, {"mi_cmd", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{EMPTY_MI_EXPORT}
};

static const mi_export_t mi_tcp_cmds[] = {
	{ "list", "list all ongoing TCP based connections, optionally filtered by proto", 0, 0, {
		{mi_tcp_list_conns, {0}},
		{mi_tcp_list_conns, {"proto", 0}},
		{EMPTY_MI_RECIPE}}, {"list_tcp_conns", 0}
	},
	{ "close", "close a given TCP connection", 0, 0, {
		{mi_tcp_close_conn, {"ipport", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{EMPTY_MI_EXPORT}
};
static const mi_export_t mi_mem_cmds[] = {
#if defined(Q_MALLOC) && defined(DBG_MALLOC)
	{ "shm_check", "complete scan of the shared memory pool "
		"(if any error is found, OpenSIPS will abort!)", 0, 0, {
		{mi_shm_check, {0}},
		{EMPTY_MI_RECIPE}}, {"mem_shm_check", 0}
	},
#endif
	{ "pkg_dump", "forces a status dump of the pkg memory (per process)", 0, 0, {
		{w_mem_pkg_dump_1, {"pid", 0}},
		{w_mem_pkg_dump_2, {"pid", "log_level", 0}},
		{EMPTY_MI_RECIPE}}, {"mem_pkg_dump", 0}
	},
	{ "shm_dump", "forces a status dump of the shm memory", 0, 0, {
		{w_mem_shm_dump, {0}},
		{w_mem_shm_dump_1, {"log_level", 0}},
		{EMPTY_MI_RECIPE}}, {"mem_shm_dump", 0}
	},
	{ "rpm_dump", "forces a status dump of the restart persistent memory", 0, 0, {
		{w_mem_rpm_dump, {0}},
		{w_mem_rpm_dump_1, {"log_level", 0}},
		{EMPTY_MI_RECIPE}}, {"mem_rpm_dump", 0}
	},
	{EMPTY_MI_EXPORT}
};
static const mi_export_t mi_cache_cmds[] = {
	{ "store", "stores in a cache system a string value", 0, 0, {
		{w_cachestore, {"system", "attr", "value", 0}},
		{w_cachestore_1, {"system", "attr", "value", "expire", 0}},
		{EMPTY_MI_RECIPE}}, {"cache_store", 0}
	},
	{ "fetch", "queries for a cache stored value", 0, 0, {
		{mi_cachefetch, {"system", "attr", 0}},
		{EMPTY_MI_RECIPE}}, {"cache_fetch", 0}
	},
	{ "remove", "removes a record from the cache system", 0, 0, {
		{mi_cacheremove, {"system", "attr", 0}},
		{EMPTY_MI_RECIPE}}, {"cache_remove", 0}
	},
	{EMPTY_MI_EXPORT}
};
static const mi_export_t mi_status_report_cmds[] = {
	{ "get", "gets the status (only) of a 'status-report' "
	"group/identifier", 0, 0, {
		{mi_sr_get_status, {"group",0}},
		{mi_sr_get_status, {"group","identifier",0}},
		{EMPTY_MI_RECIPE}}, {"sr_get_status", 0}
	},
	{ "status", "list the status of all the identifiers in OpenSIPS"
	" or from a certain 'status-report' group", 0, 0, {
		{mi_sr_list_status, {0}},
		{mi_sr_list_status, {"group",0}},
		{EMPTY_MI_RECIPE}}, {"sr_list_status", 0}
	},
	{ "reports", "list the reports produced by some 'status-report' "
	"identifiers / groups" , 0, 0, {
		{mi_sr_list_reports, {0}},
		{mi_sr_list_reports, {"group",0}},
		{mi_sr_list_reports, {"group","identifier",0}},
		{EMPTY_MI_RECIPE}}, {"sr_list_reports", 0}
	},
	{ "identifiers", "list the identifiers from a group or all",
	0, 0, {
		{mi_sr_list_identifiers, {0}},
		{mi_sr_list_identifiers, {"group",0}},
		{EMPTY_MI_RECIPE}}, {"sr_list_identifiers", 0}
	},
	{EMPTY_MI_EXPORT}
};
static const mi_export_t mi_evi_cmds[] = {
	{ "subscribe", "subscribes an event to the Event Interface", 0, 0, {
		{w_mi_event_subscribe, {"event", "socket", 0}},
		{w_mi_event_subscribe_1, {"event", "socket", "expire", 0}},
		{EMPTY_MI_RECIPE}}, {"event_subscribe", 0}
	},
	{ "list", "lists all the events advertised through the "
		"Event Interface", 0, 0, {
		{mi_events_list, {0}},
		{EMPTY_MI_RECIPE}}, {"events_list", 0}
	},
	{ "subscribers", "lists all the Event Interface subscribers; "
		"Params: [ event [ subscriber ]]", 0, 0, {
		{w_mi_subscribers_list, {0}},
		{w_mi_subscribers_list_1, {"event", 0}},
		{w_mi_subscribers_list_2, {"event", "socket", 0}},
		{EMPTY_MI_RECIPE}}, {"subscribers_list", 0}
	},
	{ "raise", "raises an event through the Event Interface; "
		"Params: event [ params ]", 0, 0, {
		{w_mi_raise_event, {"event", 0}},
		{w_mi_raise_event, {"event", "params", 0}},
		{EMPTY_MI_RECIPE}}, {"raise_event", 0}
	},
	{EMPTY_MI_EXPORT}
};



int init_mi_core(void)
{
	if (register_mi_mod( "core", mi_core_cmds)<0) {
		LM_ERR("unable to register core MI cmds\n");
		return -1;
	}
	if (register_mi_mod( "tcp", mi_tcp_cmds)<0) {
		LM_ERR("unable to register tcp MI cmds\n");
		return -1;
	}
	if (register_mi_mod( "mem", mi_mem_cmds)<0) {
		LM_ERR("unable to register mem MI cmds\n");
		return -1;
	}
	if (register_mi_mod( "cache", mi_cache_cmds)<0) {
		LM_ERR("unable to register cache MI cmds\n");
		return -1;
	}
	if (register_mi_mod( "status_report", mi_status_report_cmds)<0) {
		LM_ERR("unable to register status_report MI cmds\n");
		return -1;
	}
	if (register_mi_mod( "evi", mi_evi_cmds)<0) {
		LM_ERR("unable to register evi MI cmds\n");
		return -1;
	}

	try_load_trace_api();

	return 0;
}
