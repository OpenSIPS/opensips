/*
 * Copyright (C) 2024 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "dm_evi.h"

#include "../../dprint.h"
#include "../../ut.h"
#include "../../ipc.h"

ipc_handler_type dmev_req_ipc;

static event_id_t dmev_req_id = EVI_ERROR; /* E_DM_REQUEST */
static evi_params_p dmev_req_params;

static evi_param_p dmev_req_param_sessid;
static evi_param_p dmev_req_param_appid;
static evi_param_p dmev_req_param_cmdcode;
static evi_param_p dmev_req_param_avpsjson;
static evi_param_p dmev_req_param_fdmsg;

str dmev_req_pname_sessid = str_init("sess_id");
str dmev_req_pname_appid = str_init("app_id");
str dmev_req_pname_cmdcode = str_init("cmd_code");
str dmev_req_pname_avpsjson = str_init("avps_json");
str dmev_req_pname_fdmsg = str_init("_fdmsg_");


static int dm_init_ipc(void)
{
	dmev_req_ipc = ipc_register_handler(dm_raise_event_request,
	                                         "DM Request Dispatch");
	if (ipc_bad_handler_type(dmev_req_ipc)) {
		LM_ERR("failed to register 'DM Request Dispatch' IPC handler\n");
		return -1;
	}

	return 0;
}


int dm_init_evi(void)
{
	if (dm_init_ipc() != 0) {
		LM_ERR("failed to init IPC\n");
		return -1;
	}

	/* First publish the events */
	dmev_req_id = evi_publish_event(str_init("E_DM_REQUEST"));
	if (dmev_req_id == EVI_ERROR) {
		LM_ERR("cannot register 'request' event\n");
		return -1;
	}

	dmev_req_params = pkg_malloc(sizeof *dmev_req_params);
	if (!dmev_req_params) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(dmev_req_params, 0, sizeof *dmev_req_params);

	dmev_req_param_sessid = evi_param_create(dmev_req_params, &dmev_req_pname_sessid);
	dmev_req_param_appid = evi_param_create(dmev_req_params, &dmev_req_pname_appid);
	dmev_req_param_cmdcode = evi_param_create(dmev_req_params, &dmev_req_pname_cmdcode);
	dmev_req_param_avpsjson = evi_param_create(dmev_req_params, &dmev_req_pname_avpsjson);
	dmev_req_param_fdmsg = evi_param_create(dmev_req_params, &dmev_req_pname_fdmsg);
	if (!dmev_req_param_sessid || !dmev_req_param_appid
	        || !dmev_req_param_cmdcode || !dmev_req_param_avpsjson
	        || !dmev_req_param_fdmsg) {
		LM_ERR("failed to create EVI params\n");
		return -1;
	}

	return 0;
}


int dm_dispatch_event_req(struct msg *msg, const str *sessid, int app_id,
                          int cmd_code, const str *avps_json)
{
	dm_ipc_event_req *job;

	job = shm_malloc(sizeof *job);
	if (!job)
		goto out_oom;
	memset(job, 0, sizeof *job);

	job->fd_msg = msg;
	job->app_id = app_id;
	job->cmd_code = cmd_code;

	if (shm_nt_str_dup(&job->sessid, sessid)
	        || shm_nt_str_dup(&job->avps_json, avps_json))
		goto out_oom;

	return ipc_dispatch_job(dmev_req_ipc, job);

out_oom:
	if (job) {
		shm_free(job->sessid.s);
		shm_free(job->avps_json.s);
		shm_free(job);
	}
	LM_ERR("oom\n");
	return -1;
}


/**
 * The purpose of this dispatched job is for the logic to be ran by a
 * process other than the Diameter peer, since PROC_MODULE workers have NULL
 * @sroutes, causing a crash when attempting to raise a script event
 */
void dm_raise_event_request(int sender, void *dm_req)
{
	char buf[sizeof(long)*2 + 1], *p = buf;
	int sz = sizeof(buf);
	str ptr;

	dm_ipc_event_req *job = (dm_ipc_event_req *)dm_req;

	LM_DBG("received Diameter request via IPC, tid: %.*s\n",
	        job->sessid.len, job->sessid.s);

	if (evi_param_set_str(dmev_req_param_sessid, &job->sessid) < 0) {
		LM_ERR("failed to set 'sess_id'\n");
		goto out;
	}

	if (evi_param_set_int(dmev_req_param_appid, &job->app_id) < 0) {
		LM_ERR("failed to set 'app_id'\n");
		goto out;
	}

	if (evi_param_set_int(dmev_req_param_cmdcode, &job->cmd_code) < 0) {
		LM_ERR("failed to set 'cmd_code'\n");
		goto out;
	}

	if (evi_param_set_str(dmev_req_param_avpsjson, &job->avps_json) < 0) {
		LM_ERR("failed to set 'avps_json'\n");
		goto out;
	}

	int64_2reverse_hex(&p, &sz, (unsigned long)job->fd_msg);
	*p = '\0';
	init_str(&ptr, buf);

	if (evi_param_set_str(dmev_req_param_fdmsg, &ptr) < 0) {
		LM_ERR("failed to set '_fdmsg_'\n");
		goto out;
	}

	if (evi_raise_event(dmev_req_id, dmev_req_params) < 0)
		LM_ERR("failed to raise 'E_DM_REQUEST' event\n");

out:
	shm_free(job->sessid.s);
	shm_free(job->avps_json.s);
	shm_free(job);
}
