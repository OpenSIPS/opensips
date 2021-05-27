/*
 * Copyright (C) 2021 OpenSIPS Solutions
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
 */


#include <sys/eventfd.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../ipc.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../socket_info.h"
#include "../../mi/mi_trace.h"

static int mod_init(void);

static str trace_destination_name = {NULL, 0};
trace_dest t_dst;

/* tracing is disabled by default */
int mi_trace_mod_id = -1;
static char* mi_trace_bwlist_s;

static str backend = str_init("script");

static int mi_script_pp = 0;

static int mi_script_func(struct sip_msg *msg, str *m,
		pv_spec_p r, pv_spec_p p, pv_spec_p v);
static int mi_script_async_func(struct sip_msg *msg, async_ctx *ctx,
		str *m, pv_spec_p r, pv_spec_p p, pv_spec_p v);

static param_export_t mi_params[] = {
	{"trace_destination",	STR_PARAM,	&trace_destination_name.s},
	{"trace_bwlist",		STR_PARAM,	&mi_trace_bwlist_s},
	{"pretty_printing",		INT_PARAM,	&mi_script_pp},
	{0,0,0}
};

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type != PVT_AVP) {
		LM_ERR("Parameter must be an AVP\n");
		return E_CFG;
	}

	return 0;
}

static cmd_export_t mod_cmds[] = {
	{"mi", (cmd_function)mi_script_func, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static acmd_export_t mod_acmds[] = {
	{"mi", (acmd_function)mi_script_async_func, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{0,0,0}}},
	{0,0,{{0,0,0}}}
};

struct module_exports exports = {
	"mi_script",			/* module name */
	MOD_TYPE_DEFAULT,		/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	0,						/* load function */
	NULL,					/* OpenSIPS module dependencies */
	mod_cmds,				/* exported functions */
	mod_acmds,				/* exported async functions */
	mi_params,				/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,						/* exported transformations */
	0,						/* extra processes */
	0,						/* module pre-initialization function */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	0,						/* destroy function */
	0,						/* per-child init function */
	0						/* reload confirm function */
};

static int mod_init(void)
{
	if (trace_destination_name.s) {
		trace_destination_name.len = strlen( trace_destination_name.s);
		if (mi_trace_api && mi_trace_api->get_trace_dest_by_name) {
			t_dst = mi_trace_api->get_trace_dest_by_name(&trace_destination_name);
		}

		mi_trace_mod_id = register_mi_trace_mod();
		if ( t_dst ) {
			if ( load_correlation_id() < 0 ) {
				LM_ERR("can't find correlation id params!\n");
				exit(-1);
			}

			if ( mi_trace_api && mi_trace_bwlist_s ) {
				if ( parse_mi_cmd_bwlist( mi_trace_mod_id,
							mi_trace_bwlist_s, strlen(mi_trace_bwlist_s) ) < 0 ) {
					LM_ERR("invalid bwlist <%s>!\n", mi_trace_bwlist_s);
					exit(-1);
				}
			}
		}
	}

	return 0;
}

static void mi_script_free_request(mi_request_t *req, int shared)
{
	if (!req)
		return;
	if (shared)
		_init_mi_shm_mem_hooks();
	else
		_init_mi_sys_mem_hooks();

	if (req->req_obj)
		cJSON_Delete(req->req_obj);
	if (shared)
		shm_free(req);
	_init_mi_pkg_mem_hooks();
}

static mi_request_t *mi_script_parse_request(str *method, str *params,
		pv_spec_p attrs, pv_spec_p vals, int shared)
{
	static mi_request_t static_req;
	mi_request_t *req = NULL;
	struct usr_avp *v_avp = NULL;
	struct usr_avp *a_avp = NULL;
	int_str avp_val;
	unsigned int tmp;
	cJSON *val;
	char *p;

	if (shared) {
		req = shm_malloc(sizeof *req);
		if (!req) {
			LM_ERR("oom for new request\n");
			return NULL;
		}
		_init_mi_shm_mem_hooks();
	} else {
		req = &static_req;
		_init_mi_sys_mem_hooks();
	}
	memset(req, 0, sizeof *req);

	req->req_obj = cJSON_CreateObject();
	if (!req->req_obj) {
		LM_ERR("Failed to build temporary json request\n");
		goto error;
	}

	/* if no parameters whatso ever */
	if (!attrs && !vals && params->len == 0)
		return req;

	/* if they specified only vals, but not attributes
	 * swap them as a best effort chance to run the command */
	if (!attrs && vals) {
		attrs = vals;
		vals = NULL;
	}

	if (vals)
		req->params = cJSON_CreateObject();
	else
		req->params = cJSON_CreateArray();
	if (!req->params) {
		LM_ERR("Failed to build temporary json params\n");
		goto error;
	}
	cJSON_AddItemToObject(req->req_obj, JSONRPC_PARAMS_S, req->params);

	if (!attrs) {
		/* parameters are in command */
		do {
			trim_leading(params);
			p = q_memchr(params->s, ' ', params->len);
			avp_val.s = *params;
			if (p)
				avp_val.s.len = p - avp_val.s.s;
			if (avp_val.s.len <= 0)
				break;
			val = cJSON_CreateStr(avp_val.s.s, avp_val.s.len);
			if (!val) {
				LM_ERR("failed to create json param name!\n");
				goto error;
			}
			cJSON_AddItemToArray(req->params, val);
		} while (p);
		goto check;
	}

	while ((a_avp = search_first_avp(attrs->pvp.pvn.u.isname.type,
					attrs->pvp.pvn.u.isname.name.n, &avp_val, a_avp))) {

		if (!(a_avp->flags & AVP_VAL_STR)) {
			tmp = avp_val.n;
			avp_val.s.s = int2str(tmp, &avp_val.s.len);
		}

		/* check attribute */
		if (vals) {
			v_avp = search_first_avp(vals->pvp.pvn.u.isname.type,
					vals->pvp.pvn.u.isname.name.n, &avp_val, v_avp);
			if (!v_avp) {
				LM_ERR("missing attribute\n");
				goto error;
			}
			if (a_avp->flags & AVP_VAL_STR)
				val = cJSON_CreateStr(avp_val.s.s, avp_val.s.len);
			else
				val = cJSON_CreateNumber(avp_val.n);
			/* avp is always null terminated */
			cJSON_AddItemToObject(req->params, avp_val.s.s, val);
		} else {
			val = cJSON_CreateStr(avp_val.s.s, avp_val.s.len);
			if (!val) {
				LM_ERR("failed to create json param name!\n");
				goto error;
			}
			cJSON_AddItemToArray(req->params, val);
		}
	}

check:
	/* check if there were too many attribute names */
	if (vals && search_first_avp(vals->pvp.pvn.u.isname.type,
				vals->pvp.pvn.u.isname.name.n, &avp_val, v_avp)) {
		/* only signal error - continue */
		if (v_avp)
		LM_WARN("too many attribute vals - ignoring...\n");
	}
	_init_mi_pkg_mem_hooks();
	return req;
error:
	mi_script_free_request(req, shared);
	return NULL;
}

static void trace_script_su(struct sip_msg *msg,
		union sockaddr_union **src, union sockaddr_union **dst)
{
	static union sockaddr_union dummy_su;
	if (msg) {
		*src = &msg->rcv.src_su;
		if (msg->rcv.bind_address)
			*dst = &msg->rcv.bind_address->su;
		else
			*dst = *src;
	} else {
		*src = *dst = &dummy_su;
	}
}

static void trace_script_err(struct sip_msg *msg, str *method,
		const char *error)
{
	str message;
	union sockaddr_union *src, *dst;
	trace_script_su(msg, &src, &dst);
	mi_trace_request(src, dst, method->s, method->len,
			NULL, &backend, t_dst);
	init_str(&message, error);
	mi_trace_reply(src, dst, &message, t_dst);
}

static void trace_script_request(struct sip_msg *msg, str *method,
		mi_item_t *params)
{
	union sockaddr_union *src, *dst;
	trace_script_su(msg, &src, &dst);
	mi_trace_request(src, dst, method->s, method->len,
			params, &backend, t_dst);
}

static void trace_script_reply(struct sip_msg *msg, str *message)
{
	union sockaddr_union *src, *dst;
	trace_script_su(msg, &src, &dst);
	mi_trace_reply(src, dst, message, t_dst);
}

struct mi_script_async_hdl {
	int process_no;
	mi_response_t *resp;
};

static void mi_script_notify_async_handler(mi_response_t *resp,
		struct mi_handler *hdl, int done)
{
	struct mi_script_async_hdl *async;
	if (!done) {
		/* we do not pass provisional stuff (yet) */
		if (resp) free_mi_response( resp );
		return;
	}

	async = (struct mi_script_async_hdl *)(hdl + 1);
	async->resp = shm_clone_mi_response(resp);
	if (!async->resp)
		LM_ERR("could not clone response\n");
	if (resp) free_mi_response( resp );
	if (ipc_send_sync_reply(async->process_no, async) < 0) {
		LM_CRIT("could not send async reply!\n");
		if (async->resp)
			free_shm_mi_response(async->resp);
	}
}

static struct mi_handler *mi_script_new_async_handler(void)
{
	struct mi_script_async_hdl *async;
	struct mi_handler *hdl = shm_malloc(sizeof *hdl + sizeof *async);
	if (!hdl) {
		LM_ERR("could not start async handler\n");
		return NULL;
	}
	memset(hdl, 0, sizeof *hdl);
	async = (struct mi_script_async_hdl *)(hdl + 1);
	hdl->handler_f = mi_script_notify_async_handler;
	return hdl;
}

static mi_response_t *mi_script_wait_async_handler(void *hdl)
{
	struct mi_script_async_hdl *async = NULL;
	mi_response_t *resp = NULL;;

	if (ipc_recv_sync_reply((void **)&async) < 0)
		LM_ERR("could not receive async reply!\n");
	else
		resp = async->resp;

	shm_free(hdl);
	return resp;
}

static void mi_script_get_method(str *m, str *method, str *params)
{
	char *p = q_memchr(m->s, ' ', m->len);
	if (p) {
		method->s = m->s;
		method->len = p - m->s;
		params->s = p + 1;
		params->len = m->len - method->len - 1;
	} else {
		*method = *m;
		params->len = 0;
	}
	trim(method);
}

static int mi_script_handle_response(mi_response_t *resp, char **res, int *release)
{

	int ret = 1;
	mi_item_t *item, *tmp;
	char *r = NULL;

	*release = 0;

	item = cJSON_GetObjectItem(resp, JSONRPC_ERROR_S);
	if (item) {
		tmp = cJSON_GetObjectItem(item, JSONRPC_ERR_CODE_S);
		if (!tmp)
			ret = -3;
		else if (tmp->valueint > 0)
			ret = -tmp->valueint;
		else
			ret = tmp->valueint;

		tmp = cJSON_GetObjectItem(item, JSONRPC_ERR_MSG_S);
		if (!tmp)
			r = "no error message provideded";
		else
			r = tmp->valuestring;
	} else if (res) {
		tmp = cJSON_GetObjectItem(resp, JSONRPC_RESULT_S);
		if (tmp) {
			if (mi_script_pp)
				r = cJSON_Print(tmp);
			else
				r = cJSON_PrintUnformatted(tmp);
			*release = 1;
		}
	}
	if (res)
		*res = r;
	return ret;
}

static int mi_script_handle_sync_response(struct sip_msg *msg,
		mi_response_t *resp, pv_spec_p r)
{
	int ret, release;
	pv_value_t val;
	char *res = NULL;

	ret = mi_script_handle_response(resp, (r?&res:NULL), &release);
	if (res) {
		val.rs.s = res;
		val.rs.len = strlen(res);
		val.flags = PV_VAL_STR;
	} else {
		val.rs.s = NULL;
		val.rs.len = 0;
		val.flags = PV_VAL_NULL;
	}

	if (pv_set_value(msg, r, 0, &val) < 0)
		ret = -3;
	if (release)
		cJSON_PurgeString(res);
	return ret;
}

static int mi_script_func(struct sip_msg *msg, str *m,
		pv_spec_p r, pv_spec_p p, pv_spec_p v)
{
	struct mi_handler *hdl = NULL;
	struct mi_cmd *cmd = NULL;
	mi_response_t *resp = NULL;
	mi_request_t *req = NULL;
	pv_value_t val;
	int traced = 0, shared = 0;
	int ret = -2;
	char *err = "unknown error";
	str error;
	str method, params;

	mi_script_get_method(m, &method, &params);

	cmd = lookup_mi_cmd(method.s, method.len);
	if (!cmd)
		return -1;
	traced = is_mi_cmd_traced(mi_trace_mod_id, cmd);
	if (cmd->flags & MI_ASYNC_RPL_FLAG) {
		LM_DBG("command is async\n");
		/* We need to build an async handler */
		hdl = mi_script_new_async_handler();
		if (!hdl) {
			err = "failed to build async handler";
			goto error;
		}
	}

	req = mi_script_parse_request(&method, &params, p, v, 0);
	if (!req) {
		err = "could not parse script params!";
		goto error;
	}
	resp = handle_mi_request(req, cmd, hdl);
	if (traced)
		trace_script_request(msg, &method, req->params);
	if (resp == MI_ASYNC_RPL) {
		resp = mi_script_wait_async_handler(hdl);
		shared = 1;
	}
	if (!resp) {
		err = "failed to build MI response";
		if (traced) {
			init_str(&error, err);
			trace_script_reply(msg, &error);
		}
		ret = -3;
		goto end;
	} else {
		ret = mi_script_handle_sync_response(msg, resp, r);
	}
	goto ret;

error:
	if (traced)
		trace_script_err(msg, &method, err);
end:
	LM_ERR("%s\n", err);
	if (r) {
		init_str(&val.rs, err);
		val.flags = PV_VAL_STR;
		pv_set_value(msg, r, 0, &val);
	}
ret:
	if (req)
		mi_script_free_request(req, 0);
	if (resp) {
		if (shared)
			free_shm_mi_response(resp);
		else
			free_mi_response(resp);
	}
	return ret;
}

struct mi_script_async_job {
	int rc;
	int fd;
	str msg;
	pv_spec_p ret;
	int process_no;
	struct mi_cmd *cmd;
	mi_request_t *req;
};

static void mi_script_async_resume_job(int sender, void *param)
{
	int ret;
	unsigned long r;
	struct mi_script_async_job *job = (struct mi_script_async_job *)param;
	/* just notify the event socket */
	do {
		ret = write(job->fd, &r, sizeof r);
	} while (ret < 0 && (errno == EINTR || errno == EAGAIN));
	if (ret < 0)
		LM_ERR("could not notify resume: %s\n", strerror(errno));
}

static void mi_script_async_job(mi_response_t *resp, struct mi_script_async_job *job)
{
	str msg;
	char *res = NULL;
	int release;

	/* we got a response - handle it */
	job->rc = mi_script_handle_response(resp, (job->ret?&res:NULL), &release);
	if (job->ret && res) {
		init_str(&msg, res);
		shm_str_dup(&job->msg, &msg);
	}

	if (release)
		cJSON_PurgeString(res);

	if (ipc_send_rpc(job->process_no, mi_script_async_resume_job, job) < 0) {
		LM_ERR("could not resume async MI command!\n");
		if (job->msg.s)
			shm_free(job->msg.s);
		shm_free(job);
	}
}

static void mi_script_notify_async_job(mi_response_t *resp,
		struct mi_handler *hdl, int done)
{
	struct mi_script_async_job *job = hdl->param;

	if (!done) {
		/* we do not pass provisional stuff (yet) */
		if (resp) free_mi_response( resp );
		return;
	}
	mi_script_async_job(resp, job);
	shm_free(hdl);
}

static void mi_script_async_start_job(int sender, void *param)
{
	struct mi_script_async_job *job = (struct mi_script_async_job *)param;
	struct mi_handler *hdl = NULL;
	mi_response_t *resp = NULL;

	if (job->cmd->flags & MI_ASYNC_RPL_FLAG) {
		hdl = shm_malloc(sizeof *hdl);
		if (hdl) {
			hdl->handler_f = mi_script_notify_async_job;
			hdl->param = job;
		} else {
			LM_ERR("could not create async handler!\n");
		}
	}

	resp = handle_mi_request(job->req, job->cmd, hdl);
	if (resp != MI_ASYNC_RPL) {
		mi_script_async_job(resp, job);
		free_mi_response(resp);
	}
	mi_script_free_request(job->req, 1);
	job->req = NULL;
}

/* we use this just for notifying that the request is terminated */
static int mi_script_async_resume(int fd,
		struct sip_msg *msg, void *param)
{
	struct mi_script_async_job *job = (struct mi_script_async_job *)param;
	pv_value_t val;
	unsigned long r;
	int ret;

	do {
		ret = read(fd, &r, sizeof r);
	} while(ret < 0 && (errno == EINTR || errno == EAGAIN));
	async_status = ASYNC_DONE_CLOSE_FD;

	if (ret < 0) {
		LM_ERR("could not resume async route!\n");
		goto end;
	}
	if (!job->rc) {
		LM_ERR("async MI command not completed!\n");
		ret = -2;
		goto end;
	}
	ret = job->rc;
	if (job->ret) {
		if (job->msg.s) {
			val.rs = job->msg;
			val.flags = PV_VAL_STR;
		} else {
			val.rs.s = NULL;
			val.rs.len = 0;
			val.flags = PV_VAL_NULL;
		}
		if (pv_set_value(msg, job->ret, 0, &val) < 0)
			ret = -3;
	}
end:
	if (job->msg.s)
		shm_free(job->msg.s);
	shm_free(job);
	return ret;
}

static int mi_script_async_func(struct sip_msg *msg, async_ctx *ctx,
		str *m, pv_spec_p r, pv_spec_p p, pv_spec_p v)
{
	struct mi_cmd *cmd = NULL;
	struct mi_script_async_job *job;
	mi_request_t *req;
	str method, params;
	int fd;
	pv_value_t val;
	char *err = "unknown error";

	mi_script_get_method(m, &method, &params);

	cmd = lookup_mi_cmd(method.s, method.len);
	if (!cmd)
		return -1;

	req = mi_script_parse_request(&method, &params, p, v, 1);
	if (!req) {
		err = "could not parse parameters";
		goto error;
	}
	fd = eventfd(0, 0);
	if (fd < 0) {
		err = "could not create event descriptor";
		goto error;
	}
	job = shm_malloc(sizeof *job);
	if (!job) {
		err = "could not create new job";
		goto error;
	}
	memset(job, 0, sizeof *job);

	async_status = fd;
	ctx->resume_f = mi_script_async_resume;
	ctx->resume_param = job;

	job->ret = r;
	job->fd = fd;
	job->cmd = cmd;
	job->req = req;
	job->process_no = process_no;

	if (ipc_dispatch_rpc(mi_script_async_start_job, job) < 0) {
		err = "could not dispatch job";
		shm_free(job);
		goto close;
	}
	return 1;

close:
	close(fd);
error:
	LM_ERR("%s!\n", err);
	if (r) {
		init_str(&val.rs, err);
		val.flags = PV_VAL_STR;
		pv_set_value(msg, r, 0, &val);
	}
	mi_script_free_request(req, 1);
	return -2;
}
