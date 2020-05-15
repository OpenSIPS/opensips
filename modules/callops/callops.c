/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */

#include "../../sr_module.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../../parser/parse_uri.h"

#define CALL_MATCH_PARAM  0
#define CALL_MATCH_MANUAL 1
#define CALL_MATCH_DEFAULT CALL_MATCH_PARAM

static str empty_str = str_init("");

#define DECLARE_CALL_EVENT(_name) \
	static evi_params_t call_event_params_##_name; \
	static event_id_t call_event_##_name = EVI_ERROR; \
	static str call_event_name_##_name = str_init("E_CALL_" #_name);

#define INIT_CALL_EVENT(_name, _param_names ...) \
	do { \
		if (call_event_init(&call_event_##_name, call_event_name_##_name, \
				&call_event_params_##_name, _param_names) < 0) { \
			LM_ERR("could not initialize E_CALL_" #_name); \
			return -1; \
		} \
	} while(0)

#define RAISE_CALL_EVENT(_name, _values ...) \
	call_event_raise(call_event_##_name, &call_event_params_##_name, _values)

static int call_event_init(event_id_t *event, str event_name, evi_params_p params, ...)
{
	const char *p;
	va_list vl;
	str tmp;

	*event = evi_publish_event(event_name);
	if (*event == EVI_ERROR) {
		LM_ERR("could not register event %.*s\n", event_name.len, event_name.s);
		return -1;
	}
	memset(params, 0, sizeof(*params));
	va_start(vl, params);
	while (1) {
		p = va_arg(vl, const char *);
		if (!p)
			break;
		init_str(&tmp, p);
		if (!evi_param_create(params, &tmp)) {
			LM_ERR("could not initialize %s param for event %.*s\n", p,
					event_name.len, event_name.s);
			return -1;
		}
	}
	va_end(vl);

	return 0;
}

static int call_event_raise(event_id_t event, evi_params_p params, ...)
{
	str *p;
	va_list vl;
	int ret = -1;
	evi_param_p param = params->first;

	if (!evi_probe_event(event)) {
		LM_DBG("no listener!\n");
		return 0;
	}
	va_start(vl, params);
	while (1) {
		if (!param)
			break;
		p = va_arg(vl, str *);
		if (!p)
			break;
		if (evi_param_set_str(param, p) < 0) {
			LM_ERR("could not set param!\n");
			goto end;
		}
		param = param->next;
	}
	ret = 0;
	if (evi_raise_event(event, params) < 0)
		LM_ERR("cannot raise event\n");
end:
	va_end(vl);

	return ret;
}

DECLARE_CALL_EVENT(BLIND_TRANSFER);

static struct tm_binds call_tm_api;
static struct dlg_binds call_dlg_api;
static int call_match_mode = CALL_MATCH_DEFAULT;
static str call_match_param = str_init("osid");
static str call_transfer_param = str_init("call_transfer_leg");


static int mod_init(void);
static int call_blind_replace(struct sip_msg *req, str *callid, str *leg);
static void call_dlg_created_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params * params);
static mi_response_t *mi_call_transfer(const mi_params_t *params,
								struct mi_handler *async_hdl);

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static cmd_export_t cmds[] = {
	{ "call_blind_replace", (cmd_function)call_blind_replace, {
		{CMD_PARAM_STR,0,0}, {CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static int calling_mode_func(modparam_t type, void *val)
{
	if (type == STR_PARAM) {
		if (strcasecmp((char *)val, "param") == 0) {
			call_match_mode = CALL_MATCH_PARAM;
		} else {
			LM_ERR("unknown matching mode type %s\n", (char *)val);
			return -1;
		}
	} else {
		call_match_mode = (int)(long)val;
	}
	return 0;
}

static param_export_t params[] = {
	{"mode", STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)calling_mode_func},
	{"match_param", STR_PARAM, &call_match_param.s},
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "call_transfer", 0, 0, 0, {
		{mi_call_transfer, {"callid", "leg", "destination", 0}},
		{EMPTY_MI_RECIPE}}
	}
};

struct module_exports exports= {
	"calling",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	NULL,
	params,
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,           /* exported transformations */
	0,           /* extra processes */
	0,
	mod_init,
	0,           /* reply processing */
	0,           /* destroy function */
	0,           /* child init */
	0            /* reload confirm function */
};

static int mod_init(void)
{
	call_match_param.len = strlen(call_match_param.s);
	if (call_match_param.len <= 0) {
		LM_ERR("invalid matching param param!\n");
		return -1;
	}

	if (load_tm_api(&call_tm_api) != 0) {
		LM_ERR("tm module not loaded! Cannot use callops module\n");
		return -1;
	}

	if (load_dlg_api(&call_dlg_api) != 0) {
		LM_ERR("could not load dialog api!\n");
		return -1;
	}

	if (call_dlg_api.register_dlgcb(NULL, DLGCB_CREATED, call_dlg_created_CB, NULL, NULL) < 0) {
		LM_ERR("could not register dialog created callback!\n");
		return -1;
	}

	INIT_CALL_EVENT(BLIND_TRANSFER, "transfered_callid", "transfered_leg",
			"new_callid", "destination", "status", NULL);

	return 0;
}

static str *call_dlg_get_uri_param(struct sip_msg *msg)
{
	int i;
	struct sip_uri *r_uri;

	if (msg->parsed_uri_ok == 0 && parse_sip_msg_uri(msg) < 0) {
		LM_DBG("could not parse URI!\n");
		return NULL;
	}
	r_uri = &msg->parsed_uri;

	for (i = 0; i < r_uri->u_params_no; i++)
		if (str_match(&r_uri->u_name[i], &call_match_param) && r_uri->u_val[i].len)
			return &r_uri->u_val[i];

	return NULL;
}

static str *call_get_ruri(struct sip_msg *msg)
{
	if (msg->new_uri.s)
		return &msg->new_uri;
	else
		return &msg->first_line.u.request.uri;
}

static void call_dlg_rm_uri_param(struct sip_msg *msg, str *param)
{
	str del;
	str *uri;
	static str buf;

	uri = call_get_ruri(msg);

	del.s = param->s - (1 /* ; */ + call_match_param.len +
			(param->len?(1 /* = */):0));
	del.len = 1 /* ; */ + call_match_param.len +
			(param->len?(1 /* = */ + param->len):0);

	if (del.s < uri->s || del.s + del.len > uri->s + uri->len) {
		LM_BUG("parameter  to delete %.*s(%d) not inside R-URI %.*s(%d) -> "
				"del.s=%p<uri.s=%p || del.s + del.len=%p > uri.s + uri.len=%p\n",
				del.len, del.s, del.len, uri->len, uri->s, uri->len,
				del.s, uri->s, del.s + del.len, uri->s + uri->len);
		return;
	}

	/* we are removing from the uri ;<call_match_param>=<param> */
	if (pkg_str_extend(&buf, uri->len - del.len) != 0) {
		LM_ERR("oom\n");
		return;
	}
	memcpy(buf.s, uri->s, del.s - uri->s);
	buf.len = del.s - uri->s;
	memcpy(buf.s + buf.len, del.s + del.len, uri->len - buf.len - del.len);
	buf.len += uri->len - buf.len - del.len;

	set_ruri(msg, &buf);
}

static void call_blind_transfer_dlg_unref(void *p)
{
	struct dlg_cell *dlg = p;
	call_dlg_api.dlg_unref(dlg, 1);
}

static void call_blind_transfer_reply(struct cell *t, int type, struct tmcb_params *ps)
{
	str status, old_leg, new_callid;
	struct dlg_cell *dlg = *ps->param;

	/* not interested in provisional replies, are we? */
	if (ps->code < 200)
		return;

	/* take the status from the message itself */
	if (ps->rpl != FAKED_REPLY) {
		status.s = ps->rpl->first_line.u.reply.status.s;
		status.len = ps->rpl->first_line.u.reply.reason.s +
			ps->rpl->first_line.u.reply.reason.len -
			ps->rpl->first_line.u.reply.status.s;
	} else {
		init_str(&status, "408 Request Timeout");
	}
	if (call_dlg_api.fetch_dlg_value(dlg, &call_transfer_param, &old_leg, 0) < 0)
		init_str(&old_leg, "unknown");
	if (get_callid(ps->req, &new_callid) < 0)
		init_str(&new_callid, "unknown");

	RAISE_CALL_EVENT(BLIND_TRANSFER, &dlg->callid, &old_leg, &new_callid,
		call_get_ruri(ps->req), &status, NULL);
	call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &empty_str);
}

static int call_blind_transfer(struct sip_msg *msg, str *old_callid, str *old_leg,
		str *new_callid)
{
	struct dlg_cell *old_dlg;
	static str status = str_init("100 Trying");
	static str failure = str_init("500 Server Internal Error");
	str *dst = call_get_ruri(msg);
	str tmp;

	/* first make sure the call still exists */
	old_dlg = call_dlg_api.get_dlg_by_callid(old_callid, 0);
	if (!old_dlg) {
		LM_DBG("no dialog available with callid %.*s\n", old_callid->len, old_callid->s);
		return -2;
	}
	/* we have the previous callid - check to see if we have a leg */
	if (old_leg) {
		/* replacing the current old leg */
		call_dlg_api.store_dlg_value(old_dlg, &call_transfer_param, old_leg);
	} else if (call_dlg_api.fetch_dlg_value(old_dlg, &call_transfer_param, &tmp, 0) < 0) {
		LM_DBG("call %.*s is not being transfered\n", old_callid->len, old_callid->s);
		init_str(&tmp, "unknown");
		old_leg = &tmp;
	} else {
		old_leg = &tmp;
	}
	RAISE_CALL_EVENT(BLIND_TRANSFER, old_callid, old_leg, new_callid,
			dst, &status, NULL);
	if (call_tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_OUT, call_blind_transfer_reply,
			old_dlg, call_blind_transfer_dlg_unref) <= 0) {
		call_dlg_api.dlg_unref(old_dlg, 1);
		LM_ERR("cannot register reply handler!\n");
		RAISE_CALL_EVENT(BLIND_TRANSFER, old_callid, old_leg, new_callid,
				dst, &failure, NULL);
		return -1;
	}
	return 1;
}

static void call_dlg_created_CB(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	str *old_callid;

	/* TODO: search for any Replaces header */

	/* this is used to match different legs of the same "logical" call */
	switch (call_match_mode) {
		case CALL_MATCH_MANUAL:
			return;
		case CALL_MATCH_PARAM:
			old_callid = call_dlg_get_uri_param(params->msg);
			if (!old_callid) {
				LM_DBG("parameter not found - call not handled\n");
				return;
			}
			call_dlg_rm_uri_param(params->msg, old_callid);
			call_blind_transfer(params->msg, old_callid, NULL, &dlg->callid);
			break;
	}
}

static str *call_dlg_get_refer_to(str *dst, str *id)
{
	static str refer_hdr;

	refer_hdr.s = pkg_malloc(11 /* Refer-To: < */ + dst->len + 1 /* ; */ +
			call_match_param.len + 1 /* = */ + id->len + 3/* >\r\n */);
	if (!refer_hdr.s) {
		LM_ERR("oom for refer hdr\n");
		return NULL;
	}
	memcpy(refer_hdr.s, "Refer-To: <", 11);
	refer_hdr.len = 11;
	memcpy(refer_hdr.s + refer_hdr.len, dst->s, dst->len);
	refer_hdr.len += dst->len;
	refer_hdr.s[refer_hdr.len++] = ';';
	memcpy(refer_hdr.s + refer_hdr.len, call_match_param.s, call_match_param.len);
	refer_hdr.len += call_match_param.len;
	refer_hdr.s[refer_hdr.len++] = '=';
	memcpy(refer_hdr.s + refer_hdr.len, id->s, id->len);
	refer_hdr.len += id->len;
	memcpy(refer_hdr.s + refer_hdr.len, ">\r\n", 3);
	refer_hdr.len += 3;

	return &refer_hdr;
}

static int mi_call_async_reply(struct sip_msg *msg, int status, void *param)
{
	struct mi_handler *async_hdl = param;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	char *reply_msg;

	if (!async_hdl) {
		LM_BUG("No async handler received!\n");
		return -1;
	}
	/* we just need to pass the status code and reason back to the caller */
	if (msg != FAKED_REPLY) {
		resp = init_mi_result_object(&resp_obj);
		if (add_mi_number(resp_obj, MI_SSTR("Code"), status) < 0 ||
				add_mi_string(resp_obj, MI_SSTR("Reason"),
					msg->first_line.u.reply.reason.s,
					msg->first_line.u.reply.reason.len) < 0) {
			free_mi_response(resp);
			resp = 0;
		}
	} else {
		reply_msg = error_text(status);
		resp = init_mi_error(status, reply_msg, strlen(reply_msg));
	}
	async_hdl->handler_f(resp, async_hdl, 1);
	return 0;
}

static int mi_call_transfer_reply(struct sip_msg *msg, int status, void *param)
{
	struct dlg_cell *dlg = call_dlg_api.get_dlg();

	if (dlg) {
		if (status < 200)
			return 0;
		if (status >= 300)
			/* transfer failed - we need to cleanup our transfer status */
			call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &empty_str);
	} else {
		LM_WARN("could not get current dialog!\n");
	}
	return (param?mi_call_async_reply(msg, status, param): 0);
}

static mi_response_t *mi_call_transfer(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	static str refer = str_init("REFER");
	mi_response_t *ret = NULL;
	str callid, leg, dst, tleg;
	struct dlg_cell *dlg;
	str *refer_hdr;
	int caller = 0;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "leg", &leg.s, &leg.len) < 0)
		return init_mi_param_error();

	if (str_match_nt(&leg, "caller"))
		caller = 1;
	else if (!str_match_nt(&leg, "callee"))
		return init_mi_param_error();

	if (get_mi_string_param(params, "destination", &dst.s, &dst.len) < 0)
		return init_mi_param_error();

	/* all good - find the dialog we need */
	dlg = call_dlg_api.get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog not found"));

	if (dlg->state >= DLG_STATE_DELETED) {
		ret = init_mi_error(410, MI_SSTR("Dialog already closed"));
		goto unref;
	}
	/* check to see if the call is already in a transfer process */
	if (call_dlg_api.fetch_dlg_value(dlg, &call_transfer_param, &tleg, 0) >= 0 &&
			tleg.len >= 0) {
		LM_INFO("%.*s is already trasfering %.*s\n",
				callid.len, callid.s, tleg.len, tleg.s);
		ret = init_mi_error(491, MI_SSTR("Request Pending"));
		goto unref;
	}

	refer_hdr = call_dlg_get_refer_to(&dst, &callid);
	if (!refer_hdr)
		goto unref;

	call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &leg);

	if (call_dlg_api.send_indialog_request(dlg, &refer,
			(caller?DLG_CALLER_LEG:callee_idx(dlg)), NULL, NULL, refer_hdr,
			mi_call_transfer_reply, async_hdl) < 0) {
		LM_ERR("could not send the transfer message!\n");
		call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &empty_str);
		goto end;
	}

	if (!async_hdl)
		ret = init_mi_result_string(MI_SSTR("Accepted"));
	else
		ret = MI_ASYNC_RPL;
end:
	pkg_free(refer_hdr->s);
unref:
	call_dlg_api.dlg_unref(dlg, 1);
	return ret;
}

static int call_blind_replace(struct sip_msg *req, str *old_callid, str *old_leg)
{
	str new_callid;

	if (get_callid(req, &new_callid) < 0) {
		LM_ERR("could not parse the callid!\n");
		return -1;
	}

	return call_blind_transfer(req, old_callid, old_leg, &new_callid);
}
