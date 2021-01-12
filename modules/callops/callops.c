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
#include "../../strcommon.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../../data_lump_rpl.h"
#include "../../parser/sdp/sdp.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_event.h"
#include "../../parser/parse_replaces.h"

#define CALL_MATCH_PARAM  0
#define CALL_MATCH_MANUAL 1
#define CALL_MATCH_CALLID 2
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
			va_end(vl);
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

DECLARE_CALL_EVENT(TRANSFER);
DECLARE_CALL_EVENT(HOLD);

static struct tm_binds call_tm_api;
static struct dlg_binds call_dlg_api;
static int call_match_mode = CALL_MATCH_DEFAULT;
static str call_match_param = str_init("osid");
static str call_transfer_param = str_init("call_transfer_leg");
static str call_transfer_callid_param = str_init("call_transfer_callid");


static int mod_init(void);
static int fixup_leg(void **param);
static int call_blind_replace(struct sip_msg *req, str *callid, str *leg);
static int call_transfer_notify(struct sip_msg *req);
static int w_call_blind_transfer(struct sip_msg *req, int leg, str *dst);
static int w_call_attended_transfer(struct sip_msg *req, int leg,
		str *callidB, int legB, str *dst);
static void call_dlg_created_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params * params);
static mi_response_t *mi_call_blind_transfer(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_call_attended_transfer(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_call_hold(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_call_unhold(const mi_params_t *params,
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
	{ "call_transfer_notify", (cmd_function)call_transfer_notify, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{ "call_transfer", (cmd_function)w_call_blind_transfer, {
		{CMD_PARAM_STR, fixup_leg,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{ "call_transfer", (cmd_function)w_call_attended_transfer, {
		{CMD_PARAM_STR, fixup_leg,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR, fixup_leg,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static int calling_mode_func(modparam_t type, void *val)
{
	if (strcasecmp((char *)val, "param") == 0) {
		call_match_mode = CALL_MATCH_PARAM;
	} else if (strcasecmp((char *)val, "manual") == 0) {
		call_match_mode = CALL_MATCH_MANUAL;
	} else if (strcasecmp((char *)val, "callid") == 0) {
		call_match_mode = CALL_MATCH_CALLID;
	} else {
		LM_ERR("unknown matching mode type %s\n", (char *)val);
		return -1;
	}
	return 0;
}

static param_export_t params[] = {
	{"mode", STR_PARAM|USE_FUNC_PARAM, (void*)calling_mode_func},
	{"match_param", STR_PARAM, &call_match_param.s},
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "call_transfer", 0, 0, 0, {
		{mi_call_blind_transfer, {"callid", "leg", "destination", 0}},
		{mi_call_attended_transfer,
			{"callid", "leg", "transfer_callid", "transfer_leg", 0}},
		{mi_call_attended_transfer,
			{"callid", "leg", "transfer_callid", "transfer_leg",
				"destination", 0}},
		{mi_call_attended_transfer,
			{"callid", "leg", "transfer_callid", "transfer_fromtag",
				"transfer_totag", "transfer_destination", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "call_hold", 0, 0, 0, {
		{mi_call_hold, {"callid", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "call_unhold", 0, 0, 0, {
		{mi_call_unhold, {"callid", 0}},
		{EMPTY_MI_RECIPE}}
	}
};

struct module_exports exports= {
	"callops",
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

	INIT_CALL_EVENT(TRANSFER, "callid", "leg",
			"transfer_callid", "destination", "state", "status", NULL);

	INIT_CALL_EVENT(HOLD, "callid", "leg", "action", "state", NULL);

	return 0;
}

static str *call_dlg_get_uri_param(struct sip_msg *msg)
{
	int i;
	struct sip_uri *r_uri;

	if (msg->parsed_orig_ruri_ok == 0 && parse_orig_ruri(msg) < 0) {
		LM_DBG("could not parse URI!\n");
		return NULL;
	}
	r_uri = &msg->parsed_orig_ruri;

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
		LM_DBG("parameter  to delete %.*s(%d) not inside R-URI %.*s(%d) -> "
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

	/* coverity[check_return: FALSE] - done on purpose CID #211369 */
	set_ruri(msg, &buf);
}

static void call_transfer_dlg_unref(void *p)
{
	struct dlg_cell *dlg = p;
	call_dlg_api.dlg_unref(dlg, 1);
}

static inline void call_transfer_raise(struct dlg_cell *dlg, str *callid, str *ruri,
		str *state, str *status)
{
	/* XXX: old leg is caller or callee, so it should be safe to use a buffer
	 * of 6 bytes */
	char buf[sizeof("caller")];
	str old_leg = str_init(buf);

	if (call_dlg_api.fetch_dlg_value(dlg, &call_transfer_param, &old_leg, 1) < 0)
		init_str(&old_leg, "unknown");

	RAISE_CALL_EVENT(TRANSFER, &dlg->callid, &old_leg,
			callid, ruri, state, status, NULL);
}

static void call_transfer_reply(struct cell *t, int type, struct tmcb_params *ps)
{
	str status, new_callid, state;
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

		/* not interested in provisional replies, are we? */
		if (ps->code >= 300)
			init_str(&state, "fail");
		else
			init_str(&state, "ok");
	} else {
		init_str(&state, "fail");
		init_str(&status, "408 Request Timeout");
	}

	if (get_callid(ps->req, &new_callid) < 0)
		init_str(&new_callid, "unknown");

	call_transfer_raise(dlg, &new_callid, call_get_ruri(ps->req), &state, &status);
	call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &empty_str);
}

/* expects the old_dlg to be reffed by the get_dlg* function
 * NOTE: on error, the success, the caller should not unref the dialog! */
static int call_blind_transfer(struct sip_msg *msg, struct dlg_cell *old_dlg,
		str *old_leg, str *new_callid)
{
	static str state = str_init("start");
	static str failure = str_init("fail");
	str *dst = call_get_ruri(msg);
	str tmp;

	/* we have the previous callid - check to see if we have a leg */
	if (old_leg) {
		/* replacing the current old leg */
		call_dlg_api.store_dlg_value(old_dlg, &call_transfer_param, old_leg);
	} else if (call_dlg_api.fetch_dlg_value(old_dlg, &call_transfer_param, &tmp, 0) < 0) {
		LM_DBG("call %.*s is not being transfered\n", old_dlg->callid.len, old_dlg->callid.s);
		init_str(&tmp, "unknown");
		old_leg = &tmp;
	} else {
		old_leg = &tmp;
	}
	/* we also need to "notice" him the callid that is replacing it */
	call_dlg_api.store_dlg_value(old_dlg, &call_transfer_callid_param, new_callid);

	RAISE_CALL_EVENT(TRANSFER, &old_dlg->callid, old_leg, new_callid,
			dst, &state, &empty_str, NULL);
	if (call_tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_OUT, call_transfer_reply,
			old_dlg, call_transfer_dlg_unref) <= 0) {
		LM_ERR("cannot register reply handler!\n");
		RAISE_CALL_EVENT(TRANSFER, &old_dlg->callid, old_leg, new_callid,
				dst, &failure, &empty_str, NULL);
		return -1;
	}
	return 1;
}

static int call_attended_transfer(struct dlg_cell *dlg, struct sip_msg *msg)
{
	static str state = str_init("start");
	static str failure = str_init("fail");
	struct replaces_body rpl;
	struct dlg_cell *init_dlg;
	struct dlg_cell *rpl_dlg;
	str rpl_leg, init_callid;
	str *ruri;
	int ret;

	/* if we have a Replaces header, this means that we have an attended transfer */
	if (parse_headers(msg, HDR_REPLACES_F, 0) < 0 || !msg->replaces)
		return 1;

	if (parse_replaces_body(msg->replaces->body.s, msg->replaces->body.len, &rpl) < 0)
		return 1;

	/* we've got the callid that is being replaced - fetch it */
	rpl_dlg = call_dlg_api.get_dlg_by_callid(&rpl.callid_val, 1);
	if (!rpl_dlg) {
		/* TODO - check to see if we know any dialog that is being transfered
		 * for this callid - should search by dialog value */
		LM_DBG("unknown callid for us - not handling\n");
		return 1;
	}

	ret = 1;
	/* double check the tags to find out the direction */
	if (str_match(&rpl_dlg->legs[DLG_CALLER_LEG].tag, &rpl.from_tag_val) &&
			str_match(&rpl_dlg->legs[callee_idx(rpl_dlg)].tag, &rpl.to_tag_val)) {
		init_str(&rpl_leg, "callee");
	} else if (str_match(&rpl_dlg->legs[DLG_CALLER_LEG].tag, &rpl.to_tag_val) &&
			str_match(&rpl_dlg->legs[callee_idx(rpl_dlg)].tag, &rpl.from_tag_val)) {
		init_str(&rpl_leg, "caller");
	} else {
		LM_WARN("tags mismatch replace=[%.*s/%.*s] dlg=[%.*s/%.*s] - not handling\n",
				rpl.from_tag_val.len, rpl.from_tag_val.s,
				rpl.to_tag_val.len, rpl.to_tag_val.s,
				rpl_dlg->legs[DLG_CALLER_LEG].tag.len,
				rpl_dlg->legs[DLG_CALLER_LEG].tag.s,
				rpl_dlg->legs[callee_idx(rpl_dlg)].tag.len,
				rpl_dlg->legs[callee_idx(rpl_dlg)].tag.s);
		goto unref_rpl;
	}

	ret = -1;
	ruri = call_get_ruri(msg);

	/* check if we are aware of the other leg being transfered */
	if (call_dlg_api.fetch_dlg_value(rpl_dlg, &call_transfer_callid_param,
			&init_callid, 0) >= 0) {
		/* search the initial dialog */
		init_dlg = call_dlg_api.get_dlg_by_callid(&init_callid, 1);
		if (init_dlg) {
			/* indicate that the current dialog is being replaced */
			call_transfer_raise(init_dlg, &dlg->callid, ruri, &state, &empty_str);
			call_dlg_api.store_dlg_value(init_dlg,
					&call_transfer_callid_param, &dlg->callid);
			if (call_tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_OUT,
					call_transfer_reply,
					init_dlg, call_transfer_dlg_unref) <= 0) {
				call_transfer_raise(init_dlg, &dlg->callid, ruri, &failure, &empty_str);
				call_dlg_api.dlg_unref(init_dlg, 1);
			}
		} else {
			LM_WARN("previous dialog %.*s was not found\n",
					init_callid.len, init_callid.s);
		}
	} else {
		LM_ERR("could not find the transfered callid\n");
	}

	call_dlg_api.store_dlg_value(rpl_dlg, &call_transfer_param, &rpl_leg);
	call_dlg_api.store_dlg_value(rpl_dlg, &call_transfer_callid_param, &dlg->callid);
	RAISE_CALL_EVENT(TRANSFER, &rpl.callid_val, &rpl_leg, &dlg->callid, ruri,
			&state, &empty_str, NULL);
	if (call_tm_api.register_tmcb(msg, 0, TMCB_RESPONSE_OUT, call_transfer_reply,
			rpl_dlg, call_transfer_dlg_unref) <= 0) {
		LM_ERR("cannot register reply handler!\n");
		RAISE_CALL_EVENT(TRANSFER, &rpl.callid_val, &rpl_leg, &dlg->callid,
				ruri, &failure, &empty_str, NULL);
		goto unref_rpl;
	}
	return 0;

unref_rpl:
	call_dlg_api.dlg_unref(rpl_dlg, 1);
	return ret;
}

static void call_dlg_created_CB(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	str *param = NULL;
	struct dlg_cell *old_dlg = NULL;

	if (!params->msg)
		return;

	if (call_attended_transfer(dlg, params->msg) == 0)
		return; /* call handled as attended transfer */

	/* this is used to match different legs of the same "logical" call */
	switch (call_match_mode) {
		case CALL_MATCH_MANUAL:
			return;
		case CALL_MATCH_PARAM:
		case CALL_MATCH_CALLID:
			param = call_dlg_get_uri_param(params->msg);
			if (!param)
				break;
			if (call_match_mode == CALL_MATCH_CALLID)
				old_dlg = call_dlg_api.get_dlg_by_callid(param, 1);
			else
				old_dlg = call_dlg_api.get_dlg_by_did(param, 1);
			break;
	}

	if (!param) {
		LM_DBG("parameter not found - call not handled\n");
		return;
	}

	if (!old_dlg) {
		LM_DBG("no dialog available with identifier %.*s (mode=%d)\n",
				param->len, param->s, call_match_mode);
		return;
	}

	call_dlg_rm_uri_param(params->msg, param);
	if (call_blind_transfer(params->msg, old_dlg, NULL, &dlg->callid) < 0)
		call_dlg_api.dlg_unref(old_dlg, 1);
}

static str *call_get_blind_refer_to(str *dst, str *id)
{
	static str refer_hdr;
	int len;

	if (!dst) {
		LM_ERR("bad params!\n");
		return NULL;
	}

	len = 11 /* Refer-To: < */ + dst->len + 3 /* >\r\n */;
	if (id)
		len += 1 /* ; */ + call_match_param.len + 1 /* = */ + id->len;

	refer_hdr.s = pkg_malloc(len);
	if (!refer_hdr.s) {
		LM_ERR("oom for refer hdr\n");
		return NULL;
	}
	memcpy(refer_hdr.s, "Refer-To: <", 11);
	refer_hdr.len = 11;
	memcpy(refer_hdr.s + refer_hdr.len, dst->s, dst->len);
	refer_hdr.len += dst->len;
	if (id) {
		refer_hdr.s[refer_hdr.len++] = ';';
		memcpy(refer_hdr.s + refer_hdr.len, call_match_param.s, call_match_param.len);
		refer_hdr.len += call_match_param.len;
		refer_hdr.s[refer_hdr.len++] = '=';
		memcpy(refer_hdr.s + refer_hdr.len, id->s, id->len);
		refer_hdr.len += id->len;
	}
	memcpy(refer_hdr.s + refer_hdr.len, ">\r\n", 3);
	refer_hdr.len += 3;

	return &refer_hdr;
}

static str *call_get_attended_refer_to(str *dst, str *callid, str *fromtag, str *totag)
{
	static str refer_hdr;
	str tmp;

	refer_hdr.s = pkg_malloc(11 /* Refer-To: < */ + dst->len +
			10 /* ?Replaces= */ + callid->len * 3 + 12 /* %3Bto-tag%3D */ +
			totag->len * 3 + /* %3Bfrom-tag%3D */ + fromtag->len * 3 + 3/* >\r\n */);
	if (!refer_hdr.s) {
		LM_ERR("oom for refer hdr\n");
		return NULL;
	}
	memcpy(refer_hdr.s, "Refer-To: <", 11);
	refer_hdr.len = 11;
	memcpy(refer_hdr.s + refer_hdr.len, dst->s, dst->len);
	refer_hdr.len += dst->len;
	memcpy(refer_hdr.s + refer_hdr.len, "?Replaces=", 10);
	refer_hdr.len += 10;
	memcpy(refer_hdr.s + refer_hdr.len, callid->s, callid->len);
	tmp.s = refer_hdr.s + refer_hdr.len;
	tmp.len = callid->len * 3 + 1;
	if (escape_user(callid, &tmp) < 0) {
		LM_ERR("could not print callid\n");
		pkg_free(refer_hdr.s);
		return NULL;
	}
	refer_hdr.len += tmp.len;
	memcpy(refer_hdr.s + refer_hdr.len, "%3Bto-tag%3D", 12);
	refer_hdr.len += 12;
	tmp.s = refer_hdr.s + refer_hdr.len;
	tmp.len = totag->len * 3 + 1;
	if (escape_user(totag, &tmp) < 0) {
		LM_ERR("could not print to-tag\n");
		pkg_free(refer_hdr.s);
		return NULL;
	}
	refer_hdr.len += tmp.len;
	memcpy(refer_hdr.s + refer_hdr.len, "%3Bfrom-tag%3D", 14);
	refer_hdr.len += 14;
	tmp.s = refer_hdr.s + refer_hdr.len;
	tmp.len = fromtag->len * 3 + 1;
	if (escape_user(fromtag, &tmp) < 0) {
		LM_ERR("could not print from-tag\n");
		pkg_free(refer_hdr.s);
		return NULL;
	}
	refer_hdr.len += tmp.len;

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

static int mi_call_hold_reply(struct sip_msg *msg, int status, void *param)
{
	str callid, leg, action, state;
	unsigned int p = (unsigned int)(long)param;

	if (status < 200)
		return 0;
	if (status >= 300)
		init_str(&state, "fail");
	else
		init_str(&state, "ok");
	if (p & 0x1)
		init_str(&leg, "callee");
	else
		init_str(&leg, "caller");
	if (p & 0x2)
		init_str(&action, "unhold");
	else
		init_str(&action, "hold");
	if (get_callid(msg, &callid) < 0) {
		LM_ERR("could not parse the callid!\n");
		return -1;
	}
	RAISE_CALL_EVENT(HOLD, &callid, &leg, &action, &state, NULL);
	return 0;
}

static int call_handle_notify(struct dlg_cell *dlg, struct sip_msg *msg)
{
	str retry = str_init("Retry-After: 1 (not found)\n");
	str state = str_init("notify");
	int status_code;
	str new_callid;
	str status;

	if (msg->REQ_METHOD != METHOD_NOTIFY)
		return -2;

	/* only interested in refer events */
	if (parse_headers(msg, HDR_EVENT_F, 0) < 0 ||
			(!msg->event || msg->event->body.len <= 0))
		return -1;

	if (!msg->event->parsed && (parse_event(msg->event) < 0))
		return -1;
	if (((event_t *)msg->event->parsed)->parsed != EVENT_REFER)
		return -2;

	status_code = 400;
	if (get_body(msg, &status) < 0 || status.len < 0)
		goto reply;
		/* try to validate, without looking at the content type */
	if (status.len <= SIP_VERSION_LEN || memcmp(status.s, SIP_VERSION, SIP_VERSION_LEN))
		goto reply;

	status_code = 480;
	if (call_dlg_api.fetch_dlg_value(dlg, &call_transfer_callid_param, &new_callid, 0) < 0) {
		add_lump_rpl(msg, retry.s, retry.len, LUMP_RPL_HDR);
		goto reply;
	}
	status.len -= SIP_VERSION_LEN;
	status.s += SIP_VERSION_LEN;
	trim(&status);
	call_transfer_raise(dlg, &new_callid, &empty_str, &state, &status);

	status_code = 200;

reply:
	status.s = error_text(status_code);
	status.len = strlen(status.s);
	if (call_tm_api.t_reply(msg, status_code, &status) < 0)
		return -1;
	return 0;
}

static void call_transfer_dlg_callback(struct dlg_cell* dlg, int type,
		struct dlg_cb_params *params)
{
	if (!params->msg)
		return;

	switch (call_handle_notify(dlg, params->msg)) {
		case 0:
			LM_DBG("dropping Notify Refer event\n");
			break;
		case -1:
			LM_ERR("error parsing Notify request\n");
			break;
		default:
			/* not an interesting event */
			break;
	}
}

static str *call_dlg_get_blind_refer_to(struct dlg_cell *dlg, str *dst)
{
	switch (call_match_mode) {
		case CALL_MATCH_MANUAL:
			return call_get_blind_refer_to(dst, NULL);
		case CALL_MATCH_CALLID:
			return call_get_blind_refer_to(dst, &dlg->callid);
		case CALL_MATCH_PARAM:
			return call_get_blind_refer_to(dst, call_dlg_api.get_dlg_did(dlg));
		default:
			LM_BUG("unknown match mode %d\n", call_match_mode);
			return NULL;
	}
}

static mi_response_t *mi_call_blind_transfer(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	static str refer = str_init("REFER");
	mi_response_t *ret = NULL;
	str callid, leg, dst, tleg;
	struct dlg_cell *dlg;
	str *refer_hdr = NULL;
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

	/* check to see if the call is already in a transfer process */
	if (call_dlg_api.fetch_dlg_value(dlg, &call_transfer_param, &tleg, 0) >= 0 &&
			tleg.len >= 0) {
		LM_INFO("%.*s is already transfering %.*s\n",
				callid.len, callid.s, tleg.len, tleg.s);
		ret = init_mi_error(491, MI_SSTR("Request Pending"));
		goto unref;
	}
	call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &leg);

	refer_hdr = call_dlg_get_blind_refer_to(dlg, &dst);
	if (!refer_hdr)
		goto unref;

	if (call_match_mode != CALL_MATCH_MANUAL) {
		/* register callbacks for handling notifies - does not matter if this
		 * fails, its not like we won't transfer if we don't get the notifications
		 * - some devices don't even send the :) */
		call_dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN,
				call_transfer_dlg_callback, 0, 0);
	}

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

static mi_response_t *mi_call_attended_transfer(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	static str refer = str_init("REFER");
	mi_response_t *ret = NULL;
	str callidA, legA, callidB, legB, tleg;
	struct dlg_cell *dlgA, *dlgB = NULL;
	str *refer_hdr, *dst;
	int callerA = 0, callerB = 0;
	str fromtag, totag, sdst;


	if (get_mi_string_param(params, "callid",
			&callidA.s, &callidA.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "leg", &legA.s, &legA.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "transfer_callid",
			&callidB.s, &callidB.len) < 0)
		return init_mi_param_error();

	if (str_match_nt(&legA, "caller"))
		callerA = 1;
	else if (!str_match_nt(&legA, "callee"))
		return init_mi_param_error();

	/* destination might be missing, but if we have something, use it */
	switch (try_get_mi_string_param(params, "destination", &sdst.s, &sdst.len)) {
		case -1:
			dst = NULL;
			break;
		case -2:
			return init_mi_param_error();
		default:
			dst = &sdst;
	}

	switch (try_get_mi_string_param(params, "transfer_leg", &legB.s, &legB.len)) {
		case -2:
			return init_mi_param_error();
		case -1:
			/* we don't have a transfer_leg - we must have from and to tags */
			if (!dst)
				return init_mi_param_error();
			if (get_mi_string_param(params, "transfer_fromtag",
					&fromtag.s, &fromtag.len) < 0)
				return init_mi_param_error();
			if (get_mi_string_param(params, "transfer_totag",
					&totag.s, &totag.len) < 0)
				return init_mi_param_error();
			break;
		default:
			if (str_match_nt(&legB, "caller"))
				callerB = 1;
			else if (!str_match_nt(&legB, "callee"))
				return init_mi_param_error();

			/* fetch the callid and get its from and to tags */
			dlgB = call_dlg_api.get_dlg_by_callid(&callidB, 1);
			if (!dlgB)
				return init_mi_error(404, MI_SSTR("Transfer dialog not found"));

			if (callerB) {
				fromtag = dlgB->legs[callee_idx(dlgB)].tag;
				totag = dlgB->legs[DLG_CALLER_LEG].tag;
				if (!dst)
					dst = &dlgB->from_uri;
			} else {
				fromtag = dlgB->legs[DLG_CALLER_LEG].tag;
				totag = dlgB->legs[callee_idx(dlgB)].tag;
				if (!dst)
					dst = &dlgB->to_uri;
			}
			break;
	}

	/* all good - find the dialog we need */
	dlgA = call_dlg_api.get_dlg_by_callid(&callidA, 1);
	if (!dlgA) {
		ret =  init_mi_error(404, MI_SSTR("Dialog not found"));
		goto unrefB;
	}

	/* check to see if the call is already in a transfer process */
	if (call_dlg_api.fetch_dlg_value(dlgA, &call_transfer_param, &tleg, 0) >= 0 &&
			tleg.len >= 0) {
		LM_INFO("%.*s is already transfering %.*s\n",
				callidA.len, callidA.s, tleg.len, tleg.s);
		ret = init_mi_error(491, MI_SSTR("Request Pending"));
		goto unrefA;
	}

	/* if we are not aware of the other callid, we need to receive it in a
	 * param */
	refer_hdr = call_get_attended_refer_to(dst, &callidB, &fromtag, &totag);
	if (!refer_hdr)
		goto unrefA;

	if (dlgB) {
		/* we also need to store in B the fact that is being replaced by A */
		if (call_dlg_api.store_dlg_value(dlgB, &call_transfer_callid_param, &callidA) < 0) {
			LM_ERR("can not store that A(%.*s) is replacing B(%.*s)\n",
					callidA.len, callidA.s, callidB.len, callidB.s);
			goto unrefA;
		}
	}

	call_dlg_api.store_dlg_value(dlgA, &call_transfer_param, &legA);
	/* register callbacks for handling notifies - does not matter if this
	 * fails, its not like we won't transfer if we don't get the notifications
	 * - some devices don't even send the :) */
	if (call_match_mode != CALL_MATCH_MANUAL)
		call_dlg_api.register_dlgcb(dlgA, DLGCB_REQ_WITHIN,
				call_transfer_dlg_callback, 0, 0);

	if (call_dlg_api.send_indialog_request(dlgA, &refer,
			(callerA?DLG_CALLER_LEG:callee_idx(dlgA)), NULL, NULL, refer_hdr,
			mi_call_transfer_reply, async_hdl) < 0) {
		LM_ERR("could not send the transfer message!\n");
		call_dlg_api.store_dlg_value((dlgB?dlgB:dlgA),
				&call_transfer_callid_param, &empty_str);
		call_dlg_api.store_dlg_value(dlgA, &call_transfer_param, &empty_str);
		goto end;
	}

	if (!async_hdl)
		ret = init_mi_result_string(MI_SSTR("Accepted"));
	else
		ret = MI_ASYNC_RPL;
end:
	pkg_free(refer_hdr->s);
unrefA:
	call_dlg_api.dlg_unref(dlgA, 1);
unrefB:
	if (dlgB)
		call_dlg_api.dlg_unref(dlgB, 1);
	return ret;
}

static int call_get_hold_body(struct dlg_cell *dlg, int leg, str *new_body)
{
	static sdp_info_t sdp;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	str body, session_hdr;
	int attr_to_add = 0;
	int len, streamnum;

	new_body->len = 0;

	body = dlg_get_out_sdp(dlg, leg);
	if (parse_sdp_session(&body, 0, NULL, &sdp) < 0) {
		LM_ERR("could not parse SDP for leg %d\n", leg);
		return -1;
	}

	/* we only have one session, so there's no need to iterate */
	streamnum = 0;
	session = sdp.sessions;
	session_hdr.s = session->body.s;
	session_hdr.len = session->body.len;
	for (stream = session->streams; stream; stream = stream->next) {
		/* first stream indicates where session header ends */
		if (session_hdr.len > stream->body.s - session->body.s)
			session_hdr.len = stream->body.s - session->body.s;
		if (stream->sendrecv_mode.len == 0)
			attr_to_add++;
		else if (strncasecmp(stream->sendrecv_mode.s, "inactive", 8) == 0)
			continue; /* do not disable already disabled stream */
		streamnum++;
	}
	if (!streamnum)
		return 0; /* nothing to change */

	new_body->s = pkg_malloc(body.len + attr_to_add * 12 /* a=inactive\r\n */);
	if (!new_body->s) {
		LM_ERR("oom for new body!\n");
		return -1;
	}

	/* copy everything untill the first stream */
	memcpy(new_body->s, session_hdr.s, session_hdr.len);
	new_body->len = session_hdr.len;
	for (streamnum = 0; streamnum < session->streams_num; streamnum++) {
		for (stream = session->streams; stream; stream = stream->next) {
			/* make sure the streams are in the same order */
			if (stream->stream_num != streamnum)
				continue;
			if (stream->sendrecv_mode.len) {
				len = stream->sendrecv_mode.s - stream->body.s;
				memcpy(new_body->s + new_body->len, stream->body.s,
						stream->sendrecv_mode.s - stream->body.s);
				new_body->len += len;
				memcpy(new_body->s + new_body->len, "inactive", 8);
				new_body->len += 8;
				len += stream->sendrecv_mode.len;
				memcpy(new_body->s + new_body->len, stream->sendrecv_mode.s +
						stream->sendrecv_mode.len, stream->body.len - len);
				new_body->len += stream->body.len - len;
			} else {
				memcpy(new_body->s + new_body->len, stream->body.s, stream->body.len);
				new_body->len += stream->body.len;
				memcpy(new_body->s + new_body->len, "a=inactive\r\n", 12);
				new_body->len += 12;
			}
		}
	}

	return 1;
}

static inline str *call_hold_leg_str(int leg)
{
	static str call_hold_param_caller = str_init("call_hold_caller");;
	static str call_hold_param_callee = str_init("call_hold_callee");;
	if (leg == DLG_CALLER_LEG)
		return &call_hold_param_caller;
	else
		return &call_hold_param_callee;
}

static int call_put_leg_onhold(struct dlg_cell *dlg, int leg)
{
	int ret;
	unsigned int param;
	str body, tmp;
	str invite = str_init("INVITE");
	str ct = str_init("application/sdp");
	str action = str_init("hold");
	str state = str_init("start");
	str *legstr = call_hold_leg_str(leg);

	if (call_dlg_api.fetch_dlg_value(dlg, legstr, &tmp, 0) >= 0 &&
			tmp.len != 0) {
		LM_DBG("call leg %d already on hold\n", leg);
		return 0;
	}

	if (call_get_hold_body(dlg, leg, &body) < 0)
		return -1;
	if (body.len == 0)
		return 1; /* nothing to do */

	if (leg == DLG_CALLER_LEG) {
		init_str(&tmp, "caller");
		param = 0x0;
	} else {
		init_str(&tmp, "callee");
		param = 0x1;
	}

	RAISE_CALL_EVENT(HOLD, &dlg->callid, &tmp, &action, &state, NULL);

	/* send it out */
	ret = call_dlg_api.send_indialog_request(dlg, &invite, leg, &body, &ct,
			NULL, mi_call_hold_reply, (void *)(long)param);
	pkg_free(body.s);
	if (ret < 0) {
		init_str(&state, "fail");
		RAISE_CALL_EVENT(HOLD, &dlg->callid, &tmp, &action, &state, NULL);
		LM_ERR("could not send re-INVITE for leg %d\n", leg);
		return -1;
	}
	if (call_dlg_api.store_dlg_value(dlg, legstr, &action) < 0)
		LM_WARN("cannot store streams for leg %d - cannot unhold properly!\n", leg);
	return 1;
}

static int call_resume_leg_onhold(struct dlg_cell *dlg, int leg)
{
	str marker, body;
	str invite = str_init("INVITE");
	str ct = str_init("application/sdp");
	str *legstr;
	str sleg;
	unsigned int param;
	str action = str_init("unhold");
	str state = str_init("start");

	legstr = call_hold_leg_str(leg);

	/* frist, check to see if the call was on hold */
	if (call_dlg_api.fetch_dlg_value(dlg, legstr, &marker, 0) < 0
			|| marker.len == 0) {
		LM_DBG("leg %d is not on hold!\n", leg);
		return 0;
	}

	body = dlg_get_out_sdp(dlg, leg);
	if (leg == DLG_CALLER_LEG) {
		init_str(&sleg, "caller");
		param = 0x0;
	} else {
		init_str(&sleg, "callee");
		param = 0x1;
	}
	param |= 0x2;

	RAISE_CALL_EVENT(HOLD, &dlg->callid, &sleg, &action, &state, NULL);
	if (call_dlg_api.send_indialog_request(dlg, &invite, leg, &body, &ct,
			NULL, mi_call_hold_reply, (void *)(long)param) < 0) {
		init_str(&state, "fail");
		RAISE_CALL_EVENT(HOLD, &dlg->callid, &sleg, &action, &state, NULL);
		LM_ERR("could not resume leg %d\n", leg);
		return -1;
	}
	/* mark the dialog that it is not on hold */
	call_dlg_api.store_dlg_value(dlg, legstr, &empty_str);
	return 1;
}

static mi_response_t *mi_call_hold(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str callid;
	str leg, action, state;
	struct dlg_cell *dlg;
	mi_response_t *ret = NULL;
	int ret_callee;
	int ret_caller;

	if (get_mi_string_param(params, "callid",
			&callid.s, &callid.len) < 0)
		return init_mi_param_error();

	dlg = call_dlg_api.get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog not found"));

	if (dlg->state < DLG_STATE_CONFIRMED) {
		ret = init_mi_error(410, MI_SSTR("Dialog not ready"));
		goto unref;
	}
	ret_caller = call_put_leg_onhold(dlg, DLG_CALLER_LEG);
	if (ret_caller < 0)
		goto unref;
	ret_callee = call_put_leg_onhold(dlg, callee_idx(dlg));
	if (ret_callee < 0) {
		if (ret_caller != 0) {
			init_str(&leg, "caller");
			init_str(&state, "state");
			init_str(&action, "action");
			RAISE_CALL_EVENT(HOLD, &dlg->callid, &leg, &action, &state, NULL);
			call_resume_leg_onhold(dlg, DLG_CALLER_LEG);
		}
		goto unref;
	}
	if (ret_caller == 0 && ret_callee == 0)
		ret = init_mi_error(480, MI_SSTR("Both dialog legs are on hold"));
	else
		ret = init_mi_result_ok();
unref:
	call_dlg_api.dlg_unref(dlg, 1);
	return ret;
}

static mi_response_t *mi_call_unhold(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str callid;
	struct dlg_cell *dlg;
	mi_response_t *ret = NULL;
	int ret_caller, ret_callee;

	if (get_mi_string_param(params, "callid",
			&callid.s, &callid.len) < 0)
		return init_mi_param_error();

	dlg = call_dlg_api.get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog not found"));

	if (dlg->state < DLG_STATE_CONFIRMED) {
		ret = init_mi_error(410, MI_SSTR("Dialog not ready"));
		goto unref;
	}
	ret_callee = call_resume_leg_onhold(dlg, callee_idx(dlg));
	ret_caller = call_resume_leg_onhold(dlg, DLG_CALLER_LEG);
	if (ret_caller == 0 && ret_callee == 0)
		ret = init_mi_error(480, MI_SSTR("No dialog legs on hold"));
	else if (ret_caller > 0 || ret_callee > 0)
		ret = init_mi_result_ok();
unref:
	call_dlg_api.dlg_unref(dlg, 1);
	return ret;
}


static int call_blind_replace(struct sip_msg *req, str *old_callid, str *old_leg)
{
	int ret;
	str new_callid;
	struct dlg_cell *old_dlg;

	if (get_callid(req, &new_callid) < 0) {
		LM_ERR("could not parse the callid!\n");
		return -1;
	}
	/* first make sure the call still exists */
	old_dlg = call_dlg_api.get_dlg_by_callid(old_callid, 0);
	if (!old_dlg) {
		LM_DBG("no dialog available with callid %.*s\n", old_callid->len, old_callid->s);
		return -2;
	}
	ret = call_blind_transfer(req, old_dlg, old_leg, &new_callid);
	if (ret < 0)
		call_dlg_api.dlg_unref(old_dlg, 1);
	return ret;
}

static int call_transfer_notify(struct sip_msg *msg)
{
	struct dlg_cell *dlg = call_dlg_api.get_dlg();
	if (!dlg) {
		LM_WARN("dialog not found - call this function only after dialog has been matched\n");
		return -1;
	}
	return call_handle_notify(dlg, msg);
}

static int fixup_leg(void **param)
{
	str *s = (str*)*param;
	if (s->len == 6) {
		if (strncasecmp(s->s, "caller", 6) == 0) {
			*param = (void*)(unsigned long)DLG_CALLER_LEG;
			return 0;
		} else if (strncasecmp(s->s, "callee", 6) == 0) {
			*param = (void*)(unsigned long)DLG_FIRST_CALLEE_LEG;
			return 0;
		}
	}

	LM_ERR("unsupported dialog indetifier <%.*s>\n",
		s->len, s->s);
	return -1;
}


static int w_call_blind_transfer(struct sip_msg *req, int leg, str *dst)
{
	int ret = -1;
	str tleg;
	str *refer_hdr;
	static str refer = str_init("REFER");

	struct dlg_cell *dlg = call_dlg_api.get_dlg();
	if (!dlg) {
		LM_WARN("dialog not found - call this function only after dialog has been matched\n");
		return -1;
	}

	if (dlg->state < DLG_STATE_CONFIRMED || dlg->state >= DLG_STATE_DELETED) {
		LM_WARN("invalid dialog state %d\n", dlg->state);
		return -1;
	}

	/* check to see if the call is already in a transfer process */
	if (call_dlg_api.fetch_dlg_value(dlg, &call_transfer_param, &tleg, 0) >= 0 &&
			tleg.len >= 0) {
		LM_INFO("%.*s is already transfering %.*s\n",
				dlg->callid.len, dlg->callid.s, tleg.len, tleg.s);
		return -1;
	}
	if (leg == DLG_CALLER_LEG)
		init_str(&tleg, "caller");
	else
		init_str(&tleg, "callee");
	call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &tleg);

	refer_hdr = call_dlg_get_blind_refer_to(dlg, dst);
	if  (call_match_mode != CALL_MATCH_MANUAL) {
		/* register callbacks for handling notifies - does not matter if this
		 * fails, its not like we won't transfer if we don't get the notifications
		 * - some devices don't even send the :) */
		call_dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN,
				call_transfer_dlg_callback, 0, 0);
	}

	if (call_dlg_api.send_indialog_request(dlg, &refer,
			(leg == DLG_CALLER_LEG?DLG_CALLER_LEG:callee_idx(dlg)), NULL, NULL,
			refer_hdr, mi_call_transfer_reply, NULL) < 0) {
		LM_ERR("could not send the transfer message!\n");
		call_dlg_api.store_dlg_value(dlg, &call_transfer_param, &empty_str);
	} else {
		ret = 1; /* success */
	}
	pkg_free(refer_hdr->s);
	return ret;
}

static int w_call_attended_transfer(struct sip_msg *req, int leg,
		str *callidB, int legB, str *dst)
{
	str tleg;
	str fromtag, totag, legA;
	str *refer_hdr;
	static str refer = str_init("REFER");
	struct dlg_cell *dlgB;
	int ret = -1;

	struct dlg_cell *dlgA = call_dlg_api.get_dlg();
	if (!dlgA) {
		LM_WARN("dialog not found - call this function only after dialog has been matched\n");
		return -1;
	}

	if (dlgA->state < DLG_STATE_CONFIRMED || dlgA->state >= DLG_STATE_DELETED) {
		LM_WARN("invalid dialog state %d\n", dlgA->state);
		return -1;
	}

	dlgB = call_dlg_api.get_dlg_by_callid(callidB, 1);
	if (!dlgB) {
		LM_ERR("could not find dialog %.*s\n", callidB->len, callidB->s);
		return -1;
	}

	/* check to see if the call is already in a transfer process */
	if (call_dlg_api.fetch_dlg_value(dlgA, &call_transfer_param, &tleg, 0) >= 0 &&
			tleg.len >= 0) {
		LM_INFO("%.*s is already transferring %.*s\n",
				dlgA->callid.len, dlgA->callid.s, tleg.len, tleg.s);
		goto unref;
	}

	if (legB == DLG_CALLER_LEG) {
		fromtag = dlgB->legs[callee_idx(dlgB)].tag;
		totag = dlgB->legs[DLG_CALLER_LEG].tag;
		if (!dst)
			dst = &dlgB->from_uri;
	} else {
		fromtag = dlgB->legs[DLG_CALLER_LEG].tag;
		totag = dlgB->legs[callee_idx(dlgB)].tag;
		if (!dst)
			dst = &dlgB->to_uri;
	}

	refer_hdr = call_get_attended_refer_to(dst, callidB, &fromtag, &totag);
	if (!refer_hdr)
		goto unref;

	if (call_dlg_api.store_dlg_value(dlgB, &call_transfer_callid_param, &dlgA->callid) < 0) {
		LM_ERR("can not store that A(%.*s) is replacing B(%.*s)\n",
				dlgA->callid.len, dlgA->callid.s, callidB->len, callidB->s);
		goto end;
	}
	if (leg == DLG_CALLER_LEG)
		init_str(&legA, "caller");
	else
		init_str(&legA, "callee");

	call_dlg_api.store_dlg_value(dlgA, &call_transfer_param, &legA);
	/* register callbacks for handling notifies - does not matter if this
	 * fails, its not like we won't transfer if we don't get the notifications
	 * - some devices don't even send the :) */
	if (call_match_mode != CALL_MATCH_MANUAL)
		call_dlg_api.register_dlgcb(dlgA, DLGCB_REQ_WITHIN,
				call_transfer_dlg_callback, 0, 0);

	if (call_dlg_api.send_indialog_request(dlgA, &refer,
			(leg == DLG_CALLER_LEG?DLG_CALLER_LEG:callee_idx(dlgA)), NULL, NULL,
			refer_hdr, mi_call_transfer_reply, NULL) < 0) {
		LM_ERR("could not send the transfer message!\n");
		call_dlg_api.store_dlg_value(dlgB,
				&call_transfer_callid_param, &empty_str);
		goto end;
	}
	ret = 1;
end:
	pkg_free(refer_hdr->s);
unref:
	call_dlg_api.dlg_unref(dlgB, 1);
	return ret;
}
