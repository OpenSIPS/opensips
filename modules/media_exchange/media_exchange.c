/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "media_exchange.h"
#include "media_sessions.h"
#include "media_utils.h"

struct tm_binds media_tm;
struct dlg_binds media_dlg;
struct b2b_api media_b2b;
struct rtpproxy_binds media_rtp;

static int mod_init(void);
static int media_fork_to_uri(struct sip_msg *msg, str *uri, int leg, str *body, str *headers);
static int media_fork_from_call(struct sip_msg *msg, str *callid, int leg);
static int media_exchange_from_uri(struct sip_msg *msg, str *uri, int leg,
		str *body, str *headers, int *nohold);
static int media_exchange_to_call(struct sip_msg *msg, str *callid, int leg, int *nohold);
static int media_terminate(struct sip_msg *msg, int leg, int *nohold);
static int fixup_media_leg(void **param);
static int fixup_media_leg_both(void **param);

static int b2b_media_server_notify(struct sip_msg *msg, str *key, int type, void *param);

static mi_response_t *mi_media_fork_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_media_exchange_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_media_terminate(const mi_params_t *params,
								struct mi_handler *async_hdl);

/* modules dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "rtpproxy", DEP_SILENT }, /* only used for streaming */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{
		{ NULL, NULL },
	},
};

/* exported commands */
static cmd_export_t cmds[] = {
	{"media_exchange_from_uri",(cmd_function)media_exchange_from_uri, {
		{CMD_PARAM_STR,0,0}, /* uri */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* body */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* headers */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_exchange_to_call",(cmd_function)media_exchange_to_call, {
		{CMD_PARAM_STR,0,0}, /* callid */
		{CMD_PARAM_STR,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_fork_to_uri",(cmd_function)media_fork_to_uri, {
		{CMD_PARAM_STR,0,0}, /* uri */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* body */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* headers */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_fork_from_call",(cmd_function)media_fork_from_call, {
		{CMD_PARAM_STR,0,0}, /* callid */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_terminate",(cmd_function)media_terminate, {
		{CMD_PARAM_STR,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* exported parameters */
static param_export_t params[] = {
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "media_fork_from_call_to_uri", 0, 0, 0, {
		{mi_media_fork_from_call_to_uri, {"callid", "uri", 0}},
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "leg", 0}},
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "headers", 0}},
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "leg", "headers", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "media_fork_from_call_to_uri_body", 0, 0, 0, {
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "body", 0}},
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "body", "leg", 0}},
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "body", "headers", 0}},
		{mi_media_fork_from_call_to_uri, {"callid", "uri", "body", "leg", "headers", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "media_exchange_from_call_to_uri", 0, 0, 0, {
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", 0}},
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "headers", 0}},
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "nohold", 0}},
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "headers", "nohold", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "media_exchange_from_call_to_uri_body", 0, 0, 0, {
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "body", 0}},
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "body", "headers", 0}},
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "body", "nohold", 0}},
		{mi_media_exchange_from_call_to_uri, {"callid", "uri", "leg", "body", "headers", "nohold", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "media_terminate", 0, 0, 0, {
		{mi_media_terminate, {"callid", 0}},
		{mi_media_terminate, {"callid", "leg", 0}},
		{mi_media_terminate, {"callid", "nohold", 0}},
		{mi_media_terminate, {"callid", "leg", "nohold", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

/* module exports */
struct module_exports exports = {
	"media_exchange",				/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load function */
	&deps,							/* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	mi_cmds,							/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* extra processes */
	0,								/* extra transformations */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	NULL,							/* response handling function */
	NULL,							/* destroy function */
	NULL,							/* per-child init function */
	0								/* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_DBG("initializing media_exchange module ...\n");

	if (load_dlg_api(&media_dlg) != 0) {
		LM_ERR("dialog module not loaded! Cannot use media bridging module\n");
		return -1;
	}

	if (load_tm_api(&media_tm) != 0) {
		LM_ERR("tm module not loaded! Cannot use media bridging module\n");
		return -1;
	}

	if (load_b2b_api(&media_b2b) != 0) {
		LM_ERR("b2b_entities module not loaded! "
				"Cannot use media bridging module\n");
		return -1;
	}

	if (load_rtpproxy_api(&media_rtp) != 0)
		LM_DBG("rtpproxy module not loaded! Cannot use streaming functions\n");

	if (init_media_sessions() < 0) {
		LM_ERR("could not initialize media sessions!\n");
		return -1;
	}

	return 0;
}

static int fixup_get_media_leg(str *s)
{
	if (s->len != 6)
		return -1;
	if (!strncasecmp(s->s, "caller", 6))
		return MEDIA_LEG_CALLER;
	if (!strncasecmp(s->s, "callee", 6))
		return MEDIA_LEG_CALLEE;
	return -2;
}

static int fixup_get_media_leg_both(str *s)
{
	if (s->len == 4 && strncasecmp(s->s, "both", 4) == 0)
		return MEDIA_LEG_BOTH;
	return fixup_get_media_leg(s);
}

static int fixup_media_leg(void **param)
{
	str *s = *param;
	int leg = fixup_get_media_leg(s);
	if (leg < 0) {
		LM_ERR("unsupported leg '%.*s'\n", s->len, s->s);
		return E_CFG;
	}
	*param = (void *)(unsigned long)leg;
	return 0;
}

static int fixup_media_leg_both(void **param)
{
	str *s = *param;
	int leg = fixup_get_media_leg_both(s);
	if (leg < 0) {
		LM_ERR("unsupported leg '%.*s'\n", s->len, s->s);
		return E_CFG;
	}
	*param = (void *)(unsigned long)leg;
	return 0;
}

static int media_fork_to_uri(struct sip_msg *msg, str *uri, int leg, str *body, str *headers)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int media_fork_from_call(struct sip_msg *msg, str *callid, int leg)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int media_exchange_from_uri(struct sip_msg *msg, str *uri, int leg,
		str *body, str *headers, int *nohold)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

#define MEDIA_SESSION_REPLY_PREP(_rd, _msl) \
	do { \
		memset((_rd), 0, sizeof (*(_rd))); \
		(_rd)->et = (_msl)->b2b_entity; \
		(_rd)->b2b_key = &(_msl)->b2b_key; \
	} while (0);

static int media_session_exchange_server_reply(struct sip_msg *msg, int status, void *param)
{
	struct media_session_leg *msl;
	b2b_rpl_data_t reply_data;
	str reason, body, *pbody;

	if (status < 200) /* don't mind about provisional */
		return 0;
	msl = (struct media_session_leg *)param;

	/* final reply here - unref the session */
	if (msg == FAKED_REPLY || status >= 300)
		goto terminate;

	if (get_body(msg, &body) < 0 || body.len == 0) {
		LM_WARN("no body received for INVITE challenge!\n");
		status = 488; /* not acceptable */
		goto terminate;
	}

	MEDIA_SESSION_REPLY_PREP(&reply_data, msl);
	reply_data.method = METHOD_INVITE;
	reply_data.code = 200;
	reason.s = "OK";
	reason.len = 2;
	reply_data.text = &reason;
	reply_data.body = &body;
	if (media_b2b.send_reply(&reply_data) < 0) {
		LM_ERR("could not send reply to media server!\n");
		goto terminate;
	}

	if (!msl->nohold && !media_session_other_leg(msl)) {
		/* we need to put the other party on hold */
		pbody = media_session_get_hold_sdp(msl);
		if (!pbody)
			goto error;
		/* XXX: should we care whether the other party is properly on hold? */
		if (media_session_reinvite(msl,
				MEDIA_SESSION_DLG_OTHER_LEG(msl), pbody) < 0)
			LM_ERR("could not copy send indialog request for hold\n");
		pkg_free(pbody->s);
	}

	/* finished processing this reply */
	MSL_UNREF(msl);
	return 0;

terminate:
	/* the client declined the invite - propagate the code */
	MEDIA_SESSION_REPLY_PREP(&reply_data, msl);
	reply_data.method = METHOD_INVITE;
	reply_data.code = status;
	reason.s = error_text(status);
	reason.len = strlen(reason.s);
	reply_data.text = &reason;
	media_b2b.send_reply(&reply_data);

	MSL_UNREF(msl);
	/* no need of this session leg - remote it */
	media_session_leg_free(msl);
	return -1;

error:
	MSL_UNREF(msl);
	return -1;
}

static int media_exchange_to_call(struct sip_msg *msg, str *callid, int leg, int *nohold)
{
	str body;
	str contact;
	str *b2b_key;
	struct dlg_cell *dlg;
	struct media_session_leg *msl;
	static str inv = str_init("INVITE");
	str hack;

	if (leg == MEDIA_LEG_UNSPEC) {
		LM_BUG("leg parameter is mandatory for media_exchange_to_call!\n");
		return -1;
	}

	if (get_body(msg, &body) < 0 || body.len == 0) {
		LM_WARN("no body to fetch media from!\n");
		return -3;
	}

	if (!msg->content_type &&
			(parse_headers(msg, HDR_CONTENTTYPE_F, 0) < 0 || !msg->content_type)) {
		LM_ERR("could not parse content type!\n");
		return -3;
	}
	contact.s = contact_builder(msg->rcv.bind_address, &contact.len);

	/* we first try to find the dialog */
	dlg = media_dlg.get_dlg_by_callid(callid, 1);
	if (!dlg) {
		LM_ERR("dialog with callid %.*s not found!\n",
				callid->len, callid->s);
		return -1;
	}

	msl = media_session_new_leg(dlg, MEDIA_SESSION_TYPE_EXCHANGE, leg,
			((nohold && *nohold)?1:0));
	if (!msl) {
		LM_ERR("cannot create new exchange leg!\n");
		goto unref;
	}

	hack.s = (char *)&msl;
	hack.len = sizeof(void *);
	b2b_key = media_b2b.server_new(msg, &contact, b2b_media_server_notify, &hack);
	if (!b2b_key) {
		LM_ERR("could not create b2b server for callid %.*s\n", callid->len, callid->s);
		goto destroy;
	}
	if (shm_str_dup(&msl->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b server key for callid %.*s\n", callid->len, callid->s);
		/* key is not yet stored, so cannot be deleted */
		media_b2b.entity_delete(B2B_SERVER, b2b_key, NULL, 1);
		goto destroy;
	}
	msl->b2b_entity = B2B_SERVER;
	/* all good - send the invite to the client */
	MSL_REF(msl);
	if (media_dlg.send_indialog_request(dlg, &inv, MEDIA_SESSION_DLG_LEG(msl),
			&body, &msg->content_type->body, media_session_exchange_server_reply, msl) < 0) {
		LM_ERR("could not send indialog request for callid %.*s\n", callid->len, callid->s);
		goto destroy;
	}
	media_dlg.dlg_unref(dlg, 1);
	return 0;

destroy:
	MSL_UNREF(msl);
unref:
	media_dlg.dlg_unref(dlg, 1);
	return -2;
}

static int media_terminate(struct sip_msg *msg, int leg, int *nohold)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int b2b_media_server_notify(struct sip_msg *msg, str *key, int type, void *param)
{
	str reason;
	b2b_rpl_data_t reply_data;
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)param)->s;

	if (type == B2B_REPLY) {
		if (msg->REQ_METHOD == METHOD_BYE) {
			LM_DBG("final BYE for %.*s\n", key->len, key->s);
			/* TODO: handle final BYE */
		} else {
			LM_DBG("unexpected method %d for %.*s\n", msg->REQ_METHOD,
					key->len, key->s);
		}
	} else {
		switch (msg->REQ_METHOD) {
			case METHOD_ACK:
				return 0;
			case METHOD_BYE:
				LM_DBG("media server ended the playback for %.*s\n",
						key->len, key->s);
				MEDIA_SESSION_REPLY_PREP(&reply_data, msl);
				reply_data.method = METHOD_BYE;
				reply_data.code = 200;
				reason.s = "OK";
				reason.len = 2;
				reply_data.text = &reason;
				if (media_b2b.send_reply(&reply_data) < 0)
					LM_ERR("could not confirm session ending!\n");

				if (media_session_resume_dlg(msl) < 0)
					LM_ERR("could not resume media session!\n");

				/* should be last unref */
				MSL_UNREF(msl);

				break;
			/* TODO: handle re-invite? */
			default:
				LM_DBG("unexpected reply for method %d for %.*s\n",
						msg->REQ_METHOD, key->len, key->s);
				return -1;
		}
	}
	return 0;
}

static mi_response_t *mi_media_fork_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	LM_WARN("not implemented yet!\n");
	return NULL;
}

static mi_response_t *mi_media_exchange_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	LM_WARN("not implemented yet!\n");
	return NULL;
}

static mi_response_t *mi_media_terminate(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int hold;
	int media_leg;
	str callid, leg;
	struct dlg_cell *dlg;
	struct media_session *ms;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	switch (try_get_mi_string_param(params, "leg", &leg.s, &leg.len)) {
		case 0:
			media_leg = fixup_get_media_leg_both(&leg);
			if (media_leg < 0)
				return init_mi_error(406, MI_SSTR("invalid leg parameter"));
			break;
		case -1:
			/* not found: terminate both */
			media_leg = MEDIA_LEG_BOTH;
			break;
		default:
			return init_mi_param_error();
	}

	switch (try_get_mi_int_param(params, "hold", &hold)) {
		case -1:
			hold = 0;
		case 0:
			break;
		default:
			return init_mi_param_error();
	}

	/* params are now ok, let's lookup the media session */
	dlg = media_dlg.get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog not found"));

	ms = media_session_get(dlg);
	if (!ms) {
		media_dlg.dlg_unref(dlg, 1);
		return init_mi_error(404, MI_SSTR("Media Session not found"));
	}

	/* all good - implement the logic now */
	if (media_session_end(ms, media_leg, hold) < 0) {
		media_dlg.dlg_unref(dlg, 1);
		return init_mi_error(500, MI_SSTR("Terminate failed"));
	}
	media_dlg.dlg_unref(dlg, 1);
	return init_mi_result_ok();
}
