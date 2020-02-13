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
static int b2b_media_client_notify(struct sip_msg *msg, str *key, int type, void *param);
static int b2b_media_confirm(str* key, str* entity_key, int src, b2b_dlginfo_t* info);

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
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg,0}, /* leg */
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

static inline client_info_t *media_get_client_info(struct socket_info *si,
		str *uri, str *hdrs, str *body)
{
	static client_info_t ci;

	memset(&ci, 0, sizeof ci);

	ci.method.s = INVITE;
	ci.method.len = INVITE_LEN;
	ci.req_uri = *uri;
	ci.to_uri = ci.req_uri;
	ci.from_uri = ci.req_uri;
	ci.extra_headers = hdrs;
	ci.body = body;
	ci.send_sock = si;

	ci.local_contact.s = contact_builder(si, &ci.local_contact.len);
	return &ci;
}

struct media_session_tm_param {
	struct cell *t;
	int leg;
};

static int handle_media_exchange_from_uri(struct socket_info *si, struct dlg_cell *dlg,
		str *uri, int leg, str *body, str *headers, int nohold,
		struct media_session_tm_param *p)
{
	str hack;
	struct media_session_leg *msl;
	static client_info_t *ci;
	str *b2b_key;

	msl = media_session_new_leg(dlg, MEDIA_SESSION_TYPE_EXCHANGE, leg, nohold);
	if (!msl) {
		LM_ERR("cannot create new exchange leg!\n");
		return -2;
	}
	if ((ci = media_get_client_info(si, uri, headers, body)) == NULL) {
		LM_ERR("could not create client!\n");
		goto destroy;
	}
	if (p) {
			media_tm.ref_cell(p->t); /* ref the cell to be able to reply */
			MSL_REF(msl); /* make sure the media session leg does not dissapear either */
			msl->params = p;
	}

	hack.s = (char *)&msl;
	hack.len = sizeof(void *);
	MSL_REF(msl);
	b2b_key = media_b2b.client_new(ci, b2b_media_client_notify,
			b2b_media_confirm, &hack);
	if (!b2b_key) {
		LM_ERR("could not create b2b client!\n");
		goto unref;
	}
	if (shm_str_dup(&msl->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b client key\n");
		/* key is not yet stored, so cannot be deleted */
		media_b2b.entity_delete(B2B_CLIENT, b2b_key, NULL, 1);
		goto unref;
	}
	msl->b2b_entity = B2B_CLIENT;
	return 1;
unref:
	if (p) {
		MSL_UNREF(msl);
		media_tm.unref_cell(p->t);
		msl->params = NULL;
	}
destroy:
	MSL_UNREF(msl);
	return -2;
}

static int media_exchange_from_uri(struct sip_msg *msg, str *uri, int leg,
		str *body, str *headers, int *nohold)
{
	struct cell *t = NULL;
	struct dlg_cell *dlg;
	str sbody;
	int req_leg;
	struct socket_info *si;
	struct media_session_tm_param *p = NULL;

	/* if we have an indialog re-invite, we need to respond to it after we get
	 * the SDP - so we need to store the transaction until we have a new body
	 */
	if (msg->REQ_METHOD == METHOD_INVITE) {
		media_tm.t_newtran(msg);
		t = media_tm.t_gett();
	}

	dlg = media_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("dialog does not exist! please engage this function "
				"after creating/matching the dialog!\n");
		return -1;
	}
	if (media_dlg.get_direction() == DLG_DIR_DOWNSTREAM)
		req_leg = DLG_CALLER_LEG;
	else
		req_leg = callee_idx(dlg);
	if (leg == MEDIA_LEG_UNSPEC) {
		/* media not specified - use the current leg */
		if (req_leg == DLG_CALLER_LEG)
			leg = MEDIA_LEG_CALLEE;
		else
			leg = MEDIA_LEG_CALLER;
	}
	if (!body) {
		sbody = dlg_get_out_sdp(dlg, req_leg);
		body = &sbody;
	}

	if (!msg->force_send_socket) {
		union sockaddr_union tmp;
		si = uri2sock(msg, uri, &tmp, PROTO_NONE);
		if (!si) {
			LM_ERR("could not find suitable socket for originating "
					"traffic to %.*s\n", uri->len, uri->s);
			return -2;
		}
	} else {
		si = msg->force_send_socket;
	}

	if (t) {
		p = shm_malloc(sizeof(struct media_session_tm_param));
		if (p) {
			p->t = t;
			p->leg = req_leg;
		} else {
			LM_WARN("could not allocate media session tm param!\n");
		}
	}
	if (handle_media_exchange_from_uri(si, dlg, uri, leg,
			body, headers, ((nohold && *nohold)?1:0), p) < 0) {
		if (p)
			shm_free(p);
		return -3;
	}
	return 1;
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
	struct dlg_cell *dlg;
	struct media_session *ms;
	struct cell *t = NULL;
	int proxied;

	dlg = media_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("dialog does not exist! please engage this function "
				"after creating/matching the dialog!\n");
		return -1;
	}
	if (leg == MEDIA_LEG_UNSPEC)
		leg = MEDIA_LEG_BOTH;
	ms = media_session_get(dlg);
	if (!ms) {
		LM_WARN("could not find media session for dialog %.*s\n",
				dlg->callid.len, dlg->callid.s);
		return -1;
	}
	proxied = 0;
	if (msg->REQ_METHOD == METHOD_INVITE) {
		media_tm.t_newtran(msg);
		t = media_tm.t_gett();
		if (t && !nohold) {
			/* we have a transaction, and we were triggered by a proxied
			 * invite, therefore we should let this invite go through and
			 * resume the call
			 */
			proxied = 1;
		}
	}
	if (media_session_end(ms,leg, ((nohold && *nohold)?1:0), proxied) < 0) {
		LM_ERR("could not terminate media session!\n");
		return -2;
	}
	return 1;
}

static str *get_dlg_headers(struct dlg_cell *dlg, int dleg)
{
	static str content_type = str_init("Content-Type: application/sdp\r\n");
	static str contact_start = str_init("Contact: <");
	static str contact_end = str_init(">\r\n");
	static str hdrs;
	char *p;
	int sleg = other_leg(dlg, dleg);

	if (dlg->legs[dleg].adv_contact.len)
		hdrs.len =  dlg->legs[dleg].adv_contact.len;
	else
		hdrs.len = contact_start.len +
			dlg->legs[sleg].contact.len +
			contact_end.len;
	hdrs.len += content_type.len;
	hdrs.s = pkg_malloc(hdrs.len);
	if (!hdrs.s) {
		LM_ERR("No more pkg for extra headers \n");
		return 0;
	}
	p = hdrs.s;
	if (dlg->legs[dleg].adv_contact.len) {
		memcpy(p, dlg->legs[dleg].adv_contact.s,
				dlg->legs[dleg].adv_contact.len);

		p += dlg->legs[dleg].adv_contact.len;
	} else {
		memcpy(p, contact_start.s, contact_start.len);
		p += contact_start.len;
		memcpy(p, dlg->legs[sleg].contact.s,
				dlg->legs[sleg].contact.len);

		p += dlg->legs[sleg].contact.len;
		memcpy(p, contact_end.s, contact_end.len);
		p += contact_end.len;
	}
	memcpy(p, content_type.s, content_type.len);
	p += content_type.len;
	return &hdrs;
}

static int handle_media_session_reply(struct media_session_leg *msl, struct sip_msg *msg)
{
	/* we end up here with a request that has to be forwarded to
	 * one of the participants
	 */
	int ret;
	str *hdrs;
	str body, *pbody;
	str ok = str_init("OK");
	struct dlg_cell *dlg;
	struct media_session_tm_param *p = msl->params;

	/* all good now :D */
	if (get_body(msg, &body) < 0 || body.len == 0) {
		LM_WARN("no body to exchange media with!\n");
		return -1;
	}
	dlg = msl->ms->dlg;
	if (!p) {
		/* here we were triggered outside of a request - simply reinvite the
		 * other leg with the new body */
		ret = media_session_reinvite(msl, MEDIA_SESSION_DLG_LEG(msl), &body);
		if (!msl->nohold && !media_session_other_leg(msl)) {
			/* we need to put the other party on hold */
			pbody = media_session_get_hold_sdp(msl);
			if (pbody) {
				if (media_session_reinvite(msl,
						MEDIA_SESSION_DLG_OTHER_LEG(msl), pbody) < 0)
					LM_ERR("could not copy send indialog request for hold\n");
				pkg_free(pbody->s);
			}
		}
		return 0;
	}
	/* if we have params, this means that the request was
	 * triggered in the context of a transaction, so we have to
	 * reply to that transaction
	 */
	msl->params = NULL;
	if ((p->leg == DLG_CALLER_LEG && msl->leg == MEDIA_LEG_CALLER) ||
		(p->leg != DLG_CALLER_LEG && msl->leg == MEDIA_LEG_CALLEE)) {
		/* if we have media on the same leg that triggered the request,
		 * then we have to send the body to that leg, in reply */
		ret = media_tm.t_reply_with_body(p->t, 200, &ok,
				&body, NULL, &dlg->legs[p->leg].tag);

		if (!msl->nohold && !media_session_other_leg(msl)) {
			/* we need to put the other party on hold */
			pbody = media_session_get_hold_sdp(msl);
			if (pbody) {
				if (media_session_reinvite(msl,
						MEDIA_SESSION_DLG_OTHER_LEG(msl), pbody) < 0)
					LM_ERR("could not copy send indialog request for hold\n");
				pkg_free(pbody->s);
			}
		}

	} else {
		/* we have a differet leg, so we need to request in the oposite
		 * direction */
		ret = media_session_reinvite(msl, other_leg(dlg, p->leg), &body);
		hdrs = get_dlg_headers(dlg, p->leg);
		if (!msl->nohold && !media_session_other_leg(msl)) {
			/* we need to put the other party on hold */
			pbody = media_session_get_hold_sdp(msl);
			if (media_tm.t_reply_with_body(p->t, 200, &ok,
					pbody, hdrs, &dlg->legs[other_leg(dlg, p->leg)].tag) < 0)
				LM_ERR("could not copy send indialog reply for hold\n");
			pkg_free(pbody->s);
		} else {
			body = dlg_get_out_sdp(dlg, other_leg(dlg, p->leg));
			if (media_tm.t_reply_with_body(p->t, 200, &ok,
					&body, hdrs, &dlg->legs[other_leg(dlg, p->leg)].tag) < 0)
				LM_ERR("could not copy send indialog reply for hold\n");
		}
		pkg_free(hdrs->s);
	}
	MSL_UNREF(msl);
	media_tm.unref_cell(p->t);
	shm_free(p);
	return ret;
}


static int b2b_media_client_notify(struct sip_msg *msg, str *key, int type, void *param)
{
	str reason;
	b2b_rpl_data_t reply_data;
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)param)->s;

	if (type == B2B_REQUEST) {
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

				return 0;
			default:
				LM_DBG("unexpected method %d for %.*s\n", msg->REQ_METHOD,
						key->len, key->s);
				return -1;
		}
	} else {
		if (msg->REPLY_STATUS < 200) /* don't care about provisional replies */
			return 0;

		if (parse_headers(msg, HDR_CSEQ_F, 0) < 0) {
			LM_ERR("could not parse reply cseq!\n");
			return -1;
		}
		switch (get_cseq(msg)->method_id) {
			case METHOD_INVITE:
				if (msg->REPLY_STATUS >= 300) {
					LM_ERR("could not stream media due to negative reply %d\n",
							msg->REPLY_STATUS);
					goto drop_leg;
				}
				media_session_req(msl, ACK);
				if (handle_media_session_reply(msl, msg) < 0) {
					LM_ERR("could not establish media exchange!\n");
					goto terminate;
				}
				/* successfully processed reply */
				MSL_UNREF(msl);
				break;
			case METHOD_BYE:
				/* nothing to do now, just absorb! */
				return 0;
			default:
				LM_DBG("unexpected reply with status %d for %.*s\n",
						msg->REPLY_STATUS, key->len, key->s);
				return -1;
		}
	}
	return 0;
terminate:
	media_session_req(msl, BYE);
drop_leg:
	MSL_UNREF(msl);
	media_session_leg_free(msl);
	return -1;
}

static int b2b_media_confirm(str* key, str* entity_key, int src, b2b_dlginfo_t* info)
{
	/* TODO: copy from info fromtag, totag, callid
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)key)->s;
	*/
	return 0;
}

static int b2b_media_server_notify(struct sip_msg *msg, str *key, int type, void *param)
{
	str reason;
	b2b_rpl_data_t reply_data;
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)param)->s;

	if (type == B2B_REPLY) {
			LM_DBG("unexpected reply with status %d for %.*s\n",
					msg->REPLY_STATUS, key->len, key->s);
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
				LM_DBG("unexpected method %d for %.*s\n", msg->REQ_METHOD,
						key->len, key->s);
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
	int nohold;
	int media_leg;
	str callid, leg, uri;
	str body, shdrs, *hdrs;
	struct dlg_cell *dlg;
	struct socket_info *si;
	union sockaddr_union tmp;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "uri", &uri.s, &uri.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "leg", &leg.s, &leg.len) < 0)
		return init_mi_param_error();

	switch (try_get_mi_int_param(params, "nohold", &nohold)) {
		case -1:
			nohold = 0;
		case 0:
			break;
		default:
			return init_mi_param_error();
	}
	if (try_get_mi_string_param(params, "headers", &shdrs.s, &shdrs.len) < 0)
		hdrs = NULL;
	else
		hdrs = &shdrs;

	media_leg = fixup_get_media_leg(&leg);
	if (media_leg < 0)
		return init_mi_error(406, MI_SSTR("invalid leg parameter"));

	si = uri2sock(NULL, &uri, &tmp, PROTO_NONE);
	if (!si)
		return init_mi_error(500, MI_SSTR("No suitable socket"));

	/* params are now ok, let's lookup the media session */
	dlg = media_dlg.get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog not found"));

	if (try_get_mi_string_param(params, "body", &body.s, &body.len) < 0) {
		/* body not found - need to get the body from dialog */
		body = dlg_get_out_sdp(dlg, DLG_MEDIA_SESSION_LEG(dlg, media_leg));
	}

	if (handle_media_exchange_from_uri(si, dlg, &uri, media_leg, &body,
			hdrs, nohold, NULL) < 0) {
		media_dlg.dlg_unref(dlg, 1);
		return init_mi_error(500, MI_SSTR("Could not start media session"));
	}

	/* all good now, unref the dialog as it is reffed by the ms */
	media_dlg.dlg_unref(dlg, 1);
	return init_mi_result_ok();
}

static mi_response_t *mi_media_terminate(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int nohold;
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

	switch (try_get_mi_int_param(params, "nohold", &nohold)) {
		case -1:
			nohold = 0;
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
	if (media_session_end(ms, media_leg, nohold, 0) < 0) {
		media_dlg.dlg_unref(dlg, 1);
		return init_mi_error(500, MI_SSTR("Terminate failed"));
	}
	media_dlg.dlg_unref(dlg, 1);
	return init_mi_result_ok();
}
