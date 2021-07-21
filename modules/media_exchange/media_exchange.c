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

static str b2b_media_exchange_cap = str_init("media_exchange");

static int mod_init(void);
static int media_fork_to_uri(struct sip_msg *msg, str *uri,
		int leg, str *headers, int *medianum);
static int media_fork_from_call(struct sip_msg *msg, str *callid,
		int leg, int *medianum);
static int media_fork_pause(struct sip_msg *msg, int leg, int *medianum);
static int media_fork_resume(struct sip_msg *msg, int leg, int *medianum);
static int media_exchange_from_uri(struct sip_msg *msg, str *uri,
		int leg, str *body, str *headers, int *nohold);
static int media_exchange_to_call(struct sip_msg *msg, str *callid,
		int leg, int *nohold);
static int media_terminate(struct sip_msg *msg, int leg, int *nohold);
static int media_indialog(struct sip_msg *msg);
static int fixup_media_leg(void **param);
static int fixup_media_leg_both(void **param);

static int b2b_media_notify(struct sip_msg *msg, str *key, int type, void *param,
	int flags);
static int b2b_media_confirm(str* key, str* entity_key, int src, b2b_dlginfo_t* info);

static mi_response_t *mi_media_fork_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_media_exchange_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_media_terminate(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int media_send_ok(struct cell *t, struct dlg_cell *dlg,
		int leg, str *body);
static int media_send_fail(struct cell *t, struct dlg_cell *dlg, int leg);

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
		{0,0,0}}, ALL_ROUTES},
	{"media_exchange_to_call",(cmd_function)media_exchange_to_call, {
		{CMD_PARAM_STR,0,0}, /* callid */
		{CMD_PARAM_STR,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE},
	{"media_fork_to_uri",(cmd_function)media_fork_to_uri, {
		{CMD_PARAM_STR,0,0}, /* uri */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* headers */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* medianum */
		{0,0,0}}, ALL_ROUTES},
	{"media_fork_from_call",(cmd_function)media_fork_from_call, {
		{CMD_PARAM_STR,0,0}, /* callid */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* medianum */
		{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE},
	{"media_fork_pause",(cmd_function)media_fork_pause, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* medianum */
		{0,0,0}}, ALL_ROUTES},
	{"media_fork_resume",(cmd_function)media_fork_resume, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* medianum */
		{0,0,0}}, ALL_ROUTES},
	{"media_terminate",(cmd_function)media_terminate, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}}, ALL_ROUTES},
	{"media_handle_indialog",(cmd_function)media_indialog, {
		{0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE},
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

	if (media_b2b.register_cb(media_exchange_event_received,
			B2BCB_RECV_EVENT, &b2b_media_exchange_cap) < 0) {
		LM_ERR("could not register loaded callback!\n");
		return -1;
	}

	if (media_b2b.register_cb(media_exchange_event_trigger,
			B2BCB_TRIGGER_EVENT, &b2b_media_exchange_cap) < 0) {
		LM_ERR("could not register loaded callback!\n");
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

static int handle_media_fork_to_uri(struct media_session_leg *msl, struct socket_info *si,
		str *uri, str *headers, int medianum, str *caller_body, str *callee_body)
{
	str hack;
	static client_info_t *ci;
	struct media_fork_info *mf;
	str *b2b_key;

	if (media_util_init_static() < 0) {
		LM_ERR("could not initalize media util static!\n");
		goto release;
	}
	mf = media_sdp_get(msl->ms->dlg, msl->leg, medianum, caller_body, callee_body);
	if (!mf) {
		LM_ERR("could not generate media fork SDP!\n");
		goto destroy;
	}
	MEDIA_LEG_LOCK(msl);
	if (msl->params) {
		LM_WARN("already an ongoing forking for this leg!\n");
		MEDIA_LEG_UNLOCK(msl);
		goto destroy;
	}
	msl->params = mf;
	MEDIA_LEG_UNLOCK(msl);
	if ((ci = media_get_client_info(si, uri, headers, media_sdp_buf_get())) == NULL) {
		LM_ERR("could not create client!\n");
		goto release;
	}

	hack.s = (char *)&msl;
	hack.len = sizeof(void *);
	b2b_key = media_b2b.client_new(ci, b2b_media_notify,
			b2b_media_confirm, &b2b_media_exchange_cap, &hack);
	if (!b2b_key) {
		LM_ERR("could not create b2b client!\n");
		goto release;
	}
	if (shm_str_dup(&msl->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b client key\n");
		/* key is not yet stored, so cannot be deleted */
		media_b2b.entity_delete(B2B_CLIENT, b2b_key, NULL, 1, 1);
		goto release;
	}
	msl->params = mf;
	msl->b2b_entity = B2B_CLIENT;
	media_util_release_static();
	return 1;
release:
	media_util_release_static();
destroy:
	MSL_UNREF(msl);
	return -2;
}

struct media_fork_params {
	struct media_session_leg *msl;
	struct socket_info *si;
	str uri;
	str headers;
	int medianum;
};

void media_fork_params_free(void *p)
{
	struct media_fork_params *mp = (struct media_fork_params *)p;
	MSL_UNREF(mp->msl);
	shm_free(mp);
}

static void media_fork_start(struct cell *t, int type, struct tmcb_params *ps)
{
	str callee_body, caller_body;
	struct media_fork_params *mp;

	if (!is_invite(t) || ps->code >= 300)
		return;
	/* check if we have a reply with body */
	if (get_body(ps->rpl, &callee_body) != 0 || callee_body.len==0)
		return;

	if (get_body(ps->req, &caller_body) != 0) {
		caller_body.s = NULL;
		caller_body.len = 0;
	}

	mp = (struct media_fork_params *)*ps->param;

	if (handle_media_fork_to_uri(mp->msl, mp->si, &mp->uri, &mp->headers,
			mp->medianum, (caller_body.len?&caller_body:NULL), &callee_body) < 0) {
		LM_ERR("could not start media forking!\n");
	}
}

static int media_fork_to_uri(struct sip_msg *msg,
		str *uri, int leg, str *headers, int *medianum)
{
	struct dlg_cell *dlg;
	struct socket_info *si;
	struct media_session_leg *msl;
	struct media_fork_params *mp;

	dlg = media_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("dialog does not exist! please engage this function "
				"after creating/matching the dialog!\n");
		return -1;
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

	if (leg == MEDIA_LEG_UNSPEC) {
		if (media_dlg.get_direction() == DLG_DIR_DOWNSTREAM)
			leg = MEDIA_LEG_CALLER;
		else
			leg = MEDIA_LEG_CALLEE;
	}

	msl = media_session_new_leg(dlg, MEDIA_SESSION_TYPE_FORK, leg, 0);
	if (!msl) {
		LM_ERR("cannot create new exchange leg!\n");
		return -2;
	}
	mp = shm_malloc(sizeof *mp + uri->len + (headers?headers->len:0));
	if (!mp) {
		LM_ERR("could not allocate media fork params!\n");
		MSL_UNREF(msl);
		return -2;
	}
	mp->msl = msl;
	mp->si = si;
	mp->medianum = (medianum?*medianum:-1);
	mp->uri.s = (char *)(mp + 1);
	mp->uri.len = uri->len;
	memcpy(mp->uri.s, uri->s, uri->len);
	if (headers && headers->len) {
		mp->headers.s = mp->uri.s + mp->uri.len;
		mp->headers.len = headers->len;
		memcpy(mp->headers.s, headers->s, headers->len);
	}
	MSL_REF(msl);
	if (media_tm.register_tmcb(msg, 0, TMCB_RESPONSE_OUT, media_fork_start,
			mp, media_fork_params_free) <= 0) {
		LM_ERR("could not schedule media fork start!\n");
		MSL_UNREF(msl);
		/* also destroy! */
		MSL_UNREF(msl);
		return -3;
	}

	/* all good now, unref the dialog as it is reffed by the ms */
	return 1;
}

static int media_fork_from_call(struct sip_msg *msg, str *callid, int leg, int *medianum)
{
	str hack;
	str contact;
	str *b2b_key;
	sdp_info_t *sdp;
	struct dlg_cell *dlg;
	struct media_session_leg *msl;
	struct media_fork_info *mf;

	if (msg->REQ_METHOD != METHOD_INVITE) {
		LM_ERR("this method should only be called on initial invites!\n");
		return -1;
	}
	if (!media_rtp.start_recording) {
		LM_ERR("rtpproxy module not loaded!\n");
		return -1;
	}

	if (leg == MEDIA_LEG_UNSPEC)
		leg = MEDIA_LEG_BOTH;

	sdp = parse_sdp(msg);
	if (!sdp) {
		LM_ERR("could not parse message SDP!\n");
		return -2;
	}
	if (!sdp->streams_num) {
		LM_WARN("no stream to fork media to!\n");
		return -2;
	}

	contact.s = contact_builder(msg->rcv.bind_address, &contact.len);

	/* we first try to find the dialog */
	dlg = media_dlg.get_dlg_by_callid(callid, 1);
	if (!dlg) {
		LM_ERR("dialog with callid %.*s not found!\n",
				callid->len, callid->s);
		return -2;
	}

	if (media_util_init_static() < 0) {
		LM_ERR("could not initalize media util static!\n");
		goto release;
	}
	mf = media_sdp_match(dlg, leg, sdp, (medianum?*medianum:-1));
	if (!mf)
		goto unref;

	msl = media_session_new_leg(dlg, MEDIA_SESSION_TYPE_FORK, leg, 0);
	if (!msl) {
		LM_ERR("cannot create new fetch leg!\n");
		media_forks_free(mf);
		goto release;
	}
	MEDIA_LEG_LOCK(msl);
	if (msl->params) {
		LM_WARN("already an ongoing forking for this leg!\n");
		MEDIA_LEG_UNLOCK(msl);
		goto destroy;
	}
	msl->params = mf;
	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_UPDATING);
	MEDIA_LEG_UNLOCK(msl);

	hack.s = (char *)&msl;
	hack.len = sizeof(void *);
	b2b_key = media_b2b.server_new(msg, &contact, b2b_media_notify,
			&b2b_media_exchange_cap, &hack);
	if (!b2b_key) {
		LM_ERR("could not create b2b server for callid %.*s\n", callid->len, callid->s);
		goto destroy;
	}
	if (shm_str_dup(&msl->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b server key for callid %.*s\n", callid->len, callid->s);
		/* key is not yet stored, so cannot be deleted */
		media_b2b.entity_delete(B2B_SERVER, b2b_key, NULL, 1, 1);
		goto destroy;
	}
	msl->b2b_entity = B2B_SERVER;

	if (media_fork_streams(msl, mf) < 0) {
		LM_ERR("could not fork streams!\n");
		goto destroy;
	}
	MEDIA_LEG_STATE_SET(msl, MEDIA_SESSION_STATE_RUNNING);
	media_util_release_static();
	media_dlg.dlg_unref(dlg, 1);
	return 1;
destroy:
	MSL_UNREF(msl);
release:
	media_util_release_static();
unref:
	media_dlg.dlg_unref(dlg, 1);
	return -2;
}


struct media_session_tm_param {
	struct cell *t;
	int leg;
};

static struct media_session_tm_param *media_session_tm_new(struct cell *t, int leg)
{
	struct media_session_tm_param *p = shm_malloc(sizeof *p);
	if (!p) {
		LM_WARN("could not allocate media session tm param!\n");
		return NULL;
	}
	p->t = t;
	p->leg = leg;
	media_tm.ref_cell(t); /* ref the cell to be able to reply */
	return p;
}

static void media_session_tm_free(struct media_session_tm_param *p)
{
	media_tm.unref_cell(p->t);
	shm_free(p);
}

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
			MSL_REF(msl); /* make sure the media session leg does not dissapear either */
			msl->params = p;
	}

	hack.s = (char *)&msl;
	hack.len = sizeof(void *);
	b2b_key = media_b2b.client_new(ci, b2b_media_notify,
			b2b_media_confirm, &b2b_media_exchange_cap, &hack);
	if (!b2b_key) {
		LM_ERR("could not create b2b client!\n");
		goto unref;
	}
	if (shm_str_dup(&msl->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b client key\n");
		/* key is not yet stored, so cannot be deleted */
		media_b2b.entity_delete(B2B_CLIENT, b2b_key, NULL, 1, 1);
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

	if (t)
		p = media_session_tm_new(t, req_leg);

	if (handle_media_exchange_from_uri(si, dlg, uri, leg,
			body, headers, ((nohold && *nohold)?1:0), p) < 0) {
		if (p)
			media_session_tm_free(p);
		return -3;
	}
	return 1;
}

static int media_session_exchange_server_reply(struct sip_msg *msg, int status, void *param)
{
	struct media_session_leg *msl;
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

	reason.s = "OK";
	reason.len = 2;
	if (media_session_rpl(msl, METHOD_INVITE, 200, &reason, &body) < 0) {
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
	reason.s = error_text(status);
	reason.len = strlen(reason.s);
	media_session_rpl(msl, METHOD_INVITE, status, &reason, NULL);

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
	b2b_key = media_b2b.server_new(msg, &contact, b2b_media_notify,
			&b2b_media_exchange_cap, &hack);
	if (!b2b_key) {
		LM_ERR("could not create b2b server for callid %.*s\n", callid->len, callid->s);
		goto destroy;
	}
	if (shm_str_dup(&msl->b2b_key, b2b_key) < 0) {
		LM_ERR("could not copy b2b server key for callid %.*s\n", callid->len, callid->s);
		/* key is not yet stored, so cannot be deleted */
		media_b2b.entity_delete(B2B_SERVER, b2b_key, NULL, 1, 1);
		goto destroy;
	}
	msl->b2b_entity = B2B_SERVER;
	/* all good - send the invite to the client */
	MSL_REF(msl);
	if (media_dlg.send_indialog_request(dlg, &inv, MEDIA_SESSION_DLG_LEG(msl),
			&body, &msg->content_type->body, NULL, media_session_exchange_server_reply, msl) < 0) {
		LM_ERR("could not send indialog request for callid %.*s\n", callid->len, callid->s);
		MSL_UNREF(msl);
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
	if (media_session_end(ms, leg, ((nohold && *nohold)?1:0), proxied) < 0) {
		LM_ERR("could not terminate media session!\n");
		return -2;
	}
	return 1;
}

struct handle_media_indialog_params {
	int dlg_leg;
	int update_reply;
	struct media_session_leg *msl;
};

static void handle_media_indialog_fork_release(void *p)
{
	MSL_UNREF(((struct handle_media_indialog_params *)p)->msl);
	shm_free(p);
}

static void handle_media_indialog_fork_reply(struct cell* t,
		int type, struct tmcb_params *p)
{
	str body;
	struct sip_msg *rpl;
	struct handle_media_indialog_params *params =
		(struct handle_media_indialog_params *)*p->param;
	struct media_session_leg *msl;

	if ( !t || !t->uas.request || !p->rpl )
		return;

	rpl = p->rpl;
	if (rpl == FAKED_REPLY || rpl == FAKED_REPLY)
		return;
	if (rpl->REPLY_STATUS < 200 || rpl->REPLY_STATUS >= 300) {
		LM_DBG("ignoring reply %d\n", rpl->REPLY_STATUS);
		return;
	}
	msl = params->msl;
	MEDIA_LEG_LOCK(msl);
	if (msl->state != MEDIA_SESSION_STATE_PENDING) {
		LM_DBG("invalid media exchange state! state=%d\n", msl->state);
		MEDIA_LEG_UNLOCK(msl);
		return;
	}
	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_UPDATING);
	MEDIA_LEG_UNLOCK(msl);
	if (params->update_reply) {
		/* we need to update the media from the reply */
		if (get_body(rpl, &body) < 0 || body.len == 0) {
			LM_DBG("no body received for INVITE challenge!\n");
			return;
		}
		if (media_fork_body_update(msl, &body, params->dlg_leg) < 0) {
			LM_ERR("could not update reply forks!\n");
			return;
		}
	}

	if (media_session_fork_update(msl) >= 0)
		MEDIA_LEG_STATE_SET(msl, MEDIA_SESSION_STATE_RUNNING);
}


static int handle_media_indialog_fork(struct sip_msg *msg, str *body,
		struct media_session_leg *msl, int leg)
{
	int ret;
	struct handle_media_indialog_params *params;

	MEDIA_LEG_LOCK(msl);
	if (msl->state != MEDIA_SESSION_STATE_RUNNING) {
		LM_DBG("this media leg is already involved in a different negociation! "
				"state=%d\n", msl->state);
		MEDIA_LEG_UNLOCK(msl);
		return -2; /* drop this request */
	}
	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_PENDING);
	MEDIA_LEG_UNLOCK(msl);

	params = shm_malloc(sizeof *params);
	if (!params) {
		LM_ERR("could not allocate params!\n");
		goto error;
	}

	if (body) {
		/* we need to treat this body too! */
		ret = media_fork_body_update(msl, body, leg);
		if (ret < 0) {
			LM_ERR("could not update forks!\n");
			goto error;
		}
	}
	params->dlg_leg = other_leg(msl->ms->dlg, leg);
	params->msl = msl;
	if (!body || msl->leg == MEDIA_LEG_BOTH || MEDIA_SESSION_DLG_LEG(msl) != leg)
		params->update_reply = 1;
	else
		params->update_reply = 0;
	MSL_REF(msl);
	if (media_tm.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED,
			handle_media_indialog_fork_reply, params,
			handle_media_indialog_fork_release) < 0) {
		LM_ERR("failed to register TMCB\n");
		MSL_UNREF(msl);
		goto error;
	}
	return 1;
error:
	shm_free(params);
	return -3;
}

static int handle_media_indialog_refresh(struct sip_msg *msg,
		struct media_session *ms, str *body)
{
	int ret = -1;
	str sbody;
	int req_leg;
	struct cell *t;
	struct media_session_tm_param *p;
	struct media_session_leg *leg, *oleg;

	if (media_dlg.get_direction() == DLG_DIR_DOWNSTREAM)
		req_leg = DLG_CALLER_LEG;
	else
		req_leg = callee_idx(ms->dlg);
	leg = media_session_get_leg(ms,
			(req_leg==DLG_CALLER_LEG?MEDIA_LEG_CALLER:MEDIA_LEG_CALLEE));
	oleg = media_session_get_leg(ms,
			(req_leg==DLG_CALLER_LEG?MEDIA_LEG_CALLEE:MEDIA_LEG_CALLER));
	if (!leg && !oleg) {
		LM_DBG("no legs involved!\n");
		return -1;
	}
	t = media_tm.t_gett();
	if (t == T_UNDEFINED)
		t = NULL;

	if (!leg) {
		/* here, we have a sequential request, but this leg is not involved in
		 * any media session */
		if (oleg->type == MEDIA_SESSION_TYPE_FORK) {
			return handle_media_indialog_fork(msg, NULL, oleg, req_leg);
		} else {
			/* we should reply with whatever reply we last sent to it and
			 * drop the request - if this is not correct, but unfortunately
			 * we can't bother the other leg with a re-invite, as he's already
			 * involved in a different media session */
			if (t) {
				if (oleg->nohold) {
					sbody = dlg_get_out_sdp(ms->dlg, other_leg(ms->dlg, req_leg));
					body = &sbody;
				} else {
					body = media_session_get_hold_sdp(oleg);
				}
				media_send_ok(t, ms->dlg, req_leg, body);
			}
			return -2;
		}
	}

	/* here, we still have the initial leg */
	if (leg->type == MEDIA_SESSION_TYPE_FORK) {
		ret = handle_media_indialog_fork(msg, body, leg, req_leg);;

		if (oleg) {
			if (oleg->type == MEDIA_SESSION_TYPE_FORK) {
				/* register callback to update the codecs on reply */
				 handle_media_indialog_fork(msg, NULL, oleg,
						 other_leg(ms->dlg, req_leg));
			} else {
				/* reply to current leg whatever was last sent */
				sbody = dlg_get_out_sdp(ms->dlg, other_leg(ms->dlg, req_leg));
				media_send_ok(t, ms->dlg, req_leg, body);
				ret = -2;
			}
		}
	} else {
		/* here leg is part of an exchange - proxy it */
		if (media_session_req(leg, INVITE, body) < 0) {
			media_send_fail(t, ms->dlg, req_leg);
			ret = -3;
		} else if (t) {
			/* link the transaction here */
			p = media_session_tm_new(t, req_leg);
			if (p) {
				MSL_REF(leg); /* make sure the media session leg does not dissapear either */
				leg->params = p;
			}
			ret = -2;
		}
	}

	return ret;
}

static int handle_media_indialog(struct sip_msg *msg, struct media_session *ms)
{
	str body;

	if (get_body(msg, &body) < 0)
		memset(&body, 0, sizeof(body));

	if (msg->first_line.type == SIP_REQUEST) {
		switch(msg->REQ_METHOD) {
			case METHOD_INVITE:
			case METHOD_UPDATE:
				if (body.len == 0)
					return -1;
				return handle_media_indialog_refresh(msg, ms, &body);
			default:
				LM_DBG("don't know what do do with %d\n", msg->REQ_METHOD);
				return -1;
		}
	} else {
		/* reply with no body - we don't really care */
		if (body.len == 0)
			return -1;
	}
	return -1;
}

static int media_indialog(struct sip_msg *msg)
{
	struct dlg_cell *dlg;
	struct media_session *ms;

	dlg = media_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("dialog does not exist! please engage this function "
				"after creating/matching the dialog!\n");
		return -1;
	}
	ms = media_session_get(dlg);
	if (!ms) {
		LM_DBG("could not find media session for dialog %.*s\n",
				dlg->callid.len, dlg->callid.s);
		return -1;
	}
	return handle_media_indialog(msg, ms);
}

static int media_send_ok(struct cell *t, struct dlg_cell *dlg,
		int leg, str *body)
{
	int ret;
	str *hdrs;
	str ok = str_init("OK");
	hdrs = media_get_dlg_headers(dlg, leg, 1);
	ret = media_tm.t_reply_with_body(t, 200, &ok,
			body, hdrs, &dlg->legs[other_leg(dlg, leg)].tag);
	pkg_free(hdrs->s);
	return ret;
}

static int media_send_fail(struct cell *t, struct dlg_cell *dlg, int leg)
{
	int ret;
	str *hdrs;
	str reason = str_init("Not Acceptable Here");
	hdrs = media_get_dlg_headers(dlg, leg, 0);
	ret = media_tm.t_reply_with_body(t, 488, &reason,
			NULL, hdrs, &dlg->legs[other_leg(dlg, leg)].tag);
	pkg_free(hdrs->s);
	return ret;
}

static int media_fork_pause(struct sip_msg *msg, int leg, int *medianum)
{
	struct dlg_cell *dlg;
	struct media_session *ms;
	struct media_session_leg *msl;
	int ret = 0;

	dlg = media_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("dialog does not exist! please engage this function "
				"after creating/matching the dialog!\n");
		return -1;
	}

	ms = media_session_get(dlg);
	if (!ms) {
		LM_WARN("could not find media session for dialog %.*s\n",
				dlg->callid.len, dlg->callid.s);
		return -1;
	}
	if (leg == MEDIA_LEG_UNSPEC) {
		for (msl = ms->legs; msl; msl = msl->next)
			ret += media_fork_pause_resume(msl, medianum?*medianum:-1, 0);
	} else {
		msl = media_session_get_leg(ms, leg);
		if (!msl) {
			LM_WARN("media session leg %d does not exist!\n", leg);
			return -1;
		}
		ret = media_fork_pause_resume(msl, medianum?*medianum:-1, 0);
	}

	if (ret == 0) {
		LM_DBG("no sessions to resume!\n");
		return -1;
	}
	return ret;
}

static int media_fork_resume(struct sip_msg *msg, int leg, int *medianum)
{
	struct dlg_cell *dlg;
	struct media_session *ms;
	struct media_session_leg *msl;
	int ret = 0;

	dlg = media_dlg.get_dlg();
	if (!dlg) {
		LM_WARN("dialog does not exist! please engage this function "
				"after creating/matching the dialog!\n");
		return -1;
	}

	ms = media_session_get(dlg);
	if (!ms) {
		LM_WARN("could not find media session for dialog %.*s\n",
				dlg->callid.len, dlg->callid.s);
		return -1;
	}
	if (leg == MEDIA_LEG_UNSPEC) {
		for (msl = ms->legs; msl; msl = msl->next)
			ret += media_fork_pause_resume(msl, medianum?*medianum:-1, 1);
	} else {
		msl = media_session_get_leg(ms, leg);
		if (!msl) {
			LM_WARN("media session leg %d does not exist!\n", leg);
			return -1;
		}
		ret = media_fork_pause_resume(msl, medianum?*medianum:-1, 1);
	}

	if (ret == 0) {
		LM_DBG("no sessions to resume!\n");
		return -1;
	}
	return ret;
}

static int media_session_exchange_negative_reply(struct sip_msg *msg, int status, void *param)
{
	struct media_session_leg *msl;
	struct media_session_tm_param *p;
	str sbody, *body;

	if (status < 200) /* don't mind about provisional */
		return 0;
	msl = (struct media_session_leg *)param;
	p = msl->params;
	msl->params = NULL;

	if (msg != FAKED_REPLY) {
		if (get_body(msg, &sbody) < 0 || sbody.len == 0)
			body = NULL;
		else
			body = &sbody;
	} else {
		status = 408;
		body = NULL;
	}
	if (status < 300)
		media_send_ok(p->t, msl->ms->dlg, p->leg, body);
	else
		media_send_fail(p->t, msl->ms->dlg, p->leg);
	MSL_UNREF(msl);
	media_session_tm_free(p);
	return 1;
}

static void handle_media_session_negative(struct media_session_leg *msl)
{
	static str inv = str_init("INVITE");
	struct media_session_tm_param *p = msl->params;
	int dlg_leg;
	str sbody, *body;

	/* if it is a fork, there's nothing to do */
	if (msl->type != MEDIA_SESSION_TYPE_EXCHANGE)
		return;

	/* if no transaction is hanging, we don't have anything to do */
	if (!p)
		return;

	/* now we reinvite the other participant with the actual body, and wait
	 * for the reply to relay it downstream */
	dlg_leg = MEDIA_SESSION_DLG_LEG(msl);

	/* we need to get the body from the request */
	if (get_body(p->t->uas.request, &sbody) < 0 || sbody.len == 0)
		body = NULL;
	else
		body = &sbody;
	if (media_dlg.send_indialog_request(msl->ms->dlg,
			&inv, dlg_leg, body, &content_type_sdp, NULL,
			media_session_exchange_negative_reply, msl) < 0) {
		LM_ERR("could not forward INVITE!\n");
		media_send_fail(p->t, msl->ms->dlg, dlg_leg);
		msl->params = NULL;
		MSL_UNREF(msl);
		media_session_tm_free(p);
	}
}

static int handle_media_session_reply_exchange(struct media_session_leg *msl,
		str *body, struct media_session_tm_param *p)
{
	int ret;
	str sbody;
	struct dlg_cell *dlg;

	dlg = msl->ms->dlg;
	if (!p) {
		/* here we were triggered outside of a request - simply reinvite the
		 * other leg with the new body */
		ret = media_session_reinvite(msl, MEDIA_SESSION_DLG_LEG(msl), body);
		if (!msl->nohold && !media_session_other_leg(msl)) {
			/* we need to put the other party on hold */
			body = media_session_get_hold_sdp(msl);
			if (body) {
				if (media_session_reinvite(msl,
						MEDIA_SESSION_DLG_OTHER_LEG(msl), body) < 0)
					LM_ERR("could not copy send indialog request for hold\n");
				pkg_free(body->s);
			}
		}
		return 0;
	}
	/* if we have params, this means that the request was
	 * triggered in the context of a transaction, so we have to
	 * reply to that transaction
	 */
	msl->params = NULL;
	MSL_UNREF(msl);
	if ((p->leg == DLG_CALLER_LEG && msl->leg == MEDIA_LEG_CALLER) ||
		(p->leg != DLG_CALLER_LEG && msl->leg == MEDIA_LEG_CALLEE)) {
		/* if we have media on the same leg that triggered the request,
		 * then we have to send the body to that leg, in reply */
		ret = media_send_ok(p->t, dlg, p->leg, body);

		if (!msl->nohold && !media_session_other_leg(msl)) {
			/* we need to put the other party on hold */
			body = media_session_get_hold_sdp(msl);
			if (body) {
				if (media_session_reinvite(msl,
						MEDIA_SESSION_DLG_OTHER_LEG(msl), body) < 0)
					LM_ERR("could not copy send indialog request for hold\n");
				pkg_free(body->s);
			}
		}

	} else {
		/* we have a differet leg, so we need to request in the oposite
		 * direction */
		ret = media_session_reinvite(msl, other_leg(dlg, p->leg), body);
		if (!msl->nohold && !media_session_other_leg(msl)) {
			/* we need to put the other party on hold */
			body = media_session_get_hold_sdp(msl);
			if (body) {
				if (media_send_ok(p->t, dlg, p->leg, body) < 0)
					LM_ERR("could not copy send indialog reply for hold\n");
				pkg_free(body->s);
			}
		} else {
			sbody = dlg_get_out_sdp(dlg, other_leg(dlg, p->leg));
			if (media_send_ok(p->t, dlg, other_leg(dlg, p->leg), &sbody) < 0)
				LM_ERR("could not copy send indialog reply for hold\n");
		}
	}
	media_session_tm_free(p);
	return ret;
}

static int handle_media_session_reply_fork(struct media_session_leg *msl, str *body)
{
	sdp_info_t sdp;
	sdp_stream_cell_t *stream;
	sdp_session_cell_t *session;
	struct media_fork_info *mf = msl->params;
	struct media_fork_info *minfo;
	int ret = -2;
	int disabled = 0;
	str *ip;
	str nullip = str_init("0.0.0.0");

	if (!mf) {
		LM_ERR("media fork info not available!\n");
		return -1;
	}
	MEDIA_LEG_LOCK(msl);
	if (msl->state != MEDIA_SESSION_STATE_PENDING &&
			msl->state != MEDIA_SESSION_STATE_INIT) {
		LM_DBG("media session not in update mode! probably a retransmission. "
				"state=%d\n", msl->state);
		MEDIA_LEG_UNLOCK(msl);
		return 0;
	}
	MEDIA_LEG_STATE_SET_UNSAFE(msl, MEDIA_SESSION_STATE_UPDATING);
	MEDIA_LEG_UNLOCK(msl);

	memset(&sdp, 0, sizeof(sdp));
	if (parse_sdp_session(body, 0, NULL, &sdp) < 0) {
		LM_ERR("invalid SDP body in reply!\n");
		goto error;
	}
	ret = 0;
	/* we need to match the SDP against the media_fork_info we have */
	for (session = sdp.sessions; session; session = session->next) {
		for (stream = session->streams; stream; stream = stream->next) {
			disabled = stream->is_on_hold;
			if (stream->ip_addr.len)
				ip = &stream->ip_addr;
			else
				ip = &session->ip_addr;
			/* skip disabled media streams */
			if (str_strcmp(ip, &nullip) == 0)
				disabled = 1;
			if (stream->port.len == 1 && stream->port.s[0] == '0')
				disabled = 1;

			minfo = media_fork_search(mf, stream->stream_num);
			if (minfo)
				ret += media_fork_update(msl, minfo, ip, &stream->port, disabled);
		}
	}
	free_sdp_content(&sdp);
error:
	MEDIA_LEG_STATE_SET(msl, MEDIA_SESSION_STATE_RUNNING);

	/* done - release the media forks */
	if (ret == 0) {
		LM_WARN("no valid streams to update!\n");
		ret = -1;
	}
	return ret;
}

static int handle_media_session_reply(struct media_session_leg *msl, struct sip_msg *msg)
{
	/* we end up here with a request that has to be forwarded to
	 * one of the participants
	 */
	int ret;
	str body;

	/* all good now :D */
	if (get_body(msg, &body) < 0 || body.len == 0) {
		LM_WARN("no body to exchange media with!\n");
		return -1;
	}
	if (msl->type == MEDIA_SESSION_TYPE_EXCHANGE)
		ret = handle_media_session_reply_exchange(msl, &body, msl->params);
	else
		ret = handle_media_session_reply_fork(msl, &body);

	return ret;
}

static int handle_indialog_request(struct sip_msg *msg, struct media_session_leg *msl, str *key)
{
	str reason;
	switch (msg->REQ_METHOD) {
		case METHOD_ACK:
			return 0;
		case METHOD_BYE:
			LM_DBG("media server ended the playback/forking for %.*s\n",
					key->len, key->s);
			reason.s = "OK";
			reason.len = 2;
			if (media_session_rpl(msl, METHOD_BYE, 200, &reason, NULL) < 0)
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
}

static int b2b_media_notify(struct sip_msg *msg, str *key, int type, void *param,
	int flags)
{
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)param)->s;
	int initial_state;

	if (type == B2B_REPLY) {
		if (msg->REPLY_STATUS < 200) /* don't care about provisional replies */
			return 0;

		if (parse_headers(msg, HDR_CSEQ_F, 0) < 0) {
			LM_ERR("could not parse reply cseq!\n");
			return -1;
		}
		switch (get_cseq(msg)->method_id) {
			case METHOD_INVITE:
				MEDIA_LEG_LOCK(msl);
				initial_state = msl->state;
				MEDIA_LEG_UNLOCK(msl);
				if (msg->REPLY_STATUS >= 300) {
					LM_ERR("could not stream media due to negative reply %d\n",
							msg->REPLY_STATUS);
					goto terminate;
				}
				media_session_req(msl, ACK, NULL);
				if (handle_media_session_reply(msl, msg) < 0) {
					LM_ERR("could not establish media exchange!\n");
					goto terminate;
				}
				/* successfully processed reply */
				break;
			case METHOD_BYE:
				/* nothing to do now, just absorb! */
				return 0;
			default:
				LM_DBG("unexpected reply with status %d for %.*s\n",
						msg->REPLY_STATUS, key->len, key->s);
				return -1;
		}
		return 0;
	} else {
		return handle_indialog_request(msg, msl, key);
	}
terminate:
	MEDIA_LEG_LOCK(msl);
	if (initial_state == MEDIA_SESSION_STATE_INIT) {
		/* this is the initial leg, not a re-invite */
		MEDIA_LEG_UNLOCK(msl);
		handle_media_session_negative(msl);
		MSL_UNREF(msl);
	} else {
		MEDIA_LEG_UNLOCK(msl);
	}
	return -1;
}

static int b2b_media_confirm(str* key, str* entity_key, int src, b2b_dlginfo_t* info)
{
	/* TODO: copy from info fromtag, totag, callid
	struct media_session_leg *msl = *(struct media_session_leg **)((str *)key)->s;
	*/
	return 0;
}

int b2b_media_restore_callbacks(struct media_session_leg *msl)
{
	str hack;
	hack.s = (char *)&msl;
	hack.len = sizeof(void *);
	if (media_b2b.update_b2bl_param(msl->b2b_entity, &msl->b2b_key, &hack, 0) < 0) {
		LM_ERR("could not update restore param!\n");
		return -1;
	}
	if (media_b2b.restore_logic_info(msl->b2b_entity,
			&msl->b2b_key, b2b_media_notify) < 0) {
		LM_ERR("could not register restore logic!\n");
		return -1;
	}

	return 0;
}

static mi_response_t *mi_media_fork_from_call_to_uri(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int medianum;
	int media_leg;
	str shdrs, *hdrs;
	str callid, leg, uri;
	struct dlg_cell *dlg;
	struct socket_info *si;
	union sockaddr_union tmp;
	struct media_session_leg *msl;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "uri", &uri.s, &uri.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "leg", &leg.s, &leg.len) < 0)
		return init_mi_param_error();

	if (try_get_mi_int_param(params, "medianum", &medianum) < 0)
		medianum = -1;
	if (try_get_mi_string_param(params, "headers", &shdrs.s, &shdrs.len) < 0)
		hdrs = NULL;
	else
		hdrs = &shdrs;

	media_leg = fixup_get_media_leg_both(&leg);
	if (media_leg < 0)
		return init_mi_error(406, MI_SSTR("invalid leg parameter"));

	si = uri2sock(NULL, &uri, &tmp, PROTO_NONE);
	if (!si)
		return init_mi_error(500, MI_SSTR("No suitable socket"));

	/* params are now ok, let's lookup the media session */
	dlg = media_dlg.get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog not found"));

	msl = media_session_new_leg(dlg, MEDIA_SESSION_TYPE_FORK, media_leg, 0);
	if (!msl) {
		LM_ERR("cannot create new exchange leg!\n");
		return init_mi_error(500, MI_SSTR("Could not create media forking"));
	}

	if (handle_media_fork_to_uri(msl, si, &uri, hdrs, medianum, NULL, NULL) < 0) {
		MSL_UNREF(msl);
		media_dlg.dlg_unref(dlg, 1);
		return init_mi_error(500, MI_SSTR("Could not start media forking"));
	}

	/* all good now, unref the dialog as it is reffed by the ms */
	media_dlg.dlg_unref(dlg, 1);
	return init_mi_result_ok();
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
