/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../lib/hash.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../tm/tm_load.h"

#include "../msrp_ua/api.h"

struct msrpgw_session {
	str key;
	str sipua_from;
	str sipua_to;
	str sipua_ruri;
	str msrpua_sess_id;
	unsigned int last_send;
	unsigned int last_message;
	struct list_head queued_messages; /* list of struct queue_msg_entry */
};

struct queue_msg_entry {
	str body;
	str content_type;
	struct list_head list;
};

int msrpgw_sessions_hsize = 10;
gen_hash_t *msrpgw_sessions;

struct msrp_ua_binds msrpua_api;
struct tm_binds tmb;

static str msrpgw_mod_name = str_init("msrp_gateway");

int cleanup_interval = 60;
int session_timeout = 12*3600;
int message_timeout = 2*3600;

static int mod_init(void);
static void destroy(void);

static int msrpgw_answer(struct sip_msg *msg, str *key, str *content_types,
	str *from, str *to, str *ruri);
static int msg_to_msrp(struct sip_msg *msg, str *key, str *content_types);

static void clean_msrpgw_sessions(unsigned int ticks,void *param);

mi_response_t *msrpgw_mi_end(const mi_params_t *params,
	struct mi_handler *_);
mi_response_t *msrpgw_mi_list(const mi_params_t *_,
	struct mi_handler *__);

static event_id_t evi_id = EVI_ERROR;
static str evi_name = str_init("E_MSRP_GW_SETUP_FAILED");

static evi_params_p evi_params;
static evi_param_p evi_key_p, evi_from_p, evi_to_p, evi_ruri_p,
	evi_code_p, evi_reason_p;
static str evi_key_pname = str_init("key");
static str evi_from_pname = str_init("from_uri");
static str evi_to_pname = str_init("to_uri");
static str evi_ruri_pname = str_init("ruri");
static str evi_code_pname = str_init("code");
static str evi_reason_pname = str_init("reason");

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "msrp_ua", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static param_export_t params[] = {
	{"hash_size", INT_PARAM, &msrpgw_sessions_hsize},
	{"cleanup_interval", INT_PARAM, &cleanup_interval},
	{"session_timeout", INT_PARAM, &session_timeout},
	{"message_timeout", INT_PARAM, &message_timeout},
};

static cmd_export_t cmds[]=
{
	{"msrp_gw_answer", (cmd_function)msrpgw_answer, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE},
	{"msg_to_msrp", (cmd_function)msg_to_msrp, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static mi_export_t mi_cmds[] = {
	{ "msrp_gw_end_session", 0, 0, 0, {
		{msrpgw_mi_end, {"key", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "msrp_gw_list_sessions", 0, 0, 0, {
		{msrpgw_mi_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

struct module_exports exports = {
	"msrp_gateway",       /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,      /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static int msrpgw_evi_init(void)
{
	evi_id = evi_publish_event(evi_name);
	if (evi_id == EVI_ERROR) {
		LM_ERR("cannot register event\n");
		return -1;
	}

	evi_params = pkg_malloc(sizeof(evi_params_t));
	if (evi_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(evi_params, 0, sizeof(evi_params_t));

	evi_key_p = evi_param_create(evi_params, &evi_key_pname);
	if (evi_key_p == NULL)
		goto error;
	evi_from_p = evi_param_create(evi_params, &evi_from_pname);
	if (evi_from_p == NULL)
		goto error;
	evi_to_p = evi_param_create(evi_params, &evi_to_pname);
	if (evi_to_p == NULL)
		goto error;
	evi_ruri_p = evi_param_create(evi_params, &evi_ruri_pname);
	if (evi_ruri_p == NULL)
		goto error;
	evi_code_p = evi_param_create(evi_params, &evi_code_pname);
	if (evi_code_p == NULL)
		goto error;
	evi_reason_p = evi_param_create(evi_params, &evi_reason_pname);
	if (evi_reason_p == NULL)
		goto error;

	return 0;

error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

static int mod_init(void)
{
	LM_INFO("initializing...\n");

	if (msrpgw_sessions_hsize < 1 || msrpgw_sessions_hsize > 20) {
		LM_ERR("hash size should be between 1 and 20\n");
		return -1;
	}
	msrpgw_sessions_hsize = 1 << msrpgw_sessions_hsize;

	msrpgw_sessions = hash_init(msrpgw_sessions_hsize);
	if (!msrpgw_sessions) {
		LM_ERR("Failed to init MSRP gateway sessions table\n");
		return -1;
	}

	/* load msrp_ua API */
	if(load_msrp_ua_api(&msrpua_api)< 0){
		LM_ERR("can't load MSRP functions\n");
		return -1;
	}

	if (load_tm_api(&tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	if (session_timeout < message_timeout) {
		LM_ERR("'session_timeout' can't be lower than 'message_timeout'\n");
		return -1;
	}

	register_timer("msrpgw-expire", clean_msrpgw_sessions, NULL,
		cleanup_interval, TIMER_FLAG_DELAY_ON_DELAY);

	if (msrpgw_evi_init() < 0) {
		LM_ERR("Failed to init events\n");
		return -1;
	}

	return 0;
}

static void free_msrpgw_session(void *val)
{
	struct msrpgw_session *sess = (struct msrpgw_session *)val;
	struct list_head *it, *tmp;
	struct queue_msg_entry *msg;

	list_for_each_safe(it, tmp, &sess->queued_messages) {
		msg = list_entry(it, struct queue_msg_entry, list);
		list_del(&msg->list);
		shm_free(msg);
	}

	shm_free(sess);
}

static void msrpgw_delete_session(struct msrpgw_session *sess)
{
	LM_DBG("Deleting session [%.*s\n", sess->key.len, sess->key.s);

	hash_remove_key(msrpgw_sessions, sess->key);
	free_msrpgw_session(sess);
}

static void destroy(void)
{
	hash_destroy(msrpgw_sessions, free_msrpgw_session);

	evi_free_params(evi_params);
}

static int raise_failed_event(str *key, str *from, str *to, str *ruri,
	struct sip_msg *msg)
{
	if (evi_param_set_str(evi_key_p, key) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_from_p, from) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_to_p, to) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_ruri_p, ruri) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (msg && msg->first_line.type == SIP_REPLY &&
		msg->REPLY_STATUS >= 300) {
		if (evi_param_set_int(evi_code_p, &msg->REPLY_STATUS) < 0) {
			LM_ERR("cannot set event parameter\n");
			return -1;
		}

		if (evi_param_set_str(evi_reason_p,
			&msg->first_line.u.reply.reason) < 0) {
			LM_ERR("cannot set event parameter\n");
			return -1;
		}
	}

	if (evi_raise_event(evi_id, evi_params) < 0) {
		LM_ERR("cannot raise event\n");
		return -1;
	}

	return 0;
}

int msrpua_notify_cb(struct msrp_ua_notify_params *params, void *hdl_param)
{
	struct msrpgw_session *sess = (struct msrpgw_session *)hdl_param;
	unsigned int hentry;
	struct list_head *it, *tmp;
	struct queue_msg_entry *msg;
	str key = STR_NULL;
	str from = STR_NULL, to = STR_NULL, ruri = STR_NULL;

	hentry = hash_entry(msrpgw_sessions, sess->key);
	hash_lock(msrpgw_sessions, hentry);

	switch (params->event) {
	case MSRP_UA_SESS_ESTABLISHED:
		LM_DBG("SIP session established on MSRP side\n");

		if (shm_str_dup(&sess->msrpua_sess_id, params->session_id) < 0) {
			LM_ERR("out of pkg memory\n");
			goto end;
		}

		/* send queued messages */
		list_for_each_safe(it, tmp, &sess->queued_messages) {
			msg = list_entry(it, struct queue_msg_entry, list);
			list_del(&msg->list);

			if (msrpua_api.send_message(&sess->msrpua_sess_id,
				&msg->content_type, &msg->body, MSRP_FAILURE_REPORT_NO, 0) < 0)
				LM_ERR("Failed to send queued message to MSRP side\n");

			shm_free(msg);
		}

		break;
	case MSRP_UA_SESS_FAILED:
		LM_ERR("Failed to establish SIP session on MSRP side\n");

		/* session was created by msg_to_msrp() */
		if (!list_empty(&sess->queued_messages)) {
			if (pkg_str_dup(&key, &sess->key) < 0) {
				LM_ERR("no more pkg memory\n");
				goto err_fail;
			}
			if (pkg_str_dup(&from, &sess->sipua_from) < 0) {
				LM_ERR("no more pkg memory\n");
				goto err_fail;
			}
			if (pkg_str_dup(&to, &sess->sipua_to) < 0) {
				LM_ERR("no more pkg memory\n");
				goto err_fail;
			}
			if (pkg_str_dup(&ruri, &sess->sipua_ruri) < 0) {
				LM_ERR("no more pkg memory\n");
				goto err_fail;
			}
		}

		msrpgw_delete_session(sess);
		hash_unlock(msrpgw_sessions, hentry);

		if (key.s) {
			if (raise_failed_event(&key, &from, &to, &ruri, params->msg) < 0)
				LM_ERR("Failed to raise setup failed event\n");

			pkg_free(key.s);
			pkg_free(from.s);
			pkg_free(to.s);
			pkg_free(ruri.s);
		}

		return 0;
	case MSRP_UA_SESS_TERMINATED:
		msrpgw_delete_session(sess);
		LM_DBG("SIP session terminated on MSRP side\n");
		break;
	}

end:
	hash_unlock(msrpgw_sessions, hentry);
	return 0;
err_fail:
	if (key.s)
		pkg_free(key.s);
	if (from.s)
		pkg_free(from.s);
	if (to.s)
		pkg_free(to.s);
	if (ruri.s)
		pkg_free(ruri.s);

	msrpgw_delete_session(sess);
	hash_unlock(msrpgw_sessions, hentry);
	return 0;
}

#define CONTENT_TYPE_PREFIX "Content-Type: "
#define CONTENT_TYPE_PREFIX_LEN (sizeof(CONTENT_TYPE_PREFIX) - 1)

int msrp_req_cb(struct msrp_msg *req, void *hdl_param)
{
	struct msrpgw_session *sess = (struct msrpgw_session *)hdl_param;
	unsigned int hentry;
	str hdrs;
	char *p;

	hentry = hash_entry(msrpgw_sessions, sess->key);
	hash_lock(msrpgw_sessions, hentry);

	sess->last_send = get_ticks();

	hdrs.len = CONTENT_TYPE_PREFIX_LEN + req->content_type->body.len + CRLF_LEN;
	hdrs.s = pkg_malloc(hdrs.len);
	if (!hdrs.s) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	p = hdrs.s;
	memcpy(p, CONTENT_TYPE_PREFIX, CONTENT_TYPE_PREFIX_LEN);
	p += CONTENT_TYPE_PREFIX_LEN;
	memcpy(p, req->content_type->body.s, req->content_type->body.len);
	p += req->content_type->body.len;
	memcpy(p, CRLF, CRLF_LEN);

	tmb.t_request(&str_init("MESSAGE"), &sess->sipua_ruri, &sess->sipua_to,
		&sess->sipua_from, &hdrs, &req->body, NULL, NULL, NULL, NULL);

	pkg_free(hdrs.s);

	hash_unlock(msrpgw_sessions, hentry);
	return 0;
error:
	hash_unlock(msrpgw_sessions, hentry);
	return -1;
}

int msrp_rpl_cb(struct msrp_msg *rpl, void *hdl_param)
{
	return 0;
}

static struct msrpgw_session *msrpgw_init_session(str *key,
	str *from, str *to, str *ruri, int locked)
{
	unsigned int hentry;
	struct msrpgw_session *sess;
	void **val;
	int len;

	sess = shm_malloc(sizeof *sess + key->len + from->len + to->len + ruri->len);
	if (!sess) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}
	memset(sess, 0, sizeof *sess);

	sess->key.s = (char*)(sess + 1);
	sess->key.len = key->len;
	memcpy(sess->key.s, key->s, key->len);
	len = key->len;

	sess->sipua_from.s = (char*)(sess + 1) + len;
	sess->sipua_from.len = from->len;
	memcpy(sess->sipua_from.s, from->s, from->len);
	len += from->len;

	sess->sipua_to.s = (char*)(sess + 1) + len;
	sess->sipua_to.len = to->len;
	memcpy(sess->sipua_to.s, to->s, to->len);
	len += to->len;

	sess->sipua_ruri.s = (char*)(sess + 1) + len;
	sess->sipua_ruri.len = ruri->len;
	memcpy(sess->sipua_ruri.s, ruri->s, ruri->len);
	len += ruri->len;

	INIT_LIST_HEAD(&sess->queued_messages);

	hentry = hash_entry(msrpgw_sessions, *key);

	if (!locked)
		hash_lock(msrpgw_sessions, hentry);

	val = hash_get(msrpgw_sessions, hentry, sess->key);
	if (!val) {
		if (!locked)
			hash_unlock(msrpgw_sessions, hentry);
		LM_ERR("Failed to allocate new hash entry\n");
		goto error;
	}
	if (*val != NULL) {
		if (!locked)
			hash_unlock(msrpgw_sessions, hentry);
		LM_ERR("Duplicate session key\n");
		goto error;
	}
	*val = sess;

	LM_DBG("New MSRP gateway session, key: %.*s\n", key->len, key->s);

	return sess;
error:
	if (!locked)
		hash_unlock(msrpgw_sessions, hentry);
	free_msrpgw_session(sess);
	return NULL;
}

static int msrpgw_answer(struct sip_msg *msg, str *key, str *content_types,
	str *from, str *to, str *ruri)
{
	unsigned int hentry;
	struct msrpgw_session *sess;
	struct msrp_ua_handler msrpua_hdl;
	struct sip_uri sip_uri;

	if (parse_uri(from->s, from->len, &sip_uri) < 0) {
		LM_ERR("Not a valid sip uri in From param [%.*s]\n",
			from->len, from->s);
		return -1;
	}
	if (parse_uri(to->s, to->len, &sip_uri) < 0) {
		LM_ERR("Not a valid sip uri in To param [%.*s]\n",
			to->len, to->s);
		return -1;
	}

	trim(ruri);
	if (ruri->s[0] == '<') {
		ruri->s++;
		ruri->len-=2;
	}
	if (parse_uri(ruri->s, ruri->len, &sip_uri) < 0) {
		LM_ERR("Not a valid sip uri in RURI param [%.*s]\n",
			ruri->len, ruri->s);
		return -1;
	}

	sess = msrpgw_init_session(key, from, to, ruri, 0);
	if (!sess) {
		LM_ERR("Failed to init MSRP gateway session\n");
		return -1;
	}

	memset(&msrpua_hdl, 0, sizeof msrpua_hdl);
	msrpua_hdl.name = &msrpgw_mod_name;
	msrpua_hdl.param = sess;
	msrpua_hdl.notify_cb = msrpua_notify_cb;
	msrpua_hdl.msrp_req_cb = msrp_req_cb;
	msrpua_hdl.msrp_rpl_cb = msrp_rpl_cb;

	if (msrpua_api.init_uas(msg, content_types, &msrpua_hdl) < 0) {
		LM_ERR("Failed to init MSRP UAS\n");
		goto error;
	}

	hentry = hash_entry(msrpgw_sessions, sess->key);
	hash_unlock(msrpgw_sessions, hentry);

	return 1;
error:
	msrpgw_delete_session(sess);

	hentry = hash_entry(msrpgw_sessions, sess->key);
	hash_unlock(msrpgw_sessions, hentry);
	return -1;
}

static int queue_message(str *body, str *content_type,
	struct msrpgw_session *sess)
{
	struct queue_msg_entry *msg;

	msg = shm_malloc(sizeof *msg + body->len + content_type->len);
	if (!msg) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(msg, 0, sizeof *msg);

	msg->body.s = (char*)(msg + 1);
	msg->body.len = body->len;
	memcpy(msg->body.s, body->s, body->len);

	msg->content_type.s = (char*)(msg + 1) + body->len;
	msg->content_type.len = content_type->len;
	memcpy(msg->content_type.s, content_type->s, content_type->len);

	list_add_tail(&msg->list, &sess->queued_messages);

	return 0;
}

static int msg_to_msrp(struct sip_msg *msg, str *key, str *content_types)
{
	unsigned int hentry;
	struct msrpgw_session *sess;
	void **val;
	struct msrp_ua_handler msrpua_hdl;
	str body;

	if (get_body(msg, &body) != 0) {
		LM_ERR("cannot extract body from msg\n");
		return -1;
	}

	hentry = hash_entry(msrpgw_sessions, *key);
	hash_lock(msrpgw_sessions, hentry);

	val = hash_find(msrpgw_sessions, hentry, *key);
	if (!val) {
		LM_DBG("session [%.*s] does not exist\n", key->len, key->s);

		if (parse_from_header(msg) < 0) {
			LM_ERR("cannot parse From header\n");
			goto error;
		}
		if (parse_to_header(msg) < 0) {
			LM_ERR("cannot parse To header\n");
			goto error;
		}

		/* take from the SIP MESSAGE the To (to become From) and From (to
		 * become To + RURI) URIs and save them for the SIP UAC */
		sess = msrpgw_init_session(key, &get_to(msg)->uri, &get_from(msg)->uri,
			&get_from(msg)->uri, 1);
		if (!sess) {
			LM_ERR("Failed to init MSRP gateway session\n");
			goto error;
		}

		sess->last_message = get_ticks();

		memset(&msrpua_hdl, 0, sizeof msrpua_hdl);
		msrpua_hdl.name = &msrpgw_mod_name;
		msrpua_hdl.param = sess;
		msrpua_hdl.notify_cb = msrpua_notify_cb;
		msrpua_hdl.msrp_req_cb = msrp_req_cb;
		msrpua_hdl.msrp_rpl_cb = msrp_rpl_cb;

		if (msrpua_api.init_uac(content_types, &get_from(msg)->uri,
			&get_to(msg)->uri, GET_RURI(msg), &msrpua_hdl) < 0) {
			LM_ERR("Failed to init MSRP UAC\n");
			goto error;
		}

		if (queue_message(&body, &msg->content_type->body, sess) < 0) {
			LM_ERR("Failed to queue message\n");
			goto error;
		}
	} else {
		sess = *val;

		sess->last_message = get_ticks();

		if (sess->msrpua_sess_id.s) {
			if (msrpua_api.send_message(&sess->msrpua_sess_id,
				&msg->content_type->body, &body, MSRP_FAILURE_REPORT_NO, 0) < 0) {
				LM_ERR("Failed to send message to MSRP side\n");
				goto error;
			}
		} else {
			/* SIP session not fully established yet on the MSRP side */
			if (queue_message(&body, &msg->content_type->body, sess) < 0) {
				LM_ERR("Failed to queue message\n");
				goto error;
			}
		}
	}

	hash_unlock(msrpgw_sessions, hentry);
	return 1;
error:
	hash_unlock(msrpgw_sessions, hentry);
	return -1;
}

static int timer_clean_session(void *param, str key, void *value)
{
	struct msrpgw_session *sess = (struct msrpgw_session *)value;
	unsigned int send_interval, message_interval;

	send_interval = get_ticks() - sess->last_send;
	message_interval = get_ticks() - sess->last_message;

	if (send_interval >= session_timeout || message_interval >= session_timeout ||
		message_interval >= message_timeout) {
		LM_DBG("[%d] seconds since last MESSAGE, [%d] seconds since last SEND\n",
			message_interval, send_interval);
		LM_DBG("Timeout for session [%.*s], \n",
			sess->key.len, sess->key.s);

		if (msrpua_api.end_session(&sess->msrpua_sess_id) < 0)
			LM_ERR("Failed to end MSRP UA session [%.*s] on timeout\n",
				sess->msrpua_sess_id.len, sess->msrpua_sess_id.s);
		msrpgw_delete_session(sess);
	}

	return 0;
}

static void clean_msrpgw_sessions(unsigned int ticks,void *param)
{
	hash_for_each_locked(msrpgw_sessions, timer_clean_session, NULL);
}

mi_response_t *msrpgw_mi_end(const mi_params_t *params,
	struct mi_handler *_)
{
	str key;
	int rc;
	unsigned int hentry;
	struct msrpgw_session *sess;
	void **val;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();

	hentry = hash_entry(msrpgw_sessions, key);
	hash_lock(msrpgw_sessions, hentry);

	val = hash_find(msrpgw_sessions, hentry, key);
	if (!val) {
		LM_ERR("session [%.*s] does not exist\n", key.len, key.s);
		hash_unlock(msrpgw_sessions, hentry);
		return init_mi_error(404, MI_SSTR("Session doesn't exist"));
	}
	sess = *val;

	rc = msrpua_api.end_session(&sess->msrpua_sess_id);
	msrpgw_delete_session(sess);

	hash_unlock(msrpgw_sessions, hentry);

	if (rc < 0) {
		LM_ERR("Failed to end MSRP UA session [%.*s]\n",
			sess->msrpua_sess_id.len, sess->msrpua_sess_id.s);

		return init_mi_error(500, MI_SSTR("Unable to end session"));
	}

	return init_mi_result_ok();
}

struct mi_list_params {
	mi_item_t *resp_arr;
	int rc;
};

static int mi_print_session(void *param, str key, void *value)
{
	struct msrpgw_session *sess = (struct msrpgw_session *)value;
	struct mi_list_params *params = (struct mi_list_params *)param;
	mi_item_t *sess_obj;

	sess_obj = add_mi_object(params->resp_arr, NULL, 0);
	if (!sess_obj) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(sess_obj, MI_SSTR("key"),
		sess->key.s, sess->key.len) < 0) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(sess_obj, MI_SSTR("msg_side_to"),
		sess->sipua_to.s, sess->sipua_to.len) < 0) {
		params->rc = 1;
		return 1;
	}
	if (add_mi_string(sess_obj, MI_SSTR("msg_side_ruri"),
		sess->sipua_ruri.s, sess->sipua_ruri.len) < 0) {
		params->rc = 1;
		return 1;
	}

	if (add_mi_string(sess_obj, MI_SSTR("msrp_ua_session_id"),
		sess->msrpua_sess_id.s, sess->msrpua_sess_id.len) < 0) {
		params->rc = 1;
		return 1;
	}

	return 0;
}

mi_response_t *msrpgw_mi_list(const mi_params_t *_,
	struct mi_handler *__)
{
	mi_response_t *resp;
	struct mi_list_params params = {0};

	resp = init_mi_result_array(&params.resp_arr);
	if (!resp)
		return NULL;

	hash_for_each_locked(msrpgw_sessions, mi_print_session, &params);
	if (params.rc != 0)
		goto error;

	return resp;
error:
	free_mi_response(resp);
	return NULL;
}
