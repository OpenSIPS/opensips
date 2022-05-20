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
	str *msrpua_sess_id;
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

static int mod_init(void);
static void destroy(void);

static int msrpgw_answer(struct sip_msg *msg, str *key, str *content_types,
	str *from, str *to, str *ruri);
static int msg_to_msrp(struct sip_msg *msg, str *key, str *content_types);

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
	0,          /* exported MI functions */
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
}

int msrpua_notify_cb(struct msrp_ua_notify_params *params, void *hdl_param)
{
	struct msrpgw_session *sess = (struct msrpgw_session *)hdl_param;
	unsigned int hentry;
	struct list_head *it, *tmp;
	struct queue_msg_entry *msg;

	hentry = hash_entry(msrpgw_sessions, sess->key);
	hash_lock(msrpgw_sessions, hentry);

	switch (params->event) {
	case MSRP_UA_SESS_ESTABLISHED:
		LM_DBG("SIP session established on MSRP side\n");

		if (shm_str_dup(sess->msrpua_sess_id, params->session_id) < 0) {
			LM_ERR("out of pkg memory\n");
			goto end;
		}

		/* send queued messages */
		list_for_each_safe(it, tmp, &sess->queued_messages) {
			msg = list_entry(it, struct queue_msg_entry, list);
			list_del(&msg->list);

			if (msrpua_api.send_message(sess->msrpua_sess_id,
				&msg->content_type, &msg->body) < 0)
				LM_ERR("Failed to send queued message to MSRP side\n");

			shm_free(msg);
		}

		break;
	case MSRP_UA_SESS_FAILED:
		LM_ERR("Failed to establish SIP session on MSRP side\n");
		msrpgw_delete_session(sess);
		break;
	case MSRP_UA_SESS_TERMINATED:
		msrpgw_delete_session(sess);
		LM_DBG("SIP session terminated on MSRP side\n");
		break;
	}

end:
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
	memcpy(p, req->content_type->body.s, req->content_type->body.len);

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
	str *from, str *to, str *ruri)
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
	hash_lock(msrpgw_sessions, hentry);

	val = hash_get(msrpgw_sessions, hentry, sess->key);
	if (!val) {
		hash_unlock(msrpgw_sessions, hentry);
		LM_ERR("Failed to allocate new hash entry\n");
		goto error;
	}
	if (*val != NULL) {
		hash_unlock(msrpgw_sessions, hentry);
		LM_ERR("Duplicate session key\n");
		goto error;
	}
	*val = sess;

	LM_DBG("New MSRP gateway session, key: %.*s\n", key->len, key->s);

	return sess;
error:
	hash_lock(msrpgw_sessions, hentry);
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

	sess = msrpgw_init_session(key, from, to, ruri);
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
	if (msg) {
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
			&get_from(msg)->uri);
		if (!sess) {
			LM_ERR("Failed to init MSRP gateway session\n");
			goto error;
		}

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
	} else {
		sess = *val;

		if (sess->msrpua_sess_id) {
			if (msrpua_api.send_message(sess->msrpua_sess_id,
				&msg->content_type->body, &body) < 0) {
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
