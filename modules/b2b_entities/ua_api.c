/*
 * Copyright (C) 2023 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
 *
 */

#include "../../dprint.h"
#include "../../str.h"
#include "../../pvar.h"
#include "../../msg_translator.h"
#include "../../parser/parse_methods.h"

#include "b2be_db.h"
#include "server.h"
#include "client.h"
#include "ua_api.h"
#include "b2b_entities.h"

static str b2be_mod_name = str_init("b2b_entities");

int ua_default_timeout = UA_SESSION_DEFAULT_TIMEOUT;
str adv_contact;

struct ua_sess_timer *ua_dlg_timer;

static event_id_t evi_ua_sess_id = EVI_ERROR;
static str evi_ua_sess_name = str_init("E_UA_SESSION");

static evi_params_p evi_ua_sess_params;
static evi_param_p evi_key_param, evi_ev_type_param, evi_ent_type_param,
	evi_status_param, evi_reason_param, evi_method_param, evi_body_param,
	evi_headers_param;

static str evi_key_pname = str_init("key");
static str evi_ent_type_pname = str_init("entity_type");
static str evi_ev_type_pname = str_init("event_type");
static str evi_status_pname = str_init("status");
static str evi_reason_pname = str_init("reason");
static str evi_method_pname = str_init("method");
static str evi_body_pname = str_init("body");
static str evi_headers_pname = str_init("headers");

int ua_evi_init(void)
{
	evi_ua_sess_id = evi_publish_event(evi_ua_sess_name);
	if (evi_ua_sess_id == EVI_ERROR) {
		LM_ERR("cannot register event\n");
		return -1;
	}

	evi_ua_sess_params = pkg_malloc(sizeof(evi_params_t));
	if (evi_ua_sess_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(evi_ua_sess_params, 0, sizeof(evi_params_t));

	evi_key_param = evi_param_create(evi_ua_sess_params,
		&evi_key_pname);
	if (evi_key_param == NULL)
		goto error;
	evi_ev_type_param = evi_param_create(evi_ua_sess_params,
		&evi_ev_type_pname);
	if (evi_ev_type_param == NULL)
		goto error;
	evi_ent_type_param = evi_param_create(evi_ua_sess_params,
		&evi_ent_type_pname);
	if (evi_ent_type_param == NULL)
		goto error;
	evi_status_param = evi_param_create(evi_ua_sess_params,
		&evi_status_pname);
	if (evi_status_param == NULL)
		goto error;
	evi_reason_param = evi_param_create(evi_ua_sess_params,
		&evi_reason_pname);
	if (evi_reason_param == NULL)
		goto error;
	evi_method_param = evi_param_create(evi_ua_sess_params,
		&evi_method_pname);
	if (evi_method_param == NULL)
		goto error;
	evi_body_param = evi_param_create(evi_ua_sess_params,
		&evi_body_pname);
	if (evi_body_param == NULL)
		goto error;
	evi_headers_param = evi_param_create(evi_ua_sess_params,
		&evi_headers_pname);
	if (evi_headers_param == NULL)
		goto error;

	return 0;
error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

static int get_all_headers(struct sip_msg *msg, str *hdrs)
{
	struct hdr_field *it;
	char *p;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse message\n");
		return -1;
	}

	for (it = msg->headers; it; it = it->next)
		hdrs->len += it->len;

	hdrs->s = pkg_malloc(hdrs->len);
	if (!hdrs->s) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	p = hdrs->s;
	for (it = msg->headers; it; it = it->next) {
		memcpy(p, it->name.s, it->len);
		p += it->len;
	}

	return 0;
}

/* indexed with the values from enum ua_sess_event_type */
static str event_type_str[] = {
	str_init("EARLY"),
	str_init("ANSWERED"),
	str_init("REJECTED"),
	str_init("UPDATED"),
	str_init("TERMINATED")
};

static str entity_type_str[] = {str_init("UAS"), str_init("UAC")};

int raise_ua_sess_event(str *key, enum b2b_entity_type ent_type,
	enum ua_sess_event_type ev_type, unsigned int flags, struct sip_msg *msg)
{
	str body = {0,0};
	str hdrs = {0,0};
	str method;
	str *reason;
	int statuscode;

	if (evi_param_set_str(evi_key_param, key) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (evi_param_set_str(evi_ent_type_param, &entity_type_str[ent_type]) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (evi_param_set_str(evi_ev_type_param, &event_type_str[ev_type]) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if (msg->first_line.type == SIP_REQUEST) {
		method = msg->first_line.u.request.method;
		statuscode = 0;
		reason = &STR_NULL;
	} else {
		method = get_cseq(msg)->method;
		statuscode = msg->first_line.u.reply.statuscode;
		reason = &msg->first_line.u.reply.reason;
	}

	if (evi_param_set_str(evi_method_param, &method) < 0) {
		LM_ERR("cannot set event parameter\n");
		goto error;
	}
	if (evi_param_set_int(evi_status_param, &statuscode) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}
	if (evi_param_set_str(evi_reason_param, reason) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if ((flags&UA_FL_PROVIDE_BODY) && msg->content_length &&
		(get_body(msg, &body) < 0)) {
		LM_ERR("cannot extract body\n");
		return -1;
	}

	if (evi_param_set_str(evi_body_param, &body) < 0) {
		LM_ERR("cannot set event parameter\n");
		return -1;
	}

	if ((flags&UA_FL_PROVIDE_HDRS) && (get_all_headers(msg, &hdrs) < 0)) {
		LM_ERR("Failed to get all msg headers\n");
		return -1;
	}

	if (evi_param_set_str(evi_headers_param, &hdrs) < 0) {
		LM_ERR("cannot set event parameter\n");
		goto error;
	}

	if (evi_raise_event(evi_ua_sess_id, evi_ua_sess_params) < 0) {
		LM_ERR("cannot raise event\n");
		goto error;
	}

	if (hdrs.s)
		pkg_free(hdrs.s);

	return 0;
error:
	if (hdrs.s)
		pkg_free(hdrs.s);
	return -1;
}

int init_ua_sess_timer(void)
{
	ua_dlg_timer = shm_malloc(sizeof *ua_dlg_timer);
	if (!ua_dlg_timer) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(ua_dlg_timer, 0, sizeof *ua_dlg_timer);

	ua_dlg_timer->lock = lock_alloc();
	if (ua_dlg_timer->lock==0) {
		LM_ERR("failed to alloc lock\n");
		return -1;
	}

	if (lock_init(ua_dlg_timer->lock)==0) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	return 0;
}

void destroy_ua_sess_timer(void)
{
	if (ua_dlg_timer==0)
		return;

	lock_destroy(ua_dlg_timer->lock);
	lock_dealloc(ua_dlg_timer->lock);

	shm_free(ua_dlg_timer);
	ua_dlg_timer = 0;
}

struct ua_sess_t_list *insert_ua_sess_tl(str *b2b_key, unsigned int timeout)
{
	struct ua_sess_t_list *tl, *tmp;

	tl = shm_malloc(sizeof *tl + b2b_key->len);
	if (!tl) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}
	memset(tl, 0, sizeof *tl);

	tl->b2b_key.s = (char*)(tl + 1);
	tl->b2b_key.len = b2b_key->len;
	memcpy(tl->b2b_key.s, b2b_key->s, b2b_key->len);

	tl->timeout = get_ticks() + timeout;

	lock_get(ua_dlg_timer->lock);

	if (!ua_dlg_timer->first) {
		ua_dlg_timer->first = tl;
		ua_dlg_timer->last = tl;
	} else {
		if (ua_dlg_timer->last->timeout <= tl->timeout) {
			ua_dlg_timer->last->next = tl;
			tl->prev = ua_dlg_timer->last;
			ua_dlg_timer->last = tl;
		} else {
			for (tmp = ua_dlg_timer->last; tmp->prev &&
				tmp->prev->timeout > tl->timeout;
				tmp = tmp->prev) ;

			if (tmp == ua_dlg_timer->first) {
				tmp->prev = tl;
				tl->next = tmp;
				ua_dlg_timer->first = tl;
			} else {
				tmp->prev->next = tl;
				tl->prev = tmp->prev;
				tl->next = tmp;
				tmp->prev = tl;
			}
		}
	}

	lock_release(ua_dlg_timer->lock);

	return tl;
}

void remove_ua_sess_tl(struct ua_sess_t_list *tl)
{
	if (!tl || !ua_dlg_timer->first)
		return;

	if (tl == ua_dlg_timer->first) {
		if (tl->next)
			tl->next->prev = NULL;
		else
			ua_dlg_timer->last = NULL;

		ua_dlg_timer->first = tl->next;
	} else {
		if (tl == ua_dlg_timer->last) {
			tl->prev->next = NULL;
			ua_dlg_timer->last = tl->prev;
		} else {
			tl->prev->next = tl->next;
			tl->next->prev = tl->prev;
		}
	}

	shm_free(tl);
}

struct ua_sess_t_list *get_ua_sess_expired(unsigned int now)
{
	struct ua_sess_t_list *ret = NULL, *tl = NULL;

	lock_get(ua_dlg_timer->lock);

	/* empty list */
	if (!ua_dlg_timer->first) {
		lock_release(ua_dlg_timer->lock);
		return NULL;
	}

	if (ua_dlg_timer->first->timeout > now) {
		/* no expired dlgs in list at all */
		lock_release(ua_dlg_timer->lock);
		return NULL;
	}

	for (tl = ua_dlg_timer->first; tl->next && tl->next->timeout <= now;
		tl = tl->next) ;

	ret = ua_dlg_timer->first;

	ua_dlg_timer->first = tl->next;
	if (!ua_dlg_timer->first)
		ua_dlg_timer->last = NULL;
	else
		tl->next->prev = NULL;

	tl->next = NULL;

	lock_release(ua_dlg_timer->lock);

	return ret;
}

int ua_terminate_expired(str *b2b_key)
{
	if (ua_send_request(B2B_NONE, b2b_key, &str_init("BYE"), NULL, NULL,
		NULL, 1) < 0) {
		LM_ERR("Failed to send BYE request\n");
		return -1;
	}

	if (ua_entity_delete(B2B_NONE, b2b_key, 1, 0) < 0) {
		LM_ERR("Failed to delete UA session\n");
		return -1;
	}

	return 0;
}

void ua_dlg_timer_routine(unsigned int ticks, void* param)
{
	struct ua_sess_t_list *tl, *tmp;

	tl = get_ua_sess_expired(ticks);

	while (tl) {
		if (ua_terminate_expired(&tl->b2b_key) < 0)
			LM_ERR("Failed to terminate entity\n");

		tmp = tl;
		tl = tl->next;
		shm_free(tmp);
	}
}

static struct ua_sess_init_params *ua_parse_flags(str *s)
{
	int st;
	struct ua_sess_init_params *params;

	params = pkg_malloc(sizeof *params);
	if (!params) {
		LM_ERR("out of pkg memory\n");
		return NULL;
	}
	memset(params, 0, sizeof *params);

	params->timeout = ua_default_timeout;

	if (!s)
		return params;

	for (st = 0; st < s->len; st++)
		switch (s->s[st]) {
		case 't':
			params->timeout = 0;
			while (st<s->len-1 && isdigit(s->s[st+1])) {
				params->timeout =
					params->timeout*10 + s->s[st+1] - '0';
				st++;
			}
			break;
		case 'a':
			params->flags |= UA_FL_REPORT_ACK;
			break;
		case 'r':
			params->flags |= UA_FL_REPORT_REPLIES;
			break;
		case 'd':
			params->flags |= UA_FL_DISABLE_AUTO_ACK;
			break;
		case 'h':
			params->flags |= UA_FL_PROVIDE_HDRS;
			break;
		case 'b':
			params->flags |= UA_FL_PROVIDE_BODY;
			break;
		default:
			LM_WARN("unknown option `%c'\n", s->s[st]);
		}

	return params;
}

int fixup_ua_flags(void** param)
{
	str *s = (str*)*param;

	*param = (void*)ua_parse_flags(s);
	if (!*param)
		return -1;

	return 0;
}

int fixup_free_ua_flags(void** param)
{
	if (*param)
		pkg_free(*param);

	return 0;
}

static int ua_build_hdrs(str *hdrs, int body, str *content_type, str *extra_headers)
{
	static str ct_type_sdp_str = str_init("Content-Type: application/sdp\r\n");

	hdrs->len = extra_headers ? extra_headers->len : 0;
	if (body && !content_type)
		hdrs->len += ct_type_sdp_str.len;
	else if (body && content_type)
		hdrs->len += content_type->len;

	if (hdrs->len) {
		hdrs->s = pkg_malloc(hdrs->len);
		if (!hdrs->s) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}

		if (body && !content_type) {
			memcpy(hdrs->s, ct_type_sdp_str.s, ct_type_sdp_str.len);
			if (extra_headers)
				memcpy(hdrs->s + ct_type_sdp_str.len,
					extra_headers->s, extra_headers->len);
		} else if (body && content_type) {
			memcpy(hdrs->s, content_type->s, content_type->len);
			if (extra_headers)
				memcpy(hdrs->s + content_type->len,
					extra_headers->s, extra_headers->len);
		}
	}

	return 0;
}

static b2b_dlg_t *ua_get_dlg_by_key(unsigned int hash_index,
	unsigned int local_index, int *et)
{
	b2b_dlg_t *dlg;

	*et = B2B_SERVER;
	B2BE_LOCK_GET(server_htable, hash_index);

	dlg = b2b_search_htable(server_htable, hash_index, local_index);
	if (!dlg) {
		B2BE_LOCK_RELEASE(server_htable, hash_index);

		*et = B2B_CLIENT;
		B2BE_LOCK_GET(client_htable, hash_index);
	
		dlg = b2b_search_htable(client_htable, hash_index, local_index);
		if (!dlg)
			return NULL;
	}

	return dlg;
}

int ua_send_reply(int et, str *b2b_key, int method, int code, str *reason,
	str *body, str *content_type, str *extra_headers)
{
	b2b_rpl_data_t rpl_data;
	str hdrs = {0,0};
	int rc;
	b2b_dlg_t *dlg = NULL;
	unsigned int hash_index, local_index;

	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", b2b_key->len, b2b_key->s);
		return -1;
	}

	/* if we don't know what type(server/client) of entity this is 
	 * we do a lookup now in both hashtables */
	if (et == B2B_NONE) {
		/* ua_get_dlg_by_key also aquires the dlg lock */
		dlg = ua_get_dlg_by_key(hash_index, local_index, &et);
		if (!dlg) {
			LM_ERR("No dialog found for b2b key [%.*s]\n",
				b2b_key->len, b2b_key->s);
			goto error;
		}
	}

	memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
	rpl_data.et = et;
	rpl_data.b2b_key = b2b_key;
	rpl_data.method = method;
	rpl_data.code = code;
	rpl_data.text = reason;
	rpl_data.body = body;

	if (ua_build_hdrs(&hdrs, body?1:0, content_type, extra_headers) < 0) {
		LM_ERR("Failed to build headers\n");
		goto error;
	}
	rpl_data.extra_headers = hdrs.len ? &hdrs : NULL;

	/* _b2b_send_request() with non-NULL dlg param expects
	 * the dlg lock to be aquired but will release it itself at the end */
	rc = _b2b_send_reply(dlg, &rpl_data);

	if (hdrs.s)
		pkg_free(hdrs.s);

	return rc;
error:
	if (et == B2B_SERVER)
		B2BE_LOCK_RELEASE(server_htable, hash_index);
	else
		B2BE_LOCK_RELEASE(client_htable, hash_index);
	return -1;
}

int ua_send_request(int et, str *b2b_key, str *method, str *body,
	str *content_type, str *extra_headers, unsigned int no_cb)
{
	b2b_req_data_t req_data;
	str hdrs = {0,0};
	int rc;
	b2b_dlg_t *dlg = NULL;
	unsigned int hash_index, local_index;

	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", b2b_key->len, b2b_key->s);
		return -1;
	}

	/* if we don't know what type(server/client) of entity this is 
	 * we do a lookup now in both hashtables */
	if (et == B2B_NONE) {
		/* ua_get_dlg_by_key also aquires the dlg lock */
		dlg = ua_get_dlg_by_key(hash_index, local_index, &et);
		if (!dlg) {
			LM_ERR("No dialog found for b2b key [%.*s]\n",
				b2b_key->len, b2b_key->s);
			goto error;
		}
	}

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	req_data.et = et;
	req_data.b2b_key = b2b_key;
	req_data.method = method;
	req_data.body = body;
	req_data.no_cb = no_cb;

	if (ua_build_hdrs(&hdrs, body?1:0, content_type, extra_headers) < 0) {
		LM_ERR("Failed to build headers\n");
		goto error;
	}
	req_data.extra_headers = hdrs.len ? &hdrs : NULL;

	/* _b2b_send_request() with non-NULL dlg param expects
	 * the dlg lock to be aquired but will release it itself at the end */
	rc = _b2b_send_request(dlg, &req_data);

	if (hdrs.s)
		pkg_free(hdrs.s);

	return rc;
error:
	if (et == B2B_SERVER)
		B2BE_LOCK_RELEASE(server_htable, hash_index);
	else
		B2BE_LOCK_RELEASE(client_htable, hash_index);
	return -1;
}

int ua_entity_delete(int et, str* b2b_key, int db_del, int remove_tl)
{
	b2b_table table;
	unsigned int hash_index, local_index;
	b2b_dlg_t* dlg;

	/* parse the key and find the position in hash table */
	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key\n");
		return -1;
	}

	/* if we don't know what type(server/client) of entity this is 
	 * we do a lookup now in both hashtables */
	if (et == B2B_NONE) {
		/* ua_get_dlg_by_key also aquires the dlg lock */
		dlg = ua_get_dlg_by_key(hash_index, local_index, &et);

		if(et == B2B_SERVER)
			table = server_htable;
		else
			table = client_htable;

		if (!dlg) {
			LM_ERR("No dialog found for b2b key [%.*s]\n",
				b2b_key->len, b2b_key->s);
			B2BE_LOCK_RELEASE(table, hash_index);
			return -1;
		}
	} else {
		if(et == B2B_SERVER)
			table = server_htable;
		else
			table = client_htable;

		B2BE_LOCK_GET(table, hash_index);

		dlg = b2b_search_htable(table, hash_index, local_index);
		if(dlg== NULL)
		{
			LM_ERR("No dialog found\n");
			B2BE_LOCK_RELEASE(table, hash_index);
			return -1;
		}
	}

	LM_DBG("Deleted dlg [%p]->[%.*s]\n", dlg, b2b_key->len, b2b_key->s);

	if (remove_tl)
		remove_ua_sess_tl(dlg->ua_timer_list);

	if(db_del)
		b2b_entity_db_delete(et, dlg);

	b2b_delete_record(dlg, table, hash_index);

	B2BE_LOCK_RELEASE(table, hash_index);

	return 0;
}

int b2b_ua_terminate(struct sip_msg *msg, str *key, str *extra_headers)
{
	if (ua_send_request(B2B_NONE, key, &str_init("BYE"), NULL, NULL,
		extra_headers, 1) < 0) {
		LM_ERR("Failed to send BYE request\n");
		return -1;
	}

	if (ua_entity_delete(B2B_NONE, key, 1, 1) < 0) {
		LM_ERR("Failed to delete UA session\n");
		return -1;
	}

	return 1;
}

int b2b_ua_update(struct sip_msg *msg, str *key, str *method, str *body,
	str *extra_headers, str *content_type)
{
	if (ua_send_request(B2B_NONE, key, method, body, content_type,
		extra_headers, 0) < 0) {
		LM_ERR("Failed to send request\n");
		return -1;
	}

	return 1;
}

int b2b_ua_reply(struct sip_msg *msg, str *key, str *method, int *code,
	str *reason, str *body, str *extra_headers, str *content_type)
{
	unsigned int method_value;

	parse_method(method->s, method->s+method->len, &method_value);

	if (ua_send_reply(B2B_NONE, key, method_value, *code, reason,
		body, content_type, extra_headers) < 0) {
		LM_ERR("Failed to send reply\n");
		return -1;
	}

	return 1;
}

int b2b_ua_server_init(struct sip_msg *msg, pv_spec_t *key_spec,
	struct ua_sess_init_params *init_params)
{
	pv_value_t key_pval;
	str *key_ret = NULL;
	str contact;
	static str key_buf;

	init_params->flags |= UA_FL_IS_UA_ENTITY;

	contact.s = contact_builder(msg->rcv.bind_address, &contact.len);

	key_ret = _server_new(msg, &contact, NULL, &b2be_mod_name, NULL,
		init_params, NULL, NULL, NULL);
	if (!key_ret) {
		LM_ERR("failed to create new b2b server instance\n");
		return -1;
	}

	if (key_spec) {
		if (pkg_str_sync(&key_buf, key_ret) < 0) {
			LM_ERR("no more pkg memory\n");
			goto error;
		}

		memset(&key_pval, 0, sizeof(pv_value_t));
		key_pval.flags = PV_VAL_STR;
		key_pval.rs = key_buf;

		if (pv_set_value(msg, key_spec, 0, &key_pval) < 0) {
			LM_ERR("Unable to set tag pvar\n");
			goto error;
		}
	}

	pkg_free(key_ret);

	return 1;
error:
	b2b_entity_delete(B2B_SERVER, key_ret, NULL, 1, 1);
	if (key_ret)
		pkg_free(key_ret);
	return -1;
}

mi_response_t *b2b_ua_session_client_start(const mi_params_t *params,
	struct mi_handler *_)
{
	str to, from;
	str body, content_type, extra_headers, flags_str, socket;
	str to_uri, to_dname = {0,0}, from_uri, from_dname={0,0};
	str hdrs = {0,0};
	struct ua_sess_init_params *init_params = NULL;
	str *key_ret = NULL;
	client_info_t ci;
	static str method_invite = str_init("INVITE");
	char *p;
	mi_response_t *resp;

	memset(&ci, 0, sizeof ci);

	if (get_mi_string_param(params, "ruri", &ci.req_uri.s, &ci.req_uri.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "to", &to.s, &to.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "from", &from.s, &from.len) < 0)
		return init_mi_param_error();

	switch (try_get_mi_string_param(params, "proxy", &ci.dst_uri.s,
		&ci.dst_uri.len)) {
	case 0:
		break;
	case -1:
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "body", &body.s, &body.len)) {
	case 0:
		ci.body = &body;
		break;
	case -1:
		body.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "content_type",
		&content_type.s, &content_type.len)) {
	case 0:
		break;
	case -1:
		content_type.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "extra_headers",
		&extra_headers.s, &extra_headers.len)) {
	case 0:
		break;
	case -1:
		extra_headers.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "flags", &flags_str.s, &flags_str.len)) {
	case 0:
		init_params = ua_parse_flags(&flags_str);
		break;
	case -1:
		init_params = ua_parse_flags(NULL);
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "socket", &socket.s, &socket.len)) {
	case 0:
		ci.send_sock = parse_sock_info(&socket);
		if (!ci.send_sock) {
			LM_ERR("non-local socket <%.*s>\n", socket.len, socket.s);
			return init_mi_error(500, MI_SSTR("Non-local socket specified"));
		}
		break;
	case -1:
		socket.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}

	p = q_memchr(to.s, ',', to.len);
	if (p) {
		to_dname.s = to.s;
		to_dname.len = p - to.s;
		to_uri.s = p + 1;
		to_uri.len = to.len - to_dname.len - 1;
	} else {
		to_uri = to;
	}

	p = q_memchr(from.s, ',', from.len);
	if (p) {
		from_dname.s = from.s;
		from_dname.len = p - from.s;
		from_uri.s = p + 1;
		from_uri.len = from.len - from_dname.len - 1;
	} else {
		from_uri = from;
	}

	ci.method = method_invite;
	ci.to_uri = to_uri;
	ci.to_dname = to_dname;
	ci.from_uri = from_uri;
	ci.from_dname = from_dname;

	if (ua_build_hdrs(&hdrs, body.s ? 1:0, content_type.s ? &content_type:0,
		extra_headers.s ? &extra_headers:0) < 0) {
		LM_ERR("Failed to build headers\n");
		goto error;
	}
	ci.extra_headers = &hdrs;

	if (adv_contact.s) {
		ci.local_contact = adv_contact;
	} else if (ci.send_sock) {
		ci.local_contact.s = contact_builder(ci.send_sock, &ci.local_contact.len);
	} else {
		LM_ERR("'advertised_contact' parameter required\n");
		goto error;
	}

	init_params->flags |= UA_FL_IS_UA_ENTITY;

	key_ret = _client_new(&ci, NULL, NULL,
		&b2be_mod_name, NULL, init_params, NULL, NULL, NULL);
	if (!key_ret) {
		LM_ERR("failed to create new b2b client instance\n");
		goto error;
	}

	pkg_free(init_params);
	init_params = NULL;

	if (hdrs.s) {
		pkg_free(hdrs.s);
		hdrs.s = NULL;
	}

	resp = init_mi_result_string(key_ret->s, key_ret->len);

	pkg_free(key_ret);

	return resp;
error:
	if (init_params)
		pkg_free(init_params);
	if (hdrs.s)
		pkg_free(hdrs.s);
	return init_mi_error(500, MI_SSTR("Failed to start session"));
}

mi_response_t *b2b_ua_mi_update(const mi_params_t *params,
	struct mi_handler *_)
{
	str key, method, body, content_type, extra_headers;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "method", &method.s, &method.len) < 0)
		return init_mi_param_error();

	switch (try_get_mi_string_param(params, "body",
		&body.s, &body.len)) {
	case 0:
		break;
	case -1:
		body.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "content_type",
		&content_type.s, &content_type.len)) {
	case 0:
		break;
	case -1:
		content_type.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "extra_headers",
		&extra_headers.s, &extra_headers.len)) {
	case 0:
		break;
	case -1:
		extra_headers.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}

	if (ua_send_request(B2B_NONE, &key, &method, body.s?&body:NULL,
		content_type.s?&content_type:NULL,
		extra_headers.s?&extra_headers:NULL, 0) < 0) {
		LM_ERR("Failed to send request\n");
		return init_mi_error(500, MI_SSTR("Failed to send sequential request"));
	}

	return init_mi_result_ok();
}

mi_response_t *b2b_ua_mi_reply(const mi_params_t *params,
	struct mi_handler *_)
{
	str key, method, body, content_type, extra_headers;
	int code;
	str reason;
	unsigned int method_value;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "method", &method.s, &method.len) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "code", &code) < 0)
		return init_mi_param_error();

	switch (try_get_mi_string_param(params, "reason", &reason.s, &reason.len)) {
	case 0:
		break;
	case -1:
		reason.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "body", &body.s, &body.len)) {
	case 0:
		break;
	case -1:
		body.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "content_type",
		&content_type.s, &content_type.len)) {
	case 0:
		break;
	case -1:
		content_type.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}
	switch (try_get_mi_string_param(params, "extra_headers",
		&extra_headers.s, &extra_headers.len)) {
	case 0:
		break;
	case -1:
		extra_headers.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}

	parse_method(method.s, method.s+method.len, &method_value);

	if (ua_send_reply(B2B_NONE, &key, method_value, code,
		reason.s?&reason:NULL, body.s?&body:NULL,
		content_type.s?&content_type:NULL,
		extra_headers.s?&extra_headers:NULL) < 0) {
		LM_ERR("Failed to send reply\n");
		return init_mi_error(500, MI_SSTR("Failed to send reply"));
	}

	return init_mi_result_ok();
}

mi_response_t *b2b_ua_mi_terminate(const mi_params_t *params,
	struct mi_handler *_)
{
	str key, extra_headers;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();

	switch (try_get_mi_string_param(params, "extra_headers",
		&extra_headers.s, &extra_headers.len)) {
	case 0:
		break;
	case -1:
		extra_headers.s = NULL;
		break;
	default:
		return init_mi_param_error();
	}

	if (ua_send_request(B2B_NONE, &key, &str_init("BYE"), NULL, NULL,
		extra_headers.s?&extra_headers:NULL, 1) < 0) {
		LM_ERR("Failed to send BYE request\n");
		goto error;
	}

	if (ua_entity_delete(B2B_NONE, &key, 1, 1) < 0) {
		LM_ERR("Failed to delete UA session\n");
	}

	return init_mi_result_ok();	
error:
	return init_mi_error(500, MI_SSTR("Failed to terminate session"));
}

mi_response_t *b2b_ua_session_list(const mi_params_t *params,
	struct mi_handler *_)
{
	mi_response_t *resp;
	mi_item_t *resp_arr, *resp_obj;
	str key = {0,0};
	b2b_dlg_t *dlg = NULL;
	int et;
	unsigned int hash_index, local_index;
	b2b_table table;

	switch (try_get_mi_string_param(params, "key", &key.s, &key.len)) {
	case 0:
		break;
	case -1:
		break;
	default:
		return init_mi_param_error();
	}

	if (key.s) {
		if(b2b_parse_key(&key, &hash_index, &local_index) < 0)
		{
			LM_ERR("Wrong format for b2b key [%.*s]\n", key.len, key.s);
			return init_mi_error(400, MI_SSTR("Bad format for b2b key"));
		}

		/* ua_get_dlg_by_key also aquires the dlg lock */
		dlg = ua_get_dlg_by_key(hash_index, local_index, &et);

		if(et == B2B_SERVER)
			table = server_htable;
		else
			table = client_htable;

		if (!dlg) {
			LM_ERR("No dialog found for b2b key [%.*s]\n", key.len, key.s);
			B2BE_LOCK_RELEASE(table, hash_index);
			return init_mi_error(404, MI_SSTR("Entity not found"));
		}

		resp = init_mi_result_object(&resp_obj);
		if (!resp) {
			LM_ERR("Failed to init result object\n");
			B2BE_LOCK_RELEASE(table, hash_index);
			return NULL;
		}

		if (mi_print_b2be_dlg(dlg, resp_obj) < 0)
			goto error;

		B2BE_LOCK_RELEASE(table, hash_index);
	} else {
		resp = init_mi_result_array(&resp_arr);
		if (!resp) {
			LM_ERR("Failed to init result array\n");
			return NULL;
		}

		if (server_htable)
			if (mi_print_b2be_all_dlgs(resp_arr, server_htable, server_hsize, 1)!=0)
				goto error;
		if (client_htable)
			if (mi_print_b2be_all_dlgs(resp_arr, client_htable, client_hsize, 1)!=0)
				goto error;
	}

	return resp;
error:
	LM_ERR("Unable to create response\n");
	free_mi_response(resp);
	return NULL;
}
