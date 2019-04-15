/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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
 *
 */

#include "../../ut.h"
#include "cgrates_common.h"

static int cgr_proc_auth_reply(struct cgr_conn *c, json_object *jobj,
		void *p, char *error)
{
	struct cgr_kv *k;
	int_str val;
	if (error) {
		val.s.s = error;
		val.s.len = strlen(error);
		if (cgrates_set_reply(CGR_KVF_TYPE_STR, &val) < 0) {
			LM_ERR("cannot set the reply code!\n");
			return -1;
		}
		return -2;
	}

	if (cgre_compat_mode) {
		if (json_object_get_type(jobj) != json_type_int) {
			LM_ERR("CGRateS returned a non-int type in Auth reply: %d %s\n",
					json_object_get_type(jobj), json_object_to_json_string(jobj));
			return -5;
		}
		val.n = json_object_get_int(jobj);
		/* -1: always allowed (postpaid)
		 *  0: not allowed to call
		 *  *: allowed
		 */
		if (cgrates_set_reply(CGR_KVF_TYPE_INT, &val) < 0) {
			LM_ERR("cannot set the reply value!\n");
			return -1;
		}
		return ((val.n == 0) ? -2: 1);
	} else if (cgrates_set_reply_with_values(jobj) < 0) {
			LM_ERR("cannot set the reply values!\n");
			return -1;
	}
	val.s.s = "MaxUsage";
	val.s.len = strlen(val.s.s);
	k = cgr_get_local(val.s);
	if (!k || !(k->flags & CGR_KVF_TYPE_INT)) {
		LM_ERR("MaxUsage not found in command reply!\n");
		return -1;
	}

	return ((k->value.n == 0) ? -2: 1);
}

static json_object *cgr_get_auth_msg(struct sip_msg *msg, str *acc, str *dst, str *tag)
{
	struct cgr_session *s;
	struct cgr_msg *cmsg = NULL;
	static str cmd_ng = str_init("SessionSv1.AuthorizeEventWithDigest");
	static str cmd_compat = str_init("SMGenericV1.GetMaxUsage");
	str stime;
	str *cmd = (cgre_compat_mode ? &cmd_compat: &cmd_ng);

	if (msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
			(msg->callid==NULL)) ) {
		LM_ERR("Cannot get callid of the message!\n");
		return NULL;
	}
	s = cgr_get_sess(cgr_try_get_ctx(), tag);
	stime.s = int2str(time(NULL), &stime.len);

	cmsg = cgr_get_generic_msg(cmd, s);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	if (!cgre_compat_mode &&
			((s && !cgr_get_const_kv(&s->req_kvs, "GetMaxUsage")) || !s) &&
			cgr_obj_push_bool(cmsg->opts, "GetMaxUsage", 1) < 0) {
		LM_ERR("cannot push GetMaxUsage to request opts!\n");
		goto error;
	}

	/* OriginID */
	/* if origin was not added from script, add it now */
	if (((s && !cgr_get_const_kv(&s->event_kvs, "OriginID")) || !s) &&
			cgr_obj_push_str(cmsg->params, "OriginID", &msg->callid->body) < 0) {
		LM_ERR("cannot push OriginID!\n");
		goto error;
	}

	/* Account */
	if (cgr_obj_push_str(cmsg->params, "Account", acc) < 0) {
		LM_ERR("cannot push Account info!\n");
		goto error;
	}

	/* SetupTime */
	if (cgr_obj_push_str(cmsg->params, "SetupTime", &stime) < 0) {
		LM_ERR("cannot push SetupTime info!\n");
		goto error;
	}

	/* Destination */
	if (cgr_obj_push_str(cmsg->params, "Destination", dst) < 0) {
		LM_ERR("cannot push Destination info!\n");
		goto error;
	}

	return cmsg->msg;
error:
	json_object_put(cmsg->msg);
	return NULL;
}


int w_cgr_auth(struct sip_msg* msg, str* acc_c, str *dst_c, str *tag_c)
{
	str *acc;
	str *dst;
	json_object *jmsg = NULL;

	if ((acc = cgr_get_acc(msg, acc_c)) == NULL)
		return -4;
	if ((dst = cgr_get_dst(msg, dst_c)) == NULL)
		return -4;

	jmsg = cgr_get_auth_msg(msg, acc, dst, tag_c);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return -1;
	}

	return cgr_handle_cmd(msg, jmsg, cgr_proc_auth_reply, NULL);
}

int w_acgr_auth(struct sip_msg* msg, async_ctx *ctx,
		str* acc_c, str *dst_c, str *tag_c)
{
	str *acc;
	str *dst;
	json_object *jmsg = NULL;

	if ((acc = cgr_get_acc(msg, acc_c)) == NULL)
		return -4;
	if ((dst = cgr_get_dst(msg, dst_c)) == NULL)
		return -4;

	jmsg = cgr_get_auth_msg(msg, acc, dst, tag_c);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return -1;
	}

	return cgr_handle_async_cmd(msg, jmsg, cgr_proc_auth_reply, NULL, ctx);
}
