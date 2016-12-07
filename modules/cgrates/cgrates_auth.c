/*
 * Copyright (C) 2016 Razvan Crainea <razvan@opensips.org>
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
#include "../../mod_fix.h"
#include "cgrates_common.h"

static int cgr_proc_auth_reply(struct cgr_conn *c, json_object *jobj,
		void *p, char *error)
{
	int_str val;
	if (error) {
		val.s.s = error;
		val.s.len = strlen(error);
		if (cgrates_set_reply(CGR_KVF_TYPE_STR, &val) < 0) {
			LM_ERR("cannot set the reply code!\n");
			return -2;
		}
		return -1;
	}

	if (json_object_get_type(jobj) != json_type_int) {
		LM_ERR("CGRateS returned a non-int type in Auth reply: %d %s\n",
				json_object_get_type(jobj), json_object_to_json_string(jobj));
		return -4;
	}
	val.n = json_object_get_int(jobj);
	/* -1: always allowed (postpaid)
	 *  0: not allowed to call
	 *  *: allowed
	 */
	if (cgrates_set_reply(CGR_KVF_TYPE_INT, &val) < 0) {
		LM_ERR("cannot set the reply value!\n");
		return -2;
	}
	return ((val.n == 0) ? -1: 1);
}

static json_object *cgr_get_auth_msg(struct sip_msg *msg, str *acc, str *dst)
{
	struct cgr_ctx *ctx;
	struct list_head extra_list;
	struct list_head *l, *t;
	json_object *ret = NULL;
	str name;

	INIT_LIST_HEAD(&extra_list);

	/* OriginID */
	if (msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
			(msg->callid==NULL)) ) {
		LM_ERR("Cannot get callid of the message!\n");
		return NULL;
	}
	if (cgr_push_kv_str(&extra_list, "OriginID", &msg->callid->body) < 0) {
		LM_ERR("cannot add OriginID node\n");
		goto exit;
	}

	if (acc && cgr_push_kv_str(&extra_list, "Account", acc) < 0) {
		LM_ERR("cannot add Account node\n");
		goto exit;
	}

	name.s = int2str(time(NULL), &name.len);
	if (cgr_push_kv_str(&extra_list, "SetupTime", &name) < 0) {
		LM_ERR("cannot add SetupTime node\n");
		goto exit;
	}

	ctx = CGR_GET_CTX();
	/* add username in r-uri only if not already added in the structure from
	 * the script by someone */
	if (!dst) {
		name.s = "Destination";
		name.len = strlen(name.s);
		if (ctx && !cgr_get_kv(&ctx->kv_store, name)) {
			dst = get_request_user(msg);
			if (!dst) {
				LM_ERR("no destination specified!\n");
				goto exit;
			}
		}
	}

	if (dst) {
		if (cgr_push_kv_str(&extra_list, "Destination", dst) < 0) {
			LM_ERR("cannot add Destination node\n");
			goto exit;
		}
	}


	ret = cgr_get_generic_msg("SMGenericV1.MaxUsage",
			ctx ? &ctx->kv_store : NULL, &extra_list);

exit:
	list_for_each_safe(l, t, &extra_list)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	return ret;
}


int w_cgr_auth(struct sip_msg* msg, char* acc_c, char *dst_c)
{
	str acc_str;
	str dst;
	json_object *jmsg = NULL;

	if (acc_c && fixup_get_svalue(msg, (gparam_p)acc_c, &acc_str) < 0) {
		LM_ERR("failed fo fetch account's name\n");
		return -2;
	}

	if (dst_c && fixup_get_svalue(msg, (gparam_p)dst_c, &dst) < 0) {
		LM_ERR("failed fo fetch the destination\n");
		return -2;
	}

	jmsg = cgr_get_auth_msg(msg, (acc_c?&acc_str:NULL), (dst_c?&dst:NULL));
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return -2;
	}

	/* reset the error */
	CGR_RESET_REPLY_CTX();

	return cgr_handle_cmd(msg, jmsg, cgr_proc_auth_reply, NULL);
}
