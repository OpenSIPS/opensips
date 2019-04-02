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
#include "../../mod_fix.h"
#include "cgrates_cmd.h"
#include "cgrates_common.h"

static int cgr_proc_cmd_reply(struct cgr_conn *c, json_object *jobj,
		void *p, char *error)
{
	int_str val;
	int type = CGR_KVF_TYPE_STR;
	int ret = 1;
	if (error) {
		val.s.s = error;
		val.s.len = strlen(error);
		if (cgrates_set_reply(CGR_KVF_TYPE_STR, &val) < 0) {
			LM_ERR("cannot set the reply code!\n");
			return -1;
		}
		return -2;
	}

	if (!cgre_compat_mode)
		return cgrates_set_reply_with_values(jobj);

	switch (json_object_get_type(jobj)) {
	case json_type_int:
		val.n = json_object_get_int(jobj);
		type = CGR_KVF_TYPE_INT;
		break;
	case json_type_string:
		val.s.s = (char *)json_object_get_string(jobj);
		break;
	case json_type_boolean:
		if (json_object_get_boolean(jobj) == TRUE)
			val.n = 1;
		else
			val.n = 0;
		ret = ((val.n == 0) ? -1 : val.n);
		type = CGR_KVF_TYPE_INT;
		break;

	case json_type_object:
	case json_type_array:
		val.s.s = (char *)json_object_to_json_string(jobj);
		break;

	case json_type_null:
		return 1;

	default:
		LM_INFO("unsupported json type %d in reply\n",
				json_object_get_type(jobj));
		return -2;
	}
	/* fix the length of the strings for everyone */
	if (type == CGR_KVF_TYPE_STR)
		val.s.len = strlen(val.s.s);

	if (cgrates_set_reply(type, &val) < 0) {
		LM_ERR("cannot set the reply value!\n");
		return -1;
	}

	return ret;
}

int w_cgr_cmd(struct sip_msg* msg, str* cmd, str *tag_c)
{
	static struct cgr_msg *cmsg;
	struct cgr_session *s;

	s = cgr_get_sess(cgr_try_get_ctx(), tag_c);

	cmsg = cgr_get_generic_msg(cmd, s);
	if (!cmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return -1;
	}

	return cgr_handle_cmd(msg, cmsg->msg, cgr_proc_cmd_reply, NULL);
}

int w_acgr_cmd(struct sip_msg* msg, async_ctx *actx, str* cmd, str *tag_c)
{
	static struct cgr_msg *cmsg;
	struct cgr_session *s;

	s = cgr_get_sess(cgr_try_get_ctx(), tag_c);

	cmsg = cgr_get_generic_msg(cmd, s);
	if (!cmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return -1;
	}

	return cgr_handle_async_cmd(msg, cmsg->msg, cgr_proc_cmd_reply, NULL,actx);
}
