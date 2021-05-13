/**
 * Copyright (C) 2021 OpenSIPS Solutions
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
 */

#include <freeDiameter/extension.h>

#include "../../sr_module.h"

#include "aaa_impl.h"
#include "peer.h"

#define EVENT_RECORD 1

int diameter_send_msg(void)
{
	struct msg *dmsg;
	struct avp *avp;
	union avp_value val;
    os0_t sess_bkp;
    size_t sess_bkp_len;

	FD_CHECK(fd_msg_new(acr_model, MSGFL_ALLOC_ETEID, &dmsg));

	/* App id */
	{
		struct msg_hdr *h;
		FD_CHECK(fd_msg_hdr(dmsg, &h));
		h->msg_appl = 3;
	}

	//if ((rc = fd_msg_new_session(dmsg, (os0_t)STR_L("app_opensips"))) < 0) {
	//	LM_ERR("failed to create new acc session, rc: %d\n", rc);
	//	return -1;
	//}

	/* sid */
	{
		struct session * sess = NULL;
		os0_t s;
		FD_CHECK(fd_sess_new( &sess, fd_g_config->cnf_diamid, fd_g_config->cnf_diamid_len, NULL, 0));
		FD_CHECK(fd_sess_getsid(sess, &s, &sess_bkp_len));
		_FD_CHECK(!!(sess_bkp = os0dup(s, sess_bkp_len)), 1);

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &acr_model, ENOENT));
		FD_CHECK(fd_msg_avp_new(acr_model, 0, &avp));
		memset(&val, 0, sizeof val);
		val.os.data = sess_bkp;
		val.os.len = sess_bkp_len;
		FD_CHECK(fd_msg_avp_setvalue(avp, &val));
		FD_CHECK(fd_msg_avp_add(dmsg, MSG_BRW_FIRST_CHILD, avp));
	}

	/* Origin-* */
	FD_CHECK(fd_msg_add_origin(dmsg, 0));

	/* Destination-Realm */
	{
		FD_CHECK(fd_msg_avp_new(acc_dict.Destination_Realm, 0, &avp));

		memset(&val, 0, sizeof val);
		val.os.data = (unsigned char *)"diameter.test";
		val.os.len = strlen("diameter.test");
		FD_CHECK(fd_msg_avp_setvalue(avp, &val));
		FD_CHECK(fd_msg_avp_add(dmsg, MSG_BRW_LAST_CHILD, avp));
	}

	/* Accounting-Record-Type */
	{
		FD_CHECK(fd_msg_avp_new(acc_dict.Accounting_Record_Type, 0, &avp));

		memset(&val, 0, sizeof val);
		val.i32 = EVENT_RECORD;
		FD_CHECK(fd_msg_avp_setvalue(avp, &val));
		FD_CHECK(fd_msg_avp_add(dmsg, MSG_BRW_LAST_CHILD, avp));
	}

	/* Accounting-Record-Number */
	{
		FD_CHECK(fd_msg_avp_new(acc_dict.Accounting_Record_Number, 0, &avp));

		memset(&val, 0, sizeof val);
		val.i32 = 0; /* just 0; the Session-Id makes it unique anyway */
		FD_CHECK(fd_msg_avp_setvalue(avp, &val));
		FD_CHECK(fd_msg_avp_add(dmsg, MSG_BRW_LAST_CHILD, avp));
	}

	/* Route-Record */
	{
		FD_CHECK(fd_msg_avp_new(acc_dict.Route_Record, 0, &avp));

		memset(&val, 0, sizeof val);
		val.os.data = (unsigned char *)"server";
		val.os.len = strlen("server");
		FD_CHECK(fd_msg_avp_setvalue(avp, &val));
		FD_CHECK(fd_msg_avp_add(dmsg, MSG_BRW_LAST_CHILD, avp));
	}

	sleep(2);

	FD_CHECK(fd_msg_send(&dmsg, NULL, NULL));
	return 0;
}


void diameter_peer_loop(int _)
{
	if (freeDiameter_init() != 0) {
		LM_ERR("failed to init freeDiameter library\n");
		return;
	}

	LM_INFO("XXXXX parse: %d\n", fd_core_parseconf("freeDiameter-client.conf"));
	LM_INFO("XXXXX start: %d\n", fd_core_start());

	if (diameter_send_msg() != 0) {
		LM_ERR("failed to send message!\n");
		return;
	}

	LM_INFO("XXXX successfully sent msg!!?\n");

	fd_core_wait_shutdown_complete();

	LM_INFO("XXXX exiting!!\n");
}
