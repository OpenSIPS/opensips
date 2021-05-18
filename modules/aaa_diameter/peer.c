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

#include "../../ut.h"
#include "../../sr_module.h"
#include "../../locking.h"
#include "../../lib/list.h"

#include "aaa_impl.h"
#include "peer.h"

#define EVENT_RECORD 1

/* OpenSIPS processes will use this list + locking in order to queue
 * messages to be sent to the Diameter server peer */
struct list_head *msg_send_queue;
pthread_cond_t *msg_send_cond;
pthread_mutex_t *msg_send_lk;


int dm_init_peer(void)
{
	struct {
		struct list_head queue;
		pthread_cond_t cond;
		pthread_mutex_t mutex;
	} *wrap;

	wrap = shm_malloc(sizeof *wrap);
	if (!wrap) {
		LM_ERR("oom\n");
		return -1;
	}

	msg_send_queue = &wrap->queue;
	INIT_LIST_HEAD(msg_send_queue);

	msg_send_lk = &wrap->mutex;
	pthread_mutexattr_t mattr;
	FD_CHECK(pthread_mutexattr_init(&mattr));
	FD_CHECK(pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED));
	FD_CHECK(pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST));
	FD_CHECK(pthread_mutex_init(msg_send_lk, &mattr));
	pthread_mutexattr_destroy(&mattr);

	msg_send_cond = &wrap->cond;
	pthread_condattr_t cattr;
	FD_CHECK(pthread_condattr_init(&cattr));
	FD_CHECK(pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED));
	FD_CHECK(pthread_cond_init(msg_send_cond, &cattr));
	pthread_condattr_destroy(&cattr);

	return 0;
}


static int dm_acct(struct dm_message *msg)
{
	struct msg *dmsg;
	struct avp *avp;
	struct dm_avp *dm_avp;
	struct list_head *it;
	union avp_value val;
	os0_t sess_bkp;
	size_t sess_bkp_len;
	struct dict_object *acr; /* Accounting-Request (ACR, code: 271) */

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME,
	      "Accounting-Request", &acr, ENOENT));

	FD_CHECK(fd_msg_new(acr, MSGFL_ALLOC_ETEID, &dmsg));

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
		sess_bkp = os0dup(s, sess_bkp_len);
		if (!sess_bkp) {
			LM_ERR("oom\n");
			return -1;
		}

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &acr, ENOENT));
		FD_CHECK(fd_msg_avp_new(acr, 0, &avp));
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

	/* Event-Timestamp */
	{
		time_t ts = 0;
		int have_bytes = 0;
		unsigned char bytes[4]; /* per RFC 3588 § 4.3 */

		/* was the event timestamp passed to us? */
		list_for_each (it, &msg->avps) {
			dm_avp = list_entry(it, struct dm_avp, list);
			if (str_match(&dm_avp->name, _str("Event-Timestamp"))) {

				/* did the upper module pass an UNIX timestamp or NTP bytes? */
				if (dm_avp->value.len >= 0) {
					if (dm_avp->value.len != 4) {
						LM_BUG("Event-Timestamp must have 4 octets (%d given)",
						       dm_avp->value.len);
						continue;
					}

					memcpy(bytes, dm_avp->value.s, dm_avp->value.len);
					have_bytes = 1;
				} else {
					ts = (time_t)dm_avp->value.s;
					LM_DBG("found Event-Timestamp AVP as UNIX ts: %lu\n", ts);
					break;
				}
			}
		}

		if (!have_bytes) {
			/* ... if no ts found, just use current time */
			if (!ts)
				ts = time(NULL);

			LM_DBG("final Event-Timestamp (UNIX ts): %lu\n", ts);

			ts += 2208988800UL; /* convert to Jan 1900 00:00 UTC epoch time */
			bytes[0] = (ts >> 24) & 0xFF;
			bytes[1] = (ts >> 16) & 0xFF;
			bytes[2] = (ts >> 8) & 0xFF;
			bytes[3] = ts & 0xFF;
		}

		FD_CHECK(fd_msg_avp_new(acc_dict.Event_Timestamp, 0, &avp));

		memset(&val, 0, sizeof val);
		val.os.len = 4;
		val.os.data = bytes;
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

	list_for_each (it, &msg->avps) {
		dm_avp = list_entry(it, struct dm_avp, list);

		if (str_match(&dm_avp->name, _str("Event-Timestamp")))
			continue; /* added earlier */

		if (dm_avp->value.len < 0)
			LM_INFO("XXX appending AVP: %.*s: int(%lu)\n",
					dm_avp->name.len, dm_avp->name.s, (unsigned long)dm_avp->value.s);
		else
			LM_INFO("XXX appending AVP: %.*s: str(%.*s)\n",
					dm_avp->name.len, dm_avp->name.s,
					dm_avp->value.len, dm_avp->value.s);

		// TODO
		//FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
		//      avp->name, &wrap->davp.obj, ENOENT));
	}

	FD_CHECK(fd_msg_send(&dmsg, NULL, NULL));
	return 0;
}


static inline int diameter_send_msg(struct dm_message *msg)
{
	aaa_message *am = msg->am;

	switch (am->type) {
	case AAA_ACCT:
		return dm_acct(msg);
	default:
		LM_ERR("unsupported AAA message type (%d), skipping\n", am->type);
	}

	return -1;
}


void diameter_peer_loop(int _)
{
	struct dm_message *msg;

	if (freeDiameter_init() != 0) {
		LM_ERR("failed to init freeDiameter library\n");
		return;
	}

	__FD_CHECK(fd_core_parseconf(dm_conf_filename), 0, );
	__FD_CHECK(dm_register_osips_avps(), 0, );

	__FD_CHECK(fd_core_start(), 0, );

	pthread_mutex_lock(msg_send_lk);

	for (;;) {
		LM_INFO("XXX waiting for new messages...\n");
		pthread_cond_wait(msg_send_cond, msg_send_lk);

		if (list_empty(msg_send_queue)) {
			LM_BUG("pthread cond signal on empty queue");
			continue;
		}

		LM_INFO("XXX have new message! <3 sending...\n");
		msg = list_entry(msg_send_queue->next, struct dm_message, list);
		list_del(&msg->list);

		if (diameter_send_msg(msg) != 0)
			LM_ERR("failed to send message!\n");

		LM_INFO("Done sending!\n");

		_dm_destroy_message(msg->am);
	}

	pthread_mutex_unlock(msg_send_lk);

	LM_INFO("XXXX successfully sent msg!!?\n");

	__FD_CHECK(fd_core_wait_shutdown_complete(), 0, );

	LM_INFO("XXXX exiting!!\n");
}
