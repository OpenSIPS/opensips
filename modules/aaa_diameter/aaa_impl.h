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

#ifndef AAA_DIAMETER_IMPL
#define AAA_DIAMETER_IMPL

#include "../../aaa/aaa.h"

#define __FD_CHECK(__call__, __retok__, __retval__) \
	do { \
		int __ret__; \
		__ret__ = (__call__); \
		if (__ret__ > 0) \
			__ret__ = -__ret__; \
		if (__ret__ != (__retok__)) { \
			LM_ERR("error in %s: %d\n", #__call__, __ret__); \
			return __retval__; \
		} \
	} while (0)
#define _FD_CHECK(__call__, __retok__) \
	__FD_CHECK((__call__), (__retok__), __ret__)
#define FD_CHECK(__call__) _FD_CHECK((__call__), 0)

#define FD_CHECK_dict_new(type, data, parent, ref) \
	FD_CHECK(fd_dict_new(fd_g_config->cnf_dict, (type), \
				(data), (parent), (ref)))

#define FD_CHECK_dict_search(type, criteria, what, result) \
	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, (type), \
				(criteria), (what), (result), ENOENT))

#define DM_MSG_SENT ((void *)1)
#define DM_DUMMY_HANDLE ((void *)-1)

struct _dm_dict {
	struct dict_object *Destination_Realm;
	struct dict_object *Result_Code;
	struct dict_object *Error_Message;

	struct dict_object *Accounting_Record_Type;
	struct dict_object *Accounting_Record_Number;
	struct dict_object *Acct_Session_Id;

	struct dict_object *Auth_Application_Id;
	struct dict_object *Auth_Session_State;
	struct dict_object *SIP_AOR;
	struct dict_object *SIP_Method;

	struct dict_object *Event_Timestamp;
	struct dict_object *Route_Record;
};

struct dm_message {
	aaa_message *am; /* back-reference, useful during cleanup */

	str sip_method;
	struct dm_cond *reply_cond; /* the cond to signal on reply arrival */

	struct list_head avps;
	struct list_head list;
};

struct dm_avp {
	struct dict_object *obj;
	str name;
	str value;
	int vendor_id;

	struct list_head subavps;

	struct list_head list;
};

struct dm_cond {
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	int rc; /* the Diameter Result-Code AVP value */
	int is_error;
};
int init_mutex_cond(pthread_mutex_t *mutex, pthread_cond_t *cond);

extern char *dm_conf_filename;
extern char *extra_avps_file;
extern struct _dm_dict dm_dict;

int freeDiameter_init(void);

aaa_conn *dm_init_prot(str *aaa_url);
int dm_init_minimal(void);
int dm_init_sip_application(void);
int dm_register_osips_avps(void);
int dm_register_callbacks(void);

int dm_find(aaa_conn *con, aaa_map *map, int op);
aaa_message *dm_create_message(aaa_conn *con, int msg_type);
int dm_avp_add(aaa_conn *con, aaa_message *msg, aaa_map *avp, void *val,
               int val_length, int vendor);
int dm_send_message(aaa_conn *con, aaa_message *req, aaa_message **_);
int dm_destroy_message(aaa_conn *con, aaa_message *msg);
void _dm_destroy_message(aaa_message *msg);

int dm_init_reply_cond(int proc_rank);
int dm_add_pending_reply(const str *callid, struct dm_cond *reply_cond);

void dm_destroy(void);

#endif
