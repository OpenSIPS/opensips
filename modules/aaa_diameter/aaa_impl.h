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

#define _FD_CHECK(__call__, __retok__) \
	do { \
		int __ret__; \
		__ret__ = (__call__); \
		if (__ret__ != (__retok__)) { \
			LM_ERR("error in %s: %d\n", #__call__, __ret__); \
			return __ret__; \
		} \
	} while (0)
#define FD_CHECK(__call__) _FD_CHECK((__call__), 0)

struct _acc_dict {
	struct dict_object *Destination_Realm;
	struct dict_object *Accounting_Record_Type;
	struct dict_object *Accounting_Record_Number;
	struct dict_object *Route_Record;
};

extern struct _acc_dict acc_dict;
extern struct dict_object *acr_model;

int freeDiameter_init(void);

aaa_message *dm_create_message(aaa_conn *con, int msg_type);
int dm_avp_add(aaa_conn *con, aaa_message *msg, aaa_map *name, void *val,
               int val_length, int vendor);
int dm_send_message(aaa_conn *con, aaa_message *req, aaa_message **rpl);
int dm_destroy_message(aaa_conn *con, aaa_message *msg);

#endif
