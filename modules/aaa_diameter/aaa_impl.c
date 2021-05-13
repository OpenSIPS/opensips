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
#include "../../lib/list.h"
#include "aaa_impl.h"

struct _acc_dict acc_dict;
struct dict_object *acr_model;

static int os_cb( struct msg ** msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	struct msg_hdr *hdr = NULL;

	FD_CHECK(fd_msg_hdr(*msg, &hdr));

	if (hdr->msg_flags & CMD_FLAG_REQUEST) {
		/* we received an ACR message (??), just discard it */
		FD_CHECK(fd_msg_free(*msg));
		*msg = NULL;
		return 0;
	}

	if (hdr->msg_flags & CMD_FLAG_ERROR) {
		LM_ERR("XXXXXXXXXXX failed to send msg?!\n");
		FD_CHECK(fd_msg_free(*msg));
		*msg = NULL;
		return 0;
	}

	/* we received an ACA reply! */

	LM_ERR("XXXXXXXXXXX wooot?!\n");
	FD_CHECK(fd_msg_free(*msg));
	*msg = NULL;

	return 0;
}

/* entry point: register handler for Base Accounting messages in the daemon */
static int tac_entry(void)
{
	struct disp_when data;

	memset(&data, 0, sizeof data);

	/* Initialize the dictionary objects we use */
	fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_NAME, "Diameter Base Accounting", &data.app, ENOENT);

	/* Register the dispatch callback */
	FD_CHECK(fd_disp_register(os_cb, DISP_HOW_APPID, &data, NULL, NULL));

	/* Advertise the support for the Diameter Base Accounting application in the peer */
	FD_CHECK(fd_disp_app_support(data.app, NULL, 0, 1 ));

	return 0;
}

int freeDiameter_init(void)
{
	extern int fd_log_level;
	int rc;

	if (fd_log_level < FD_LOG_ANNOYING)
		fd_log_level = FD_LOG_ANNOYING;

	if (fd_log_level > FD_LOG_FATAL)
		fd_log_level = FD_LOG_FATAL;

	rc = fd_core_initialize();
	if (rc != 0) {
		LM_ERR("failed to initialize libfdcore (rc: %d)\n", rc);
		return -1;
	}

	fd_g_debug_lvl = fd_log_level;

	memset(&acc_dict, 0, sizeof acc_dict);

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME,
	      "Accounting-Request", &acr_model, ENOENT));

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Destination-Realm", &acc_dict.Destination_Realm, ENOENT));

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Accounting-Record-Type", &acc_dict.Accounting_Record_Type, ENOENT));
	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Accounting-Record-Number", &acc_dict.Accounting_Record_Number, ENOENT));

	FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
	      "Route-Record", &acc_dict.Route_Record, ENOENT));

	tac_entry();

	return 0;
}


aaa_message *dm_create_message(aaa_conn *con, int msg_type)
{
	return NULL;
}


int dm_avp_add(aaa_conn *con, aaa_message *msg, aaa_map *name, void *val,
               int val_length, int vendor)
{

	return 0;
}


int dm_send_message(aaa_conn *con, aaa_message *req, aaa_message **rpl)
{
	return 0;
}


int dm_destroy_message(aaa_conn *conn, aaa_message *msg)
{
	return 0;
}
