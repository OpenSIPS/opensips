/*
 * Copyright (C) 2024 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __AAA_DIAMETER_EVI__
#define __AAA_DIAMETER_EVI__

#include <freeDiameter/extension.h>
#include "../../str.h"

typedef struct _dm_ipc_event_req {
	void *fd_msg;

	str sessid;
	int app_id;
	int cmd_code;
	str avps_json;
} dm_ipc_event_req;

#define DMEV_REQ_NAME "E_DM_REQUEST"
extern str dmev_req_pname_sessid;
extern str dmev_req_pname_appid;
extern str dmev_req_pname_cmdcode;
extern str dmev_req_pname_avpsjson;
extern str dmev_req_pname_fdmsg;

int dm_init_evi(void);
int dm_dispatch_event_req(struct msg *msg, const str *sessid, int app_id,
                          int cmd_code, const str *avps_json);
void dm_raise_event_request(int sender, void *esl_event);

#endif /* __AAA_DIAMETER_EVI__ */
