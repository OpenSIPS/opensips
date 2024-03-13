/**
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef DIAMETER_API_IMPL_H
#define DIAMETER_API_IMPL_H

#include "diameter_api.h"

int dm_api_find_cmd(diameter_conn *conn, int cmd_code);
int dm_api_send_req(diameter_conn *conn, int app_id, int cmd_code, cJSON *req,
		diameter_reply *reply);
int dm_api_send_req_async(diameter_conn *conn, int app_id, int cmd_code, cJSON *req,
		diameter_reply_cb *reply);
cJSON *dm_api_get_reply(diameter_reply *rpl);
int dm_api_get_reply_status(diameter_reply *rpl);
void dm_api_free_reply(diameter_reply *rpl);

#endif /* DIAMETER_API_IMPL_H */
