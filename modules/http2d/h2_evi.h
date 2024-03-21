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

#ifndef __H2_EVI__
#define __H2_EVI__

#include "../../str.h"

#define H2EV_REQ_NAME "E_HTTP2_REQUEST"
extern str h2ev_req_pname_msg;

int h2_init_evi(void);
void h2_raise_event_request(const char *method, const char *path,
		const char *headers_json, const str *body, void *msg);

#endif /* __H2_EVI__ */
