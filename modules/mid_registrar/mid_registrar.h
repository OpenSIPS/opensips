/*
 * Support for:
 *  - REGISTER traffic throttling, optionally with outbound contact aggregation
 *  - proxying REGISTER traffic while saving registration state
 *       (contact expirations are taken from the downstream UAS's 200 OK reply)
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 * History:
 * --------
 *  2016-07-06 initial version (liviu)
 */

#ifndef __MID_REG_
#define __MID_REG_

#include "../../parser/msg_parser.h"

enum mid_reg_mode {
	MID_REG_MIRROR,
	MID_REG_THROTTLE_CT,
	MID_REG_THROTTLE_AOR,
};

enum mid_reg_routing_mode {
	ROUTE_BY_CONTACT,
	ROUTE_BY_PATH,
};

enum mid_reg_matching_mode {
	MATCH_BY_PARAM,
	MATCH_BY_USER,
};

extern struct usrloc_api ul_api;
extern struct tm_binds tm_api;
extern struct sig_binds sig_api;

extern enum mid_reg_mode reg_mode;
extern enum mid_reg_routing_mode routing_mode;
extern enum mid_reg_matching_mode matching_mode;

extern str matching_param;

extern int attr_avp_name;

time_t get_act_time(void);
void update_act_time(void);
int extract_aor(str* _uri, str* _a,str *sip_instance,str *call_id);

#endif /* __MID_REG_ */
