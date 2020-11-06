/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#ifndef __UL_EVI_H__
#define __UL_EVI_H__

#include "urecord.h"

/* event names */
#define UL_EV_AOR_INSERT     "E_UL_AOR_INSERT"
#define UL_EV_AOR_DELETE     "E_UL_AOR_DELETE"
#define UL_EV_CT_INSERT      "E_UL_CONTACT_INSERT"
#define UL_EV_CT_UPDATE      "E_UL_CONTACT_UPDATE"
#define UL_EV_CT_DELETE      "E_UL_CONTACT_DELETE"
#define UL_EV_CT_REFRESH     "E_UL_CONTACT_REFRESH"
#define UL_EV_LATENCY_UPDATE "E_UL_LATENCY_UPDATE"

/* event params */
#define UL_EV_PARAM_DOMAIN    "domain"
#define UL_EV_PARAM_AOR       "aor"
#define UL_EV_PARAM_CT_URI    "uri"
#define UL_EV_PARAM_CT_RCV    "received"
#define UL_EV_PARAM_CT_PATH   "path"
#define UL_EV_PARAM_CT_QVAL   "qval"
#define UL_EV_PARAM_CT_UA     "user_agent"
#define UL_EV_PARAM_CT_SOCK   "socket"
#define UL_EV_PARAM_CT_BFL    "bflags"
#define UL_EV_PARAM_CT_EXP    "expires"
#define UL_EV_PARAM_CT_CLID   "callid"
#define UL_EV_PARAM_CT_CSEQ   "cseq"
#define UL_EV_PARAM_CT_ATTR   "attr"
#define UL_EV_PARAM_CT_LTCY   "latency"
#define UL_EV_PARAM_CT_SHTAG  "shtag"
#define UL_EV_PARAM_CT_REASON "reason"
#define UL_EV_PARAM_CT_RCLID  "req_callid"

struct ct_refresh_event_data {
	ucontact_t *ct;
	str reason;
	str req_callid;
};

/* AoR event IDs */
extern event_id_t ei_ins_id;
extern event_id_t ei_del_id;

/* Contact event IDs */
extern event_id_t ei_c_ins_id;
extern event_id_t ei_c_del_id;
extern event_id_t ei_c_update_id;
extern event_id_t ei_c_latency_update_id;
extern event_id_t ei_c_refresh_id;

int ul_event_init(void);
void ul_raise_aor_event(event_id_t _e, struct urecord *_r);
void ul_raise_contact_event(event_id_t _e, const ucontact_t *_c);
void ul_raise_ct_refresh_event(const ucontact_t *c, const str *reason,
                               const str *req_callid);

#endif /* __UL_EVI_H__ */
