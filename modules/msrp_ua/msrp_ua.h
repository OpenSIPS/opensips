/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 *
 */

#ifndef _MSRP_UA_H_
#define _MSRP_UA_H_

#include "../b2b_entities/b2be_load.h"
#include "api.h"

#define MSRPUA_SESS_DEL_TOUT 30
#define MSRPUA_SESS_SETUP_TOUT 60

typedef enum msrpua_dlg_state {
	MSRPUA_DLG_NEW,   /* New dialog, no final reply sent/received yet */
	MSRPUA_DLG_CONF,  /* Confirmed dialog, 2xx sent/received */
	MSRPUA_DLG_EST,   /* Established dialog, ACK sent/received  */
	MSRPUA_DLG_TERM,  /* Terminated dialog */
} msrpua_dlg_state_t;

struct msrpua_session {
	str session_id;
	str b2b_key;
	enum b2b_entity_type b2b_type;
	msrpua_dlg_state_t dlg_state;
	str ruri;
	str accept_types;
	str peer_accept_types;
	str use_path;
	str peer_path;
	struct msrp_url *peer_path_parsed;
	union sockaddr_union to_su;
	int sdp_sess_id;
	int sdp_sess_vers;
	int lifetime;
	b2b_dlginfo_t *dlginfo;
	struct msrp_ua_handler hdl;
};

struct uac_init_params {
	struct msrpua_session *sess;
	str from_uri;
	str to_uri;
	str ruri;
};

struct uas_init_params {
	struct msrpua_session *sess;
};

#endif
