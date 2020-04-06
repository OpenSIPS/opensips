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

#include "../../evi/evi_modules.h"

#include "ul_evi.h"

event_id_t ei_ins_id = EVI_ERROR;
event_id_t ei_del_id = EVI_ERROR;

event_id_t ei_c_ins_id = EVI_ERROR;
event_id_t ei_c_del_id = EVI_ERROR;
event_id_t ei_c_update_id = EVI_ERROR;
event_id_t ei_c_latency_update_id = EVI_ERROR;
event_id_t ei_c_refresh_id = EVI_ERROR;

static str ei_ins_name = str_init(UL_EV_AOR_INSERT);
static str ei_del_name = str_init(UL_EV_AOR_DELETE);
static str ei_contact_ins_name = str_init(UL_EV_CT_INSERT);
static str ei_contact_update_name = str_init(UL_EV_CT_UPDATE);
static str ei_contact_del_name = str_init(UL_EV_CT_DELETE);
static str ei_contact_refresh_name = str_init(UL_EV_CT_REFRESH);
static str ei_contact_latency_update_name = str_init(UL_EV_LATENCY_UPDATE);

static str ei_aor_name = str_init(UL_EV_PARAM_AOR_URI);
static str ei_c_uri_name = str_init(UL_EV_PARAM_CT_URI);
static str ei_c_recv_name = str_init(UL_EV_PARAM_CT_RCV);
static str ei_c_path_name = str_init(UL_EV_PARAM_CT_PATH);
static str ei_c_qval_name = str_init(UL_EV_PARAM_CT_QVAL);
static str ei_c_user_agent_name = str_init(UL_EV_PARAM_CT_UA);
static str ei_c_socket_name = str_init(UL_EV_PARAM_CT_SOCK);
static str ei_c_bflags_name = str_init(UL_EV_PARAM_CT_BFL);
static str ei_c_expires_name = str_init(UL_EV_PARAM_CT_EXP);
static str ei_c_callid_name = str_init(UL_EV_PARAM_CT_CLID);
static str ei_c_cseq_name = str_init(UL_EV_PARAM_CT_CSEQ);
static str ei_c_attr_name = str_init(UL_EV_PARAM_CT_ATTR);
static str ei_c_latency_name = str_init(UL_EV_PARAM_CT_LTCY);
static str ei_c_shtag_name = str_init(UL_EV_PARAM_CT_SHTAG);

static evi_params_p ul_aor_event_params;
static evi_params_p ul_contact_event_params;

static evi_param_p ul_aor_param;
static evi_param_p ul_c_aor_param;
static evi_param_p ul_c_uri_param;
static evi_param_p ul_c_recv_param;
static evi_param_p ul_c_path_param;
static evi_param_p ul_c_qval_param;
static evi_param_p ul_c_user_agent_param;
static evi_param_p ul_c_socket_param;
static evi_param_p ul_c_bflags_param;
static evi_param_p ul_c_expires_param;
static evi_param_p ul_c_callid_param;
static evi_param_p ul_c_cseq_param;
static evi_param_p ul_c_attr_param;
static evi_param_p ul_c_latency_param;
static evi_param_p ul_c_shtag_param;

/*! \brief
 * Initialize event structures
 */
int ul_event_init(void)
{
	ei_ins_id = evi_publish_event(ei_ins_name);
	if (ei_ins_id == EVI_ERROR) {
		LM_ERR("cannot register aor insert event\n");
		return -1;
	}

	ei_del_id = evi_publish_event(ei_del_name);
	if (ei_del_id == EVI_ERROR) {
		LM_ERR("cannot register aor delete event\n");
		return -1;
	}

	ei_c_ins_id = evi_publish_event(ei_contact_ins_name);
	if (ei_c_ins_id == EVI_ERROR) {
		LM_ERR("cannot register contact insert event\n");
		return -1;
	}

	ei_c_del_id = evi_publish_event(ei_contact_del_name);
	if (ei_c_del_id == EVI_ERROR) {
		LM_ERR("cannot register contact delete event\n");
		return -1;
	}

	ei_c_update_id = evi_publish_event(ei_contact_update_name);
	if (ei_c_update_id == EVI_ERROR) {
		LM_ERR("cannot register contact update event\n");
		return -1;
	}

	ei_c_refresh_id = evi_publish_event(ei_contact_refresh_name);
	if (ei_c_refresh_id == EVI_ERROR) {
		LM_ERR("cannot register contact refresh event\n");
		return -1;
	}

	ei_c_latency_update_id = evi_publish_event(ei_contact_latency_update_name);
	if (ei_c_latency_update_id == EVI_ERROR) {
		LM_ERR("cannot register contact latency update event\n");
		return -1;
	}

	ul_aor_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_aor_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_aor_event_params, 0, sizeof(evi_params_t));
	ul_aor_param = evi_param_create(ul_aor_event_params, &ei_aor_name);
	if (!ul_aor_param) {
		LM_ERR("cannot create AOR parameter\n");
		return -1;
	}

	ul_contact_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_contact_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_contact_event_params, 0, sizeof(evi_params_t));

	ul_c_aor_param = evi_param_create(ul_contact_event_params, &ei_aor_name);
	if (!ul_c_aor_param) {
		LM_ERR("cannot create contact aor parameter\n");
		return -1;
	}

	ul_c_uri_param = evi_param_create(ul_contact_event_params,
		&ei_c_uri_name);
	if (!ul_c_uri_param) {
		LM_ERR("cannot create contact address parameter\n");
		return -1;
	}

	ul_c_recv_param = evi_param_create(ul_contact_event_params,
		&ei_c_recv_name);
	if (!ul_c_recv_param) {
		LM_ERR("cannot create received parameter\n");
		return -1;
	}

	ul_c_path_param = evi_param_create(ul_contact_event_params,
		&ei_c_path_name);
	if (!ul_c_path_param) {
		LM_ERR("cannot create path parameter\n");
		return -1;
	}

	ul_c_qval_param = evi_param_create(ul_contact_event_params,
		&ei_c_qval_name);
	if (!ul_c_qval_param) {
		LM_ERR("cannot create Qval parameter\n");
		return -1;
	}

	ul_c_user_agent_param = evi_param_create(ul_contact_event_params,
		&ei_c_user_agent_name);
	if (!ul_c_user_agent_param) {
		LM_ERR("cannot create user_agent parameter\n");
		return -1;
	}

	ul_c_socket_param = evi_param_create(ul_contact_event_params,
		&ei_c_socket_name);
	if (!ul_c_socket_param) {
		LM_ERR("cannot create socket parameter\n");
		return -1;
	}

	ul_c_bflags_param = evi_param_create(ul_contact_event_params,
		&ei_c_bflags_name);
	if (!ul_c_bflags_param) {
		LM_ERR("cannot create bflags parameter\n");
		return -1;
	}

	ul_c_expires_param = evi_param_create(ul_contact_event_params,
		&ei_c_expires_name);
	if (!ul_c_expires_param) {
		LM_ERR("cannot create expires parameter\n");
		return -1;
	}

	ul_c_callid_param = evi_param_create(ul_contact_event_params,
		&ei_c_callid_name);
	if (!ul_c_callid_param) {
		LM_ERR("cannot create callid parameter\n");
		return -1;
	}

	ul_c_cseq_param = evi_param_create(ul_contact_event_params, &ei_c_cseq_name);
	if (!ul_c_cseq_param) {
		LM_ERR("cannot create cseq parameter\n");
		return -1;
	}

	ul_c_attr_param = evi_param_create(ul_contact_event_params, &ei_c_attr_name);
	if (!ul_c_attr_param) {
		LM_ERR("cannot create cseq parameter\n");
		return -1;
	}

	ul_c_latency_param = evi_param_create(ul_contact_event_params, &ei_c_latency_name);
	if (!ul_c_latency_param) {
		LM_ERR("cannot create latency parameter\n");
		return -1;
	}

	ul_c_shtag_param = evi_param_create(ul_contact_event_params, &ei_c_shtag_name);
	if (!ul_c_shtag_param) {
		LM_ERR("cannot create shtag parameter\n");
		return -1;
	}

	return 0;
}


/*! \brief
 * Raise an event when an AOR is inserted/deleted
 */
void ul_raise_aor_event(event_id_t _e, struct urecord* _r)
{
	if (_e == EVI_ERROR) {
		LM_ERR("event not yet registered %d\n", _e);
		return;
	}
	if (evi_param_set_str(ul_aor_param, &_r->aor) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}
	if (evi_raise_event(_e, ul_aor_event_params) < 0)
		LM_ERR("cannot raise event\n");
}


void ul_raise_contact_event(event_id_t _e, struct ucontact *_c)
{
	static str str_empty = {"", 0};

	if (_e == EVI_ERROR) {
		LM_ERR("event not yet registered %d\n", _e);
		return;
	}

	/* the AOR */
	if (evi_param_set_str(ul_c_aor_param, _c->aor) < 0) {
		LM_ERR("cannot set contact aor parameter\n");
		return;
	}

	/* the contact URI */
	if (evi_param_set_str(ul_c_uri_param, &_c->c) < 0) {
		LM_ERR("cannot set contact URI parameter\n");
		return;
	}

	/* the received URI */
	if (evi_param_set_str(ul_c_recv_param, &_c->received) < 0) {
		LM_ERR("cannot set received parameter\n");
		return;
	}

	/* the PATH URI */
	if (evi_param_set_str(ul_c_path_param, &_c->path) < 0) {
		LM_ERR("cannot set path parameter\n");
		return;
	}

	/* the Q value */
	if (evi_param_set_int(ul_c_qval_param, &_c->q) < 0) {
		LM_ERR("cannot set Qval parameter\n");
		return;
	}

	/* the User Agent */
	if (evi_param_set_str(ul_c_user_agent_param, &_c->user_agent) < 0) {
		LM_ERR("cannot set user_agent parameter\n");
		return;
	}

	/* the socket */
	if (evi_param_set_str(ul_c_socket_param,
			(_c->sock ? &_c->sock->sock_str : &str_empty)) < 0) {
		LM_ERR("cannot set socket parameter\n");
		return;
	}

	/* the Branch flags */
	if (evi_param_set_int(ul_c_bflags_param, &_c->cflags) < 0) {
		LM_ERR("cannot set bflags parameter\n");
		return;
	}

	/* the Expires value */
	if (evi_param_set_int(ul_c_expires_param, &_c->expires) < 0) {
		LM_ERR("cannot set expires parameter\n");
		return;
	}

	/* the Call-ID value */
	if (evi_param_set_str(ul_c_callid_param, &_c->callid) < 0) {
		LM_ERR("cannot set callid parameter\n");
		return;
	}

	/* the CSeq value */
	if (evi_param_set_int(ul_c_cseq_param, &_c->cseq) < 0) {
		LM_ERR("cannot set cseq parameter\n");
		return;
	}

	/* the ATTR value */
	if(evi_param_set_str(ul_c_attr_param,_c->attr.len?&_c->attr:&str_empty)<0){
		LM_ERR("cannot set attr parameter\n");
		return;
	}

	/* the last known ping latency */
	if (evi_param_set_int(ul_c_latency_param, &_c->sipping_latency) < 0) {
		LM_ERR("cannot set latency parameter\n");
		return;
	}

	/* the shared tag */
	if (evi_param_set_str(ul_c_shtag_param,
		                   _c->shtag.s ? &_c->shtag : &str_empty) < 0) {
		LM_ERR("cannot set shtag parameter\n");
		return;
	}

	if (evi_raise_event(_e, ul_contact_event_params) < 0)
		LM_ERR("cannot raise event\n");
}
