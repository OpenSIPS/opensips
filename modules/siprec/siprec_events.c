/*
 * Copyright (C) 2024 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "siprec_events.h"
#include "../../str.h"
#include "../../evi/evi.h"
#include "../../evi/evi_params.h"
#include "../../evi/evi_modules.h"
#include "../../mem/mem.h"

static str siprec_event_start_name = str_init("E_SIPREC_START");
static str siprec_event_stop_name = str_init("E_SIPREC_STOP");
static event_id_t siprec_start_event = EVI_ERROR;
static event_id_t siprec_stop_event = EVI_ERROR;
static evi_params_p siprec_state_event_params;
static str siprec_state_event_did_s = str_init("dlg_id");
static str siprec_state_event_dlg_callid_s = str_init("dlg_callid");
static str siprec_state_event_callid_s = str_init("callid");
static str siprec_state_event_session_s = str_init("session_id");
static str siprec_state_event_server_s = str_init("server");
static evi_param_p siprec_state_event_did;
static evi_param_p siprec_state_event_dlg_callid;
static evi_param_p siprec_state_event_callid;
static evi_param_p siprec_state_event_session;
static evi_param_p siprec_state_event_server;

int src_init_events(void)
{
	siprec_start_event = evi_publish_event(siprec_event_start_name);
	if (siprec_start_event == EVI_ERROR) {
		LM_ERR("cannot register %s event\n", siprec_event_start_name.s);
		return -1;
	}

	siprec_stop_event = evi_publish_event(siprec_event_stop_name);
	if (siprec_stop_event == EVI_ERROR) {
		LM_ERR("cannot register %s event\n", siprec_event_stop_name.s);
		return -1;
	}

	siprec_state_event_params = pkg_malloc(sizeof(evi_params_t));
	if (siprec_state_event_params == NULL) {
		LM_ERR("no more pkg mem for %s event params\n", siprec_event_start_name.s);
		return -1;
	}
	memset(siprec_state_event_params, 0, sizeof(evi_params_t));
	if ((siprec_state_event_did = evi_param_create(siprec_state_event_params,
				&siprec_state_event_did_s)) == NULL) {
		LM_ERR("could not create %s param for %s event\n",
				siprec_state_event_did_s.s, siprec_event_start_name.s);
		goto error;
	}
	if ((siprec_state_event_callid = evi_param_create(siprec_state_event_params,
				&siprec_state_event_callid_s)) == NULL) {
		LM_ERR("could not create %s param for %s event\n",
				siprec_state_event_callid_s.s, siprec_event_start_name.s);
		goto error;
	}
	if ((siprec_state_event_dlg_callid = evi_param_create(siprec_state_event_params,
				&siprec_state_event_dlg_callid_s)) == NULL) {
		LM_ERR("could not create %s param for %s event\n",
				siprec_state_event_dlg_callid_s.s, siprec_event_start_name.s);
		goto error;
	}
	if ((siprec_state_event_server = evi_param_create(siprec_state_event_params,
				&siprec_state_event_server_s)) == NULL) {
		LM_ERR("could not create %s param for %s event\n",
				siprec_state_event_server_s.s, siprec_event_start_name.s);
		goto error;
	}

	return 0;
error:
	evi_free_params(siprec_state_event_params);
	return -1;
}

static void raise_siprec_state_event(event_id_t event, char *name, struct src_sess *sess)
{
	str sess_uuid;

	if (!evi_probe_event(event)) {
		LM_DBG("no %s event subscriber!\n", name);
		return;
	}

	if (!sess->dlg) {
		LM_DBG("no dialog for %s event - skipping!\n", name);
		return;
	}

	sess_uuid.s = (char *)sess->uuid;
	sess_uuid.len = SIPREC_UUID_LEN;

	if (evi_param_set_str(siprec_state_event_did, srec_dlg.get_dlg_did(sess->dlg)) < 0) {
		LM_ERR("cannot set %s event %s parameter\n",
				name, siprec_state_event_did_s.s);
		return;
	}

	if (evi_param_set_str(siprec_state_event_dlg_callid, &sess->dlg->callid) < 0) {
		LM_ERR("cannot set %s event %s parameter\n",
				name, siprec_state_event_dlg_callid_s.s);
		return;
	}

	if (evi_param_set_str(siprec_state_event_callid, &sess->b2b_key) < 0) {
		LM_ERR("cannot set %s event %s parameter\n",
				name, siprec_state_event_callid_s.s);
		return;
	}

	if (evi_param_set_str(siprec_state_event_session, &sess_uuid) < 0) {
		LM_ERR("cannot set %s event %s parameter\n",
				name, siprec_state_event_session_s.s);
		return;
	}

	if (evi_param_set_str(siprec_state_event_server, &SIPREC_SRS(sess)) < 0) {
		LM_ERR("cannot set %s event %s parameter\n",
				name, siprec_state_event_server_s.s);
		return;
	}
	if (evi_raise_event(event, siprec_state_event_params))
		LM_ERR("unable to send %s event\n", name);
}

void raise_siprec_start_event(struct src_sess *sess)
{
	raise_siprec_state_event(siprec_start_event, siprec_event_start_name.s, sess);
}

void raise_siprec_stop_event(struct src_sess *sess)
{
	raise_siprec_state_event(siprec_stop_event, siprec_event_stop_name.s, sess);
}
