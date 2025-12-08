/*
 * Copyright (C) 2019 OpenSIPS Project
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../evi/evi_params.h"
#include "../../evi/evi_modules.h"

#include "reg_events.h"

static str reg_event_aor = str_init("aor");
static str reg_event_contact = str_init("contact");
static str reg_event_registrar = str_init("registrar");

static str reg_registering_ev_name = str_init("E_REGISTRANT_REGISTERING");
static event_id_t reg_registering_ev_id = EVI_ERROR;
static evi_params_p reg_registering_event_params;
static evi_param_p reg_registering_aor_p, reg_registering_contact_p, reg_registering_registrar_p;

static str reg_authenticating_ev_name = str_init("E_REGISTRANT_AUTHENTICATING");
static event_id_t reg_authenticating_ev_id = EVI_ERROR;
static evi_params_p reg_authenticating_event_params;
static evi_param_p reg_authenticating_aor_p, reg_authenticating_contact_p, reg_authenticating_registrar_p;

static str reg_registered_ev_name = str_init("E_REGISTRANT_REGISTERED");
static event_id_t reg_registered_ev_id = EVI_ERROR;
static evi_params_p reg_registered_event_params;
static evi_param_p reg_registered_aor_p, reg_registered_contact_p, reg_registered_registrar_p;


int init_registrant_events(void)
{
	/* publish the E_REGISTRANT_REGISTERING event */
	reg_registering_ev_id = evi_publish_event(reg_registering_ev_name);
	if (reg_registering_ev_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n",
		reg_registering_ev_name.len,reg_registering_ev_name.s);
		return -1;
	}

	reg_registering_event_params = pkg_malloc(sizeof(evi_params_t));
	if (reg_registering_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(reg_registering_event_params, 0, sizeof(evi_params_t));

	reg_registering_aor_p = evi_param_create(reg_registering_event_params, &reg_event_aor);
	if (reg_registering_aor_p == NULL)
		goto create_error;

	reg_registering_contact_p = evi_param_create(reg_registering_event_params, &reg_event_contact);
	if (reg_registering_contact_p == NULL)
		goto create_error;

	reg_registering_registrar_p = evi_param_create(reg_registering_event_params, &reg_event_registrar);
	if (reg_registering_registrar_p == NULL)
		goto create_error;

	/* publish the E_REGISTRANT_AUTHENTICATING event */
	reg_authenticating_ev_id = evi_publish_event(reg_authenticating_ev_name);
	if (reg_authenticating_ev_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n",
		reg_authenticating_ev_name.len,reg_authenticating_ev_name.s);
		return -1;
	}

	reg_authenticating_event_params = pkg_malloc(sizeof(evi_params_t));
	if (reg_authenticating_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(reg_authenticating_event_params, 0, sizeof(evi_params_t));

	reg_authenticating_aor_p = evi_param_create(reg_authenticating_event_params, &reg_event_aor);
	if (reg_authenticating_aor_p == NULL)
		goto create_error;

	reg_authenticating_contact_p = evi_param_create(reg_authenticating_event_params, &reg_event_contact);
	if (reg_authenticating_contact_p == NULL)
		goto create_error;

	reg_authenticating_registrar_p = evi_param_create(reg_authenticating_event_params, &reg_event_registrar);
	if (reg_authenticating_registrar_p == NULL)
		goto create_error;

	/* publish the E_REGISTRANT_REGISTERED event */
	reg_registered_ev_id = evi_publish_event(reg_registered_ev_name);
	if (reg_registered_ev_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n",
		reg_registered_ev_name.len,reg_registered_ev_name.s);
		return -1;
	}

	reg_registered_event_params = pkg_malloc(sizeof(evi_params_t));
	if (reg_registered_event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(reg_registered_event_params, 0, sizeof(evi_params_t));

	reg_registered_aor_p = evi_param_create(reg_registered_event_params, &reg_event_aor);
	if (reg_registered_aor_p == NULL)
		goto create_error;

	reg_registered_contact_p = evi_param_create(reg_registered_event_params, &reg_event_contact);
	if (reg_registered_contact_p == NULL)
		goto create_error;

	reg_registered_registrar_p = evi_param_create(reg_registered_event_params, &reg_event_registrar);
	if (reg_registered_registrar_p == NULL)
		goto create_error;

	return 0;

create_error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

void raise_registering_event(reg_record_t *rec)
{
	if (!evi_probe_event(reg_registering_ev_id))
		return;

	if (evi_param_set_str(reg_registering_aor_p, &rec->td.rem_uri) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_param_set_str(reg_registering_aor_p, &rec->td.rem_uri) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_param_set_str(reg_registering_contact_p, &rec->contact_uri) < 0) {
		LM_ERR("cannot set Contact parameter\n");
		return;
	}

	if (evi_param_set_str(reg_registering_registrar_p, &rec->td.rem_target) < 0) {
		LM_ERR("cannot set Registrar parameter\n");
		return;
	}

	if (evi_raise_event(reg_registering_ev_id, reg_registering_event_params) < 0)
		LM_ERR("cannot raise %.*s event\n",
		reg_registering_ev_name.len,
		reg_registering_ev_name.s);
}

void raise_authenticating_event(reg_record_t *rec)
{
	if (!evi_probe_event(reg_authenticating_ev_id))
		return;

	if (evi_param_set_str(reg_authenticating_aor_p, &rec->td.rem_uri) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_param_set_str(reg_authenticating_aor_p, &rec->td.rem_uri) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_param_set_str(reg_authenticating_contact_p, &rec->contact_uri) < 0) {
		LM_ERR("cannot set Contact parameter\n");
		return;
	}

	if (evi_param_set_str(reg_authenticating_registrar_p, &rec->td.rem_target) < 0) {
		LM_ERR("cannot set Registrar parameter\n");
		return;
	}

	if (evi_raise_event(reg_authenticating_ev_id, reg_authenticating_event_params) < 0)
		LM_ERR("cannot raise %.*s event\n",
		reg_authenticating_ev_name.len,
		reg_authenticating_ev_name.s);
}

void raise_registered_event(reg_record_t *rec)
{
	if (!evi_probe_event(reg_registered_ev_id))
		return;

	if (evi_param_set_str(reg_registered_aor_p, &rec->td.rem_uri) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_param_set_str(reg_registered_aor_p, &rec->td.rem_uri) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}

	if (evi_param_set_str(reg_registered_contact_p, &rec->contact_uri) < 0) {
		LM_ERR("cannot set Contact parameter\n");
		return;
	}

	if (evi_param_set_str(reg_registered_registrar_p, &rec->td.rem_target) < 0) {
		LM_ERR("cannot set Registrar parameter\n");
		return;
	}

	if (evi_raise_event(reg_registered_ev_id, reg_registered_event_params) < 0)
		LM_ERR("cannot raise %.*s event\n",
		reg_registered_ev_name.len,
		reg_registered_ev_name.s);
}
