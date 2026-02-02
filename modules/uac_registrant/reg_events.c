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

static str reg_register_timeout_ev_name = str_init("E_REGISTRANT_REGISTER_TIMEOUT");
static event_id_t reg_register_timeout_ev_id = EVI_ERROR;
static evi_params_p reg_register_timeout_event_params;
static evi_param_p reg_register_timeout_aor_p, reg_register_timeout_contact_p, reg_register_timeout_registrar_p;

static str reg_internal_error_ev_name = str_init("E_REGISTRANT_INTERNAL_ERROR");
static event_id_t reg_internal_error_ev_id = EVI_ERROR;
static evi_params_p reg_internal_error_event_params;
static evi_param_p reg_internal_error_aor_p, reg_internal_error_contact_p, reg_internal_error_registrar_p;

static str reg_wrong_credentials_ev_name = str_init("E_REGISTRANT_WRONG_CREDENTIALS");
static event_id_t reg_wrong_credentials_ev_id = EVI_ERROR;
static evi_params_p reg_wrong_credentials_event_params;
static evi_param_p reg_wrong_credentials_aor_p, reg_wrong_credentials_contact_p, reg_wrong_credentials_registrar_p;

static str reg_registrar_error_ev_name = str_init("E_REGISTRANT_REGISTRAR_ERROR");
static event_id_t reg_registrar_error_ev_id = EVI_ERROR;
static evi_params_p reg_registrar_error_event_params;
static evi_param_p reg_registrar_error_aor_p, reg_registrar_error_contact_p, reg_registrar_error_registrar_p;

static str reg_unregistering_ev_name = str_init("E_REGISTRANT_UNREGISTERING");
static event_id_t reg_unregistering_ev_id = EVI_ERROR;
static evi_params_p reg_unregistering_event_params;
static evi_param_p reg_unregistering_aor_p, reg_unregistering_contact_p, reg_unregistering_registrar_p;

static str reg_authenticating_unregister_ev_name = str_init("E_REGISTRANT_AUTHENTICATING_UNREGISTER");
static event_id_t reg_authenticating_unregister_ev_id = EVI_ERROR;
static evi_params_p reg_authenticating_unregister_event_params;
static evi_param_p reg_authenticating_unregister_aor_p, reg_authenticating_unregister_contact_p, reg_authenticating_unregister_registrar_p;

#define EVI_PUBLISH_OR_FAIL(_ev_id, _ev_name)                                    \
	do {                                                                     \
		(_ev_id) = evi_publish_event((_ev_name));                        \
		if ((_ev_id) == EVI_ERROR) {                                     \
			LM_ERR("cannot register %.*s event\n",                   \
			(_ev_name).len, (_ev_name).s);                           \
			return -1;                                               \
		}                                                                \
	} while (0)

#define EVI_PARAMS_ALLOC_OR_FAIL(_params_ptr)                                    \
	do {                                                                     \
		(_params_ptr) = pkg_malloc(sizeof(evi_params_t));                \
		if ((_params_ptr) == NULL) {                                     \
			LM_ERR("no more pkg mem\n");                             \
			return -1;                                               \
		}                                                                \
		memset((_params_ptr), 0, sizeof(evi_params_t));                  \
	} while (0)

#define EVI_PARAM_CREATE_OR_FAIL(_out_param, _params, _spec)                     \
	do {                                                                     \
		(_out_param) = evi_param_create((_params), (_spec));             \
		if ((_out_param) == NULL) {                                      \
			LM_ERR("Failed to create param \n");                     \
			return -1;                                               \
		}                                                                \
	} while (0)

#define INIT_REG_EVENT(_prefix)                                                  \
	do {                                                                     \
		EVI_PUBLISH_OR_FAIL(_prefix##_ev_id, _prefix##_ev_name);         \
		EVI_PARAMS_ALLOC_OR_FAIL(_prefix##_event_params);                \
		EVI_PARAM_CREATE_OR_FAIL(_prefix##_aor_p,                        \
		_prefix##_event_params, &reg_event_aor);                         \
		EVI_PARAM_CREATE_OR_FAIL(_prefix##_contact_p,                    \
		_prefix##_event_params, &reg_event_contact);                     \
		EVI_PARAM_CREATE_OR_FAIL(_prefix##_registrar_p,                  \
		_prefix##_event_params, &reg_event_registrar);                   \
	} while (0)

int init_registrant_events(void)
{
	INIT_REG_EVENT(reg_registering);
	INIT_REG_EVENT(reg_authenticating);
	INIT_REG_EVENT(reg_registered);
	INIT_REG_EVENT(reg_register_timeout);
	INIT_REG_EVENT(reg_internal_error);
	INIT_REG_EVENT(reg_wrong_credentials);
	INIT_REG_EVENT(reg_registrar_error);
	INIT_REG_EVENT(reg_unregistering);
	INIT_REG_EVENT(reg_authenticating_unregister);

	return 0;
}

#define REG_EVI_SET_STR_OR_RETURN(_param, _str, _errmsg)                 \
	do {                                                             \
		if (evi_param_set_str((_param), (_str)) < 0) {           \
			LM_ERR(_errmsg);                                 \
			return;                                          \
		}                                                        \
	} while (0)

#define RAISE_REG_EVENT(_prefix, _rec)                                            \
	do {                                                                      \
		if (!evi_probe_event(_prefix##_ev_id))                            \
			return;                                                   \
		REG_EVI_SET_STR_OR_RETURN(_prefix##_aor_p,                        \
		&(_rec)->td.rem_uri,                                              \
		"cannot set AOR parameter\n");                                    \
		REG_EVI_SET_STR_OR_RETURN(_prefix##_contact_p,                    \
		&(_rec)->contact_uri,                                             \
		"cannot set Contact parameter\n");                                \
		REG_EVI_SET_STR_OR_RETURN(_prefix##_registrar_p,                  \
		&(_rec)->td.rem_target,                                           \
		"cannot set Registrar parameter\n");                              \
		if (evi_raise_event(_prefix##_ev_id, _prefix##_event_params) < 0) \
			LM_ERR("cannot raise %.*s event\n",                       \
			_prefix##_ev_name.len,                                    \
			_prefix##_ev_name.s);                                     \
	} while (0)

void raise_registering_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_registering, rec);
}

void raise_authenticating_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_authenticating, rec);
}

void raise_registered_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_registered, rec);
}

void raise_register_timeout_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_register_timeout, rec);
}

void raise_internal_error_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_internal_error, rec);
}

void raise_wrong_credentials_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_wrong_credentials, rec);
}

void raise_registrar_error_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_registrar_error, rec);
}

void raise_unregistering_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_unregistering, rec);
}

void raise_authenticating_unregister_event(reg_record_t *rec)
{
	RAISE_REG_EVENT(reg_authenticating_unregister, rec);
}
