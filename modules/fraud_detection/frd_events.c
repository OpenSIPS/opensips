/**
 * Fraud Detection Module
 *
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * History
 * -------
 *  2014-09-26  initial version (Andrei Datcu)
*/

#include "../../evi/evi_params.h"
#include "../../evi/evi_modules.h"

#include "../dialog/dlg_load.h"
#include "frd_events.h"
#include "../../mem/shm_mem.h"


/* Events name and ids */

static event_id_t ei_warn_id = EVI_ERROR;
static event_id_t ei_crit_id = EVI_ERROR;

static str ei_warn_name = str_init("E_FRD_WARNING");
static str ei_crit_name = str_init("E_FRD_CRITICAL");
static evi_params_p event_params;

/* Events' parameters name and pointers*/

static str ei_param_name = str_init("param");
static str ei_val_name = str_init("value");
static str ei_thr_name = str_init("threshold");
static str ei_user_name = str_init("user");
static str ei_number_name = str_init("called_number");
static str ei_ruleid_name = str_init("rule_id");

static evi_param_p param_p, val_p, thr_p, user_p, number_p, ruleid_p;


/*
 * Function to init the warning and critical events
*/

int frd_event_init(void)
{
	/* First publish the events */
	ei_warn_id = evi_publish_event(ei_warn_name);
	if (ei_warn_id == EVI_ERROR) {
		LM_ERR("cannot register warning event\n");
		return -1;
	}
	ei_crit_id = evi_publish_event(ei_crit_name);
	if (ei_crit_id == EVI_ERROR) {
		LM_ERR("cannot register critical event\n");
		return -1;
	}

	event_params = pkg_malloc(sizeof(evi_params_t));
	if (event_params == NULL)
		return -1;
	memset(event_params, 0, sizeof(evi_params_t));

#define CREATE_PARAM(pname) \
	pname ## _p = evi_param_create(event_params, &ei_ ## pname ## _name);\
	if (! pname ## _p) \
		goto create_param_err

	CREATE_PARAM(param);
	CREATE_PARAM(val);
	CREATE_PARAM(thr);
	CREATE_PARAM(user);
	CREATE_PARAM(number);
	CREATE_PARAM(ruleid);
#undef CREATE_PARAM

	return 0;

create_param_err:
	LM_ERR("cannot create event parameter");
	return -1;
}

void frd_event_destroy(void)
{
	evi_free_params(event_params);
}

/*
 * Function to be called internally for raising an event
*/
static void raise_event(event_id_t e,
		str *param, unsigned int *val, unsigned int *thr, str *user,
		str *number, unsigned int *ruleid)
{
#define SET_PARAM(pname, ptype) \
	if (evi_param_set_ ##ptype (pname ## _p, pname) < 0) { \
		LM_ERR("cannot set " # pname "parameter\n"); \
		return; \
	}

	SET_PARAM(param, str);
	SET_PARAM(val, int);
	SET_PARAM(thr, int);
	SET_PARAM(user, str);
	SET_PARAM(number, str);
	SET_PARAM(ruleid, int);
#undef SET_PARAM

	if (evi_raise_event(e, event_params) < 0)
		LM_ERR("cannot raise event\n");
}

void raise_warning_event(str *param, unsigned int *val, unsigned int *thr,
		str *user, str *number, unsigned int *ruleid)
{
	raise_event(ei_warn_id, param, val, thr, user, number, ruleid);
}

void raise_critical_event(str *param, unsigned int *val, unsigned int *thr,
		str *user, str *number, unsigned int *ruleid)
{
	raise_event(ei_crit_id, param, val, thr, user, number, ruleid);
}


/*
 * Callback called whenever a dialog is ended.
 * Check the duration against the thresholds (sent through the params)
 * and raise appropriate event
*/

 void dialog_terminate_CB(struct dlg_cell *dlgc, int type,
		struct dlg_cb_params *params)
{
	static str call_dur_name = str_init ("call_duration");
	frd_dlg_param *frdparam = (frd_dlg_param*) *(params->param);
	extern unsigned int frd_data_rev;

	if (type == DLGCB_TERMINATED && frd_data_rev == frdparam->data_rev) {
		unsigned int duration = time(NULL) - dlgc->start_ts;
		if ( duration >= frdparam->thr->call_duration_thr.critical)
			raise_critical_event(&call_dur_name, &duration,
					&frdparam->thr->call_duration_thr.critical,
					&frdparam->user, &frdparam->number, &frdparam->ruleid);

		else if ( duration >= frdparam->thr->call_duration_thr.warning)
			raise_warning_event(&call_dur_name, &duration,
					&frdparam->thr->call_duration_thr.warning,
					&frdparam->user, &frdparam->number, &frdparam->ruleid);
	}

	lock_get(&frdparam->stats->lock);
	--frdparam->stats->stats.concurrent_calls;
	lock_release(&frdparam->stats->lock);

	shm_free(frdparam->number.s);
	shm_free(frdparam);
}
