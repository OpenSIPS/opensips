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

#ifndef __FRD_EVENTS_H__
#define __FRD_EVENTS_H__

#include "frd_stats.h"

int frd_event_init(void);
void frd_event_destroy(void);
void raise_warning_event(str *param, unsigned int *val, unsigned int *thr,
		str *user, str *number, unsigned int *ruleid);
void raise_critical_event(str *param, unsigned int *val, unsigned int *thr,
		str *user, str *number, unsigned int *ruleid);


/* Dialog callback */

typedef struct {
	frd_stats_entry_t *stats;
	str user;
	str number;
	unsigned int ruleid;
	unsigned int interval_id;

	unsigned int calldur_warn;
	unsigned int calldur_crit;
} frd_dlg_param;

 void dialog_terminate_CB(struct dlg_cell *dlgc, int type,
		struct dlg_cb_params *params);
 void free_dialog_CB_param(void *param);

#endif
