/*
 * $Id$
 *
 * dialog module - basic support for dialog tracking
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-01-12 initial version (bogdan)
 */


#ifndef _DIALOG_DLG_VALS_H
#define _DIALOG_DLG_VALS_H

#include "../../pvar.h"
#include "dlg_hash.h"

struct dlg_val {
	unsigned int id;
	str name;
	str val;
	struct dlg_val *next;
};


int pv_parse_name(pv_spec_p sp, str *in);

int pv_get_dlg_val(struct sip_msg *msg,  pv_param_t *param,
		pv_value_t *res);

int pv_set_dlg_val(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val);


typedef int (*store_dlg_value_f)(struct dlg_cell *dlg,
		str *name, str *val);

typedef int (*fetch_dlg_value_f)(struct dlg_cell *dlg,
		str *name, str *val, int val_has_buf);


int store_dlg_value(struct dlg_cell *dlg, str *name, str *val);

int fetch_dlg_value(struct dlg_cell *dlg, str *name, str *val,int val_has_buf);

int check_dlg_value_unsafe(struct dlg_cell *dlg, str *name, str *val);


#endif
