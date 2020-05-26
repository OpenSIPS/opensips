/*
 * Copyright (C) 2009-2020 OpenSIPS Solutions
 * Copyright (C) 2006 Voice Sistem SRL
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

#ifndef _DIALOG_DLG_LOAD_H_
#define _DIALOG_DLG_LOAD_H_

#include "dlg_cb.h"
#include "dlg_ctx.h"
#include "dlg_handlers.h"
#include "dlg_profile.h"
#include "dlg_vals.h"
#include "../../sr_module.h"

typedef struct dlg_cell *(*get_dlg_f) (void);
typedef str *(*get_dlg_did_f) (struct dlg_cell *dlg);
typedef struct dlg_cell *(*get_dlg_by_callid_f) (str *, int);
typedef struct dlg_cell *(*get_dlg_by_did_f) (str *, int);
typedef int (*match_dialog_f) (struct sip_msg *msg, int _seq_match_mode);
typedef int (*get_direction_f) (void);

struct dlg_binds {
	register_dlgcb_f     register_dlgcb;
	create_dlg_f         create_dlg;
	get_dlg_f            get_dlg;
	add_profiles_f       add_profiles;
	search_dlg_profile_f search_profile;
	set_dlg_profile_f    set_profile;
	unset_dlg_profile_f  unset_profile;
	get_profile_size_f   get_profile_size;
	store_dlg_value_f    store_dlg_value;
	fetch_dlg_value_f    fetch_dlg_value;
	terminate_dlg_f      terminate_dlg;

	match_dialog_f       match_dialog;
	validate_dialog_f    validate_dialog;
	fix_route_dialog_f   fix_route_dialog;

	set_mod_flag_f       set_mod_flag;
	is_mod_flag_set_f    is_mod_flag_set;

	ref_dlg_f            dlg_ref;
	unref_dlg_f          dlg_unref;

	get_direction_f      get_direction;
	get_dlg_did_f        get_dlg_did;
	get_dlg_by_did_f     get_dlg_by_did;
	get_dlg_by_callid_f  get_dlg_by_callid;
	send_indialog_req_f  send_indialog_request;

	get_rr_param_f       get_rr_param;

	dlg_ctx_register_int_f dlg_ctx_register_int;
	dlg_ctx_register_str_f dlg_ctx_register_str;
	dlg_ctx_register_ptr_f dlg_ctx_register_ptr;

	dlg_ctx_put_int_f dlg_ctx_put_int;
	dlg_ctx_put_str_f dlg_ctx_put_str;
	dlg_ctx_put_ptr_f dlg_ctx_put_ptr;

	dlg_ctx_get_int_f dlg_ctx_get_int;
	dlg_ctx_get_str_f dlg_ctx_get_str;
	dlg_ctx_get_ptr_f dlg_ctx_get_ptr;
};


typedef int(*load_dlg_f)( struct dlg_binds *dlgb );
int load_dlg( struct dlg_binds *dlgb);


static inline int load_dlg_api( struct dlg_binds *dlgb )
{
	load_dlg_f load_dlg;

	/* import the DLG auto-loading function */
	if ( !(load_dlg=(load_dlg_f)find_export("load_dlg", 0)))
		return -1;

	/* let the auto-loading function load all DLG stuff */
	if (load_dlg( dlgb )==-1)
		return -1;

	return 0;
}


#endif
