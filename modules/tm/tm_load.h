/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * History:
 * --------
 * 2003-03-06  voicemail changes accepted
 * 2005-05-30  light version of tm_load() - no find_export() (bogdan)
 * 2007-01-25  t_forward_nonack removed as it merged into t_relay,
 *             t_replicate completely removed (bogdan)
 * 2008-04-04  added support for local and remote dispaly name in TM dialogs
 *             (by Andrei Pisau <andrei.pisau at voice-system dot ro> )
 *
 */


#ifndef _TM_BIND_H
#define _TM_BIND_H

#include "../../sr_module.h"
#include "t_hooks.h"
#include "uac.h"
#include "t_fwd.h"
#include "t_reply.h"
#include "t_lookup.h"
#include "t_cancel.h"
#include "dlg.h"
#include "h_table.h"
#include "t_ctx.h"


struct tm_binds {
	register_tmcb_f  register_tmcb;
	cmd_function     t_relay;
	cmd_function     t_check_trans;

	/* Return:
	 *		1 (success)
	 *		0 (retransmission)
	 *	  < 0 (error)
	 *			* E_SCRIPT (the current transaction (@T) is already populated)
	 *			* (others)
	 */
	tnewtran_f       t_newtran;

	treply_f         t_reply;
	treply_wb_f      t_reply_with_body;
	tgen_totag_f     t_gen_totag;
	tislocal_f       t_is_local;
	tget_ti_f        t_get_trans_ident;
	tlookup_ident_f  t_lookup_ident;
	taddblind_f      t_addblind;
	treply_f         t_reply_unsafe;

	/*
	 * Return: 1 (success) or an error.h code otherwise.  On error, make sure
	 * to free your parameter manually, as @release_func will be skipped!
	 */
	reqwith_t        t_request_within;

	reqout_t         t_request_outside;
	req_t            t_request;
	new_dlg_uac_f      new_dlg_uac;
	new_auto_dlg_uac_f new_auto_dlg_uac;
	dlg_add_extra_f    dlg_add_extra;
	dlg_response_uac_f dlg_response_uac;
	free_dlg_f         free_dlg;
	print_dlg_f        print_dlg;
	tgett_f            t_gett;
	tgett_f            t_get_e2eackt;
	tget_picked_f      t_get_picked;
	tset_remotet_f     t_set_remote_t;
	tunrefcell_f       unref_cell;
	tunrefcell_f       ref_cell;
	tlookuporiginalt_f t_lookup_original_t;
	tcanceltrans_f     t_cancel_trans;
	setkr_f            t_setkr;
	set_localT_holder_f setlocalTholder;
	tgetbranch_f       get_branch_index;

	/* Return: 1 on success, -1 otherwise */
	int (*t_wait_for_new_branches) (struct sip_msg *msg);

	/**
	 * Injects and relays a new branch for the current transaction using the
	 * attributes of the current usrloc contact EVI event, packed as AVPs.
	 *
	 * IMPORTANT: make sure to only call this after a successful EBR
	 * subscription match (e.g. within some EBR route or function callback),
	 * since that is the only flow which ensures that the necessary globals
	 * required by this function are populated.
	 *
	 * Return: 1 on success, negative on error
	 */
	int (*t_inject_ul_event_branch) (void);

	t_ctx_register_int_f t_ctx_register_int;
	t_ctx_register_str_f t_ctx_register_str;
	t_ctx_register_ptr_f t_ctx_register_ptr;

	t_ctx_put_int_f t_ctx_put_int;
	t_ctx_put_str_f t_ctx_put_str;
	t_ctx_put_ptr_f t_ctx_put_ptr;

	t_ctx_get_int_f t_ctx_get_int;
	t_ctx_get_str_f t_ctx_get_str;
	t_ctx_get_ptr_f t_ctx_get_ptr;
};


typedef int(*load_tm_f)( struct tm_binds *tmb );
int load_tm( struct tm_binds *tmb);


static inline int load_tm_api( struct tm_binds *tmb )
{
	load_tm_f load_tm;

	/* import the TM auto-loading function */
	if ( !(load_tm=(load_tm_f)find_export("load_tm", 0))) {
		return -1;
	}
	/* let the auto-loading function load all TM stuff */
	if (load_tm( tmb )==-1)
		return -1;

	return 0;
}


#endif
