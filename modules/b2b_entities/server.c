/*
 * $Id: server.c $
 *
 * back-to-back entities modules
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../parser/parse_rr.h"
#include "../../parser/parse_content.h"
#include "../../ut.h"
#include "../../mem/shm_mem.h"
#include "../presence/hash.h"
#include "../tm/dlg.h"
#include "server.h"
#include "dlg.h"
#include "b2b_entities.h"

/** 
 * Function to create a new server entity 
 *	msg: SIP message
 *	b2b_cback: callback function to notify the logic about a change in dialog 
 *	param: the parameter that will be used when calling b2b_cback function
 *
 *	Return value: the dialog key allocated in private memory
 *	*/

str* server_new(struct sip_msg* msg, b2b_notify_t b2b_cback,
		void* param)
{
	b2b_dlg_t* dlg;
	unsigned int hash_index;
	static	str reason = {"Trying", 6};

	/* create new entry in hash table */
	dlg = b2b_new_dlg(msg, 0);
	if( dlg == NULL )
	{
		LM_ERR("failed to create new dialog structure entry\n");
		return NULL;
	}

	dlg->state = B2B_NEW;
	dlg->b2b_cback = b2b_cback;
	dlg->param = param;

	/* get the pointer to the tm transaction to store it the tuple record */
	dlg->tm_tran = tmb.t_gett();
	if(dlg->tm_tran == NULL)
	{
		tmb.t_newtran(msg);
		dlg->tm_tran = tmb.t_gett();
	}
	tmb.ref_cell(dlg->tm_tran);
	
	tmb.t_reply(msg, 100, &reason);

	/* add the record in hash table */
	hash_index = core_hash(&dlg->callid, &dlg->tag[CALLER_LEG], server_hsize);

	return b2b_htable_insert(server_htable, dlg, hash_index, B2B_SERVER);
}


dlg_t* b2b_server_build_dlg(b2b_dlg_t* dlg)
{
	dlg_t* td =NULL;

	td = (dlg_t*)pkg_malloc(sizeof(dlg_t));
	if(td == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(td, 0, sizeof(dlg_t));

	td->loc_seq.value = dlg->cseq[CALLEE_LEG];
	td->loc_seq.is_set = 1;
	dlg->cseq[CALLEE_LEG]++;

	td->id.call_id = dlg->callid;
	td->id.rem_tag = dlg->tag[CALLER_LEG];
	td->id.loc_tag = dlg->tag[CALLEE_LEG];

	td->rem_target = dlg->contact[CALLER_LEG];

	td->loc_uri = dlg->to_uri;
	td->rem_uri = dlg->from_uri;

	if(dlg->route_set[CALLER_LEG].s && dlg->route_set[CALLER_LEG].len)
	{
		if(parse_rr_body(dlg->route_set[CALLER_LEG].s, dlg->route_set[CALLER_LEG].len,
			&td->route_set)< 0)
		{
			LM_ERR("failed to parse record route body\n");
			goto error;
		}
	}	
	td->state= DLG_CONFIRMED ;
	td->send_sock = dlg->bind_addr[CALLER_LEG];

	return td;
error:
	if(td)
		pkg_free(td);

	return 0;
}

void b2b_server_tm_cback( struct cell *t, int type, struct tmcb_params *ps)
{
	return b2b_tm_cback(server_htable, ps);
}

