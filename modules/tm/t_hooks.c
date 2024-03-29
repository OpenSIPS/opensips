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
 * History:
 * --------
 *  2003-03-19  replaced all the mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-12-04  global callbacks moved into transaction callbacks;
 *              multiple events per callback added; single list per
 *              transaction for all its callbacks (bogdan)
 *  2004-08-23  user avp(attribute value pair) added -> making avp list
 *              available in callbacks (bogdan)
 */

#include "stdlib.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../usr_avp.h"
#include "t_hooks.h"
#include "t_lookup.h"
#include "t_funcs.h"

struct tmcb_head_list* new_tran_tmcb_hl = 0;

struct tmcb_head_list tmcb_pending_hl = {0,0};
unsigned int tmcb_pending_id = (unsigned int)-1;


void empty_tmcb_list(struct tmcb_head_list *head)
{
	struct tm_callback *cbp, *cbp_tmp;

	for( cbp=head->first; cbp ; ) {
		cbp_tmp = cbp;
		cbp = cbp->next;
		if (cbp_tmp->release)
			cbp_tmp->release(cbp_tmp->param);
		shm_free( cbp_tmp );
	}
	head->first = 0 ;
	head->reg_types = 0;
}

static struct tmcb_head_list *new_tmcb_list(void)
{
	struct tmcb_head_list *list = (struct tmcb_head_list*)shm_malloc
		(sizeof(struct tmcb_head_list));
	if (list==0) {
		LM_CRIT("no more shared memory\n");
		return NULL;
	}
	list->first = 0;
	list->reg_types = 0;
	return list;
}

int init_tmcb_lists(void)
{

	new_tran_tmcb_hl = new_tmcb_list();
	if (!new_tran_tmcb_hl)
		return -1;
	return 1;
}


void destroy_tmcb_lists(void)
{
	if (!new_tran_tmcb_hl) {
		empty_tmcb_list(new_tran_tmcb_hl);
		shm_free(new_tran_tmcb_hl);
	}
}


int insert_tmcb(struct tmcb_head_list *cb_list, int types,
				transaction_cb f, void *param, release_tmcb_param release_func )
{
	struct tm_callback *cbp;

	/* build a new callback structure */
	if (!(cbp=shm_malloc( sizeof( struct tm_callback)))) {
		LM_ERR("no more shared memory\n");
		return E_OUT_OF_MEM;
	}

	/* link it into the proper place... */
	cbp->next = cb_list->first;
	cb_list->first = cbp;
	cb_list->reg_types |= types;
	/* ... and fill it up */
	cbp->callback = f;
	cbp->param = param;
	cbp->release = release_func;
	cbp->types = types;
	if (cbp->next)
		cbp->id = cbp->next->id+1;
	else
		cbp->id = 0;

	return 1;
}



/* register a callback function 'f' for 'types' mask of events;
 * will be called back whenever one of the events occurs in transaction module
 * (global or per transaction, depending of event type)
*/
int register_tmcb( struct sip_msg* p_msg, struct cell *t, int types,
				  transaction_cb f, void *param, release_tmcb_param release_func )
{
	struct tmcb_head_list *cb_list;

	/* are the callback types valid?... */
	if ( types<0 || types>TMCB_MAX ) {
		LM_CRIT("invalid callback types: mask=%d\n",
			types);
		return E_BUG;
	}
	/* we don't register null functions */
	if (f==0) {
		LM_CRIT("null callback function\n");
		return E_BUG;
	}

	if (types&(TMCB_REQUEST_IN|TMCB_LOCAL_TRANS_NEW)) {
		if (types&(~(TMCB_REQUEST_IN|TMCB_LOCAL_TRANS_NEW))) {
			LM_CRIT("callback type TMCB_REQUEST_IN and/or TMCB_LOCAL_TRANS_NEW "
				"can't be register along with other types\n");
			return E_BUG;
		}
		if (new_tran_tmcb_hl==0) {
			LM_ERR("callback type TMCB_REQUEST_IN and/or TMCB_LOCAL_TRANS_NEW "
				"registration attempt before TM module initialization\n");
			return E_CFG;
		}
		cb_list = new_tran_tmcb_hl;
	} else {
		if (!t) {
			if (!p_msg) {
				LM_CRIT("no sip_msg, nor transaction given\n");
				return E_BUG;
			}
			/* look for the transaction */
			t = get_t();
			if ( t!=NULL && t!=T_UNDEFINED ){
				cb_list = &(t->tmcb_hl);
			} else {
				/* no transaction found -> link it to waitting list */
				if (p_msg->id!=tmcb_pending_id) {
					empty_tmcb_list(&tmcb_pending_hl);
					tmcb_pending_id = p_msg->id;
				}
				cb_list = &(tmcb_pending_hl);
			}
		} else {
			cb_list = &(t->tmcb_hl);
		}
	}

	return insert_tmcb( cb_list, types, f, param, release_func );
}


static void *tmcb_extra1 = NULL;
static void *tmcb_extra2 = NULL;

void set_extra_tmcb_params(void *extra1, void *extra2)
{
	tmcb_extra1 = extra1;
	tmcb_extra2 = extra2;
}

static void run_any_trans_callbacks(struct tmcb_head_list *list, unsigned int type,
		struct cell *trans, struct sip_msg *req, struct sip_msg *rpl, int code)
{
	struct tmcb_params params;
	struct tm_callback    *cbp;
	struct usr_avp **backup;
	struct cell *trans_backup = get_t();

	params.req = req;
	params.rpl = rpl;
	params.code = code;
	params.extra1 = tmcb_extra1;
	params.extra2 = tmcb_extra2;

	if (list->first==0 || ((list->reg_types)&type)==0)
		return;

	backup = set_avp_list( &trans->user_avps );
	for (cbp=list->first; cbp; cbp=cbp->next)  {
		if ((cbp->types)&type) {
			LM_DBG("trans=%p, callback type %d, id %d entered\n",
				trans, type, cbp->id );
			params.param = &(cbp->param);
			cbp->callback( trans, type, &params );
			if ((cbp->types)&(TMCB_REQUEST_IN|TMCB_LOCAL_TRANS_NEW)) {
				if (req && req->dst_uri.len==-1) {
					LM_CRIT("callback %s id %d entered\n",
							(type&TMCB_REQUEST_IN?"REQIN":"LOCAL_NEW"),cbp->id );
					req->dst_uri.len = 0;
				}
			}
		}
	}
	/* env cleanup */
	set_avp_list( backup );
	tmcb_extra1 = tmcb_extra2 = 0;
	set_t(trans_backup);
}

void run_trans_callbacks( int type , struct cell *trans,
						struct sip_msg *req, struct sip_msg *rpl, int code )
{
	run_any_trans_callbacks(&trans->tmcb_hl, type, trans, req, rpl, code);
}

void run_new_local_callbacks(struct cell *trans, struct sip_msg *req, int code)
{
	run_any_trans_callbacks(new_tran_tmcb_hl, TMCB_LOCAL_TRANS_NEW, trans, req, NULL, code);
}

void run_reqin_callbacks(struct cell *trans, struct sip_msg *req, int code)
{
	run_any_trans_callbacks(new_tran_tmcb_hl, TMCB_REQUEST_IN, trans, req, NULL, code);
}

void run_trans_callbacks_locked( int type , struct cell *trans,
						struct sip_msg *req, struct sip_msg *rpl, int code )
{
	if (trans->tmcb_hl.first==0 || ((trans->tmcb_hl.reg_types)&type)==0 )
		return;

	LOCK_REPLIES(trans);

	/* run callbacks */
	run_trans_callbacks( type , trans, req, rpl, code );
	/* SHM message cleanup */
	if (trans->uas.request && trans->uas.request->msg_flags&FL_SHM_CLONE)
		clean_msg_clone( trans->uas.request, trans->uas.request,
			trans->uas.end_request);

	UNLOCK_REPLIES(trans);
}


