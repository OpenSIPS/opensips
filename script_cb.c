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
 *  2003-03-29  cleaning pkg allocation introduced (jiri)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2005-02-13  script callbacks devided into request and reply types (bogdan)
 *  2009-05-21  keep the callback lists in the same order as callbacks
                 were registered (bogdan)
 */

/*!
 * \file
 * \brief Script callbacks
 */


#include <stdlib.h>
#include "script_cb.h"
#include "dprint.h"
#include "error.h"
#include "mem/mem.h"

static struct script_cb *pre_req_cb=0;
static struct script_cb *post_req_cb=0;

static struct script_cb *pre_rpl_cb=0;
static struct script_cb *post_rpl_cb=0;

static struct script_cb *parse_err_cb=0;

static unsigned int cb_id=0;

struct raw_processing_cb_list* pre_processing_cb_list = NULL;
struct raw_processing_cb_list* post_processing_cb_list = NULL;

static inline int add_callback( struct script_cb **list,
	cb_function f, void *param, int prio)
{
	struct script_cb *last_cb;
	struct script_cb *new_cb;

	new_cb=pkg_malloc(sizeof(struct script_cb));
	if (new_cb==0) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	new_cb->cbf = f;
	new_cb->id = cb_id++;
	new_cb->param = param;
	new_cb->next = NULL;
	new_cb->prio = prio;

	/* descending priority sorting; equal priorities are inserted at the end
	  it is important to keep the order at register time, as this reflects the
	  order of loading/init the modules --bogdan */
	if (*list==NULL) {
		*list = new_cb;
	} else if ((*list)->prio < prio) {
		new_cb->next = *list;
		*list = new_cb;
	} else {
		for (last_cb = *list;
		     last_cb->next && last_cb->next->prio >= prio;
		     last_cb = last_cb->next)
			;

		new_cb->next = last_cb->next;
		last_cb->next = new_cb;
	}

	return 0;
}


int __register_script_cb( cb_function f, int type, void *param, int prio)
{
	/* type checkings */
	if ( (type&(REQ_TYPE_CB|RPL_TYPE_CB|PARSE_ERR_CB))==0 ) {
		LM_CRIT("request / reply / error type not specified\n");
		goto error;
	}
	if ( (type&(PRE_SCRIPT_CB|POST_SCRIPT_CB|PARSE_ERR_CB))==0 ||
	(type&PRE_SCRIPT_CB && type&POST_SCRIPT_CB) ) {
		LM_CRIT("callback POST or PRE type must be exactly one\n");
		goto error;
	}

	if (type&PARSE_ERR_CB) {
		if (add_callback( &parse_err_cb, f, param, prio)<0)
			goto add_error;
	}

	if (type&REQ_TYPE_CB) {
		/* callback for request script */
		if (type&PRE_SCRIPT_CB) {
			if (add_callback( &pre_req_cb, f, param, prio)<0)
				goto add_error;
		} else if (type&POST_SCRIPT_CB) {
			if (add_callback( &post_req_cb, f, param, prio)<0)
				goto add_error;
		}
	}
	if (type&RPL_TYPE_CB) {
		/* callback (also) for reply script */
		if (type&PRE_SCRIPT_CB) {
			if (add_callback( &pre_rpl_cb, f, param, prio)<0)
				goto add_error;
		} else if (type&POST_SCRIPT_CB) {
			if (add_callback( &post_rpl_cb, f, param, prio)<0)
				goto add_error;
		}
	}

	return 0;
add_error:
	LM_ERR("failed to add callback\n");
error:
	return -1;
}


static inline void destroy_cb_list(struct script_cb **list)
{
	struct script_cb *foo;

	while( *list ) {
		foo = *list;
		*list = (*list)->next;
		pkg_free( foo );
	}
}


void destroy_script_cb(void)
{
	destroy_cb_list( &pre_req_cb  );
	destroy_cb_list( &post_req_cb );
	destroy_cb_list( &pre_rpl_cb  );
	destroy_cb_list( &post_req_cb );
	destroy_cb_list( &parse_err_cb );
}


static inline int exec_pre_cb( struct sip_msg *msg, struct script_cb *cb)
{
	int bitmask = SCB_RUN_ALL;

	for ( ; cb ; cb=cb->next ) {
		bitmask &= cb->cbf(msg, cb->param);

		if (bitmask == SCB_DROP_MSG)
			break;
	}

	return bitmask;
}


static inline int exec_post_cb( struct sip_msg *msg, struct script_cb *cb)
{
	for ( ; cb ; cb=cb->next){
		cb->cbf( msg, cb->param);
	}
	return 1;
}


int exec_pre_req_cb( struct sip_msg *msg)
{
	return exec_pre_cb( msg, pre_req_cb);
}

int exec_pre_rpl_cb( struct sip_msg *msg)
{
	return exec_pre_cb( msg, pre_rpl_cb);
}

int exec_post_req_cb( struct sip_msg *msg)
{
	return exec_post_cb( msg, post_req_cb);
}

int exec_post_rpl_cb( struct sip_msg *msg)
{
	return exec_post_cb( msg, post_rpl_cb);
}

int exec_parse_err_cb( struct sip_msg *msg)
{
	return exec_post_cb( msg, parse_err_cb);
}

static inline int insert_raw_processing_cb(raw_processing_func f, int type, struct raw_processing_cb_list* list, char freeable)
{
	struct raw_processing_cb_list *elem;

	if (f == NULL) {
		LM_ERR("null callback\n");
		return -1;
	}

	elem = pkg_malloc(sizeof(struct raw_processing_cb_list));
	if (elem == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	elem->f = f;
	elem->freeable = freeable;
	elem->next = NULL;

	if (list == NULL) {
		list = elem;
		return !(type==PRE_RAW_PROCESSING ? (pre_processing_cb_list=list)
										  : (post_processing_cb_list=list));
	} else {
		while (list->next != NULL)
			list = list->next;
		list->next=elem;
	}

	return 0;

}

int register_pre_raw_processing_cb(raw_processing_func f, int type, char freeable)
{
	return  insert_raw_processing_cb(f, type, pre_processing_cb_list, freeable);
}

int register_post_raw_processing_cb(raw_processing_func f, int type, char freeable)
{
	return  insert_raw_processing_cb(f, type, post_processing_cb_list, freeable);
}





int run_pre_raw_processing_cb(int type, str* data, struct sip_msg* msg)
{
	return run_raw_processing_cb(type, data, msg, pre_processing_cb_list);
}

int run_post_raw_processing_cb(int type, str* data, struct sip_msg* msg)
{
	return run_raw_processing_cb(type, data, msg, post_processing_cb_list);
}

int run_raw_processing_cb(int type, str *data, struct sip_msg* msg, struct raw_processing_cb_list* list)
{

	struct raw_processing_cb_list *foo=NULL, *last_good=NULL, *head=NULL;
	char *initial_data = data->s, *input_data;
	int rc;

	if (list == NULL)
		return 0;

	while (list) {
		input_data = data->s;
		/* a return code bigger than 0 means you want to keep the callback */
		if ((rc = list->f(data, msg)) < 0) {
			LM_ERR("failed to run callback\n");
			return -1;
		}

		if (input_data != initial_data && input_data != data->s)
			pkg_free(input_data);

		foo = list;
		list = list->next;

		if (foo != NULL) {
			if (foo->freeable && rc == 0) {
				/* foo will be gone so link the last good element
				 * to the next one */
				if (last_good)
					last_good->next=list;

				pkg_free(foo);
			} else {
				/* keep the first element not to be freed */
				if (head == NULL)
					head = foo;
				/* and keep track of the last viable element to link with the
				 * next viable element */
				last_good = foo;
			}
		}
	}

	return !(type==PRE_RAW_PROCESSING?(pre_processing_cb_list=head)
										:(post_processing_cb_list=head));
}

