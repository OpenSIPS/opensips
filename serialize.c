/*
 * $Id$
 *
 * Copyright (C) 2005 Juha Heinanen
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
 * -------
 *  2005-11-29 splitted from lcr module (bogdan)
 */

/*!
 * \file
 * \brief Sequential forking implementation
 */

#include "str.h"
#include "qvalue.h"
#include "usr_avp.h"
#include "dset.h"
#include "action.h"
#include "route.h"
#include "parser/msg_parser.h"



struct serial_contact {
	str uri;
	qvalue_t q;
	unsigned short q_flag;
	int next;
};

#define Q_FLAG            (1<<4)		/*!< usr_avp flag for sequential forking */
#define SERIAL_AVP_ALIAS  "serial_branch"	/*!< avp alias to be used */
#define SERIAL_AVL_ID     0xff3434		/*!< avp ID of serial AVP */

static int_str serial_avp;



int init_serialization(void)
{
	str alias = { SERIAL_AVP_ALIAS, sizeof(SERIAL_AVP_ALIAS)-1 };

	serial_avp.n = SERIAL_AVL_ID;
	return add_avp_galias( &alias, 0 /*type*/, serial_avp );
}



/*! \brief
 * Loads contacts in destination set into "serial_fork" AVP in reverse
 * priority order and associated each contact with Q_FLAG telling if
 * contact is the last one in its priority class.  Finally, removes
 * all branches from destination set.
 */
int serialize_branches(struct sip_msg *msg, int clean_before )
{
	static struct serial_contact contacts[MAX_BRANCHES];
	int n, last, first, i;
	str branch, *ruri;
	qvalue_t q, ruri_q;
	int_str val;
	int idx;

	/* Check if anything needs to be done */
	if (nr_branches == 0) {
		LM_DBG("nothing to do - no branches!\n");
		return 0;
	}

	ruri = GET_RURI(msg);
	ruri_q = get_ruri_q();

	for( idx=0 ; (branch.s=get_branch(idx,&branch.len,&q,0,0,0,0))!=0 ; idx++ ) {
		if (q != ruri_q)
			break;
	}
	if (branch.s==0) {
		LM_DBG("nothing to do - all same q!\n");
		return 0;
	}

	/* reset contact array */
	n = 0;

	/* Insert Request-URI to contact list */
	contacts[n].uri = *ruri;
	contacts[n].q = ruri_q;
	contacts[n].next = -1;
	last = n;
	first = n;
	n++;

	/* Insert branch URIs to contact list in increasing q order */
	for( idx=0 ; (branch.s=get_branch(idx,&branch.len,&q,0,0,0,0))!=0 ; idx++){
		contacts[n].uri = branch;
		contacts[n].q = q;

		/* insert based on q */
		for( i=first ; i!=-1 && contacts[i].q < q ; i=contacts[i].next );
		if (i==-1) {
			/* append */
			last = contacts[last].next = n;
			contacts[n].next = -1;
		} else {
			if (i==first) {
				/* first element */
				contacts[n].next = first;
				first = n;
			} else {
				/* after pos i */
				contacts[n].next = contacts[i].next;
				contacts[i].next = n;
			}
		}

		n++;
	}

	/* Assign values for q_flags */
	for( i=first ; contacts[i].next!=-1 ; i=contacts[i].next ) {
		if (contacts[i].q < contacts[contacts[i].next].q)
			contacts[contacts[i].next].q_flag = Q_FLAG;
		else
			contacts[contacts[i].next].q_flag = 0;
	}

	if (clean_before)
		destroy_avps( 0/*type*/, serial_avp, 1/*all*/);

	/* Add contacts to "contacts" AVP */
	for ( i=first ; i!=-1; i=contacts[i].next ) {
		val.s = contacts[i].uri;
		if (add_avp( AVP_VAL_STR|contacts[i].q_flag, serial_avp,
		val)!=0 ) {
			LM_ERR("failed to add avp\n");
			goto error;
		}
		LM_DBG("loaded <%.*s>, q=%d q_flag <%d>\n", val.s.len, val.s.s,
			contacts[i].q, contacts[i].q_flag);
	}

	/* Clear all branches */
	clear_branches();

	return 0;
error:
	return -1;
}



/*! \brief
 * Adds to request a destination set that includes all highest priority
 * class contacts in "serial_avp" AVP.   If called from a route block,
 * rewrites the request uri with first contact and adds the remaining
 * contacts as branches.  If called from failure route block, adds all
 * contacts as brances.  Removes added contacts from "serial_avp" AVP.
 */
int next_branches( struct sip_msg *msg)
{
	struct usr_avp *avp, *prev;
	int_str val;
	struct action act;
	int rval;

	if ( route_type!=REQUEST_ROUTE && route_type!=FAILURE_ROUTE ) {
		/* unsupported route type */
		LM_ERR("called from unsupported route type %d\n", route_type);
		goto error;
	}

	/* Find first avp  */
	avp = search_first_avp( 0, serial_avp, &val, 0);
	if (!avp) {
		LM_DBG("no AVPs -- we are done!\n");
		goto error;
	}

	if ( route_type == REQUEST_ROUTE) {
		/* Set Request-URI */
		act.type = SET_URI_T;
		act.elem[0].type = STRING_ST;
		act.elem[0].u.string = val.s.s;
		rval = do_action(&act, msg);
		if (rval != 1)
			goto error1;
		LM_DBG("R-URI is <%s>\n", val.s.s);
		if (avp->flags & Q_FLAG) {
			destroy_avp(avp);
			return 0;
		}
		if ( (avp=search_next_avp(avp, &val))==0 )
			return 0;
		/* continue */
	}

	/* Append branches until out of branches or Q_FLAG is set */
	do {
		act.type = APPEND_BRANCH_T;
		act.elem[0].type = STRING_ST;
		act.elem[0].u.s = val.s;
		act.elem[1].type = NUMBER_ST;
		act.elem[1].u.number = 0;
		rval = do_action(&act, msg);
		if (rval != 1) {
			LM_ERR("do_action failed with return value <%d>\n", rval);
			goto error1;
			}
		LM_DBG("branch is <%s>\n", val.s.s);

		/* continuu ? */
		if (avp->flags & Q_FLAG) {
			destroy_avp(avp);
			return 0;
		}
		prev = avp;
		avp=search_next_avp(prev, &val);
		destroy_avp(prev);
	}while ( avp );

	return 0;
error1:
	destroy_avp(avp);
error:
	return -1;
}
