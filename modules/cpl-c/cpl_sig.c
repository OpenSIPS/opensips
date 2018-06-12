/*
 * $Id$
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "../../action.h"
#include "../../dset.h"
#include "../tm/tm_load.h"
#include "loc_set.h"
#include "cpl_sig.h"

extern struct tm_binds cpl_tmb;
extern int    proxy_route;
extern int    cpl_nat_flag;


/* forwards the msg to the given location set; if flags has set the
 * CPL_PROXY_DONE, all locations will be added as braches, otherwise, the first
 * one will set as RURI (this is ha case when this is the first proxy of the
 * message)
 * The given list of location will be freed, returning 0 insted.
 * Returns:  0 - OK
 *          -1 - error */
int cpl_proxy_to_loc_set( struct sip_msg *msg, struct location **locs,
													unsigned char flag)
{
	struct location *foo;
	struct action act;

	if (!*locs) {
		LOG(L_ERR,"ERROR:cpl_c:cpl_proxy_to_loc_set: empty loc set!!\n");
		goto error;
	}

	/* if it's the first time when this sip_msg is proxyed, use the first addr
	 * in loc_set to rewrite the RURI */
	if (!(flag&CPL_PROXY_DONE)) {
		DBG("DEBUG:cpl_c:cpl_proxy_to_loc_set: rewriting Request-URI with "
			"<%s>\n",(*locs)->addr.uri.s);
		/* build a new action for setting the URI */
		act.type = SET_URI_T;
		act.p1_type = STRING_ST;
		act.p1.string = (*locs)->addr.uri.s;
		act.next = 0;
		/* push the action */
		if (do_action(&act, msg) < 0) {
			LOG(L_ERR,"ERROR:cpl_c:cpl_proxy_to_loc_set: do_action failed\n");
			goto error;
		}
		/* is the location NATED? */
		if ((*locs)->flags&CPL_LOC_NATED) setflag(msg,cpl_nat_flag);
		/* free the location and point to the next one */
		foo = (*locs)->next;
		free_location( *locs );
		*locs = foo;
	}

	/* add the rest of the locations as branches */
	while(*locs) {
		DBG("DEBUG:cpl_c:cpl_proxy_to_loc_set: appending brach "
			"<%.*s>\n",(*locs)->addr.uri.len,(*locs)->addr.uri.s);
		if(append_branch(msg,(*locs)->addr.uri.s,(*locs)->addr.uri.len)==-1){
			LOG(L_ERR,"ERROR:cpl_c:cpl_proxy_to_loc_set: failed when "
				"appending branch <%s>\n",(*locs)->addr.uri.s);
			goto error;
		}
		/* is the location NATED? */
		if ((*locs)->flags&CPL_LOC_NATED) setflag(msg,cpl_nat_flag);
		/* free the location and point to the next one */
		foo = (*locs)->next;
		free_location( *locs );
		*locs = foo;
	}

	/* run what proxy route is set */
	if (proxy_route) {
		if (run_actions( rlist[proxy_route], msg)<0) {
			LOG(L_ERR,"ERROR:cpl_c:cpl_proxy_to_loc_set: "
				"Error in do_action for proxy_route\n");
		}
	}

	/* do t_forward */
	if (cpl_tmb.t_forward_nonack(msg, 0/*no proxy*/)==-1) {
		LOG(L_ERR,"ERROR:cpl_c:cpl_proxy_to_loc_set: t_forward_nonack "
			"failed !\n");
		goto error;
	}

	return 1;
error:
	return -1;
}


