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
 *  2004-03-16  created (bogdan)
 */

/*! \file
 *  \brief USRLOC - Callback functions
 *  \ingroup usrloc
 */


#include <stdlib.h>

#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/shm_mem.h"
#include "../../lib/list.h"
#include "ul_callback.h"


struct ulcb_head_list *ulcb_list;

int init_ulcb_list(void)
{
	ulcb_list = shm_malloc(sizeof *ulcb_list);
	if (!ulcb_list) {
		LM_CRIT("no more shared mem\n");
		return -1;
	}
	memset(ulcb_list, 0, sizeof *ulcb_list);
	INIT_LIST_HEAD(&ulcb_list->first);

	return 1;
}


void destroy_ulcb_list(void)
{
	struct list_head *ele, *next;
	struct ul_callback *cbp;

	if (!ulcb_list)
		return;

	list_for_each_safe(ele, next, &ulcb_list->first) {
		cbp = list_entry(ele, struct ul_callback, list);
		shm_free(cbp);
	}

	shm_free(ulcb_list);
}



/*! \brief
	register a callback function 'f' for 'types' mask of events;
*/
int register_ulcb(ul_cb_type types, ul_cb f)
{
	struct ul_callback *cbp;

	/* are the callback types valid?... */
	if (types > ULCB_MAX) {
		LM_CRIT("invalid callback types: mask=%d\n",types);
		return E_BUG;
	}

	/* we don't register null functions */
	if (f==0) {
		LM_CRIT("null callback function\n");
		return E_BUG;
	}

	/* build a new callback structure */
	if (!(cbp=(struct ul_callback*)shm_malloc(sizeof( struct ul_callback)))) {
		LM_ERR("no more share mem\n");
		return E_OUT_OF_MEM;
	}
	memset(cbp, 0, sizeof *cbp);

	if (list_empty(&ulcb_list->first))
		cbp->id = 0;
	else
		cbp->id = list_last_entry(
		               &ulcb_list->first, struct ul_callback, list)->id + 1;

	/* link it into the proper place... */
	list_add_tail(&cbp->list, &ulcb_list->first);

	ulcb_list->reg_types |= types;

	/* ... and fill it up */
	cbp->callback = f;

	cbp->types = types;

	return 1;
}
