/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#include "evi_params.h"
#include "../mem/mem.h"
#include <string.h>


/* creates an element and links it to the parameters list
 * but without populating the parameter value */
evi_param_p evi_param_create(evi_params_p list, str *name)
{
	evi_param_p new_p;

	if (!list) {
		LM_ERR("invalid param list\n");
		return 0;
	}

	new_p = pkg_malloc(sizeof(evi_param_t));
	if (!new_p) {
		LM_ERR("no more pkg mem for new parameter\n");
		return 0;
	}
	memset(new_p, 0, sizeof(evi_param_t));

	if (name) {
		new_p->name.s = name->s;
		new_p->name.len = name->len;
	}

	new_p->next = NULL;
	if (list->last) {
		list->last->next = new_p;
		list->last = new_p;
	} else {
		list->last = list->first = new_p;
	}
	return new_p;
}

int evi_param_set(evi_param_p el, void *param, int flags)
{
	if (!el) {
		LM_ERR("no parameter specified\n");
		return 1;
	}
	if (!(EVI_INT_VAL & flags) && !(EVI_STR_VAL & flags)) {
		LM_ERR("params should be int or str [%x]\n", flags);
		return -1;
	}

	LM_DBG("adding %s param\n", EVI_INT_VAL & flags ? "int" : "string");

	el->flags = flags;

	if (flags & EVI_INT_VAL)
		el->val.n = *((int*)param);
	else
		memcpy(&el->val, param, sizeof(str));

	return 0;
}



/* adds a new parameter to the list */
int evi_param_add(evi_params_p list, str *name, void *param, int flags)
{
	evi_param_p new_p;

	if (!(EVI_INT_VAL & flags) && !(EVI_STR_VAL & flags)) {
		LM_ERR("params should be int or str [%x]\n", flags);
		return -1;
	}
	new_p = evi_param_create(list, name);
	if (!new_p) {
		LM_ERR("cannot create parameter\n");
		return -1;
	}
	if (evi_param_set(new_p, param, flags) < 0) {
		LM_ERR("cannot set the parameter value\n");
		return -1;
	}
	return 0;
}

/* allocs a new structure and initializes it with 0 */
evi_params_p evi_get_params(void)
{
	evi_params_p new_list = pkg_malloc(sizeof(evi_params_t));
	if (!new_list) {
		LM_ERR("no more pkg memory for the list\n");
		return NULL;
	}
	memset(new_list, 0, sizeof(evi_params_t));

	/* used to remember to free it */
	new_list->flags = EVI_FREE_LIST;

	return new_list;
}

/* frees a parameters list */
void evi_free_params(evi_params_p list)
{
	evi_param_p node, nxt;

	if (!list)
		return;

	for (node = list->first; node; node = nxt) {
		nxt = node->next;
		pkg_free(node);
	}

	list->first = list->last = NULL;

	/* list should be freed */
	pkg_free(list);
}
