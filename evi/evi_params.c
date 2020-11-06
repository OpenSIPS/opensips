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
#include "../mem/shm_mem.h"
#include <string.h>


/* creates an element and links it to the parameters list
 * but without populating the parameter value */
evi_param_p evi_param_create(evi_params_p list, const str *name)
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

	if (name)
		new_p->name = *name;

	new_p->next = NULL;
	if (list->last) {
		list->last->next = new_p;
		list->last = new_p;
	} else {
		list->last = list->first = new_p;
	}
	return new_p;
}

int evi_param_set(evi_param_p el, const void *param, int flags)
{
	if (!el) {
		LM_ERR("no parameter specified\n");
		return 1;
	}

	if (!(flags & (EVI_INT_VAL|EVI_STR_VAL))) {
		LM_ERR("params should be int or str [%x]\n", flags);
		return -1;
	}

	el->flags = flags;

	if (flags & EVI_INT_VAL) {
		el->val.n = *((int*)param);
		LM_DBG("set int %.*s=%d\n", el->name.len, el->name.s,
		       el->val.n);
	} else {
		memcpy(&el->val, param, sizeof(str));
		LM_DBG("set str %.*s='%.*s'\n", el->name.len, el->name.s,
		       el->val.s.len, el->val.s.s);
	}

	return 0;
}



/* adds a new parameter to the list */
int evi_param_add(evi_params_p list, const str *name, const void *param, int flags)
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

evi_params_p evi_dup_shm_params(evi_params_p pkg_params)
{
	int shm_size;
	evi_params_p shm_params;
	evi_param_p param, prev, sp;
	char *p;

	if(!pkg_params)
		return NULL;

	shm_size = sizeof(evi_params_t);
	for (param = pkg_params->first; param; param = param->next) {
		shm_size += sizeof(evi_param_t) + param->name.len;
		if (param->flags & EVI_STR_VAL)
			shm_size += param->val.s.len;
	}

	shm_params = shm_malloc(shm_size);
	if (!shm_params) {
		return NULL;
	}
	shm_params->flags = 0;

	p = (char *)(shm_params + 1);
	for (param = pkg_params->first, prev = NULL; param;
			prev = sp, param = param->next) {
		sp = (evi_param_p)p;
		p += sizeof(evi_param_t);
		sp->flags = param->flags;
		sp->next = NULL;
		sp->name.len = param->name.len;
		if (sp->name.len) {
			sp->name.s = p;
			p += param->name.len;
			memcpy(sp->name.s, param->name.s, param->name.len);
		}
		if (param->flags & EVI_STR_VAL) {
			sp->val.s.len = param->val.s.len;
			sp->val.s.s = p;
			p += param->val.s.len;
			memcpy(sp->val.s.s, param->val.s.s, param->val.s.len);
		} else
			sp->val.n = param->val.n;
		if (prev) {
			prev->next = sp;
			shm_params->last = sp;
		} else
			shm_params->first = sp;
	}
	return shm_params;
}

void evi_free_shm_params(evi_params_p shm_params)
{
	shm_free(shm_params);
}
