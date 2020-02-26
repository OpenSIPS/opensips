/**
 *
 * drouting module callbacks
 *
 * Copyright (C) 2014-2020 OpenSIPS Solutions
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
 */


#include <stdlib.h>
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "dr_cb.h"

struct dr_head_cbl {
    struct dr_callback *first;
    int types;
};

#define POINTER_CLOSED_MARKER  ((void *)(-1))

unsigned char sort_algs[N_MAX_SORT_CBS] = {'N', 'W', 'Q'};

/* the array with all the cb lists (per type) */
static struct dr_callback *dr_cbs[DRCB_MAX];

/* an array of sorting cbs registered by different modules */
static struct dr_callback *dr_sort_cbs[N_MAX_SORT_CBS];



static void destroy_dr_callbacks_list(struct dr_callback *cb)
{
	struct dr_callback *cb_t;

	while(cb) {
		cb_t = cb;
		cb = cb->next;
		if(cb_t->callback_param_free && cb_t->param) {
			cb_t->callback_param_free(cb_t->param);
			cb_t->param = NULL;
		}
		pkg_free(cb_t);
	}
}

void destroy_dr_cbs(void)
{
	int i;
	struct dr_callback *dr_sort_cb_it;

	for( i=0 ; i<DRCB_MAX ; i++ ) {
		if (dr_cbs[i] && dr_cbs[i]!=POINTER_CLOSED_MARKER)
			destroy_dr_callbacks_list(dr_cbs[i]);
		dr_cbs[i] = POINTER_CLOSED_MARKER;
	}

	for(i=0; i <N_MAX_SORT_CBS; i++) {
		if ( (dr_sort_cb_it=dr_sort_cbs[i])!=NULL &&
		dr_sort_cb_it->callback_param_free && dr_sort_cb_it->param) {
			dr_sort_cb_it->callback_param_free(dr_sort_cb_it->param);
			dr_sort_cb_it->param = NULL;
		}
	}
}

/*
 * adds a given callback to a given callback list
 */
int insert_drcb(struct dr_head_cbl **dr_cb_list, struct dr_callback *cb,
		int types)
{
	int i;
	struct dr_callback *dr_sort_cb_it;

	for( i=0 ; i<DRCB_MAX ; i++ ) {
		if (dr_cbs[i] && dr_cbs[i]!=POINTER_CLOSED_MARKER)
			destroy_dr_callbacks_list(dr_cbs[i]);
		dr_cbs[i] = POINTER_CLOSED_MARKER;
	}

	for(i=0; i <N_MAX_SORT_CBS; i++) {
		if ( (dr_sort_cb_it=dr_sort_cbs[i])!=NULL &&
		dr_sort_cb_it->callback_param_free && dr_sort_cb_it->param) {
			dr_sort_cb_it->callback_param_free(dr_sort_cb_it->param);
			dr_sort_cb_it->param = NULL;
		}
	}
	cb->next = (*dr_cb_list)->first;
	(*dr_cb_list)->first = cb;
	(*dr_cb_list)->types |= types;
	return 0;
}

int register_dr_cb(enum drcb_types type, dr_cb f, void *param,
                   dr_param_free_cb ff)
{
	sort_cb_type alg = (sort_cb_type)param;
	struct dr_callback *cb;

	cb = pkg_malloc(sizeof *cb);
	if (!cb) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(cb, 0, sizeof *cb);

	cb->callback = f;
	cb->callback_param_free = ff;

	if (type != DRCB_SORT_DST) {
		cb->param = param; /* because now param holds the type of the
							* sorting function */
		/* insert callback to the right list (based on type) */
		if (dr_cbs[type] == POINTER_CLOSED_MARKER) {
			LM_CRIT("DRCB_SORT_DST registered after shut down!\n");
			goto error;
		}
		cb->next = dr_cbs[type];
		dr_cbs[type] = cb;
	} else {
		if (alg >= N_MAX_SORT_CBS) {
			LM_ERR("invalid sorting algorithm: %u\n", alg);
			goto error;
		}

		if (dr_sort_cbs[alg])
			LM_WARN("sort callback for alg %u will be overwritten\n", alg);

		dr_sort_cbs[alg] = cb;
	}

	return 0;
error:
	pkg_free(cb);
	return -1;
}


/* runs a callback from an array - sort_cb_type will represent
 * the index within the array */
int run_dr_sort_cbs(sort_cb_type type, struct dr_sort_params *param)
{
	if (!dr_sort_cbs[type]) {
		LM_WARN("callback type '%d' not registered\n", type);
		return -1;
	}

	dr_sort_cbs[type]->callback(param);
	return 0;
}

int run_dr_cbs(enum drcb_types type, void *param)
{
	struct dr_callback *it = dr_cbs[type];

	if (!it)
		return -1;

	for (; it; it = it->next)
		it->callback(param);

	return 0;
}
