/**
 *
 * drouting module developer api
 *
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * History
 * -------
 *  2014-08-13  initial version (Andrei Datcu)
*/

#include "dr_api_internal.h"
#include "dr_api.h"


#include "../../str.h"

static void* match_number (dr_head_t *partition, int grp_id,
		const str *number);
static dr_head_p create_dr_head(void);
static void free_dr_head(dr_head_p partition);


/* Warning this function assumes the lock is already taken */
rt_info_t* find_rule_by_prefix_unsafe(ptree_t *pt, ptree_node_t *noprefix,
		str prefix, unsigned int grp_id)
{
	unsigned int matched_len, rule_idx = 0;
	rt_info_t *rt_info;

	rt_info = get_prefix(pt, &prefix, grp_id,&matched_len, &rule_idx);

	if (rt_info==NULL) {
		LM_DBG("no matching for prefix \"%.*s\"\n",
				prefix.len, prefix.s);

		/* try prefixless rules */
		rt_info = check_rt( noprefix, grp_id);
		if (rt_info == NULL)
			LM_DBG("no prefixless matching for "
					"grp %d\n", grp_id);
	}
	return rt_info;
}

int load_dr (struct dr_binds *drb)
{
	drb->match_number = match_number;
	drb->create_head = create_dr_head;
	drb->free_head = free_dr_head;
	return 0;
}

/* Function which will try to match a number and return the rule id */
static void *match_number (dr_head_p partition, int grp_id, const str *number)
{
	rt_info_t *route;

	lock_start_read( partition->ref_lock );
	route = find_rule_by_prefix_unsafe(partition->pt, &(partition->noprefix), *number, grp_id);
	if (route == NULL) {
		lock_stop_read(partition->ref_lock );
		return NULL;
	}
	void * attr = (void*)route->attrs.s;
	lock_stop_read(partition->ref_lock );
	return attr;
}

static dr_head_p create_dr_head(void)
{
	dr_head_p new = shm_malloc(sizeof(dr_head_p));
	if( new == NULL ) {
		LM_ERR(" no more shm memory(add_head_db)\n");
		return NULL;
	}
	memset( new, 0, sizeof(dr_head_t));

	/* data pointer in shm */

	/* create & init lock */
	if ((new->ref_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init lock\n");
		goto error;
	}

	return new;
error:
	shm_free(new);
	return NULL;
}

static void free_dr_head(dr_head_p partition)
{
	lock_destroy_rw(partition->ref_lock);
	shm_free(partition);
}

