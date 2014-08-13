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
static int add_rule_api(dr_head_p partition,
		str *prefix, unsigned int gr_id, unsigned int priority,
		tmrec_t *time_rec, void *attr);


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
	drb->add_rule = add_rule_api;
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
		LM_ERR(" no more shm memory\n");
		return NULL;
	}
	memset( new, 0, sizeof(dr_head_t));

	/* data pointer in shm */
	new->pt = shm_malloc(sizeof (ptree_t));
	if (new->pt == NULL) {
		LM_ERR ("no more shm memory");
		shm_free(new);
		return NULL;
	}
	memset(new->pt, 0, sizeof(ptree_t));

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
	int j;
	lock_start_read(partition->ref_lock);
	del_tree(partition->pt);
	if(NULL!=partition->noprefix.rg) {
		for(j=0;j<partition->noprefix.rg_pos;j++) {
			if(partition->noprefix.rg[j].rtlw !=NULL) {
				del_rt_list(partition->noprefix.rg[j].rtlw);
				partition->noprefix.rg[j].rtlw = 0;
			}
		}
		shm_free(partition->noprefix.rg);
		partition->noprefix.rg = 0;
	}
	lock_stop_read(partition->ref_lock);
	lock_destroy_rw(partition->ref_lock);
	shm_free(partition);
}

static int add_rule_api(dr_head_p partition,
		str *prefix, unsigned int gr_id, unsigned int priority,
		tmrec_t *time_rec, void *attr)
{
	static unsigned int autoinc = 0;
	rt_info_t * rule = shm_malloc(sizeof(rt_info_t));
	if (rule == NULL){
		LM_ERR("no more shm mem(1)\n");
		return -1;
	}

	memset(rule, 0, sizeof(rt_info_t));
	rule->id = autoinc++;
	rule->priority = priority;
	rule->time_rec = time_rec;
	rule->attrs.s = (char*) attr;

	if (prefix->len) {
		if ( add_prefix(partition->pt, prefix, rule, gr_id)!=0 ) {
			LM_ERR("failed to add prefix route\n");
			return -1;
		}
	} else {
		if ( add_rt_info( &partition->noprefix, rule, gr_id)!=0 ) {
			LM_ERR("failed to add prefixless route\n");
			return -1;
		}
	}
	return 0;
}

