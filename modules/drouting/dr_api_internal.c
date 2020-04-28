/**
 * drouting module developer api
 *
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2015-2020 OpenSIPS Solutions
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
 */

#include "dr_api_internal.h"
#include "dr_api.h"
#include "dr_cb.h"


#include "../../str.h"

static rt_info_t *match_number (dr_head_p partition, unsigned int grp_id,
		const str *number, unsigned int *matched_len);
static dr_head_p create_dr_head(void);
static void free_dr_head(dr_head_p partition);
static int add_rule_api(dr_head_p partition, unsigned int rid,
		str *prefix, unsigned int gr_id, unsigned int priority,
		tmrec_t *time_rec, void *attr);


static str * get_gw_name(pgw_t * gw);
static str * get_cr_name(pcr_t * cr);
static int get_cr_n_gw(pcr_t * cr); /* gets the number of gateways from a carrier */
static  pgw_t * get_gw_from_cr (pcr_t *cr, int n);
static void * get_qr_rule_handle(rt_info_t *rule);


static str * get_gw_name(pgw_t *gw) {
	return &gw->id;
}

static int get_cr_n_gw(pcr_t * cr) {
	return cr->pgwa_len;
}

static inline pgw_t * get_gw_from_cr(pcr_t *cr, int n) {
	if (cr->pgwa_len > n)
		return cr->pgwl[n].dst.gw; /* a carrier cannot contain another carrier */
	return NULL; /* provided index was bigger than the vector */
}

static inline str *get_cr_name(pcr_t * cr) {
	return &cr->id;
}

static inline void * get_qr_rule_handle(rt_info_t *rule) {
	return rule->qr_handler;
}


/* Warning this function assumes the lock is already taken */
rt_info_t* find_rule_by_prefix_unsafe(ptree_t *pt, ptree_node_t *noprefix,
		str prefix, unsigned int grp_id, unsigned int *matched_len)
{
	unsigned int rule_idx = 0;
	rt_info_t *rt_info;

	rt_info = get_prefix(pt, &prefix, grp_id,matched_len, &rule_idx);

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
	drb->register_drcb = register_dr_cb;
	drb->get_gw_name = get_gw_name;
	drb->get_cr_n_gw = get_cr_n_gw;
	drb->get_cr_name = get_cr_name;
	drb->get_gw_from_cr = get_gw_from_cr;
	drb->get_qr_rule_handle = get_qr_rule_handle;
	return 0;
}

/* Function which will try to match a number and return the rule id */
static rt_info_t *match_number (dr_head_p partition, unsigned int grp_id,
		const str *number, unsigned int *matched_len)
{

	return find_rule_by_prefix_unsafe(partition->pt, &(partition->noprefix),
			*number, grp_id, matched_len);
}

static dr_head_p create_dr_head(void)
{
	dr_head_p new = shm_malloc(sizeof(dr_head_t));
	if( new == NULL ) {
		LM_ERR(" no more shm memory\n");
		return NULL;
	}
	memset( new, 0, sizeof(dr_head_t));

	INIT_PTREE_NODE(shm_malloc_func, NULL, new->pt);
	return new;

err_exit:
	LM_ERR("oom\n");
	shm_free(new);
	return NULL;
}

static void del_rt_list_api(rt_info_wrp_t *rwl)
{
	rt_info_wrp_t* t=rwl;
	while(rwl!=NULL) {
		t=rwl;
		rwl=rwl->next;
		if ( (--t->rtl->ref_cnt)==0)
			shm_free(t->rtl);
		shm_free(t);
	}
}

static void del_tree_api(ptree_t* t)
{
	int i,j;
	if(NULL == t)
		return;
	/* delete all the children */
	for(i=0; i< ptree_children; i++) {
		/* shm_free the rg array of rt_info */
		if(NULL!=t->ptnode[i].rg) {
			for(j=0;j<t->ptnode[i].rg_pos;j++) {
				/* if non intermediate delete the routing info */
				if(t->ptnode[i].rg[j].rtlw !=NULL)
					del_rt_list_api(t->ptnode[i].rg[j].rtlw);
			}
			shm_free(t->ptnode[i].rg);
		}
		/* if non leaf delete all the children */
		if(t->ptnode[i].next != NULL)
			del_tree_api(t->ptnode[i].next);
	}
	shm_free(t);
}

static void free_dr_head(dr_head_p partition)
{
	int j;
	del_tree_api(partition->pt);
	if(NULL!=partition->noprefix.rg) {
		for(j=0;j<partition->noprefix.rg_pos;j++) {
			if(partition->noprefix.rg[j].rtlw !=NULL) {
				del_rt_list_api(partition->noprefix.rg[j].rtlw);
				partition->noprefix.rg[j].rtlw = 0;
			}
		}
		shm_free(partition->noprefix.rg);
		partition->noprefix.rg = 0;
	}
	shm_free(partition);
}

static int add_rule_api(dr_head_p partition,unsigned int rid,
		str *prefix, unsigned int gr_id, unsigned int priority,
		tmrec_t *time_rec, void *attr)
{
	rt_info_t * rule = shm_malloc(sizeof(rt_info_t));
	if (rule == NULL){
		LM_ERR("no more shm mem(1)\n");
		return -1;
	}

	memset(rule, 0, sizeof(rt_info_t));
	rule->id = rid;
	rule->priority = priority;
	rule->time_rec = time_rec;
	rule->attrs.s = (char*) attr;

	if (prefix->len) {
		if ( add_prefix(partition->pt, prefix, rule, gr_id,
				shm_malloc_func, shm_free_func)!=0 ) {
			LM_ERR("failed to add prefix route\n");
			return -1;
		}
	} else {
		if ( add_rt_info( &partition->noprefix, rule, gr_id,
				shm_malloc_func, shm_free_func)!=0 ) {
			LM_ERR("failed to add prefixless route\n");
			return -1;
		}
	}
	return 0;
}

