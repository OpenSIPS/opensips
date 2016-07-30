/*
 * Copyright (C) 2005-2008 Voice Sistem SRL
 *
 * This file is part of Open SIP Server.
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * For any questions about this software and its license, please contact
 * Voice Sistem at following e-mail address:
 *         office@voice-system.ro
 *
 * History:
 * ---------
 *  2005-02-20  first version (cristian)
 *  2005-02-27  ported to 0.9.0 (bogdan)
 */


#include <stdlib.h>
#include <stdio.h>

#include "../../str.h"
#include "../../mem/shm_mem.h"
#include "../../time_rec.h"

#include "prefix_tree.h"
#include "routing.h"

extern int inode;
extern int unode;



static inline int
check_time(
		tmrec_t *time_rec
		)
{
	ac_tm_t att;

	/* shortcut: if there is no dstart, timerec is valid */
	if (time_rec->dtstart==0)
		return 1;

	memset( &att, 0, sizeof(att));

	/* set current time */
	if ( ac_tm_set_time( &att, time(0) ) )
		return 0;

	/* does the recv_time match the specified interval?  */
	if (check_tmrec( time_rec, &att, 0)!=0)
		return 0;

	return 1;
}


static inline rt_info_t*
internal_check_rt(
		ptree_node_t *ptn,
		unsigned int rgid,
		unsigned int *rgidx
		)
{
	int i,j;
	int rg_pos=0;
	rg_entry_t* rg=NULL;
	rt_info_wrp_t* rtlw=NULL;

	if((NULL==ptn) || (NULL==ptn->rg))
		goto err_exit;
	rg_pos = ptn->rg_pos;
	rg=ptn->rg;
	for(i=0;(i<rg_pos) && (rg[i].rgid!=rgid);i++);
	if(i<rg_pos) {
		LM_DBG("found rgid %d (rule list %p)\n",
				rgid, rg[i].rtlw);
		rtlw=rg[i].rtlw;
		j = 0;
		while(rtlw!=NULL) {
			if ( j++ >= *rgidx) {
				if(rtlw->rtl->time_rec == NULL || check_time(rtlw->rtl->time_rec))
					goto ok_exit;
			}
			rtlw=rtlw->next;
		}
	}
err_exit:
	return NULL;

ok_exit:
	/* if rules are still in this node, point to the next index */
	*rgidx = (rtlw->next) ? j : 0 ;
	return rtlw?rtlw->rtl:0;
}


rt_info_t*
check_rt(
	ptree_node_t *ptn,
	unsigned int rgid
	)
{
	unsigned int rgidx = 0;
	return internal_check_rt( ptn, rgid, &rgidx);
}


rt_info_t*
get_prefix(
	ptree_t *ptree,
	str* prefix,
	unsigned int rgid,
	unsigned int *matched_len,
	unsigned int *rgidx
	)
{
	rt_info_t *rt = NULL;
	char *tmp=NULL;
	char local=0;
	int idx=0;

	if(NULL == ptree)
		goto err_exit;
	if(NULL == prefix)
		goto err_exit;
	tmp = prefix->s;
	/* go the tree down to the last digit in the
	 * prefix string or down to a leaf */
	while(tmp< (prefix->s+prefix->len)) {
		if(NULL == tmp)
			goto err_exit;
		local=*tmp;
		if( !IS_DECIMAL_DIGIT(local) ) {
			/* unknown character in the prefix string */
			goto err_exit;
		}
		if( tmp == (prefix->s+prefix->len-1) ) {
			/* last digit in the prefix string */
			break;
		}
		idx = local -'0';
		if( NULL == ptree->ptnode[idx].next) {
			/* this is a leaf */
			break;
		}
		ptree = ptree->ptnode[idx].next;
		tmp++;
	}
	/* go in the tree up to the root trying to match the
	 * prefix */
	while(ptree !=NULL ) {
		if(NULL == tmp)
			goto err_exit;
		/* is it a real node or an intermediate one */
		idx = *tmp-'0';
		if(NULL != ptree->ptnode[idx].rg) {
			/* real node; check the constraints on the routing info*/
			if( NULL != (rt = internal_check_rt( &(ptree->ptnode[idx]), rgid, rgidx)))
				break;
		}
		tmp--;
		ptree = ptree->bp;
	}
	if (matched_len) *matched_len = tmp + 1 - prefix->s ;
	return rt;

err_exit:
	return NULL;
}

pgw_t*
get_gw_by_internal_id(
		map_t gw_tree,
		unsigned int id
		)
{
	pgw_t* gw;
	void** dest;
	map_iterator_t it;

	for (map_first(gw_tree, &it); iterator_is_valid(&it); iterator_next(&it)) {

		dest = iterator_val(&it);
		if (dest==NULL)
			return NULL;

		gw = (pgw_t*)*dest;
		if ( id == gw->_id)
			return gw;
	}


	return NULL;
}


pgw_t*
get_gw_by_id(
		map_t pgw_tree,
		str *id
		)
{
	pgw_t** ret;
	return (ret=(pgw_t**)map_find(pgw_tree, *id))?*ret:NULL;
}

pcr_t*
get_carrier_by_id(
		map_t carriers_tree,
		str *id
		)
{
	pcr_t** ret;

	return (ret=(pcr_t**)map_find(carriers_tree, *id))?*ret:NULL;
}




int
add_prefix(
	ptree_t *ptree,
	str* prefix,
	rt_info_t *r,
	unsigned int rg
)
{
	char* tmp=NULL;
	int res = 0;
	if(NULL==ptree) {
        LM_ERR("ptree is null\n");
		goto err_exit;
    }
	tmp = prefix->s;
	while(tmp < (prefix->s+prefix->len)) {
		if(NULL == tmp) {
            LM_ERR("prefix became null\n");
			goto err_exit;
        }
		if( !IS_DECIMAL_DIGIT(*tmp) ) {
			/* unknown character in the prefix string */
            LM_ERR("is not decimal digit\n");
			goto err_exit;
		}
		if( tmp == (prefix->s+prefix->len-1) ) {
			/* last digit in the prefix string */
			LM_DBG("adding info %p, %d at: "
				"%p (%d)\n", r, rg, &(ptree->ptnode[*tmp-'0']), *tmp-'0');
			res = add_rt_info(&(ptree->ptnode[*tmp-'0']), r,rg);
			if(res < 0 ) {
                LM_ERR("adding rt info doesn't work\n");
				goto err_exit;
            }
			unode++;
			res = 1;
			goto ok_exit;
		}
		/* process the current digit in the prefix */
		if(NULL == ptree->ptnode[*tmp - '0'].next) {
			/* allocate new node */
			INIT_PTREE_NODE(ptree, ptree->ptnode[*tmp - '0'].next);
			inode+=10;
#if 0
			printf("new tree node: %p (bp: %p)\n",
					ptree->ptnode[*tmp - '0'].next,
					ptree->ptnode[*tmp - '0'].next->bp
					);
#endif
		}
		ptree = ptree->ptnode[*tmp-'0'].next;
		tmp++;
	}

ok_exit:
	return 0;

err_exit:
	return -1;
}

int
del_tree(
		ptree_t* t
		)
{
	int i,j;
	if(NULL == t)
		goto exit;
	/* delete all the children */
	for(i=0; i< PTREE_CHILDREN; i++) {
		/* shm_free the rg array of rt_info */
		if(NULL!=t->ptnode[i].rg) {
			for(j=0;j<t->ptnode[i].rg_pos;j++) {
				/* if non intermediate delete the routing info */
				if(t->ptnode[i].rg[j].rtlw !=NULL)
					del_rt_list(t->ptnode[i].rg[j].rtlw);
			}
			shm_free(t->ptnode[i].rg);
		}
		/* if non leaf delete all the children */
		if(t->ptnode[i].next != NULL)
			del_tree(t->ptnode[i].next);
	}
	shm_free(t);
exit:
	return 0;
}

void
del_rt_list(
		rt_info_wrp_t *rwl
		)
{
	rt_info_wrp_t* t=rwl;
	while(rwl!=NULL) {
		t=rwl;
		rwl=rwl->next;
		if ( (--t->rtl->ref_cnt)==0)
			free_rt_info(t->rtl);
		shm_free(t);
	}
}

void
free_rt_info(
		rt_info_t *rl
		)
{
	if(NULL == rl)
		return;
	if(NULL!=rl->pgwl)
		shm_free(rl->pgwl);
	if(NULL!=rl->time_rec)
		tmrec_free(rl->time_rec);
	shm_free(rl);
	return;
}

