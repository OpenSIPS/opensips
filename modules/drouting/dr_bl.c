/*
 * Copyright (C) 2009 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (OpenSIPS).
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
 */



#include <string.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../trim.h"
#include "prefix_tree.h"
#include "dr_bl.h"
#include "dr_partitions.h"


/*
 * link list for black_list definitions
 * obtained via modparam
 */

//extern int use_partitions;
typedef struct blk_list_raw {
	char * def;
	struct blk_list_raw * next;
}blk_list_raw_t;


static blk_list_raw_t *bl_lists = NULL, *bl_lists_end=NULL;
static struct dr_bl *drbl_lists = NULL;

int set_dr_bl( modparam_t type, void* val)
{
	blk_list_raw_t * new_bl_def = pkg_malloc(sizeof(blk_list_raw_t));
	if (new_bl_def==NULL) {
		LM_ERR("failed to alloc element for blacklist (linked-list)\n");
		return -1;
	}
	memset(new_bl_def, 0, sizeof(blk_list_raw_t));
	new_bl_def->def = (char*)val;

	if( bl_lists==NULL ) { /* first time functions is called */
		bl_lists = new_bl_def;
		bl_lists_end = bl_lists;
	} else { /* the list is not empty. the function was called before */
		bl_lists_end->next = new_bl_def;
		bl_lists_end =new_bl_def;
	}
	return 0;
}


int init_dr_bls(struct head_db * head_db_start)
{
	struct dr_bl *drbl;
	str name;
	str val;
	str part_name;
	char *p = NULL;
	blk_list_raw_t *it_blk, *to_clean;
	struct head_db * current_partition;

	if (bl_lists==NULL)
		return 0;
	it_blk = bl_lists;

	while( it_blk!=NULL ) {
		LM_DBG("processing bl definition <%s>\n",it_blk->def);
		/* get name */
		if( use_partitions ) {
			p = strchr(it_blk->def, ':');
			part_name.s = it_blk->def;
			part_name.len = p-part_name.s;
			if( p==NULL || p==it_blk->def ) {
				LM_ERR("blacklist definition <%s> has no partition name\n",
						it_blk->def);
				return -1;
			}
			trim(&part_name);
			if( (current_partition = get_partition(&part_name))==NULL ) {
				LM_ERR("could not find partition name <%.*s> from blacklist "
						"definition <%s>\n", part_name.len, part_name.s,
						it_blk->def);
				return -1;
			}
			name.s = p+1;
		} else {
			current_partition = head_db_start;
			if( current_partition == 0 ) {
				LM_CRIT("Default partition not registered\n");
			}
			name.s = it_blk->def;
		}
		p = strchr( name.s, '=');
		if (p==NULL || p==name.s) {
			LM_ERR("blacklist definition <%s> has no name",it_blk->def);
			return -1;
		}
		name.len = p - name.s;
		trim(&name);
		if (name.len==0) {
			LM_ERR("empty name in blacklist definition <%s>\n",it_blk->def);
			return -1;
		}
		LM_DBG("found list name <%.*s>\n",name.len,name.s);
		/* alloc structure */
		drbl = (struct dr_bl*)shm_malloc( sizeof(struct dr_bl) );
		if (drbl==NULL) {
			LM_ERR("no more shme memory\n");
			return -1;
		}
		memset( drbl, 0, sizeof(struct dr_bl));
		/* fill in the types */
		p++;
		do {
			if (drbl->no_types==MAX_TYPES_PER_BL) {
				LM_ERR("too many types per rule <%s>\n",it_blk->def);
				shm_free(drbl);
				return -1;
			}
			val.s = p;
			p = strchr( p, ',');
			if (p==NULL) {
				val.len = strlen(val.s);
			} else {
				val.len = (int)(long)(p - val.s);
				p++;
			}
			trim(&val);
			if (val.len==0) {
				LM_ERR("invalid types listing in <%s>\n",it_blk->def);
				shm_free(drbl);
				return -1;
			}
			LM_DBG("found type <%.*s>\n",val.len,val.s);
			if (str2int( &val, &drbl->types[drbl->no_types])!=0) {
				LM_ERR("nonnumerical type <%.*s>\n",val.len,val.s);
				shm_free(drbl);
				return -1;
			}
			drbl->no_types++;
		}while(p!=NULL);


		/* create backlist for it */
		drbl->bl = create_bl_head( 131313, 0/*flags*/, NULL, NULL, &name);
		drbl->part = current_partition;

		to_clean = it_blk;
		it_blk = it_blk->next;

		if (drbl->bl==NULL) {
			LM_ERR("failed to create bl <%.*s>\n",name.len,name.s);
			shm_free(drbl);
			return -1;
		}

		if( to_clean ) {
			if( to_clean->def ) {
				pkg_free(to_clean->def);
			}
			memset( to_clean, 0, sizeof(blk_list_raw_t));
			pkg_free(to_clean);
		}

		/* link it */
		drbl->next = drbl_lists;
		drbl_lists = drbl;
	}

	bl_lists = NULL;
	bl_lists_end = NULL;

	return 0;
}



void destroy_dr_bls(void)
{
	struct dr_bl *drbl;
	struct dr_bl *drbl1;

	for( drbl=drbl_lists ; drbl ; ) {
		drbl1 = drbl;
		drbl = drbl->next;
		shm_free(drbl1);
	}
}


int populate_dr_bls(map_t pgw_tree)
{
	unsigned int i,j;
	struct dr_bl *drbl;
	pgw_t *gw;
	struct bl_rule *drbl_first;
	struct bl_rule *drbl_last;
	struct net *gw_net;

	void** dest;
	map_iterator_t it;

	/* each bl list at a time */
	for( drbl=drbl_lists ; drbl ; drbl = drbl->next ) {
		if( drbl->part && drbl->part->rdata && drbl->part->rdata->pgw_tree == pgw_tree) { /* check if
			list applies to current
			partition */
			drbl_first = drbl_last = NULL;
			/* each type at a time */
			for ( i=0 ; i<drbl->no_types ; i++ ) {
				/* search in the GW list all GWs of this type */
				for (map_first(pgw_tree, &it);
					iterator_is_valid(&it); iterator_next(&it)) {
					dest = iterator_val(&it);
					if (dest==NULL)
						break;

					gw = (pgw_t*)*dest;

					if (gw->type==drbl->types[i]) {
						for ( j=0 ; j<gw->ips_no ; j++ ) {
							gw_net = mk_net_bitlen( &gw->ips[j],
								gw->ips[j].len*8);
							if (gw_net==NULL) {
								LM_ERR("failed to build net mask\n");
								continue;
							}
							/* add this destination to the BL */
							if( add_rule_to_list( &drbl_first, &drbl_last,
										gw_net,
										NULL/*body*/,
										gw->ports[j],
										gw->protos[j],
										0/*flags*/) < 0) {
								LM_ERR("Something went wrong when adding %s/%d"
									" to to blacklist %.*s\n",
									ip_addr2a(&gw->ips[j]), gw->type,
									drbl->bl->name.len, drbl->bl->name.s);
							} else {
							}
							pkg_free(gw_net);
						}
					}
				}
			}
			/* the new content for the BL */
			if (drbl->bl!=NULL && add_list_to_head( drbl->bl, drbl_first, drbl_last, 1, 0)!=0) {
				LM_ERR("failed to update bl\n");
				return -1;
			}
		}
	}

	return 0;
}

