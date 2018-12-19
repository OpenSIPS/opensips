/**
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <string.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../ip_addr.h"

#include "lb_bl.h"

static struct lb_bl *lb_blists = NULL;

static char **blacklists = NULL;
static unsigned int bl_size = 0;


int set_lb_bl(modparam_t type, void *val)
{
	blacklists = pkg_realloc( blacklists, (bl_size+1) * sizeof(*blacklists));
	if (blacklists == NULL) {
		bl_size = 0;
		LM_ERR("REALLOC failed.\n");
		return -1;
	}
	blacklists[bl_size] = (char*)val;
	bl_size++;

	return 0;
}


int init_lb_bls(void)
{
	unsigned int i;
	struct lb_bl *lbbl;
	str name;
	str val;
	char *p;

	LM_DBG("Initialising lb blacklists\n");

	if (blacklists == NULL)
		return 0;

	for(i = 0; i < bl_size; i++ ) {
		LM_DBG("Processing bl definition <%s>\n", blacklists[i]);
		/* get name */
		p = strchr( blacklists[i], '=');
		if (p==NULL || p==blacklists[i]) {
			LM_ERR("blacklist definition <%s> has no name", blacklists[i]);
			return -1;
		}
		name.s = blacklists[i];
		name.len = p - name.s;
		trim(&name);
		if (name.len == 0) {
			LM_ERR("empty name in blacklist definition <%s>\n", blacklists[i]);
			return -1;
		}
		LM_DBG("found list name <%.*s>\n", name.len, name.s);
		/* alloc structure */
		lbbl = shm_malloc(sizeof(*lbbl));
		if (lbbl == NULL) {
			LM_ERR("no more shme memory\n");
			return -1;
		}
		memset(lbbl, 0, sizeof(*lbbl));
		/* fill in the types */
		p++;
		do {
			if (lbbl->no_groups == LB_BL_MAX_SETS) {
				LM_ERR("too many types per rule <%s>\n", blacklists[i]);
				shm_free(lbbl);
				return -1;
			}
			val.s = p;
			p = strchr( p, ',');
			if (p == NULL) {
				val.len = strlen(val.s);
			} else {
				val.len = (int)(long)(p - val.s);
				p++;
			}
			trim(&val);
			if (val.len == 0) {
				LM_ERR("invalid types listing in <%s>\n", blacklists[i]);
				shm_free(lbbl);
				return -1;
			}
			LM_DBG("found type <%.*s>\n", val.len, val.s);
			if (str2int( &val, &lbbl->groups[lbbl->no_groups])!=0) {
				LM_ERR("nonnumerical type <%.*s>\n", val.len, val.s);
				shm_free(lbbl);
				return -1;
			}
			lbbl->no_groups++;
		} while(p != NULL);

		pkg_free(blacklists[i]);
		blacklists[i] = NULL;

		/* create backlist for it */
		lbbl->bl = create_bl_head( 131131, 0/*flags*/, NULL, NULL, &name);
		if (lbbl->bl == NULL) {
			LM_ERR("CREATE bl <%.*s> failed.\n", name.len, name.s);
			shm_free(lbbl);
			return -1;
		}

		/* link it */
		lbbl->next = lb_blists;
		lb_blists = lbbl;
	}

	pkg_free(blacklists);
	blacklists = NULL;

	return 0;
}


void destroy_lb_bls(void)
{
	struct lb_bl *lbbl;

	while ((lbbl = lb_blists)) {
		lb_blists = lb_blists->next;
		shm_free(lbbl);
	}
}


int populate_lb_bls(struct lb_dst *dest_list)
{
	unsigned int i,j;
	struct lb_bl *lbbl;
	struct bl_rule *lbbl_first;
	struct bl_rule *lbbl_last;
	struct net *group_net;
	struct lb_dst *dst;

	LM_DBG("Updating lb blacklists...\n");

	/* each bl list at a time */
	for(lbbl = lb_blists; lbbl; lbbl = lbbl->next) {
		lbbl_first = lbbl_last = NULL;
		/* each group at a time */
		for (i = 0; i < lbbl->no_groups; i++) {
		LM_DBG("Searching for group [%d]\n", lbbl->groups[i]);
			/* search in the group list all groups of this type */
			for(dst = dest_list; dst; dst = dst->next) {
				LM_DBG("Checking dest group %d\n", dst->group);
				if (dst->group == lbbl->groups[i]) {
					LM_DBG("Group [%d] matches. Adding all IPs\n", dst->group);
					for ( j=0 ; j<dst->ips_cnt ; j++ ) {
						group_net = mk_net_bitlen( &dst->ips[j],
							dst->ips[j].len*8);
						if (group_net == NULL) {
							LM_ERR("BUILD netmask failed.\n");
							continue;
						}
						/* add this destination to the BL */
						add_rule_to_list( &lbbl_first, &lbbl_last,
							group_net,
							NULL/*body*/,
							dst->ports[j],
							dst->protos[j],
							0/*flags*/);
						pkg_free(group_net);
					}
				}
			}
		}

		/* the new content for the BL */
		if(lbbl->bl && add_list_to_head(lbbl->bl,lbbl_first,lbbl_last,1,0)!=0){
			LM_ERR("UPDATE blacklist failed.\n");
			return -1;
		}
	}

	return 0;
}

