/**
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 * 2012-09-24  created (liviuchircu)
 *
 */

#include <string.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../ip_addr.h"

#include "ds_bl.h"

static struct ds_bl *dsbl_lists = NULL;

static char **blacklists = NULL;
static unsigned int bl_size = 0;


int set_ds_bl(modparam_t type, void *val)
{
	blacklists = pkg_realloc( blacklists, (bl_size+1) * sizeof(*blacklists));
	if (blacklists == NULL) {
		LM_ERR("REALLOC failed.\n");
		return -1;
	}
	blacklists[bl_size] = (char*)val;
	bl_size++;

	return 0;
}


int init_ds_bls(void)
{
	unsigned int i;
	struct ds_bl *dsbl;
	str name;
	str val;
	char *p;

	LM_DBG("Initialising ds blacklists\n");

	if (blacklists == NULL)
		return 0;

	for(i = 0; i < bl_size; i++ ) {
		LM_DBG("processing bl definition <%s>\n", blacklists[i]);
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
		dsbl = shm_malloc(sizeof(*dsbl));
		if (dsbl == NULL) {
			LM_ERR("no more shme memory\n");
			return -1;
		}
		memset(dsbl, 0, sizeof(*dsbl));
		/* fill in the types */
		p++;
		do {
			if (dsbl->no_sets == DS_BL_MAX_SETS) {
				LM_ERR("too many types per rule <%s>\n", blacklists[i]);
				shm_free(dsbl);
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
				shm_free(dsbl);
				return -1;
			}
			LM_DBG("found type <%.*s>\n", val.len, val.s);
			if (str2int( &val, &dsbl->sets[dsbl->no_sets])!=0) {
				LM_ERR("nonnumerical type <%.*s>\n", val.len, val.s);
				shm_free(dsbl);
				return -1;
			}
			dsbl->no_sets++;
		} while(p != NULL);

		pkg_free(blacklists[i]);
		blacklists[i] = NULL;

		/* create backlist for it */
		dsbl->bl = create_bl_head( 313131, 0/*flags*/, NULL, NULL, &name);
		if (dsbl->bl == NULL) {
			LM_ERR("CREATE bl <%.*s> failed.\n", name.len, name.s);
			shm_free(dsbl);
			return -1;
		}

		/* link it */
		dsbl->next = dsbl_lists;
		dsbl_lists = dsbl;
	}

	pkg_free(blacklists);
	blacklists = NULL;

	return 0;
}


void destroy_ds_bls(void)
{
	struct ds_bl *dsbl;

	while ((dsbl = dsbl_lists)) {
		dsbl_lists = dsbl_lists->next;
		shm_free(dsbl);
	}
}


int populate_ds_bls( ds_set_t *sets)
{
	unsigned int i,k;
	struct ds_bl *dsbl;
	ds_set_p set;
	ds_dest_p dst;
	struct bl_rule *dsbl_first;
	struct bl_rule *dsbl_last;
	struct net *set_net;

	LM_DBG("Updating ds blacklists...\n");

	/* each bl list at a time */
	for(dsbl = dsbl_lists; dsbl; dsbl = dsbl->next) {
		dsbl_first = dsbl_last = NULL;
		/* each blacklisted set at a time */
		for (i = 0; i < dsbl->no_sets; i++) {
			/* search if any set matches the one above */
			for( set=sets ; set ; set = set->next) {
				if (set->id == dsbl->sets[i]) {
					LM_DBG("Set [%d] matches. Adding all destinations:\n",
						set->id);
					for (dst = set->dlist; dst; dst = dst->next) {
						/* and add all IPs for each destination */
						for( k=0 ; k<dst->ips_cnt ; k++ ) {
							//print_ip(NULL, &dst->ips[k], "\n");
							set_net = mk_net_bitlen( &dst->ips[k],
												 dst->ips[k].len*8);
							if (set_net == NULL) {
								LM_ERR("BUILD netmask failed.\n");
								continue;
							}
							/* add this destination to the BL */
							add_rule_to_list( &dsbl_first, &dsbl_last,
								set_net,
								NULL/*body*/,
								dst->ports[k],
								dst->protos[k],
								0/*flags*/);
							pkg_free(set_net);
						}
					}
				}
			}
		}

		/* the new content for the BL */
		if (dsbl->bl && add_list_to_head( dsbl->bl, dsbl_first, dsbl_last, 1, 0)
						!= 0) {
			LM_ERR("UPDATE blacklist failed.\n");
			return -1;
		}
	}

	return 0;
}

