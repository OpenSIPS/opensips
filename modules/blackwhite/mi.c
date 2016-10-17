/*
 *
 * Blackwhite MI functions
 *
 * Copyright (C) 2016 ipport.net
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


#include "../../dprint.h"
#include "../../str.h"
#include "../../ip_addr.h"
#include "mi.h"
#include "address.h"

extern int reload_bw_data(void);


static inline int bw_read_list(str *id, int black, struct address_node *node, struct mi_node *rpl)
{
	size_t n = 0;

	while (node)
	{
		if (addf_mi_node_child(rpl, 0, 0, 0,
				"%.*s\t%s/%s\t%d",
				   id->len, id->s,
				   ip_addr2a(&node->subnet->ip),
				   ip_addr2a(&node->subnet->mask),
				   black) == 0)
			return -1;
		node = node->next;
		++n;
	}
	return n;
}


static int bw_read(struct address *data, size_t data_n, struct mi_node *rpl)
{
	int i;
	for (i=0; i<data_n; ++i)
	{
		if (data[i].black && bw_read_list(&(data[i].id), 1, data[i].black, rpl) < 0) return -1;
		if (data[i].white && bw_read_list(&(data[i].id), 0, data[i].white, rpl) < 0) return -1;
	}
	return 0;
}


/*
 * MI function to reload address table
 */
struct mi_root* mi_bw_reload(struct mi_root *cmd_tree, void *param)
{
	if (reload_bw_data() == 0)
		return init_mi_tree( 200, MI_SSTR(MI_OK));

	return init_mi_tree( 400, MI_SSTR("Blackwhite table reload failed"));
}


/*
 * MI function to print address entries from current hash table
 */
struct mi_root* mi_bw_dump(struct mi_root *cmd_tree, void *param)
{
	struct mi_root* rpl_tree;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree == NULL) return 0;

	if(bw_read((*cur_data)->addrs, (*cur_data)->data_n, &rpl_tree->node) < 0) {
		LM_ERR("failed to add a node\n");
		free_mi_tree(rpl_tree);
		return 0;
	}

	return rpl_tree;
}
