/*
 * Domain MI functions
 *
 * Copyright (C) 2006 Voice Sistem SRL
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
 *
 * History:
 * --------
 *  2006-10-05  created (bogdan)
 */


#include "../../dprint.h"
#include "../../db/db.h"
#include "domain_mod.h"
#include "domain.h"
#include "hash.h"
#include "mi.h"


/*
 * MI function to reload domain table
 */
struct mi_root* mi_domain_reload(struct mi_root *cmd_tree, void *param)
{
	if(db_mode==0)
		return init_mi_tree( 500, "command not activated", 21);

	if (reload_domain_table () == 1) {
		return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	} else {
		return init_mi_tree( 500, "Domain table reload failed", 26);
	}
}


/*
 * MI function to print domains from current hash table
 */
struct mi_root* mi_domain_dump(struct mi_root *cmd_tree, void *param)
{
	struct mi_root* rpl_tree;

	if(db_mode==0)
		return init_mi_tree( 500, "command not activated", 21);

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL)
		return 0;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	if(hash_table_mi_print(*hash_table, &rpl_tree->node)< 0)
	{
		LM_ERR("Error while adding node\n");
		free_mi_tree(rpl_tree);
		return 0;
	}

	return rpl_tree;
}
