/*
 * Permissions MI functions
 *
 * Copyright (C) 2006 Juha Heinanen
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
 *  2006-10-16  created (juhe)
 */


#include "../../dprint.h"
#include "address.h"
#include "hash.h"
#include "mi.h"
#include "permissions.h"


/*
 * MI function to reload address table
 */
struct mi_root* mi_address_reload(struct mi_root *cmd_tree, void *param)
{
	struct mi_node *node = NULL;
	struct pm_part_struct *it, *ps;
	char errbuf[100] = "failed to reload partition ";
	int errlen = strlen(errbuf);

	if (cmd_tree)
		node = cmd_tree->node.kids;

	if (node == NULL) {
		/* reload all partitions */
		for (it=get_part_structs(); it; it = it->next) {
			if (it->hash_table == NULL)
				continue;

			sprintf(errbuf + errlen, " %.*s!", it->name.len, it->name.s);
			LM_DBG("trying to reload address table for %.*s\n",
										it->name.len, it->name.s);
			if (reload_address_table(it) != 1)
				return init_mi_tree( 400, MI_SSTR(errbuf));
		}

		return init_mi_tree( 200, MI_SSTR(MI_OK));
	} else {
		/* reload requested partition */
		ps = get_part_struct(&node->value);
		if (ps == NULL)
			goto err;
		if (ps->hash_table == NULL)
			return init_mi_tree( 200, MI_SSTR(MI_OK));
		LM_INFO("trying to reload address table for %.*s\n",
										ps->name.len, ps->name.s);
		if (reload_address_table(ps) == 1)
			return init_mi_tree( 200, MI_SSTR(MI_OK));
	}

err:
	return init_mi_tree( 400, MI_SSTR("Trusted table reload failed"));
}


/*
 * MI function to print address entries from current hash table
 */
struct mi_root* mi_address_dump(struct mi_root *cmd_tree, void *param)
{
	struct mi_root* rpl_tree;
	struct mi_node *node = NULL, *part_node;
	struct pm_part_struct *it, *ps;

	if (cmd_tree)
		node = cmd_tree->node.kids;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree == NULL)
		return NULL;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	if (node == NULL) {
		/* dump all partitions */
		for (it=get_part_structs(); it; it = it->next) {
			if (it->hash_table == NULL)
				continue;

			part_node = add_mi_node_child(&rpl_tree->node, MI_IS_ARRAY, "part", 4,
				it->name.s, it->name.len);
			if (part_node == NULL) {
				LM_ERR("failed to add MI node for part %.*s\n",
				       it->name.len, it->name.s);
				return NULL;
			}

			if(hash_mi_print(*it->hash_table, part_node, it)< 0) {
				LM_ERR("failed to add a node\n");
				free_mi_tree(rpl_tree);
				return 0;
			}
		}
	} else {
		/* dump only requested partition */
		ps = get_part_struct(&node->value);
		if (ps == NULL)
			return init_mi_tree(404, MI_SSTR("No such partition"));
		if (ps->hash_table == NULL)
			return init_mi_tree( 200, MI_SSTR(MI_OK));
		part_node = add_mi_node_child(&rpl_tree->node, MI_IS_ARRAY, "part", 4,
		                              ps->name.s, ps->name.len);
		if (part_node == NULL) {
			LM_ERR("failed to add MI node for part %.*s\n",
			       ps->name.len, ps->name.s);
			return NULL;
		}
		if(hash_mi_print(*ps->hash_table, &rpl_tree->node, ps)< 0) {
			LM_ERR("failed to add a node\n");
			free_mi_tree(rpl_tree);
			return 0;
		}
	}

	return rpl_tree;
}


#define MAX_FILE_LEN 128

/*
 * MI function to make allow_uri query.
 */
struct mi_root* mi_allow_uri(struct mi_root *cmd, void *param)
{
    struct mi_node *node;
    str *basenamep, *urip, *contactp;
    char basename[MAX_FILE_LEN + 1];
    char uri[MAX_URI_SIZE + 1], contact[MAX_URI_SIZE + 1];
    unsigned int allow_suffix_len;

    node = cmd->node.kids;
    if (node == NULL || node->next == NULL || node->next->next == NULL ||
	node->next->next->next != NULL)
	return init_mi_tree(400, MI_SSTR(MI_MISSING_PARM));

    /* look for base name */
    basenamep = &node->value;
    if (basenamep == NULL)
	return init_mi_tree(404, MI_SSTR("Basename is NULL"));
    allow_suffix_len = strlen(allow_suffix);
    if (basenamep->len + allow_suffix_len + 1 > MAX_FILE_LEN)
	return init_mi_tree(404, MI_SSTR("Basename is too long"));
    memcpy(basename, basenamep->s, basenamep->len);
    memcpy(basename + basenamep->len, allow_suffix, allow_suffix_len);
    basename[basenamep->len + allow_suffix_len] = 0;

    /* look for uri */
    urip = &node->next->value;
    if (urip == NULL)
	return init_mi_tree(404, MI_SSTR("URI is NULL"));
    if (urip->len > MAX_URI_SIZE)
	return init_mi_tree(404, MI_SSTR("URI is too long"));
    memcpy(uri, urip->s, urip->len);
    uri[urip->len] = 0;

    /* look for contact */
    contactp = &node->next->next->value;
    if (contactp == NULL)
	return init_mi_tree(404, MI_SSTR("Contact is NULL"));
    if (contactp->len > MAX_URI_SIZE)
	return init_mi_tree(404, MI_SSTR("Contact is too long"));
    memcpy(contact, contactp->s, contactp->len);
    contact[contactp->len] = 0;

    if (allow_test(basename, uri, contact) == 1) {
	return init_mi_tree(200, MI_SSTR(MI_OK));
    } else {
	return init_mi_tree(403, MI_SSTR("Forbidden"));
    }
}

/*
 * MI function to print subnets from current subnet table
 */
struct mi_root* mi_subnet_dump(struct mi_root *cmd_tree, void *param)
{
	struct mi_root* rpl_tree;
	struct mi_node *node = NULL, *part_node;
	struct pm_part_struct *it, *ps;

	if (cmd_tree)
		node = cmd_tree->node.kids;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree == NULL)
		return NULL;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	if (node == NULL) {
		/* dump all subnets */
		for (it=get_part_structs(); it; it = it->next) {
			if (it->subnet_table == NULL)
				continue;

			part_node = add_mi_node_child(&rpl_tree->node, MI_IS_ARRAY, "part", 4,
				it->name.s, it->name.len);
			if (part_node == NULL) {
				LM_ERR("failed to add MI node for part %.*s\n",
				       it->name.len, it->name.s);
				return NULL;
			}

			if (subnet_table_mi_print(*it->subnet_table, part_node, it) <  0) {
				LM_ERR("failed to add a node\n");
				free_mi_tree(rpl_tree);
				return 0;
			}
		}
	} else {
		ps = get_part_struct(&node->value);
		if (ps == NULL)
			return init_mi_tree(404, MI_SSTR("No such partition"));
		if (ps->subnet_table == NULL)
			return init_mi_tree( 200, MI_SSTR(MI_OK));

		part_node = add_mi_node_child(&rpl_tree->node, MI_IS_ARRAY, "part", 4,
			ps->name.s, ps->name.len);
		if (part_node == NULL) {
			LM_ERR("failed to add MI node for part %.*s\n",
			       ps->name.len, ps->name.s);
			return NULL;
		}

		if (subnet_table_mi_print(*ps->subnet_table, part_node, ps) <  0) {
			LM_ERR("failed to add a node\n");
			free_mi_tree(rpl_tree);
			return 0;
		}

		/* dump requested subnet*/
		if (subnet_table_mi_print(*ps->subnet_table, part_node, ps) <  0) {
			LM_ERR("failed to add a node\n");
			 free_mi_tree(rpl_tree);
			return 0;
		}
	}

	return rpl_tree;
}
