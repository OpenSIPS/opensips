/*
 * Header file for PIKE MI functions
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
 *  2006-12-05  created (bogdan)
 */

#include <assert.h>

#include "../../resolve.h"

#include "ip_tree.h"
#include "pike_mi.h"

#define IPv6_LEN 16
#define IPv4_LEN 4
#define MAX_IP_LEN IPv6_LEN


static struct 		 ip_node *ip_stack[MAX_IP_LEN];
extern int    		 pike_log_level;


static inline void print_ip_stack( int level, struct mi_node *node)
{
	if (level==IPv6_LEN) {
		/* IPv6 */
		addf_mi_node_child( node, 0, 0, 0,
			"%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
			ip_stack[0]->byte,  ip_stack[1]->byte,
			ip_stack[2]->byte,  ip_stack[3]->byte,
			ip_stack[4]->byte,  ip_stack[5]->byte,
			ip_stack[6]->byte,  ip_stack[7]->byte,
			ip_stack[8]->byte,  ip_stack[9]->byte,
			ip_stack[10]->byte, ip_stack[11]->byte,
			ip_stack[12]->byte, ip_stack[13]->byte,
			ip_stack[14]->byte, ip_stack[15]->byte );
	} else if (level==IPv4_LEN) {
		/* IPv4 */
		addf_mi_node_child( node, 0, 0, 0, "%d.%d.%d.%d",
			ip_stack[0]->byte,
			ip_stack[1]->byte,
			ip_stack[2]->byte,
			ip_stack[3]->byte );
	} else {
		LM_CRIT("leaf node at depth %d!!!\n", level);
		return;
	}
}


static void print_red_ips( struct ip_node *ip, int level, struct mi_node *node)
{
	struct ip_node *foo;

	if (level==MAX_IP_LEN) {
		LM_CRIT("tree deeper than %d!!!\n", MAX_IP_LEN);
		return;
	}
	ip_stack[level] = ip;

	/* is the node marked red? */
	if ( ip->flags&NODE_ISRED_FLAG)
		print_ip_stack(level+1,node);

	/* go through all kids */
	foo = ip->kids;
	while(foo){
		print_red_ips( foo, level+1, node);
		foo = foo->next;
	}

}

struct mi_root* mi_pike_rm(struct mi_root *cmd, void *param)
{
    struct mi_node   *mn;
    struct ip_node   *node;
    struct ip_node   *kid;
    struct ip_addr   *ip;
    int byte_pos;

    mn = cmd->node.kids;
    if (mn==NULL)
	return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

    ip = str2ip(&mn->value);
    if (ip==0)
	return init_mi_tree( 500, "Bad IP", 6);

    node = 0;
    byte_pos = 0;

    kid = get_tree_branch((unsigned char)ip->u.addr[byte_pos]);

    /* pilfered from ip_tree.c:mark_node(..) */
    while (kid && byte_pos < ip->len) {
	while (kid && kid->byte!=(unsigned char)ip->u.addr[byte_pos]) {
	    kid = kid->next;
	}
	if (kid) {
	    node = kid;
	    kid = kid->kids;
	    byte_pos++;
	}
    }

    /* If all octets weren't matched, 404 */
    if (byte_pos!=ip->len) {
	return init_mi_tree( 404, "Match not found", 15);
    }

    /* If the node exists, check to see if it's really blocked */
    if (!(node->flags&NODE_ISRED_FLAG)) {
	return init_mi_tree( 400, "IP not blocked", 14);
    }

    /* reset the node block flag and counters */
    node->flags &= ~(NODE_ISRED_FLAG);

    node->hits[PREV_POS] = 0;
    node->hits[CURR_POS] = 0;
    node->leaf_hits[PREV_POS] = 0;
    node->leaf_hits[CURR_POS] = 0;

    LM_GEN1(pike_log_level,
	    "PIKE - UNBLOCKing ip %s, node=%p\n",ip_addr2a(ip),node);

    return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


/*
  Syntax of "pike_list" :
    no nodes
*/
struct mi_root* mi_pike_list(struct mi_root* cmd_tree, void* param)
{
	struct mi_root* rpl_tree;
	struct ip_node *ip;
	int i;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl_tree->node.flags |= MI_IS_ARRAY;

	for( i=0 ; i<MAX_IP_BRANCHES ; i++ ) {

		if (get_tree_branch(i)==0)
			continue;

		lock_tree_branch(i);

		if ( (ip=get_tree_branch(i))!=NULL )
			print_red_ips( ip, 0, &rpl_tree->node );

		unlock_tree_branch(i);
	}

	return rpl_tree;
}


