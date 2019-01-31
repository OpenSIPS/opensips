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


static inline int print_ip_stack( int level, mi_item_t *ips_arr)
{
	if (level==IPv6_LEN) {
		/* IPv6 */
		if (add_mi_string_fmt(ips_arr, 0, 0,
			"%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
			ip_stack[0]->byte,  ip_stack[1]->byte,
			ip_stack[2]->byte,  ip_stack[3]->byte,
			ip_stack[4]->byte,  ip_stack[5]->byte,
			ip_stack[6]->byte,  ip_stack[7]->byte,
			ip_stack[8]->byte,  ip_stack[9]->byte,
			ip_stack[10]->byte, ip_stack[11]->byte,
			ip_stack[12]->byte, ip_stack[13]->byte,
			ip_stack[14]->byte, ip_stack[15]->byte) < 0)
			return -1;
	} else if (level==IPv4_LEN) {
		/* IPv4 */
		if (add_mi_string_fmt(ips_arr, 0, 0, "%d.%d.%d.%d",
			ip_stack[0]->byte,
			ip_stack[1]->byte,
			ip_stack[2]->byte,
			ip_stack[3]->byte) < 0)
			return -1;
	} else {
		LM_CRIT("leaf node at depth %d!!!\n", level);
		return -1;
	}

	return 0;
}


static int print_red_ips( struct ip_node *ip, int level, mi_item_t *ips_arr)
{
	struct ip_node *foo;

	if (level==MAX_IP_LEN) {
		LM_CRIT("tree deeper than %d!!!\n", MAX_IP_LEN);
		return -1;
	}
	ip_stack[level] = ip;

	/* is the node marked red? */
	if ( ip->flags&NODE_ISRED_FLAG)
		if (print_ip_stack(level+1,ips_arr) < 0)
			return -1;

	/* go through all kids */
	foo = ip->kids;
	while(foo){
		if (print_red_ips( foo, level+1, ips_arr) < 0)
			return -1;
		foo = foo->next;
	}

	return 0;
}

mi_response_t *mi_pike_rm(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
    struct ip_node   *node;
    struct ip_node   *kid;
    struct ip_addr   *ip;
    int byte_pos;
    str ip_param;

    if (get_mi_string_param(params, "ip", &ip_param.s, &ip_param.len) < 0)
		return init_mi_param_error();

    ip = str2ip(&ip_param);
    if (ip==0)
	return init_mi_error(500, MI_SSTR("Bad IP"));

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
	return init_mi_error(404, MI_SSTR("Match not found"));
    }

    /* If the node exists, check to see if it's really blocked */
    if (!(node->flags&NODE_ISRED_FLAG)) {
	return init_mi_error(400, MI_SSTR("IP not blocked"));
    }

    /* reset the node block flag and counters */
    node->flags &= ~(NODE_ISRED_FLAG);

    node->hits[PREV_POS] = 0;
    node->hits[CURR_POS] = 0;
    node->leaf_hits[PREV_POS] = 0;
    node->leaf_hits[CURR_POS] = 0;

    LM_GEN1(pike_log_level,
	    "PIKE - UNBLOCKing ip %s, node=%p\n",ip_addr2a(ip),node);

    return init_mi_result_ok();
}


/*
  Syntax of "pike_list" :
    no nodes
*/
mi_response_t *mi_pike_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct ip_node *ip;
	int i;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *ips_arr;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	ips_arr = add_mi_array(resp_obj, MI_SSTR("IPs"));
	if (!ips_arr)
		goto error;

	for( i=0 ; i<MAX_IP_BRANCHES ; i++ ) {

		if (get_tree_branch(i)==0)
			continue;

		lock_tree_branch(i);

		if ( (ip=get_tree_branch(i))!=NULL )
			if (print_red_ips(ip, 0, ips_arr) < 0)
				goto error;

		unlock_tree_branch(i);
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}


