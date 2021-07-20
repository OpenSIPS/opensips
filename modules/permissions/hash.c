/*
 * Hash table functions
 *
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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


#include "hash.h"
#include "../../mem/shm_mem.h"
#include "../../hash_func.h"
#include "../../ip_addr.h"
#include "../../ut.h"
#include "../../pvar.h"
#include "../../route_struct.h"
#include "../../resolve.h"
#include "../../socket_info.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fnmatch.h>
//#include <regex.h>

#define perm_hash(_s)  core_hash( &(_s), NULL, PERM_HASH_SIZE)

struct network_list** pm_hash_create(void) {
	struct network_list** ptr;

	/* Initializing hash tables and hash table variable */
	ptr = (struct network_list **)shm_malloc
		(sizeof(struct network_list*) * PERM_HASH_SIZE);
	if (!ptr) {
		LM_ERR("no shm memory for hash table\n");
		return 0;
	}

	memset(ptr, 0, sizeof(struct network_list*) * PERM_HASH_SIZE);
	return ptr;
}


void pm_hash_destroy(struct network_list** table) {
	if (!table) {
		LM_ERR("trying to destroy an empty hash table\n");
		return;
	}
	pm_empty_hash(table);
	shm_free(table);
}

int pm_hash_insert(struct network_list** table, struct net *network,
		  unsigned int grp, unsigned int port, int proto, str* pattern,
		  str* info) {

	struct network_list *node;
	unsigned int hash_val;
	str str_ip;

	node = (struct network_list*) shm_malloc (sizeof(struct network_list));
	if (!node) {
		LM_ERR("no shm memory left\n");
		return -1;
	}

	node->proto = proto;
	node->network = (struct net *) shm_malloc (sizeof(struct net));

	if (!node->network) {
		LM_ERR("cannot allocate shm memory for net struct\n");
		shm_free(node);
		return -1;
	}

	memcpy(node->network, network, sizeof(struct net));

	if (pattern->len) {
		node->pattern = (char *) shm_malloc(pattern->len + 1);
		if (!node->pattern) {
			LM_ERR("cannot allocate shm memory for pattern string\n");
			shm_free(node->network);
			shm_free(node);
			return -1;
		}
		memcpy(node->pattern, pattern->s, pattern->len);
		node->pattern[pattern->len] = 0;
	} else {
		node->pattern = NULL;
	}

	if (info->len) {
		node->info = (char *) shm_malloc(info->len + 1);
		if (!node->info) {
			LM_CRIT("cannot allocate shm memory for context info string\n");
			shm_free(node->network);
			if (node->pattern) shm_free(node->pattern);
			shm_free(node);
			return -1;
		}
		memcpy(node->info, info->s, info->len);
		node->info[info->len] = '\0';
	} else {
		node->info = NULL;
	}

    node->grp = grp;
    node->port = port;

	str_ip.len = network->ip.len;
	str_ip.s = (char*)network->ip.u.addr;

	hash_val = perm_hash(str_ip);

	node->next = table[hash_val];
	table[hash_val] = node;

	return 1;
}


int pm_hash_match(struct sip_msg *msg, struct network_list** table,
		unsigned int grp, struct ip_addr *ip, unsigned int port, int proto,
		char *pattern, pv_spec_t *info) {

	struct network_list *node;
	str str_ip;
	pv_value_t pvt;
	int i, match_res;

	if (grp != GROUP_ANY) {
		for (i = 0; i < PERM_HASH_SIZE; i++) {
			for (node = table[i]; node; node = node->next) {
				if (node->grp == grp) {
					goto grp_found;
				}
			}
		}

		/* group not found */
		if (!node) {
			LM_DBG("specified group %u does not exist in hash table\n", grp);
			return -2;
		}
	}

grp_found:

	str_ip.len = ip->len;
	str_ip.s = (char*)ip->u.addr;

	for (node = table[perm_hash(str_ip)]; node; node = node->next) {
/*	 		LM_DBG("Comparing (%s %s) , (%d %d) , (%d %d) , (%d %d)\n",
				ip_addr2a(node->ip), ip_addr2a(ip),
				node->proto, proto,
				node->port , port,
				node->grp , grp);
*/

		if	((node->grp == GROUP_ANY || node->grp == grp
					|| grp == GROUP_ANY) &&
			(node->proto == PROTO_NONE || node->proto == proto
			 		|| proto == PROTO_NONE ) &&
			(node->port == PORT_ANY || node->port == port
			 		|| port == PORT_ANY) &&
			ip_addr_cmp(ip, &node->network->ip)) {
				if (!node->pattern || !pattern) {
					LM_DBG("no pattern to match\n");
					goto found;
				}

				match_res = fnmatch(node->pattern, pattern, FNM_PERIOD);
				if (!match_res) {
					LM_DBG("pattern match\n");
					goto found;
				}
				if (match_res != FNM_NOMATCH) {
					LM_ERR("fnmatch failed\n");
					return -1;
				}
	    }
	}

	LM_DBG("no match in the hash table\n");
	return -1;

found:
	if (info) {
		pvt.flags = PV_VAL_STR;
		pvt.rs.s = node->info;
		pvt.rs.len = node->info ? strlen(node->info) : 0;

		if (pv_set_value(msg, info, (int)EQ_T, &pvt) < 0) {
			LM_ERR("setting of avp failed\n");
			return -1;
	    }
	}

	LM_DBG("match found in the hash table\n");
	return 1;
}


/*
 * Check if an ip_addr/port entry exists in hash table in any group.
 * Returns first group in which ip_addr/port is found.
 * Port 0 in hash table matches any port.
 */
int find_group_in_hash_table(struct network_list** table,
		                  struct ip_addr *ip, unsigned int port)
{
	struct network_list *node;
	str str_ip;

	if (ip == NULL){
		return -1;
	}

	str_ip.len = ip->len;
	str_ip.s = (char*) ip->u.addr;

	for (node = table[perm_hash(str_ip)]; node; node = node->next) {
			if ( (node->port == 0 || node->port == port) &&
			ip_addr_cmp(ip, &node->network->ip) )
				return node->grp;
	}
	return -1;
}




int pm_hash_mi_print(struct network_list **table, mi_item_t *dests_arr,
		struct pm_part_struct *pm)
{
	int i, len;
	struct network_list *node;
	char *p, prbuf[PROTO_NAME_MAX_SIZE];
	mi_item_t *dest_item;

	for (i = 0; i < PERM_HASH_SIZE; i++) {
		for (node = table[i]; node; node=node->next) {
			dest_item = add_mi_object(dests_arr, NULL, 0);
			if (!dest_item)
				return -1;

			if (add_mi_number(dest_item, MI_SSTR("grp"), node->grp) < 0)
				return -1;

			p = ip_addr2a(&node->network->ip);
			if (add_mi_string(dest_item, MI_SSTR("ip"), p, strlen(p)) < 0)
				return -1;

			p = ip_addr2a(&node->network->mask);
			if (add_mi_string(dest_item, MI_SSTR("mask"), p, strlen(p)) < 0)
				return -1;

			if (add_mi_number(dest_item, MI_SSTR("port"), node->port) < 0)
				return -1;

			if (node->proto == PROTO_NONE) {
				p = "any";
				len = 3;
			} else {
				p = proto2str(node->proto, prbuf);
				len = p - prbuf;
				p = prbuf;
			}
			if (add_mi_string(dest_item, MI_SSTR("proto"), p, len) < 0)
				return -1;

			if (add_mi_string(dest_item, MI_SSTR("pattern"),
				node->pattern,
			    node->pattern ? strlen(node->pattern) : 0) < 0)
			    return -1;

			if (add_mi_string(dest_item, MI_SSTR("context_info"),
				node->info,
			    node->info ? strlen(node->info) : 0) < 0)
			    return -1;
		}
	}

	return 0;
}

void pm_empty_hash(struct network_list** table) {
	int i;

	struct network_list *node = NULL, *next = NULL;

	for (i = 0; i < PERM_HASH_SIZE; i++) {
		for (node = table[i]; node; node = next) {
			next = node->next;
			if (node->network) shm_free(node->network);
			if (node->pattern) shm_free(node->pattern);
			if (node->info) shm_free(node->info);
			shm_free(node);
		}
		table[i] = 0;
	}
}


/*
 * Create and initialize a networks table
 */
struct netmask_list* new_netmask_table(void)
{
	int i;
	struct netmask_list* ptr;

	ptr = (struct netmask_list *)shm_malloc
	      (sizeof(struct netmask_list) * 129);

	if (!ptr) {
		LM_ERR("no shm memory for networks table\n");
		return 0;
	}

	memset(ptr, 0, sizeof(struct netmask_list) * 129);
	for (i = 0; i < 129; i++) {
		ptr[i].bitlen = i;
	}

	return ptr;
}


/*
 * Empty contents of networks table
 */
void empty_netmask_table(struct netmask_list *table)
{
	int i;

	for (i = 0; i < 129; i++) {
		if (table[i].hash_table) {
			pm_hash_destroy(table[i].hash_table);
			table[i].hash_table = NULL;
		}
		table[i].next = NULL;
	}
}


/*
 * Release memory allocated for a networks table
 */
void free_netmask_table(struct netmask_list* table)
{
	empty_netmask_table(table);

	if (table)
	    shm_free(table);
}
