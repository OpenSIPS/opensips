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

#define perm_hash(_s)  core_hash( &(_s), 0, PERM_HASH_SIZE)

struct address_list** hash_create(void) {
	struct address_list** ptr;

	/* Initializing hash tables and hash table variable */
	ptr = (struct address_list **)shm_malloc
		(sizeof(struct address_list*) * PERM_HASH_SIZE);
	if (!ptr) {
		LM_ERR("no shm memory for hash table\n");
		return 0;
	}

	memset(ptr, 0, sizeof(struct address_list*) * PERM_HASH_SIZE);
	return ptr;
}


void hash_destroy(struct address_list** table) {
	if (!table) {
		LM_ERR("trying to destroy an empty hash table\n");
		return;
	}
	empty_hash(table);
	shm_free(table);
}

int hash_insert(struct address_list** table, struct ip_addr *ip,
		  unsigned int grp, unsigned int port, int proto, str* pattern,
		  str* info) {

	struct address_list *node;
	unsigned int hash_val;
	str str_ip;

	node = (struct address_list*) shm_malloc (sizeof(struct address_list));
	if (!node) {
		LM_ERR("no shm memory left\n");
		return -1;
	}

	node->proto = proto;
	node->ip = (struct ip_addr *) shm_malloc (sizeof(struct ip_addr));

	if (!node->ip) {
		LM_ERR("cannot allocate shm memory for ip_addr struct\n");
		shm_free(node);
		return -1;
	}

	memcpy(node->ip, ip, sizeof(struct ip_addr));

	if (pattern->len) {
		node->pattern = (char *) shm_malloc(pattern->len + 1);
		if (!node->pattern) {
			LM_ERR("cannot allocate shm memory for pattern string\n");
			shm_free(node->ip);
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
			shm_free(node->ip);
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

	str_ip.len = ip->len;
	str_ip.s = (char*)ip->u.addr;

	hash_val = perm_hash(str_ip);

	node->next = table[hash_val];
	table[hash_val] = node;

	return 1;
}


int hash_match(struct sip_msg *msg, struct address_list** table,
		unsigned int grp, struct ip_addr *ip, unsigned int port, int proto,
		char *pattern, char *info) {

	struct address_list *node;
	str str_ip;
	pv_spec_t *pvs;
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
			ip_addr_cmp(ip, node->ip)) {
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
		pvs = (pv_spec_t *)info;
		memset(&pvt, 0, sizeof(pv_value_t));
		pvt.flags = PV_VAL_STR;

		pvt.rs.s = node->info;
		pvt.rs.len = node->info ? strlen(node->info) : 0;

		if (pv_set_value(msg, pvs, (int)EQ_T, &pvt) < 0) {
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
int find_group_in_hash_table(struct address_list** table,
		                  struct ip_addr *ip, unsigned int port)
{
	struct address_list *node;
	str str_ip;

	if (ip == NULL){
		return -1;
	}

	str_ip.len = ip->len;
	str_ip.s = (char*) ip->u.addr;

	for (node = table[perm_hash(str_ip)]; node; node = node->next) {
			if ( (node->port == 0 || node->port == port) &&
			ip_addr_cmp(ip, node->ip) )
				return node->grp;
	}
	return -1;
}




int hash_mi_print(struct address_list **table, struct mi_node* rpl,
		struct pm_part_struct *pm) {
	int i, len;
    struct address_list *node;
	struct mi_node *dst;
	char *p, prbuf[PROTO_NAME_MAX_SIZE];

    for (i = 0; i < PERM_HASH_SIZE; i++) {
		for (node = table[i]; node; node=node->next) {

			dst = add_mi_node_child(rpl, 0, MI_SSTR("dest"), NULL, 0);
			if (!dst) {
				LM_ERR("oom!\n");
				return -1;
			}

			p = int2str(node->grp, &len);
			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("grp"), p, len)) {
				goto out_free;
			}

			p = ip_addr2a(node->ip);
			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("ip"), p, strlen(p))) {
				goto out_free;
			}

			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("mask"), MI_SSTR("32"))) {
				goto out_free;
			}

			p = int2str(node->port, &len);
			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("port"), p, len)) {
				goto out_free;
			}

			if (node->proto == PROTO_NONE) {
				p = "any";
				len = 3;
			} else {
				p = proto2str(node->proto, prbuf);
				len = p - prbuf;
				p = prbuf;
			}
			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("proto"), p, len)) {
				goto out_free;
			}

			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("pattern"),
			                 node->pattern,
			                 node->pattern ? strlen(node->pattern) : 0)) {
				goto out_free;
			}

			if (!add_mi_attr(dst, MI_DUP_VALUE, MI_SSTR("context_info"),
			                 node->info,
			                 node->info ? strlen(node->info) : 0)) {
				LM_ERR("oom!\n");
				goto out_free;
			}
		}
	}
	return 0;

out_free:
	free_mi_node(dst);
	return -1;
}

void empty_hash(struct address_list** table) {
	int i;

	struct address_list *node = NULL, *next = NULL;

    for (i = 0; i < PERM_HASH_SIZE; i++) {
	    for (node = table[i]; node; node = next) {
	    	next = node->next;
			if (node->ip) shm_free(node->ip);
		    if (node->pattern) shm_free(node->pattern);
		    if (node->info) shm_free(node->info);
		    shm_free(node);
		}
		table[i] = 0;
    }
}


/*
 * Create and initialize a subnet table
 */
struct subnet* new_subnet_table(void)
{
    struct subnet* ptr;

    /* subnet record [PERM_MAX_SUBNETS] contains in its grp field
       the number of subnet records in the subnet table */
    ptr = (struct subnet *)shm_malloc
	(sizeof(struct subnet) * (PERM_MAX_SUBNETS + 1));

    if (!ptr) {
		LM_ERR("no shm memory for subnet table\n");
		return 0;
    }

    ptr[PERM_MAX_SUBNETS].grp = 0;
    return ptr;
}


/*
 * Add <grp, subnet, mask, port> into subnet table so that table is
 * kept in increasing ordered according to grp.
 */
int subnet_table_insert(struct subnet* table, unsigned int grp,
			struct net *subnet,
			unsigned int port, int proto, str* pattern, str *info)
{
    int i;
    unsigned int count;

    count = table[PERM_MAX_SUBNETS].grp;

    if (count == PERM_MAX_SUBNETS) {
		LM_CRIT("subnet table is full\n");
		return 0;
    }

    i = count - 1;

    while (i >= 0 && table[i].grp > grp) {
		table[i + 1] = table[i];
		i--;
    }

    table[i + 1].grp = grp;
    table[i + 1].port = port;
	table[i + 1].proto = proto;

	if (subnet) {
		table[i + 1].subnet = (struct net*) shm_malloc(sizeof(struct net));
		if (!table[i + 1].subnet) {
			LM_ERR("cannot allocate shm memory for table subnet\n");
			return -1;
		}
		memcpy(table[i + 1].subnet, subnet, sizeof(struct net));
	}
	else
		table[i + 1].subnet = NULL;

	if (info->len) {
		table[i + 1].info = (char*) shm_malloc(info->len + 1);
		if (!table[i + 1].info) {
			LM_ERR("cannot allocate shm memory for table info\n");
			return -1;
		}
		memcpy(table[i + 1].info, info->s, info->len);
		table[i + 1].info[info->len] = 0;
	}
	else
		table[i + 1].info = NULL;

	if (pattern->len) {
		table[i + 1].pattern = (char*) shm_malloc(pattern->len + 1);
		if (!table[i + 1].pattern) {
			LM_ERR("cannot allocate shm memory for table pattern\n");
			return -1;
		}
		memcpy(table[i + 1].pattern, pattern->s, pattern->len);
		table[i + 1].pattern[ pattern->len ] = 0;
	}
	else
		table[i + 1].pattern = NULL;


    table[PERM_MAX_SUBNETS].grp = count + 1;

    return 1;
}


/*
 * Check if an entry exists in subnet table that matches given group, ip_addr,
 * and port.  Port 0 in subnet table matches any port.
 */
int match_subnet_table(struct sip_msg *msg, struct subnet* table, unsigned int grp,
			struct ip_addr *ip, unsigned int port, int proto,
			char *pattern, char *info)
{
        unsigned int count, i;
	pv_value_t pvt;
	pv_spec_t *pvs;
	int match_res, found_group = 0;

	count = table[PERM_MAX_SUBNETS].grp;

	if (count == 0) {
		LM_DBG("subnet table is empty\n");
		return -2;
	}

	if (grp != GROUP_ANY) {
		for (i = 0; i < count; i++) {
			if (table[i].grp == grp) {
				found_group = 1;
				break;
			} else if (table[i].grp > grp) {
				break;
			}
		}

		if (!found_group) {
			LM_DBG("specified group %u does not exist in hash table\n", grp);
			return -2;
		}
	}

	i = 0;
	do {
		if ((table[i].grp == grp || table[i].grp == GROUP_ANY
				|| grp == GROUP_ANY) &&
			(table[i].port == port || table[i].port == PORT_ANY
				|| port == PORT_ANY) &&
			(table[i].proto == proto || table[i].proto == PROTO_NONE
			 	|| proto == PROTO_NONE))
			{

				match_res = matchnet(ip, table[i].subnet);

				if (match_res != 1) {
					i++;
					continue;
				}

				if (table[i].pattern && pattern) {
					match_res = fnmatch(table[i].pattern, pattern, FNM_PERIOD);

					if (match_res) {
						i++;
						continue;
					}
				}

				if (info) {
					pvs = (pv_spec_t *)info;
					memset(&pvt, 0, sizeof(pv_value_t));
					pvt.flags = PV_VAL_STR;
					pvt.rs.s = table[i].info;
					pvt.rs.len = table[i].info ? strlen(table[i].info) : 0;

					if (pv_set_value(msg, pvs, (int)EQ_T, &pvt) < 0) {
						LM_ERR("setting of avp failed\n");
						return -1;
	    			}
				}

				LM_DBG("match found in the subnet table\n");
				return 1;
			}

		if (table[i].grp > grp && grp != GROUP_ANY)
			break;
		i++;

	} while (i < count);

	LM_DBG("no match in the subnet table\n");
    return -1;
}


/*
 * Print subnets stored in subnet table
 */
int subnet_table_mi_print(struct subnet* table, struct mi_node* rpl,
		struct pm_part_struct *pm)
{
    unsigned int count, i;
	char *p, *ip, *mask, prbuf[PROTO_NAME_MAX_SIZE];
	int len;
	static char ip_buff[IP_ADDR_MAX_STR_SIZE];
	struct mi_node *net;

    count = table[PERM_MAX_SUBNETS].grp;

    for (i = 0; i < count; i++) {
		ip = ip_addr2a(&table[i].subnet->ip);
		if (!ip) {
			LM_ERR("cannot print ip address\n");
			continue;
		}
		strcpy(ip_buff, ip);
		mask = ip_addr2a(&table[i].subnet->mask);
		if (!mask) {
			LM_ERR("cannot print mask address\n");
			continue;
		}

		net = add_mi_node_child(rpl, 0, MI_SSTR("dest"), NULL, 0);
		if (!net) {
			LM_ERR("oom!\n");
			return -1;
		}

		p = int2str(table[i].grp, &len);
		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("grp"), p, len)) {
			goto out_free;
		}

		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("ip"), ip_buff,
		                 strlen(ip_buff))) {
			goto out_free;
		}

		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("mask"), mask,
		                 strlen(mask))) {
			goto out_free;
		}

		p = int2str(table[i].port, &len);
		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("port"), p, len)) {
			goto out_free;
		}

		if (table[i].proto == PROTO_NONE) {
			p = "any";
			len = 3;
		} else {
			p = proto2str(table[i].proto, prbuf);
			len = p - prbuf;
			p = prbuf;
		}
		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("proto"), p, len)) {
			goto out_free;
		}

		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("pattern"),
		                 table[i].pattern,
		                 table[i].pattern ? strlen(table[i].pattern) : 0)) {
			goto out_free;
		}

		if (!add_mi_attr(net, MI_DUP_VALUE, MI_SSTR("context_info"),
		                 table[i].info,
		                 table[i].info ? strlen(table[i].info) : 0)) {
			LM_ERR("oom!\n");
			goto out_free;
		}
    }

	return 0;

out_free:
	free_mi_node(net);
	return -1;
}


/*
 * Check if an entry exists in subnet table that matches given ip_addr,
 * and port.  Port 0 in subnet table matches any port.  Return group of
 * first match or -1 if no match is found.
 */
int find_group_in_subnet_table(struct subnet* table,
		                   struct ip_addr *ip, unsigned int port)
{
	unsigned int count, i, match_res;

	count = table[PERM_MAX_SUBNETS].grp;

	i = 0;
	while (i < count) {
		if	(table[i].port == port || table[i].port == 0) {
			match_res = matchnet(ip, table[i].subnet);

			if (match_res == 1)
		        return table[i].grp;

		}
	    i++;
	}

	return -1;
}


/*
 * Empty contents of subnet table
 */
void empty_subnet_table(struct subnet *table)
{
	int count, i;

	if (!table)
		return;

	count = table[PERM_MAX_SUBNETS].grp;

	for (i = 0; i < count; i++) {
		if (table[i].info)
    		        shm_free(table[i].info);
		if (table[i].subnet)
		        shm_free(table[i].subnet);
	}

	table[PERM_MAX_SUBNETS].grp = 0;
}


/*
 * Release memory allocated for a subnet table
 */
void free_subnet_table(struct subnet* table)
{
	empty_subnet_table(table);

	if (table)
	    shm_free(table);
}




