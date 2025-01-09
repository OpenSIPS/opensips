/*
 * Hash table functions header file
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

#ifndef PERM_HASH_H
#define PERM_HASH_H

#include "../../ip_addr.h"
#include "../../mi/mi.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../usr_avp.h"

#include "hash_table.h"
#include "partitions.h"
#include "subnet_prefix_tree.h"

#include <sys/types.h>

#define INITIAL_GROUP_BUCKET_COUNT 2
#define INITIAL_ADDRESS_BUCKET_COUNT 16

#define GROUP_ANY 0
#define MASK_ANY 32
#define PORT_ANY 0

typedef struct p_address_node_t p_address_node_t;
typedef struct p_group_node_t p_group_node_t;

typedef struct p_address_node_t {
    p_address_node_t *next;

    struct {
        struct net *subnet;
    } k;
    struct {
        unsigned int port;
        int proto;
        char *pattern;
        char *info;
    } v;
} p_address_node_t;

typedef struct p_group_node_t {
    p_group_node_t *next;

    struct {
        unsigned int group;
    } k;
    struct {
        pht_hash_table_t address;
        ppt_trie_node_t *ipv4_subnet;
        ppt_trie_node_t *ipv6_subnet;
    } v;
} p_group_node_t;

typedef struct p_address_table_t {
    pht_hash_table_t group;
} p_address_table_t;

p_address_table_t *pm_hash_create(void);
void pm_hash_destroy(p_address_table_t *table);
int pm_hash_insert(p_address_table_t *table, struct net *subnet, unsigned int group_id,
                   unsigned int port, int proto, str *pattern, str *info, int mask);
int pm_hash_match(struct sip_msg *msg, p_address_table_t *table, unsigned int group_id,
                  struct ip_addr *ip, unsigned int port, int proto, char *pattern, pv_spec_t *info);
int pm_hash_mi_print(p_address_table_t *table, mi_item_t *part_item, struct pm_part_struct *pm,
                     int is_subnet);
void pm_empty_hash(p_address_table_t *table);
int pm_hash_find_group(p_address_table_t *table, struct ip_addr *ip, unsigned int port);

#endif /* PERM_HASH_H */
