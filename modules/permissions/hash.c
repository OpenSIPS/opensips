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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "hash.h"

#include "../../ip_addr.h"
#include "../../mem/shm_mem.h"
#include "../../socket_info.h"

#include <fnmatch.h>

static inline unsigned int address_hash(pht_hash_table_t *table, str *str_ip) {
    return core_hash(str_ip, NULL, table->bucket_count);
}

unsigned int address_node_hash(pht_hash_table_t *table, void *node) {
    str str_ip;
    p_address_node_t *address;

    address = node;

    str_ip.len = address->k.subnet->ip.len;
    str_ip.s = (char *)address->k.subnet->ip.u.addr;

    return address_hash(table, &str_ip);
}

void delete_address_node(p_address_node_t *node) {
    if (node) {
        if (node->k.subnet) shm_free(node->k.subnet);
        if (node->v.pattern) shm_free(node->v.pattern);
        if (node->v.info) shm_free(node->v.info);
        shm_free(node);
    }
}

char *str_dup(str *src) {
    char *dest = NULL;
    if (src->len) {
        dest = shm_malloc(src->len + 1);
        if (!dest) return NULL;
        memcpy(dest, src->s, src->len);
        dest[src->len] = '\0';
    }
    return dest;
}

p_address_node_t *new_address_node(struct net *subnet, unsigned int port, int proto, str *pattern,
                                   str *info) {
    p_address_node_t *node;

    node = shm_malloc(sizeof(p_address_node_t));
    if (!node) return NULL;

    node->v.port = port;
    node->v.proto = proto;

    node->k.subnet = shm_malloc(sizeof(struct net));
    if (!node->k.subnet) goto err;
    memcpy(node->k.subnet, subnet, sizeof(struct net));

    node->v.pattern = str_dup(pattern);
    if (pattern->len && !node->v.pattern) goto err;

    node->v.info = str_dup(info);
    if (info->len && !node->v.info) goto err;

    return node;

err:
    delete_address_node(node);
    return NULL;
}

static inline unsigned int group_hash(pht_hash_table_t *table, unsigned int group_id) {
    return group_id % table->bucket_count;
}

unsigned int group_node_hash(pht_hash_table_t *table, void *node) {
    p_group_node_t *group;

    group = node;

    return group_hash(table, group->k.group);
}

void delete_group_node(p_group_node_t *group) {
    int i;
    p_address_node_t *address;

    if (!group) return;

    for (i = 0; i < group->v.address.bucket_count; ++i) {
        for (address = (p_address_node_t *)group->v.address.bucket[i]; address;
             address = address->next) {
            delete_address_node(address);
        }
    }

    shm_free(group->v.address.bucket);
    ppt_free_trie(group->v.ipv4_subnet);
    ppt_free_trie(group->v.ipv6_subnet);
    shm_free(group);
}

p_group_node_t *new_group_node(unsigned int group_id, unsigned int bucket_count) {
    p_group_node_t *node;

    node = shm_malloc(sizeof(p_group_node_t));
    if (!node) return NULL;
    node->k.group = group_id;
    if (!pht_init(&node->v.address, bucket_count, address_node_hash)) {
        LM_ERR("no shm memory left for address hash table\n");
        shm_free(node);
        return NULL;
    }

    node->v.ipv4_subnet = ppt_create_node();
    if (!node->v.ipv4_subnet) {
        LM_ERR("no shm memory left for IPv4 subnet prefix tree\n");
        shm_free(node);
    }

    node->v.ipv6_subnet = ppt_create_node();
    if (!node->v.ipv6_subnet) {
        LM_ERR("no shm memory left for IPv6 subnet prefix tree\n");
        ppt_free_trie(node->v.ipv4_subnet);
        shm_free(node);
    }

    return node;
}

p_group_node_t *find_group_bucket(p_address_table_t *table, unsigned int group_id) {
    p_group_node_t *node = NULL;

    for (node = (p_group_node_t *)table->group.bucket[group_hash(&table->group, group_id)]; node;
         node = node->next) {
        if (node->k.group == group_id) break;
    }

    return node;
}

p_address_table_t *pm_hash_create(void) {
    p_address_table_t *table;

    table = shm_malloc(sizeof(p_address_table_t));
    if (!table) {
        LM_ERR("no shm memory left for address table\n");
        return NULL;
    }
    if (!pht_init(&table->group, INITIAL_GROUP_BUCKET_COUNT, group_node_hash)) {
        LM_ERR("no shm memory left for group hash table\n");
        shm_free(table);
        return NULL;
    }

    return table;
}

void pm_hash_destroy(p_address_table_t *table) {
    if (!table) {
        LM_ERR("trying to destroy an empty address table\n");
        return;
    }
    pm_empty_hash(table);
    shm_free(table->group.bucket);
    shm_free(table);
}

int pm_hash_insert(p_address_table_t *table, struct net *subnet, unsigned int group_id,
                   unsigned int port, int proto, str *pattern, str *info, int mask) {
    p_group_node_t *group;
    p_address_node_t *address;

    address = new_address_node(subnet, port, proto, pattern, info);
    if (!address) {
        LM_ERR("no shm memory left for new address node\n");
        return -1;
    }

    group = find_group_bucket(table, group_id);

    if (!group) {
        group = new_group_node(group_id, INITIAL_ADDRESS_BUCKET_COUNT);
        if (!group) {
            LM_ERR("no shm memory left for new group node\n");
            delete_address_node(address);
            return -1;
        }
        pht_insert(&table->group, group);
    }

    pht_insert(&group->v.address, address);
    if (mask != 32 && mask != 128) {
        if (!ppt_insert_subnet(subnet->ip.af == AF_INET ? group->v.ipv4_subnet
                                                        : group->v.ipv6_subnet,
                               (unsigned char *)&subnet->ip.u.addr, mask, address)) {
            LM_CRIT("no shm memory left for subnet prefix tree insert operation\n");
        }
    }

    return 1;
}

int match_address(p_address_node_t *address, struct ip_addr *ip, unsigned int port, int proto,
                  char *pattern) {
    int match_res;

    if ((address->v.proto == PROTO_NONE || address->v.proto == proto || proto == PROTO_NONE) &&
        (address->v.port == PORT_ANY || address->v.port == port || port == PORT_ANY) &&
        (ip_addr_cmp(ip, &address->k.subnet->ip) || matchnet(ip, address->k.subnet))) {
        if (!address->v.pattern || !pattern) {
            LM_DBG("no pattern to match\n");
            return 1;
        }

        match_res = fnmatch(address->v.pattern, pattern, FNM_PERIOD);
        if (!match_res) {
            LM_DBG("pattern match\n");
            return 1;
        }
        if (match_res != FNM_NOMATCH) {
            LM_ERR("fnmatch failed\n");
        }
    }

    return 0;
}

int match_address_callback(void *data, va_list args) {
    p_address_node_t *address = data;

    struct ip_addr *ip = va_arg(args, struct ip_addr *);
    unsigned int port = va_arg(args, unsigned int);
    int proto = va_arg(args, int);
    char *pattern = va_arg(args, char *);

    return match_address(address, ip, port, proto, pattern);
}

p_address_node_t *match_in_group(p_group_node_t *group, struct ip_addr *ip, unsigned int port,
                                 int proto, char *pattern) {
    p_address_node_t *address;
    str str_ip;

    str_ip.len = ip->len;
    str_ip.s = (char *)ip->u.addr;

    for (address = group->v.address.bucket[address_hash(&group->v.address, &str_ip)]; address;
         address = address->next) {
        if (match_address(address, ip, port, proto, pattern)) return address;
    }

    address = (p_address_node_t *)ppt_match_subnet(
        ip->af == AF_INET ? group->v.ipv4_subnet : group->v.ipv6_subnet,
        (unsigned char *)&ip->u.addr, ip->len, match_address_callback, ip, port, proto, pattern);

    return address;
}

int pm_hash_match(struct sip_msg *msg, p_address_table_t *table, unsigned int group_id,
                  struct ip_addr *ip, unsigned int port, int proto, char *pattern,
                  pv_spec_t *info) {
    p_group_node_t *group = NULL;
    p_address_node_t *address;
    pv_value_t pvt;
    int i;

    if (group_id != GROUP_ANY) {
        for (group = table->group.bucket[group_hash(&table->group, group_id)]; group;
             group = group->next) {
            if (group->k.group == group_id) break;
        }

        if (!group) {
            LM_DBG("specified group '%u' does not exist in hash table\n", group_id);
            return -2;
        }

        address = match_in_group(group, ip, port, proto, pattern);
        if (address) goto found;
    } else {
        for (i = 0; i < table->group.bucket_count; ++i) {
            for (group = table->group.bucket[i]; group; group = group->next) {
                address = match_in_group(group, ip, port, proto, pattern);
                if (address) goto found;
            }
        }
    }

    LM_DBG("no match in the hash table\n");
    return -1;

found:
    if (info) {
        pvt.flags = PV_VAL_STR;
        pvt.rs.s = address->v.info;
        pvt.rs.len = address->v.info ? strlen(address->v.info) : 0;

        if (pv_set_value(msg, info, (int)EQ_T, &pvt) < 0) {
            LM_ERR("setting of avp failed\n");
            return -1;
        }
    }

    LM_DBG("match found in the hash table\n");
    return 1;
}

int pm_hash_find_group(p_address_table_t *table, struct ip_addr *ip, unsigned int port) {
    p_group_node_t *group;
    p_address_node_t *address;
    str str_ip;
    int i;

    if (ip == NULL) return -1;

    str_ip.len = ip->len;
    str_ip.s = (char *)ip->u.addr;

    for (i = 0; i < table->group.bucket_count; ++i) {
        for (group = table->group.bucket[i]; group; group = group->next) {
            for (address = group->v.address.bucket[address_hash(&group->v.address, &str_ip)];
                 address; address = address->next) {
                if ((address->v.port == PORT_ANY || address->v.port == port || port == PORT_ANY) &&
                    (ip_addr_cmp(ip, &address->k.subnet->ip) || matchnet(ip, address->k.subnet))) {
                    return group->k.group;
                }
            }
            if (match_in_group(group, ip, port, PROTO_NONE, NULL)) return group->k.group;
        }
    }

    return -1;
}

static const unsigned char ipv6_mask_128[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int pm_hash_mi_print(p_address_table_t *table, mi_item_t *part_item, struct pm_part_struct *pm,
                     int is_subnet) {
    int i, j, len, is_address;
    p_group_node_t *group;
    p_address_node_t *address;
    char *p, *mask, prbuf[PROTO_NAME_MAX_SIZE];
    mi_item_t *dests_arr, *dest_item;

    dests_arr = add_mi_array(part_item, MI_SSTR("Destinations"));
    if (!dests_arr) return -1;

    for (i = 0; i < table->group.bucket_count; ++i) {
        for (group = table->group.bucket[i]; group; group = group->next) {
            for (j = 0; j < group->v.address.bucket_count; ++j) {
                for (address = group->v.address.bucket[j]; address; address = address->next) {
                    mask = ip_addr2a(&address->k.subnet->mask);
                    if (!mask) {
                        LM_ERR("cannot print mask address\n");
                        continue;
                    }
                    if (memcmp(&address->k.subnet->mask.u, ipv6_mask_128,
                               address->k.subnet->mask.len) == 0) {
                        if (is_subnet) continue;
                        is_address = 1;
                    } else {
                        if (!is_subnet) continue;
                        is_address = 0;
                    }

                    dest_item = add_mi_object(dests_arr, NULL, 0);
                    if (!dest_item) return -1;

                    if (add_mi_number(dest_item, MI_SSTR("grp"), group->k.group) < 0) return -1;

                    p = ip_addr2a(&address->k.subnet->ip);
                    if (add_mi_string(dest_item, MI_SSTR("ip"), p, strlen(p)) < 0) return -1;

                    if (is_address) {
                        if (address->k.subnet->ip.af == AF_INET) {
                            if (add_mi_string(dest_item, MI_SSTR("mask"), MI_SSTR("32")) < 0)
                                return -1;
                        } else {
                            if (add_mi_string(dest_item, MI_SSTR("mask"), MI_SSTR("128")) < 0)
                                return -1;
                        }
                    } else {
                        if (add_mi_string(dest_item, MI_SSTR("mask"), mask, strlen(mask)) < 0)
                            return -1;
                    }

                    if (add_mi_number(dest_item, MI_SSTR("port"), address->v.port) < 0) return -1;

                    if (address->v.proto == PROTO_NONE) {
                        p = "any";
                        len = 3;
                    } else {
                        p = proto2str(address->v.proto, prbuf);
                        len = p - prbuf;
                        p = prbuf;
                    }
                    if (add_mi_string(dest_item, MI_SSTR("proto"), p, len) < 0) return -1;

                    if (add_mi_string(dest_item, MI_SSTR("pattern"), address->v.pattern,
                                      address->v.pattern ? strlen(address->v.pattern) : 0) < 0)
                        return -1;

                    if (add_mi_string(dest_item, MI_SSTR("context_info"), address->v.info,
                                      address->v.info ? strlen(address->v.info) : 0) < 0)
                        return -1;
                }
            }
        }
    }

    return 0;
}

void pm_empty_hash(p_address_table_t *table) {
    int i;

    p_group_node_t *group;

    for (i = 0; i < table->group.bucket_count; ++i) {
        for (group = table->group.bucket[i]; group; group = group->next) {
            delete_group_node(group);
        }
        table->group.bucket[i] = 0;
    }
    table->group.size = 0;
    if (!pht_resize_bucket(&table->group, INITIAL_GROUP_BUCKET_COUNT)) {
        LM_WARN("no shm memory left for group hash table shrink\n");
    }
}
