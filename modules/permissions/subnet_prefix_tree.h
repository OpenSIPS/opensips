/*
 *
 * Copyright (C) 2025 Genesys Cloud Services, Inc.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef PERM_SUBNET_PREFIX_TREE_H
#define PERM_SUBNET_PREFIX_TREE_H

#include <stdarg.h>

typedef struct ppt_metadata_t ppt_metadata_t;
typedef struct ppt_trie_node_t ppt_trie_node_t;

typedef struct ppt_metadata_t {
    ppt_metadata_t *next;
    void *data;
} ppt_metadata_t;

typedef struct ppt_trie_node_t {
    ppt_trie_node_t *children[2];
    int is_subnet_end;
    ppt_metadata_t *metadata_list;
} ppt_trie_node_t;

typedef int (*ppt_match_callback)(void *data, va_list args);

ppt_trie_node_t *ppt_create_node(void);
int ppt_insert_subnet(ppt_trie_node_t *root, const unsigned char *ip, int prefix_length,
                      void *data);
void *ppt_match_subnet(ppt_trie_node_t *root, const unsigned char *ip, int ip_length,
                       ppt_match_callback match, ...);
void ppt_free_trie(ppt_trie_node_t *root);

#endif /* PERM_SUBNET_PREFIX_TREE_H */
