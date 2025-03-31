 /*
￼ * Trie Module
￼ *
￼ * Copyright (C) 2024 OpenSIPS Project
￼ *
￼ * opensips is free software; you can redistribute it and/or modify
￼ * it under the terms of the GNU General Public License as published by
￼ * the Free Software Foundation; either version 2 of the License, or
￼ * (at your option) any later version.
￼ *
￼ * opensips is distributed in the hope that it will be useful,
￼ * but WITHOUT ANY WARRANTY; without even the implied warranty of
￼ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
￼ * GNU General Public License for more details.
￼ *
￼ * You should have received a copy of the GNU General Public License
￼ * along with this program; if not, write to the Free Software
￼ * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
￼ *
￼ * History:
￼ * --------
￼ * 2024-12-03 initial release (vlad)
￼ */

#ifndef trie_prefix_tree_h
#define trie_prefix_tree_h

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../time_rec.h"
#include "../../map.h"
#include "../../mem/mem_funcs.h"

#define IS_DECIMAL_DIGIT(d) \
	(((d)>='0') && ((d)<= '9'))

extern int ptree_children;
extern int tree_size;
struct head_db;

#define INIT_TRIE_NODE(f, n) \
do { \
    (n) = (trie_node_t*)func_malloc(f,sizeof(trie_node_t) + ptree_children * sizeof(trie_node_t*)); \
    if ((n) == NULL) \
        goto err_exit; \
    memset((n), 0, sizeof(trie_node_t) + ptree_children * sizeof(trie_node_t*)); \
} while(0)

#define SET_TRIE_CHILD(parent, child_index, new_node) \
do { \
    trie_node_t **child_ptr = (trie_node_t**)(((char*)parent) + sizeof(trie_node_t) + child_index * sizeof(trie_node_t*)); \
    if (child_ptr != NULL) { \
        *child_ptr = new_node;  /* Set the allocated node as the child */ \
    } \
} while(0)

typedef struct trie_info_ {
	/* opaque string with rule attributes */
	str attrs;
	/* enabled ? */
	int enabled;
} trie_info_t;

typedef struct trie_node_ {
    trie_info_t *info;
    /* this node's children follow right after
     * inside the initially allocated memory chunk 
     * use INIT_TRIE_NODE and SET_TRIE_CHILD for operating it */
} trie_node_t;

typedef struct trie_data_ {
	/* tree with routing prefixes */
	trie_node_t *pt;
}trie_data_t;

/* init new trie_data structure */
trie_data_t*
build_trie_data( struct head_db * );


void
free_trie_data(trie_data_t*, osips_free_f);

int
init_prefix_tree(
	char *extra_prefix_chars
	);

int
del_tree(
	trie_node_t *,
	osips_free_f
	);

int
add_trie_prefix(
	trie_node_t*,
	str* prefix,
	trie_info_t *info,
	osips_malloc_f,
	osips_free_f
	);

trie_info_t*
get_trie_prefix(
	trie_node_t *ptree,
	str* prefix,
	unsigned int *matched_len,
	int filter_disabled
	);

trie_info_t*
build_trie_info(
	str *attrs,
	int disabled,
	osips_malloc_f mf,
	osips_free_f ff
	);

void
free_trie_info(
	trie_info_t*,
	osips_free_f
	);

#endif
