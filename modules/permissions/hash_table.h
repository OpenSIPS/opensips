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

#ifndef PERM_HASH_TABLE_H
#define PERM_HASH_TABLE_H

#define BUCKET_MAX_LOAD_FACTOR 1.0f
#define BUCKET_GROW_FACTOR 2.0f

typedef struct pht_node_t pht_node_t;
typedef struct pht_hash_table_t pht_hash_table_t;

typedef unsigned int (*hash_fn)(pht_hash_table_t *table, void *node);

typedef struct pht_node_t {
    pht_node_t *next;
} pht_node_t;

typedef struct pht_hash_table_t {
    unsigned int size;
    unsigned int bucket_count;
    hash_fn hash;
    void **bucket;
} pht_hash_table_t;

int pht_init(pht_hash_table_t *table, unsigned int bucket_count, hash_fn hash);
int pht_resize_bucket(pht_hash_table_t *table, unsigned int bucket_count);
int pht_grow_bucket(pht_hash_table_t *table);
float pht_get_load_factor(pht_hash_table_t *table);
void pht_insert(pht_hash_table_t *table, void *node);

#endif /* PERM_HASH_TABLE_H */
