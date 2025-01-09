#ifndef PERM_HASH_TABLE_H
#define PERM_HASH_TABLE_H

#define BUCKET_MAX_LOAD_FACTOR 1.0f
#define BUCKET_GROW_FACTOR 1.5f

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
