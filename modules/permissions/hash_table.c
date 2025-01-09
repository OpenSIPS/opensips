#include "hash_table.h"

#include "../../mem/shm_mem.h"

pht_node_t **pht_new_buckets(unsigned int bucket_count) {
    unsigned int size;
    pht_node_t **buckets;

    size = sizeof(pht_node_t *) * bucket_count;
    buckets = shm_malloc(size);
    if (!buckets) return NULL;
    memset(buckets, 0, size);

    return buckets;
}

int pht_init(pht_hash_table_t *table, unsigned int bucket_count, hash_fn hash) {
    table->bucket = (void **)pht_new_buckets(bucket_count);
    if (!table->bucket) return 0;

    table->size = 0;
    table->bucket_count = bucket_count;
    table->hash = hash;

    return 1;
}

int pht_resize_bucket(pht_hash_table_t *table, unsigned int bucket_count) {
    unsigned int i, hash_val, old_bucket_count;
    pht_node_t **new_bucket;
    pht_node_t *node = NULL, *next_node = NULL;

    new_bucket = pht_new_buckets(bucket_count);
    if (!new_bucket) return 0;

    old_bucket_count = table->bucket_count;
    table->bucket_count = bucket_count;

    for (i = 0; i < old_bucket_count; ++i) {
        for (node = table->bucket[i]; node; node = next_node) {
            next_node = node->next;

            hash_val = table->hash(table, node);

            node->next = new_bucket[hash_val];
            new_bucket[hash_val] = node;
        }
    }

    shm_free(table->bucket);
    table->bucket = (void **)new_bucket;

    return 1;
}

int pht_grow_bucket(pht_hash_table_t *table) {
    return pht_resize_bucket(table, table->bucket_count * BUCKET_GROW_FACTOR);
}

float pht_get_load_factor(pht_hash_table_t *table) {
    return (float)table->size / (float)table->bucket_count;
}

void pht_insert(pht_hash_table_t *table, void *node) {
    unsigned int hash_val;

    if (pht_get_load_factor(table) >= BUCKET_MAX_LOAD_FACTOR) {
        if (!pht_grow_bucket(table)) {
            LM_WARN("no shm memory left for hash table grow, just inserting new node\n");
        }
    }

    hash_val = table->hash(table, node);
    ((pht_node_t *)node)->next = table->bucket[hash_val];
    table->bucket[hash_val] = node;
    table->size += 1;
}
