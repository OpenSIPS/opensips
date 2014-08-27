#ifndef __FRD_HASHMAP_H__
#define __FRD_HASHMAP_H__

#include "../../map.h"
#include "../../rw_locking.h"

typedef struct {
	map_t items;
	rw_lock_t   *lock;
} hash_bucket_t;

typedef struct {
	hash_bucket_t *buckets;
	size_t size;
} hash_map_t;



int init_hash_map(hash_map_t* hm);
void** get_item (hash_map_t *hm, str key);
void free_hash_map(hash_map_t* hm, void (*value_destroy_func)(void *));

#endif
