#include "frd_hashmap.h"

#include "../../hash_func.h"
#include "../../str.h"
#include "../../locking.h"

int init_hash_map(hash_map_t *hm)
{
	hm->buckets = shm_malloc(hm->size * sizeof(hash_bucket_t));
	if (hm->buckets == NULL) {
		LM_ERR("No more shm memory\n");
		return -1;
	}

	unsigned int i;

	for (i = 0; i < hm->size; ++i) {
		hm->buckets[i].items = map_create(AVLMAP_SHARED);
		hm->buckets[i].lock = lock_init_rw();
		if (hm->buckets[i].lock == NULL) {
			LM_ERR("cannot init lock\n");
			shm_free(hm->buckets);
			return -1;
		}
	}

	return 0;
}

void** get_item (hash_map_t *hm, str key)
{
	unsigned int hash = core_hash(&key, NULL, hm->size);

	lock_start_read(hm->buckets[hash].lock);
	void **find_res = map_find(hm->buckets[hash].items, key);
	lock_stop_read(hm->buckets[hash].lock);
	if (find_res) {
		return find_res;
	}
	else {
		lock_start_write(hm->buckets[hash].lock);
		find_res = map_get(hm->buckets[hash].items, key);
		lock_stop_write(hm->buckets[hash].lock);
		return find_res;
	}
}

void free_hash_map(hash_map_t* hm, void (*value_destroy_func)(void *))
{
	unsigned int i;
	for (i = 0; i < hm->size; ++i) {
		lock_start_write(hm->buckets[i].lock);
		map_destroy(hm->buckets[i].items, value_destroy_func);
		lock_stop_write(hm->buckets[i].lock);
		lock_destroy(hm->buckets[i].lock);
	}
	shm_free(hm->buckets);
}


