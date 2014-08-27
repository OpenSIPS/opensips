#include <string.h>
#include "frd_stats.h"
#include "frd_hashmap.h"


hash_map_t stats_table;

/*
 * Function to init the stats hash table
*/

int init_stats_table(void)
{
	stats_table.size = FRD_USER_HASH_SIZE;
	return init_hash_map(&stats_table);
}


frd_stats_entry_t* get_stats(str user, str prefix)
{
	/* First go one level below using the user key */
	hash_map_t **hm = (hash_map_t **)get_item(&stats_table, user);

	if (*hm == NULL) {
		/* First time the user is seen, we must create a hashmap */
		*hm = shm_malloc(sizeof(hash_map_t));
		if (*hm == NULL) {
			LM_ERR("no more shm memory\n");
			return NULL;
		}

		(*hm)->size = FRD_PREFIX_HASH_SIZE;
		if (init_hash_map(*hm) != 0) {
			LM_ERR("cannot init hashmap\n");
			shm_free(*hm);
			return NULL;
		}
	}

	frd_stats_entry_t **stats_entry = (frd_stats_entry_t**)get_item(*hm, prefix);
	if (*stats_entry == NULL) {
		/* First time the prefix is seen for this user */
		*stats_entry = shm_malloc(sizeof(frd_stats_entry_t));
		if (*stats_entry == NULL) {
			LM_ERR("no more shm memory\n");
			return NULL;
		}

		/* Now init the auxiliary info for a stats structure */
		if (!lock_init(&(*stats_entry)->lock)) {
			LM_ERR ("cannot init lock\n");
			shm_free(*stats_entry);
			return NULL;
		}
		memset(&((*stats_entry)->stats), 0, sizeof(frd_stats_t));
	}

	return *stats_entry;
}

/*
 * Functions for freeing the stats hash table
*/

static void destroy_stats_entry(void *e)
{
	lock_destroy( &((frd_stats_entry_t*)e)->lock );
}

static void destroy_users(void *u)
{
	free_hash_map((hash_map_t*)u, destroy_stats_entry);
}

void free_stats_table(void)
{
	free_hash_map(&stats_table, destroy_users);
}
