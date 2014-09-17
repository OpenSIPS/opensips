#include <string.h>
#include "frd_stats.h"
#include "frd_hashmap.h"
#include "../../ut.h"


/* Struct used for the first level of the hashmap
 * the user is kept in shm for two reasons :
 *     a) to keep using core's map
 *     b) to pass it for the dialog_end callback
*/

typedef struct {

	hash_map_t numbers_hm;
	str user;
} frd_users_map_item_t;

static hash_map_t stats_table;

/*
 * Function to init the stats hash table
*/

int init_stats_table(void)
{
	stats_table.size = FRD_USER_HASH_SIZE;
	return init_hash_map(&stats_table);
}


frd_stats_entry_t* get_stats(str user, str prefix, str *shm_user)
{
	/* First go one level below using the user key */
	frd_users_map_item_t **hm =
		(frd_users_map_item_t **)get_item(&stats_table, user);

	if (*hm == NULL) {
		/* First time the user is seen, we must create a hashmap */
		*hm = shm_malloc(sizeof(frd_users_map_item_t));
		if (*hm == NULL) {
			LM_ERR("no more shm memory\n");
			return NULL;
		}

		(*hm)->numbers_hm.size = FRD_PREFIX_HASH_SIZE;
		if (init_hash_map(&(*hm)->numbers_hm) != 0) {
			LM_ERR("cannot init hashmap\n");
			shm_free(*hm);
			return NULL;
		}

		if (shm_str_dup(&(*hm)->user, &user) != 0) {
			shm_free(*hm);
			return NULL;
		}
	}

	*shm_user = (*hm)->user;

	frd_stats_entry_t **stats_entry =
		(frd_stats_entry_t**)get_item(&(*hm)->numbers_hm, prefix);
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
	shm_free(e);
}

static void destroy_users(void *u)
{
	free_hash_map(&((frd_users_map_item_t*)u)->numbers_hm, destroy_stats_entry);
	shm_free(u);
}

void free_stats_table(void)
{
	free_hash_map(&stats_table, destroy_users);
}
