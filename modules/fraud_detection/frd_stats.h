#ifndef __FRD_STATS_H__
#define __FRD_STATS_H__

#include "../../str.h"
#include "../../locking.h"
#include "../../rw_locking.h"

#define FRD_USER_HASH_SIZE 1000
#define FRD_PREFIX_HASH_SIZE 10

typedef struct {
	unsigned int cps;
	unsigned int total_calls;
	unsigned int concurrent_calls;
} frd_stats_t;

typedef struct _frd_hash_item {
	gen_lock_t            lock;
	frd_stats_t           stats;
} frd_stats_entry_t;

int init_stats_table(void);
frd_stats_entry_t* get_stats(str user, str prefix);
void free_stats_table(void);

#endif
