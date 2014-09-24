#ifndef __FRD_STATS_H__
#define __FRD_STATS_H__

#include "../../str.h"
#include "../../locking.h"
#include "../../rw_locking.h"

#define FRD_USER_HASH_SIZE 1000
#define FRD_PREFIX_HASH_SIZE 10
#define FRD_SECS_PER_WINDOW 60

typedef struct {
	unsigned int cpm;
	unsigned int total_calls;
	unsigned int concurrent_calls;
	unsigned int seq_calls;

	unsigned int last_matched_rule;
	time_t last_matched_time;
	unsigned short calls_window[FRD_SECS_PER_WINDOW];
} frd_stats_t;

typedef struct _frd_hash_item {
	gen_lock_t            lock;
	frd_stats_t           stats;
} frd_stats_entry_t;

int init_stats_table(void);
frd_stats_entry_t* get_stats(str user, str prefix, str *shm_user);
int stats_exist(str user, str prefix);
void free_stats_table(void);


typedef struct {
	unsigned int warning;
	unsigned int critical;
} frd_threshold_t;

typedef struct {
	frd_threshold_t cpm_thr, call_duration_thr, total_calls_thr,
					concurrent_calls_thr, seq_calls_thr;
} frd_thresholds_t;

#endif
