/**
 * Fraud Detection Module
 *
 * Copyright (C) 2014 OpenSIPS Foundation
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 *  2014-09-26  initial version (Andrei Datcu)
*/

#ifndef __FRD_STATS_H__
#define __FRD_STATS_H__

#include "../../str.h"
#include "../../locking.h"
#include "../../rw_locking.h"

#define FRD_USER_HASH_SIZE 1024
#define FRD_PREFIX_HASH_SIZE 8
#define FRD_SECS_PER_WINDOW 60

typedef struct {
	unsigned int cpm;
	unsigned int total_calls;
	unsigned int concurrent_calls;

	str last_dial;
	unsigned int seq_calls;

	unsigned int last_matched_rule;
	time_t last_matched_time;
	unsigned short calls_window[FRD_SECS_PER_WINDOW];
} frd_stats_t;

typedef struct _frd_hash_item {
	gen_lock_t            lock;
	frd_stats_t           stats;
	unsigned int          interval_id; /* version of the current interval */
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
