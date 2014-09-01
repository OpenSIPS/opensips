/**
 * the truly parallel memory allocator
 *
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-01-19 initial version (liviu)
 */

#if !defined(q_malloc) && !(defined VQ_MALLOC)  && !(defined F_MALLOC) && \
	(defined HP_MALLOC)

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sys/time.h"

#include "../lock_ops.h"
#include "hp_malloc.h"
#include "hp_malloc_stats.h"

gen_lock_t *hp_stats_lock;

#ifdef STATISTICS

int stats_are_expired(struct hp_block *qm)
{
	struct timeval now;

	gettimeofday(&now, NULL);

	return (now.tv_sec * 1000000L + now.tv_usec) -
	       (qm->last_updated.tv_sec * 1000000L + qm->last_updated.tv_usec)

	       > SHM_STATS_SAMPLING_PERIOD;
}

void update_shm_stats(struct hp_block *qm)
{
	struct hp_frag_lnk *bucket, *it;
	int i, j, used_mem;
	unsigned long in_use_frags;
	long size = 0;

	lock_get(hp_stats_lock);

	qm->used = qm->real_used = qm->total_fragments = 0;

	for (i = 0, bucket = qm->free_hash;
	     bucket < &qm->free_hash[HP_HASH_SIZE];
		 i++, bucket++) {

		size = UN_HASH(i);

		if (!bucket->is_optimized) {
			in_use_frags = bucket->total_no - bucket->no;
			used_mem = in_use_frags * size;

			qm->used            += used_mem;
			qm->real_used       += used_mem + bucket->total_no * FRAG_OVERHEAD;
			qm->total_fragments += bucket->total_no;
		} else {
			for (j = 0, it = &qm->free_hash[HP_HASH_SIZE + i * shm_secondary_hash_size];
			     j < shm_secondary_hash_size;
				 j++, it++) {

				in_use_frags = it->total_no - it->no;
				used_mem = in_use_frags * size;

				qm->used            += used_mem;
				qm->real_used       += used_mem + it->total_no * FRAG_OVERHEAD;
				qm->total_fragments += it->total_no;
			}
		}
	}

	if (qm->real_used > qm->max_real_used)
		qm->max_real_used = qm->real_used;

	LM_DBG("updated shm statistics: [ us: %ld | rus: %ld | frags: %ld ]\n",
	        qm->used, qm->real_used, qm->total_fragments);

	gettimeofday(&qm->last_updated, NULL);

	lock_release(hp_stats_lock);
}

unsigned long hp_shm_get_size(struct hp_block *qm)
{
	return qm->size;
}

#ifdef HP_MALLOC_FAST_STATS
unsigned long hp_shm_get_used(struct hp_block *qm)
{
	if (stats_are_expired(qm))
		update_shm_stats(qm);

	return qm->used;
}

unsigned long hp_shm_get_real_used(struct hp_block *qm)
{
	if (stats_are_expired(qm))
		update_shm_stats(qm);

	return qm->real_used;
}

unsigned long hp_shm_get_max_real_used(struct hp_block *qm)
{
	if (stats_are_expired(qm))
		update_shm_stats(qm);

	return qm->max_real_used;
}

unsigned long hp_shm_get_free(struct hp_block *qm)
{
	if (stats_are_expired(qm))
		update_shm_stats(qm);

	return qm->size - qm->real_used;
}

unsigned long hp_shm_get_frags(struct hp_block *qm)
{
	if (stats_are_expired(qm))
		update_shm_stats(qm);

	return qm->total_fragments;
}

void hp_init_shm_statistics(struct hp_block *qm)
{
	update_shm_stats(qm);
}

#else /* HP_MALLOC_FAST_STATS */

void hp_init_shm_statistics(struct hp_block *qm)
{
	update_stat(shm_used, qm->used);
	update_stat(shm_rused, qm->real_used);
	update_stat(shm_frags, qm->total_fragments);

	LM_DBG("initializing atomic shm statistics: "
	       "[ us: %ld | rus: %ld | frags: %ld ]\n", qm->used, qm->real_used, qm->total_fragments);
}

unsigned long hp_shm_get_used(struct hp_block *qm)
{
	return get_stat_val(shm_used);
}

unsigned long hp_shm_get_real_used(struct hp_block *qm)
{
	return get_stat_val(shm_rused);
}

unsigned long hp_shm_get_max_real_used(struct hp_block *qm)
{
	return qm->max_real_used;
}

unsigned long hp_shm_get_free(struct hp_block *qm)
{
	return qm->size - get_stat_val(shm_rused);
}

unsigned long hp_shm_get_frags(struct hp_block *qm)
{
	return get_stat_val(shm_frags);
}
#endif /* HP_MALLOC_FAST_STATS */


unsigned long hp_pkg_get_size(struct hp_block *qm)
{
	return qm->size;
}

unsigned long hp_pkg_get_used(struct hp_block *qm)
{
	return qm->used;
}

unsigned long hp_pkg_get_real_used(struct hp_block *qm)
{
	return qm->real_used;
}

unsigned long hp_pkg_get_max_real_used(struct hp_block *qm)
{
	return qm->max_real_used;
}

unsigned long hp_pkg_get_free(struct hp_block *qm)
{
	return qm->size - qm->real_used;
}

unsigned long hp_pkg_get_frags(struct hp_block *qm)
{
	return qm->total_fragments;
}

#endif /* STATISTICS */

#endif
