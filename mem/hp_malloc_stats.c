/**
 * high-performance allocator with fine-grained SHM locking
 *   (note: may perform worse than F_MALLOC at low CPS values!)
 *
 * Copyright (C) 2014-2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HP_MALLOC
#ifndef HP_MALLOC_STATS_H
#define HP_MALLOC_STATS_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sys/time.h"

#include "../lock_ops.h"
#include "hp_malloc.h"
#include "hp_malloc_stats.h"

#ifdef STATISTICS

/* specified in microseconds */
#define SHM_STATS_SAMPLING_PERIOD 200000L
#define FRAG_OVERHEAD	(sizeof(struct hp_frag))

int stats_are_expired(struct hp_block *hpb)
{
	struct timeval now;

	gettimeofday(&now, NULL);

	return (now.tv_sec * 1000000L + now.tv_usec) -
	       (hpb->last_updated.tv_sec * 1000000L + hpb->last_updated.tv_usec)

	       > SHM_STATS_SAMPLING_PERIOD;
}

unsigned long hp_shm_get_size(struct hp_block *hpb)
{
	return hpb->size;
}

unsigned long hp_rpm_get_size(struct hp_block *hpb)
{
	return hpb->size;
}

#ifdef HP_MALLOC_FAST_STATS
gen_lock_t *hp_stats_lock;

void update_shm_stats(struct hp_block *hpb)
{
	struct hp_frag_lnk *bucket, *it;
	int i, j, used_mem;
	unsigned long in_use_frags;
	long size = 0;

	lock_get(hp_stats_lock);

	hpb->used = hpb->real_used = hpb->total_fragments = 0;

	for (i = 0, bucket = hpb->free_hash;
	     bucket < &hpb->free_hash[HP_HASH_SIZE];
		 i++, bucket++) {

		size = UN_HASH(i);

		if (!bucket->is_optimized) {
			in_use_frags = bucket->total_no - bucket->no;
			used_mem = in_use_frags * size;

			hpb->used            += used_mem;
			hpb->real_used       += used_mem + bucket->total_no * FRAG_OVERHEAD;
			hpb->total_fragments += bucket->total_no;
		} else {
			for (j = 0, it = &hpb->free_hash[HP_HASH_SIZE + i * shm_secondary_hash_size];
			     j < shm_secondary_hash_size;
				 j++, it++) {

				in_use_frags = it->total_no - it->no;
				used_mem = in_use_frags * size;

				hpb->used            += used_mem;
				hpb->real_used       += used_mem + it->total_no * FRAG_OVERHEAD;
				hpb->total_fragments += it->total_no;
			}
		}
	}

	if (hpb->real_used > hpb->max_real_used)
		hpb->max_real_used = hpb->real_used;

	LM_DBG("updated shm statistics: [ us: %ld | rus: %ld | frags: %ld ]\n",
	        hpb->used, hpb->real_used, hpb->total_fragments);

	gettimeofday(&hpb->last_updated, NULL);

	lock_release(hp_stats_lock);
}

unsigned long hp_shm_get_used(struct hp_block *hpb)
{
	if (stats_are_expired(hpb))
		update_shm_stats(hpb);

	return hpb->used;
}

unsigned long hp_shm_get_real_used(struct hp_block *hpb)
{
	if (stats_are_expired(hpb))
		update_shm_stats(hpb);

	return hpb->real_used;
}

unsigned long hp_shm_get_max_real_used(struct hp_block *hpb)
{
	if (stats_are_expired(hpb))
		update_shm_stats(hpb);

	return hpb->max_real_used;
}

unsigned long hp_shm_get_free(struct hp_block *hpb)
{
	if (stats_are_expired(hpb))
		update_shm_stats(hpb);

	return hpb->size - hpb->real_used;
}

unsigned long hp_shm_get_frags(struct hp_block *hpb)
{
	if (stats_are_expired(hpb))
		update_shm_stats(hpb);

	return hpb->total_fragments;
}

void hp_init_shm_statistics(struct hp_block *hpb)
{
	update_shm_stats(hpb);
}

#else /* HP_MALLOC_FAST_STATS */

void hp_init_shm_statistics(struct hp_block *hpb)
{
	/* reset stats updated by mallocs before this init */
	shm_used->flags &= ~STAT_NO_RESET;
	shm_rused->flags &= ~STAT_NO_RESET;
	shm_frags->flags &= ~STAT_NO_RESET;
	reset_stat(shm_used);
	reset_stat(shm_rused);
	reset_stat(shm_frags);
	shm_used->flags |= STAT_NO_RESET;
	shm_rused->flags |= STAT_NO_RESET;
	shm_frags->flags |= STAT_NO_RESET;
	update_stat(shm_used, (long)hpb->used);
	update_stat(shm_rused, (long)hpb->real_used);
	update_stat(shm_frags, (long)hpb->total_fragments);

	LM_INFO("initialized atomic shm statistics: "
	       "[ us: %ld | rus: %ld | frags: %ld ]\n", hpb->used, hpb->real_used,
	       hpb->total_fragments);
}

unsigned long hp_shm_get_used(struct hp_block *hpb)
{
	return get_stat_val(shm_used);
}

unsigned long hp_shm_get_real_used(struct hp_block *hpb)
{
	return get_stat_val(shm_rused);
}

unsigned long hp_shm_get_max_real_used(struct hp_block *hpb)
{
	return hpb->max_real_used;
}

unsigned long hp_shm_get_free(struct hp_block *hpb)
{
	return hpb->size - get_stat_val(shm_rused);
}

unsigned long hp_shm_get_frags(struct hp_block *hpb)
{
	return get_stat_val(shm_frags);
}
#endif /* HP_MALLOC_FAST_STATS */

void hp_init_rpm_statistics(struct hp_block *hpb)
{
#ifdef DBG_MALLOC
	/* reset stats updated by mallocs before this init */
	rpm_used->flags &= ~STAT_NO_RESET;
	rpm_rused->flags &= ~STAT_NO_RESET;
	rpm_frags->flags &= ~STAT_NO_RESET;
	reset_stat(rpm_used);
	reset_stat(rpm_rused);
	reset_stat(rpm_frags);
	rpm_used->flags |= STAT_NO_RESET;
	rpm_rused->flags |= STAT_NO_RESET;
	rpm_frags->flags |= STAT_NO_RESET;
#endif
	update_stat(rpm_used, (int)hpb->used);
	update_stat(rpm_rused, (int)hpb->real_used);
	update_stat(rpm_frags, (int)hpb->total_fragments);

	LM_DBG("initializing atomic rpm statistics: "
	       "[ us: %ld | rus: %ld | frags: %ld ]\n", hpb->used, hpb->real_used, hpb->total_fragments);
}

unsigned long hp_rpm_get_used(struct hp_block *hpb)
{
	return get_stat_val(rpm_used);
}

unsigned long hp_rpm_get_real_used(struct hp_block *hpb)
{
	return get_stat_val(rpm_rused);
}

unsigned long hp_rpm_get_max_real_used(struct hp_block *hpb)
{
	return hpb->max_real_used;
}

unsigned long hp_rpm_get_free(struct hp_block *hpb)
{
	return hpb->size - get_stat_val(rpm_rused);
}

unsigned long hp_rpm_get_frags(struct hp_block *hpb)
{
	return get_stat_val(rpm_frags);
}

unsigned long hp_pkg_get_size(struct hp_block *hpb)
{
	return hpb->size;
}

unsigned long hp_pkg_get_used(struct hp_block *hpb)
{
	return hpb->used;
}

unsigned long hp_pkg_get_real_used(struct hp_block *hpb)
{
	return hpb->real_used;
}

unsigned long hp_pkg_get_max_real_used(struct hp_block *hpb)
{
	return hpb->max_real_used;
}

unsigned long hp_pkg_get_free(struct hp_block *hpb)
{
	return hpb->size - hpb->real_used;
}

unsigned long hp_pkg_get_frags(struct hp_block *hpb)
{
	return hpb->total_fragments;
}

#endif /* STATISTICS */

#endif /* HP_MALLOC_STATS_H */
#endif /* HP_MALLOC */
