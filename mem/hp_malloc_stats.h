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

#ifndef HP_MALLOC_STATS_H
#define HP_MALLOC_STATS_H

#include "../lock_ops.h"

#ifdef STATISTICS
#ifdef HP_MALLOC_FAST_STATS
extern gen_lock_t *hp_stats_lock;
#endif

int stats_are_expired(struct hp_block *hpb);
void update_shm_stats(struct hp_block *hpb);
void hp_init_shm_statistics(struct hp_block *hpb);

unsigned long hp_shm_get_size(struct hp_block *hpb);
unsigned long hp_shm_get_used(struct hp_block *hpb);
unsigned long hp_shm_get_free(struct hp_block *hpb);
unsigned long hp_shm_get_real_used(struct hp_block *hpb);
unsigned long hp_shm_get_max_real_used(struct hp_block *hpb);
unsigned long hp_shm_get_frags(struct hp_block *hpb);

unsigned long hp_pkg_get_size(struct hp_block *hpb);
unsigned long hp_pkg_get_used(struct hp_block *hpb);
unsigned long hp_pkg_get_free(struct hp_block *hpb);
unsigned long hp_pkg_get_real_used(struct hp_block *hpb);
unsigned long hp_pkg_get_max_real_used(struct hp_block *hpb);
unsigned long hp_pkg_get_frags(struct hp_block *hpb);

unsigned long hp_rpm_get_size(struct hp_block *hpb);
unsigned long hp_rpm_get_used(struct hp_block *hpb);
unsigned long hp_rpm_get_free(struct hp_block *hpb);
unsigned long hp_rpm_get_real_used(struct hp_block *hpb);
unsigned long hp_rpm_get_max_real_used(struct hp_block *hpb);
unsigned long hp_rpm_get_frags(struct hp_block *hpb);

#define update_stats_pkg_frag_attach(blk, frag) \
	do { \
		(blk)->used -= (frag)->size; \
		(blk)->real_used -= (frag)->size + FRAG_OVERHEAD; \
	} while (0)

#define update_stats_pkg_frag_detach(blk, frag) \
	do { \
		(blk)->used += (frag)->size; \
		(blk)->real_used += (frag)->size + FRAG_OVERHEAD; \
	} while (0)

#define update_stats_pkg_frag_split(blk, ...) \
	do { \
		(blk)->used -= FRAG_OVERHEAD; \
		(blk)->total_fragments++; \
	} while (0)

#define update_stats_pkg_frag_merge(blk, ...) \
	do { \
		(blk)->used += FRAG_OVERHEAD; \
		(blk)->total_fragments--; \
	} while (0)

#if defined HP_MALLOC_FAST_STATS
	#define update_stats_shm_frag_attach(frag)
	#define update_stats_shm_frag_detach(size)
	#define update_stats_shm_frag_split()
	#define update_stats_shm_frag_merge()
	#define update_stats_rpm_frag_attach(frag)
	#define update_stats_rpm_frag_detach(frag)
	#define update_stats_rpm_frag_split()

#else /* HP_MALLOC_FAST_STATS */
	#define update_stats_shm_frag_attach(frag) \
		do { \
			update_stat(shm_used, -(long)(frag)->size); \
			update_stat(shm_rused, -(long)((frag)->size + FRAG_OVERHEAD)); \
		} while (0)

	#define update_stats_shm_frag_detach(size) \
		do { \
			update_stat(shm_used, size); \
			update_stat(shm_rused, size + FRAG_OVERHEAD); \
		} while (0)

	#define update_stats_shm_frag_split(...) \
		do { \
			update_stat(shm_used, -FRAG_OVERHEAD); \
			update_stat(shm_frags, 1); \
		} while (0)

	#define update_stats_shm_frag_merge(...) \
		do { \
			update_stat(shm_used,  FRAG_OVERHEAD); \
			update_stat(shm_frags, -1); \
		} while (0)

	#define update_stats_rpm_frag_attach(frag) \
		do { \
			update_stat(rpm_used, -(long)(frag)->size); \
			update_stat(rpm_rused, -(long)((frag)->size + FRAG_OVERHEAD)); \
		} while (0)

	#define update_stats_rpm_frag_detach(frag) \
		do { \
			update_stat(rpm_used, (frag)->size); \
			update_stat(rpm_rused, (frag)->size + FRAG_OVERHEAD); \
		} while (0)

	#define update_stats_rpm_frag_split(...) \
		do { \
			update_stat(rpm_used, -FRAG_OVERHEAD); \
			update_stat(rpm_rused, FRAG_OVERHEAD); \
			update_stat(rpm_frags, 1); \
		} while (0)

#endif /* HP_MALLOC_FAST_STATS */

#else /* STATISTICS */
	#define stats_are_expired(...) 0
	#define update_shm_stats(...)

	#define hp_init_shm_statistics(...)
	#define update_stats_pkg_frag_attach(blk, frag)
	#define update_stats_pkg_frag_detach(blk, frag)
	#define update_stats_pkg_frag_split(blk, ...)
	#define update_stats_pkg_frag_merge(blk, ...)
	#define update_stats_shm_frag_attach(frag)
	#define update_stats_shm_frag_detach(size)
	#define update_stats_shm_frag_split(...)
	#define update_stats_shm_frag_merge(...)
	#define update_stats_rpm_frag_attach(frag)
	#define update_stats_rpm_frag_detach(frag)
	#define update_stats_rpm_frag_split(...)
#endif

#endif /* HP_MALLOC_STATS_H */
