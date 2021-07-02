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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sys/time.h"

#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../locking.h"

#include "hp_malloc.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#define MIN_FRAG_SIZE	ROUNDTO

/* only perform a split if the resulting free fragment is at least this size */
#define MIN_SHM_SPLIT_SIZE	4096
#define MIN_PKG_SPLIT_SIZE	 256

#define FRAG_NEXT(f) ((struct hp_frag *)((char *)((f) + 1) + (f)->size))

#define FRAG_OVERHEAD	   HP_FRAG_OVERHEAD
#define frag_is_free(_f)   ((_f)->prev)

/* used when detaching free fragments */
static unsigned int optimized_get_indexes[HP_HASH_SIZE];

/* used when attaching free fragments */
static unsigned int optimized_put_indexes[HP_HASH_SIZE];

/* finds the hash value for s, s=ROUNDTO multiple */
#define GET_HASH(s)  (((unsigned long)(s) <= HP_MALLOC_OPTIMIZE) ? \
	(unsigned long)(s) / ROUNDTO : \
	HP_LINEAR_HASH_SIZE + big_hash_idx(s) - HP_MALLOC_OPTIMIZE_FACTOR + 1)

/*
 * - for heavily used sizes (which need some optimizing) it returns
 *   a hash entry for the given size in a round-robin manner
 * - for the non-optimized sizes, behaviour is identical to GET_HASH
 */
#define GET_HASH_RR(fmb, s)  (((unsigned long)(s) <= HP_MALLOC_OPTIMIZE) ? \
	({ \
		unsigned int ___hash, ___idx, ___ret; \
		___hash = (unsigned long)(s) / ROUNDTO; \
		!fmb->free_hash[___hash].is_optimized ? \
			___hash : \
			({ \
				___idx = optimized_put_indexes[___hash]; \
				___ret = HP_HASH_SIZE + \
				         ___hash * shm_secondary_hash_size + ___idx; \
				optimized_put_indexes[___hash] = \
					(___idx + 1) % shm_secondary_hash_size; \
				___ret; \
			}); \
	}) : \
	HP_LINEAR_HASH_SIZE + big_hash_idx((s)) - HP_MALLOC_OPTIMIZE_FACTOR + 1)

/*
 * peek at the next round-robin assigned hash
 *
 * unlike GET_HASH_RR, it always returns the same result
 */
#define PEEK_HASH_RR(fmb, s)  (((unsigned long)(s) <= HP_MALLOC_OPTIMIZE) ? \
	({ \
		unsigned int ___hash; \
		___hash = (unsigned long)(s) / ROUNDTO; \
		!fmb->free_hash[___hash].is_optimized ? \
			___hash : \
			HP_HASH_SIZE + ___hash * shm_secondary_hash_size + \
			optimized_put_indexes[___hash]; \
	}) : \
	HP_LINEAR_HASH_SIZE + big_hash_idx((s)) - HP_MALLOC_OPTIMIZE_FACTOR + 1)

extern unsigned long *shm_hash_usage;

/*
 * adaptive image of OpenSIPS's memory usage during runtime
 * used to fragment the shared memory pool at daemon startup
 */
char *mem_warming_pattern_file = MEM_WARMING_DEFAULT_PATTERN_FILE;
int mem_warming_enabled;

/*
 * percentage of shared memory which will be fragmented at startup
 * common values are between [0, 75]
 */
int mem_warming_percentage = MEM_WARMING_DEFAULT_PERCENTAGE;

#if defined(HP_MALLOC)
#if !defined(HP_MALLOC_FAST_STATS)
stat_var *shm_used;
stat_var *shm_rused;
stat_var *shm_frags;
#endif
#endif

/* ROUNDTO= 2^k so the following works */
#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

#define SHM_LOCK(i) lock_get(&mem_locks[i])
#define SHM_UNLOCK(i) lock_release(&mem_locks[i])
#define RPM_LOCK(i) lock_get(&rpmem_locks[i])
#define RPM_UNLOCK(i) lock_release(&rpmem_locks[i])

#define MEM_FRAG_AVOIDANCE

#define can_split_frag(frag, wanted_size, min_size) \
	((frag)->size - wanted_size >= min_size)

#define can_split_pkg_frag(frag, wanted_size) \
	can_split_frag(frag, wanted_size, MIN_PKG_SPLIT_SIZE)
#define can_split_shm_frag(frag, wanted_size) \
	can_split_frag(frag, wanted_size, MIN_SHM_SPLIT_SIZE)
#define can_split_rpm_frag can_split_shm_frag

/* computes hash number for big buckets */
inline static unsigned long big_hash_idx(unsigned long s)
{
	unsigned long idx;

	/* s is rounded => s = k*2^n (ROUNDTO=2^n)
	 * index= i such that 2^i > s >= 2^(i-1)
	 *
	 * => index = number of the first non null bit in s*/
	idx = 8 * sizeof(long) - 1;

	for (; !(s & (1UL << (8 * sizeof(long) - 1))); s <<= 1, idx--)
		;

	return idx;
}

static inline void hp_lock(struct hp_block *hpb, unsigned int hash)
{
	int i;

	if (!hpb->free_hash[hash].is_optimized) {
		SHM_LOCK(hash);
		return;
	}

	/* for optimized buckets, we have to lock the entire array */
	hash = HP_HASH_SIZE + hash * shm_secondary_hash_size;
	for (i = 0; i < shm_secondary_hash_size; i++)
		SHM_LOCK(hash + i);
}

static inline void hp_unlock(struct hp_block *hpb, unsigned int hash)
{
	int i;

	if (!hpb->free_hash[hash].is_optimized) {
		SHM_UNLOCK(hash);
		return;
	}

	/* for optimized buckets, we have to unlock the entire array */
	hash = HP_HASH_SIZE + hash * shm_secondary_hash_size;
	for (i = 0; i < shm_secondary_hash_size; i++)
		SHM_UNLOCK(hash + i);
}

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
unsigned long hp_stats_get_index(void *ptr)
{
	if (!ptr)
		return GROUP_IDX_INVALID;

	return HP_FRAG(ptr)->statistic_index;
}

void hp_stats_set_index(void *ptr, unsigned long idx)
{
	if (!ptr)
		return;

	HP_FRAG(ptr)->statistic_index = idx;
}
#endif

#if 0
/* walk through all fragments and write them to the log.  Useful for dev */
static void hp_dump(struct hp_block *hpb)
{
	struct hp_frag *f;

	fprintf(stderr, "dumping all fragments...\n");

	for (f = hpb->first_frag; f < hpb->last_frag; f = FRAG_NEXT(f)) {
		fprintf(stderr, "    | sz: %lu, prev: %p, next: %p |\n", f->size,
		       f->prev, f->nxt_free);
	}
}
#endif

static inline void hp_frag_attach(struct hp_block *hpb, struct hp_frag *frag)
{
	struct hp_frag **f;
	unsigned int hash;


	hash = GET_HASH_RR(hpb, frag->size);

	f = &(hpb->free_hash[hash].first);

	if (frag->size > HP_MALLOC_OPTIMIZE){ /* because of '<=' in GET_HASH,
											 purpose --andrei ) */
		for(; *f; f=&((*f)->nxt_free)){
			if (frag->size <= (*f)->size) break;
		}
	}

	/*insert it here*/
	frag->prev = f;
	frag->nxt_free=*f;
	if (*f)
		(*f)->prev = &(frag->nxt_free);

	*f = frag;

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[hash].no++;
#endif
}

static inline void hp_frag_detach(struct hp_block *hpb, struct hp_frag *frag)
{
	struct hp_frag **pf;

	pf = frag->prev;

	/* detach */
	*pf = frag->nxt_free;

	if (frag->nxt_free)
		frag->nxt_free->prev = pf;

	frag->prev = NULL;

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[GET_HASH(frag->size)].no--;
#endif
}

#include "hp_malloc_dyn.h"

#if !defined INLINE_ALLOC && defined DBG_MALLOC
#undef DBG_MALLOC
#include "hp_malloc_dyn.h"
#define DBG_MALLOC
#endif

/**
 * dumps the current memory allocation pattern of OpenSIPS into a pattern file
 */
void hp_update_shm_pattern_file(void)
{
	int i;
	FILE *f;
	unsigned long long sum = 0;
	double verification = 0;

	if (!mem_warming_enabled)
		return;

	f = fopen(mem_warming_pattern_file, "w+");
	if (!f) {
		LM_ERR("failed to open pattern file %s for writing: %d - %s\n",
		        mem_warming_pattern_file, errno, strerror(errno));
		return;
	}

	if (fprintf(f, "%lu %lu\n", ROUNDTO, HP_HASH_SIZE) < 0)
		goto write_error;

	/* first compute sum of all malloc requests since startup */
	for (i = 0; i < HP_MALLOC_OPTIMIZE / ROUNDTO; i++)
		sum += shm_hash_usage[i] * (i * ROUNDTO + FRAG_OVERHEAD);

	LM_DBG("mem warming hash sum: %llu\n", sum);

	/* save the usage rate of each bucket to the memory pattern file */
	for (i = 0; i < HP_MALLOC_OPTIMIZE / ROUNDTO; i++) {
		LM_DBG("[%d] %lf %.8lf\n", i, (double)shm_hash_usage[i],
				(double)shm_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD));

		verification += (double)shm_hash_usage[i] /
					     sum * (i * ROUNDTO + FRAG_OVERHEAD);

		if (fprintf(f, "%.12lf ",
		            (double)shm_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD)) < 0)
			goto write_error;

		if (i % 10 == 9)
			fprintf(f, "\n");
	}

	if (verification < 0.99 || verification > 1.01)
		LM_INFO("memory pattern file appears to be incorrect: %lf\n", verification);

	LM_INFO("updated memory pattern file %s\n", mem_warming_pattern_file);

	fclose(f);
	return;

write_error:
	LM_ERR("failed to update pattern file %s\n", mem_warming_pattern_file);
	fclose(f);
}

/**
 * on-demand memory fragmentation, based on an input pattern file
 *    (pre-populates the hash with free fragments)
 */
int hp_mem_warming(struct hp_block *hpb)
{
	struct size_fraction {
		int hash_index;

		double amount;
		unsigned long fragments;

		struct size_fraction *next;
	};

	struct size_fraction *sf, *it, *sorted_sf = NULL;
	FILE *f;
	size_t rc;
	unsigned long roundto, hash_size;
	long long bucket_mem;
	int i, c = 0;
	unsigned int current_frag_size;
	struct hp_frag *big_frag;
	unsigned int optimized_buckets;

	f = fopen(mem_warming_pattern_file, "r");
	if (!f) {
		LM_ERR("failed to open pattern file %s: %d - %s\n",
		        mem_warming_pattern_file, errno, strerror(errno));
		return -1;
	}

	rc = fscanf(f, "%lu %lu\n", &roundto, &hash_size);
	if (rc != 2) {
		LM_ERR("failed to read from %s: bad file format\n",
		        mem_warming_pattern_file);
		goto out;
	}
	rc = 0;

	if (roundto != ROUNDTO || hash_size != HP_HASH_SIZE) {
		LM_ERR("incompatible pattern file data: [HP_HASH_SIZE: %lu-%lu] "
		       "[ROUNDTO: %lu-%lu]\n", hash_size, HP_HASH_SIZE, roundto, ROUNDTO);
		rc = -1;
		goto out;
	}

	/* read bucket usage percentages and sort them by number of fragments */
	for (i = 0; i < HP_LINEAR_HASH_SIZE; i++) {

		sf = malloc(sizeof *sf);
		if (!sf) {
			LM_INFO("malloc failed, skipping shm warming\n");
			rc = -1;
			goto out_free;
		}

		sf->hash_index = i;
		sf->next = NULL;

		if (fscanf(f, "%lf", &sf->amount) != 1) {
			LM_CRIT("%s appears to be corrupt. Please remove it first\n",
			         mem_warming_pattern_file);
			abort();
		}
		
		if (i == 0)
			sf->fragments = 0;
		else
			sf->fragments = sf->amount * hpb->size / (ROUNDTO * i);

		if (!sorted_sf)
			sorted_sf = sf;
		else {
			for (it = sorted_sf;
			     it->next && it->next->fragments > sf->fragments;
				 it = it->next)
				;

			if (it->fragments < sf->fragments) {
				sf->next = sorted_sf;
				sorted_sf = sf;
			} else {
				sf->next = it->next;
				it->next = sf;
			}
		}
	}

	/* only optimize the configured number of buckets */
	optimized_buckets = (float)shm_hash_split_percentage / 100 * HP_LINEAR_HASH_SIZE;

	LM_INFO("Optimizing %u / %lu mem buckets\n", optimized_buckets,
	         HP_LINEAR_HASH_SIZE);

	sf = sorted_sf;
	for (i = 0; i < optimized_buckets; i++) {
		hpb->free_hash[sf->hash_index].is_optimized = 1;
		sf = sf->next;
	}

	/* the big frag is typically next-to-last */
	big_frag = hpb->first_frag;
	while (FRAG_NEXT(big_frag) != hpb->last_frag)
		big_frag = FRAG_NEXT(big_frag);

	/* populate each free hash bucket with proper number of fragments */
	for (sf = sorted_sf; sf; sf = sf->next) {
		current_frag_size = ROUNDTO * sf->hash_index;
		bucket_mem = sf->amount * hpb->size * mem_warming_percentage / 100;

		LM_INFO("[%d][%ld][%s] fraction: %.12lf total mem: %llu, %d\n",
		        sf->hash_index, sf->fragments,
		        hpb->free_hash[sf->hash_index].is_optimized ? "X" : " ",
		        sf->amount, bucket_mem, current_frag_size);

		/* create free fragments worth of 'bucket_mem' memory */
		while (bucket_mem >= FRAG_OVERHEAD + current_frag_size) {
			hp_frag_detach(hpb, big_frag);
			if (stats_are_ready()) {
				update_stats_shm_frag_detach(big_frag->size);
				#if defined(DBG_MALLOC) || defined(STATISTICS)
				hpb->used += big_frag->size;
				hpb->real_used += big_frag->size + FRAG_OVERHEAD;
				#endif
			} else {
				hpb->used += big_frag->size;
				hpb->real_used += big_frag->size + FRAG_OVERHEAD;
			}

			/* trim-insert operation on the big free fragment */
			#ifdef DBG_MALLOC
			shm_frag_split_unsafe(hpb, big_frag, current_frag_size,
									__FILE__, __FUNCTION__, __LINE__);
			#else
			shm_frag_split_unsafe(hpb, big_frag, current_frag_size);
			#endif

			/*
			 * "big_frag" now points to a smaller, free and detached frag.
			 *
			 * With optimized buckets, inserts will be automagically
			 * balanced within their dedicated hashes
			 */
			hp_frag_attach(hpb, big_frag);
			if (stats_are_ready()) {
				update_stats_shm_frag_attach(big_frag);
			} else {
				hpb->used -= big_frag->size;
				hpb->real_used -= big_frag->size + FRAG_OVERHEAD;
			}

			big_frag = FRAG_NEXT(big_frag);

			bucket_mem -= FRAG_OVERHEAD + current_frag_size;

			if (c % 1000000 == 0)
				LM_INFO("%d| %lld %p\n", c, bucket_mem, big_frag);

			c++;
		}
	}

out_free:
	while (sorted_sf) {
		sf = sorted_sf;
		sorted_sf = sorted_sf->next;
		free(sf);
	}

out:
	fclose(f);
	return rc;
}

/* initialise the allocator and return its main block */
static struct hp_block *hp_malloc_init(char *address, unsigned long size,
										char *name)
{
	char *start;
	char *end;
	struct hp_block *hpb;
	unsigned long init_overhead;

	/* make address and size multiple of 8*/
	start = (char *)ROUNDUP((unsigned long) address);
	LM_DBG("HP_OPTIMIZE=%lu, HP_LINEAR_HASH_SIZE=%lu, %lu-bytes aligned\n",
			HP_MALLOC_OPTIMIZE, HP_LINEAR_HASH_SIZE, (unsigned long)ROUNDTO);
	LM_DBG("HP_HASH_SIZE=%lu, HP_EXTRA_HASH_SIZE=%lu, hp_block size=%zu, "
			"frag_size=%zu\n", HP_HASH_SIZE, HP_EXTRA_HASH_SIZE,
			sizeof(struct hp_block), sizeof(struct hp_frag));
	LM_DBG("params (%p, %lu), start=%p\n", address, size, start);

	if (size < (unsigned long)(start - address))
		return NULL;

	size -= start - address;

	if (size < (MIN_FRAG_SIZE+FRAG_OVERHEAD))
		return NULL;

	size = ROUNDDOWN(size);

	init_overhead = ROUNDUP(sizeof(struct hp_block)) + 2 * FRAG_OVERHEAD;
	if (size < init_overhead)
	{
		LM_ERR("not enough memory for the basic structures! "
		       "need %lu bytes\n", init_overhead);
		/* not enough mem to create our control structures !!!*/
		return NULL;
	}

	end = start + size;
	hpb = (struct hp_block *)start;
	memset(hpb, 0, sizeof(struct hp_block));
	hpb->name = name;
	hpb->size = size;

	hpb->used = 0;
	hpb->real_used = init_overhead;
	hpb->max_real_used = init_overhead;
	hpb->total_fragments = 2;
	gettimeofday(&hpb->last_updated, NULL);

	hpb->first_frag = (struct hp_frag *)(start + ROUNDUP(sizeof(struct hp_block)));
	hpb->last_frag = (struct hp_frag *)(end - sizeof *hpb->last_frag);
	hpb->last_frag->size = 0;

	/* init initial fragment */
	hpb->first_frag->size = size - init_overhead;
	hpb->first_frag->prev = NULL;
	hpb->last_frag->prev  = NULL;

	hp_frag_attach(hpb, hpb->first_frag);

	return hpb;
}

struct hp_block *hp_pkg_malloc_init(char *address, unsigned long size,
									char *name)
{
	struct hp_block *hpb;
	
	hpb = hp_malloc_init(address, size, name);
	if (!hpb) {
		LM_ERR("failed to initialize shm block\n");
		return NULL;
	}

	return hpb;
}

struct hp_block *hp_shm_malloc_init(char *address, unsigned long size,
									char *name)
{
	struct hp_block *hpb;
	
	hpb = hp_malloc_init(address, size, name);
	if (!hpb) {
		LM_ERR("failed to initialize shm block\n");
		return NULL;
	}

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[PEEK_HASH_RR(hpb, hpb->first_frag->size)].total_no++;
#endif

#ifdef HP_MALLOC_FAST_STATS
#ifdef DBG_MALLOC
	hp_stats_lock = hp_shm_malloc_unsafe(hpb, sizeof *hp_stats_lock,
											__FILE__, __FUNCTION__, __LINE__);
#else
	hp_stats_lock = hp_shm_malloc_unsafe(hpb, sizeof *hp_stats_lock);
#endif
	if (!hp_stats_lock) {
		LM_ERR("failed to alloc hp statistics lock\n");
		return NULL;
	}

	if (!lock_init(hp_stats_lock)) {
		LM_CRIT("could not initialize hp statistics lock\n");
		return NULL;
	}
#endif

	return hpb;
}


#ifdef SHM_EXTRA_STATS
void hp_stats_core_init(struct hp_block *hp, int core_index)
{
	struct hp_frag *f;

	for (f=hp->first_frag; f < hp->last_frag; f=FRAG_NEXT(f))
		if (!frag_is_free(f))
			f->statistic_index = core_index;
}
#endif


/* fills a malloc info structure with info about the memory block */
void hp_info(struct hp_block *hpb, struct mem_info *info)
{
	memset(info, 0, sizeof *info);

	info->total_size = hpb->size;
	info->min_frag = MIN_FRAG_SIZE;

#ifdef HP_MALLOC_FAST_STATS
	if (stats_are_expired(hpb))
		update_shm_stats(hpb);
#endif

	info->used = hpb->used;
	info->real_used = hpb->real_used;
	info->free = hpb->size - hpb->real_used;
	info->total_frags = hpb->total_fragments;

	LM_DBG("mem_info: (sz: %ld | us: %ld | rus: %ld | free: %ld | frags: %ld)\n",
	        info->total_size, info->used, info->real_used, info->free,
	        info->total_frags);
}

#endif
