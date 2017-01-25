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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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

#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../locking.h"

#include "hp_malloc.h"
#include "common.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

extern unsigned long *mem_hash_usage;

/*
 * adaptive image of OpenSIPS's memory usage during runtime
 * used to fragment the shared memory pool at daemon startup
 */
char *mem_warming_pattern_file;
int mem_warming_enabled;

/*
 * percentage of shared memory which will be fragmented at startup
 * common values are between [0, 75]
 */
int mem_warming_percentage = -1;

#if defined(HP_MALLOC) && !defined(HP_MALLOC_FAST_STATS)
stat_var *shm_used;
stat_var *shm_rused;
stat_var *shm_frags;
#endif

/* ROUNDTO= 2^k so the following works */
#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

#define SHM_LOCK(i) lock_get(&mem_lock[i])
#define SHM_UNLOCK(i) lock_release(&mem_lock[i])

#define MEM_FRAG_AVOIDANCE

#define HP_MALLOC_LARGE_LIMIT    HP_MALLOC_OPTIMIZE
#define HP_MALLOC_DEFRAG_LIMIT (HP_MALLOC_LARGE_LIMIT * 5)
#define HP_MALLOC_DEFRAG_PERCENT 5

#define can_split_frag(frag, wanted_size) \
	((frag)->size - wanted_size > (FRAG_OVERHEAD + MIN_FRAG_SIZE))

/*
 * the *_split functions try to split a fragment in an attempt
 * to minimize memory usage
 */
#ifdef DBG_MALLOC
#define pkg_frag_split(blk, frag, sz, fl, fnc, ln) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__pkg_frag_split(blk, frag, sz, fl, fnc, ln); \
			update_stats_pkg_frag_split(blk); \
		} \
	} while (0)
#else
#define pkg_frag_split(blk, frag, sz) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__pkg_frag_split(blk, frag, sz); \
			update_stats_pkg_frag_split(blk); \
		} \
	} while (0)
#endif

#ifdef DBG_MALLOC
#define shm_frag_split_unsafe(blk, frag, sz, fl, fnc, ln) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__shm_frag_split_unsafe(blk, frag, sz, fl, fnc, ln); \
			if (stats_are_ready()) { \
				update_stats_shm_frag_split(); \
			} else { \
				(blk)->used -= FRAG_OVERHEAD; \
				(blk)->real_used += FRAG_OVERHEAD; \
				(blk)->total_fragments++; \
			} \
		} \
	} while (0)
#else
#define shm_frag_split_unsafe(blk, frag, sz) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__shm_frag_split_unsafe(blk, frag, sz); \
			if (stats_are_ready()) { \
				update_stats_shm_frag_split(); \
			} else { \
				(blk)->used -= FRAG_OVERHEAD; \
				(blk)->real_used += FRAG_OVERHEAD; \
				(blk)->total_fragments++; \
			} \
		} \
	} while (0)
#endif

/* Note: the shm lock on "hash" must be acquired when this is called */
#ifdef DBG_MALLOC
#define shm_frag_split(blk, frag, sz, hash, fl, fnc, ln) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__shm_frag_split(blk, frag, sz, hash, fl, fnc, ln); \
			update_stats_shm_frag_split(); \
		} \
	} while (0)
#else
#define shm_frag_split(blk, frag, sz, hash) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__shm_frag_split(blk, frag, sz, hash); \
			update_stats_shm_frag_split(); \
		} \
	} while (0)
#endif

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

unsigned long frag_size(void* p){
	if(!p)
		return 0;
	return ((struct hp_frag*) ((char*)p - sizeof(struct hp_frag)))->size;
}

#ifdef SHM_EXTRA_STATS
void set_stat_index (void *ptr, unsigned long idx) {
	struct hp_frag *f;
	f = (struct hp_frag *)((char*)ptr - sizeof(struct hp_frag));
	f->statistic_index = idx;
}

unsigned long get_stat_index(void *ptr) {
	struct hp_frag *f;
	f = (struct hp_frag *)((char*)ptr - sizeof(struct hp_frag));
	return f->statistic_index;
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
		for(; *f; f=&((*f)->u.nxt_free)){
			if (frag->size <= (*f)->size) break;
		}
	}

	/*insert it here*/
	frag->prev = f;
	frag->u.nxt_free=*f;
	if (*f)
		(*f)->prev = &(frag->u.nxt_free);

	/* mark fragment as "free" */
#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	frag->is_free = 1;
#endif

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
	*pf = frag->u.nxt_free;

	if (frag->u.nxt_free)
		frag->u.nxt_free->prev = pf;

	frag->prev = NULL;

#ifdef HP_MALLOC_FAST_STATS
	unsigned int hash;

	hash = GET_HASH_RR(hpb, frag->size);
	hpb->free_hash[hash].no--;
#endif
};

#ifdef DBG_MALLOC
void __pkg_frag_split(struct hp_block *hpb, struct hp_frag *frag, unsigned long size,
						const char* file, const char* func, unsigned int line)
#else
void __pkg_frag_split(struct hp_block *hpb, struct hp_frag *frag,
							 unsigned long size)
#endif
{
	unsigned long rest;
	struct hp_frag *n;

	rest = frag->size - size;
	frag->size = size;

	/* split the fragment */
	n = FRAG_NEXT(frag);
	n->size = rest - FRAG_OVERHEAD;

#ifdef DBG_MALLOC
	/* frag created by malloc or realloc, mark it*/
	n->file=file;
	n->func=func;
	n->line=line;
#ifndef STATISTICS
	hpb->used -= FRAG_OVERHEAD;
	hpb->real_used += FRAG_OVERHEAD;
	hpb->total_fragments++;
#endif
#endif

	hp_frag_attach(hpb, n);
	update_stats_pkg_frag_attach(hpb, n);

#if defined(DBG_MALLOC) && !defined(STATISTICS)
	hpb->used -= n->size;
	hpb->real_used -= n->size + FRAG_OVERHEAD;
#endif
}

#ifdef DBG_MALLOC
void __shm_frag_split_unsafe(struct hp_block *hpb, struct hp_frag *frag, unsigned long size,
								const char* file, const char* func, unsigned int line)
#else
void __shm_frag_split_unsafe(struct hp_block *hpb, struct hp_frag *frag,
							unsigned long size)
#endif
{
	unsigned long rest;
	struct hp_frag *n;

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[PEEK_HASH_RR(hpb, frag->size)].total_no--;
	hpb->free_hash[PEEK_HASH_RR(hpb, size)].total_no++;
#endif

	rest = frag->size - size;
	frag->size = size;

	/* split the fragment */
	n = FRAG_NEXT(frag);
	n->size = rest - FRAG_OVERHEAD;

#ifdef DBG_MALLOC
	/* frag created by malloc, mark it*/
	n->file=file;
	n->func="frag. from hp_malloc";
	n->line=line;
#endif

#if defined(DBG_MALLOC) || defined(STATISTICS)
	if (stats_are_ready()) {
		hpb->used -= FRAG_OVERHEAD;
		hpb->real_used += FRAG_OVERHEAD;
		hpb->total_fragments++;
	}
#endif

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[PEEK_HASH_RR(hpb, n->size)].total_no++;
#endif

	hp_frag_attach(hpb, n);

	if (stats_are_ready()) {
		update_stats_shm_frag_attach(n);
#if defined(DBG_MALLOC) || defined(STATISTICS)
		hpb->used -= n->size;
		hpb->real_used -= n->size + FRAG_OVERHEAD;
#endif
	} else {
		hpb->used -= n->size;
		hpb->real_used -= n->size + FRAG_OVERHEAD;
	}
}

 /* size should already be rounded-up */
#ifdef DBG_MALLOC
void __shm_frag_split(struct hp_block *hpb, struct hp_frag *frag, unsigned long size,
			unsigned int old_hash, const char* file, const char* func, unsigned int line)
#else
void __shm_frag_split(struct hp_block *hpb, struct hp_frag *frag,
					 unsigned long size, unsigned int old_hash)
#endif
{
	unsigned long rest, hash;
	struct hp_frag *n;

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[PEEK_HASH_RR(hpb, frag->size)].total_no--;
	hpb->free_hash[PEEK_HASH_RR(hpb, size)].total_no++;
#endif

	rest = frag->size - size;
	frag->size = size;

	/* split the fragment */
	n = FRAG_NEXT(frag);
	n->size = rest - FRAG_OVERHEAD;

#ifdef DBG_MALLOC
	/* frag created by malloc, mark it*/
	n->file=file;
	n->func="frag. from hp_malloc";
	n->line=line;
#endif

#if defined(DBG_MALLOC) || defined(STATISTICS)
	hpb->used -= FRAG_OVERHEAD;
	hpb->real_used += FRAG_OVERHEAD;
	hpb->total_fragments++;
#endif

	/* insert the newly obtained hp_frag in its free list */
	hash = PEEK_HASH_RR(hpb, n->size);

	if (hash != old_hash)
		SHM_LOCK(hash);

	hp_frag_attach(hpb, n);
	update_stats_shm_frag_attach(n);

#if defined(DBG_MALLOC) || defined(STATISTICS)
	hpb->used -= n->size;
	hpb->real_used -= n->size + FRAG_OVERHEAD;
#endif

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[hash].total_no++;
#endif

	if (hash != old_hash)
		SHM_UNLOCK(hash);
}

/**
 * dumps the current memory allocation pattern of OpenSIPS into a pattern file
 */
void hp_update_mem_pattern_file(void)
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
		sum += mem_hash_usage[i] * (i * ROUNDTO + FRAG_OVERHEAD);

	LM_DBG("mem warming hash sum: %llu\n", sum);

	/* save the usage rate of each bucket to the memory pattern file */
	for (i = 0; i < HP_MALLOC_OPTIMIZE / ROUNDTO; i++) {
		LM_DBG("[%d] %lf %.8lf\n", i, (double)mem_hash_usage[i],
				(double)mem_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD));

		verification += (double)mem_hash_usage[i] /
					     sum * (i * ROUNDTO + FRAG_OVERHEAD);

		if (fprintf(f, "%.12lf ",
		            (double)mem_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD)) < 0)
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

	big_frag = hpb->first_frag;

	/* populate each free hash bucket with proper number of fragments */
	for (sf = sorted_sf; sf; sf = sf->next) {
		LM_INFO("[%d][%s] fraction: %.12lf total mem: %llu, %lu\n", sf->hash_index,
		         hpb->free_hash[sf->hash_index].is_optimized ? "X" : " ",
				 sf->amount, (unsigned long long) (sf->amount *
				 hpb->size * mem_warming_percentage / 100),
				 ROUNDTO * sf->hash_index);

		current_frag_size = ROUNDTO * sf->hash_index;
		bucket_mem = sf->amount * hpb->size * mem_warming_percentage / 100;

		/* create free fragments worth of 'bucket_mem' memory */
		while (bucket_mem >= FRAG_OVERHEAD + current_frag_size) {
			hp_frag_detach(hpb, big_frag);
			if (stats_are_ready()) {
				update_stats_shm_frag_detach(big_frag);
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
				#if defined(DBG_MALLOC) || defined(STATISTICS)
					hpb->used -= big_frag->size;
					hpb->real_used -= big_frag->size + FRAG_OVERHEAD;
				#endif
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
	LM_DBG("HP_OPTIMIZE=%lu, HP_LINEAR_HASH_SIZE=%lu\n",
			HP_MALLOC_OPTIMIZE, HP_LINEAR_HASH_SIZE);
	LM_DBG("HP_HASH_SIZE=%lu, HP_EXTRA_HASH_SIZE=%lu, hp_block size=%zu\n",
			HP_HASH_SIZE, HP_EXTRA_HASH_SIZE, sizeof(struct hp_block));
	LM_DBG("params (%p, %lu), start=%p\n", address, size, start);

	if (size < (unsigned long)(start - address))
		return NULL;

	size -= start - address;

	if (size < (MIN_FRAG_SIZE+FRAG_OVERHEAD))
		return NULL;

	size = ROUNDDOWN(size);

	init_overhead = (ROUNDUP(sizeof(struct hp_block)) + 2 * FRAG_OVERHEAD);

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
	gettimeofday(&hpb->last_updated, NULL);

	hpb->first_frag = (struct hp_frag *)(start + ROUNDUP(sizeof(struct hp_block)));
	hpb->last_frag = (struct hp_frag *)(end - sizeof(struct hp_frag));
	/* init initial fragment*/
	hpb->first_frag->size = size - init_overhead;
	hpb->last_frag->size = 0;

	hpb->last_frag->prev  = NULL;
	hpb->first_frag->prev = NULL;

	/* link initial fragment into the free list*/

	hpb->large_space = 0;
	hpb->large_limit = hpb->size / 100 * HP_MALLOC_DEFRAG_PERCENT;

	if (hpb->large_limit < HP_MALLOC_DEFRAG_LIMIT)
		hpb->large_limit = HP_MALLOC_DEFRAG_LIMIT;

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

	hp_frag_attach(hpb, hpb->first_frag);

	/* first fragment attach is the equivalent of a split  */
#if defined(DBG_MALLOC) && !defined(STATISTICS)
	hpb->real_used += FRAG_OVERHEAD;
	hpb->total_fragments++;
#endif

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

	hp_frag_attach(hpb, hpb->first_frag);

	/* first fragment attach is the equivalent of a split  */
	if (stats_are_ready()) {
#if defined(STATISTICS) && !defined(HP_MALLOC_FAST_STATS)
		update_stat(shm_rused, FRAG_OVERHEAD);
		update_stat(shm_frags, 1);
#endif
#if defined(DBG_MALLOC) || defined(STATISTICS)
		hpb->real_used += FRAG_OVERHEAD;
		hpb->total_fragments++;
#endif
	} else {
		hpb->real_used += FRAG_OVERHEAD;
		hpb->total_fragments++;
	}

	/* if memory warming is on, pre-populate the hash with free fragments */
	if (mem_warming_enabled) {
		if (!mem_warming_pattern_file)
			mem_warming_pattern_file = MEM_WARMING_DEFAULT_PATTERN_FILE;

		if (mem_warming_percentage == -1)
			mem_warming_percentage = MEM_WARMING_DEFAULT_PERCENTAGE;

		if (hp_mem_warming(hpb) != 0)
			LM_INFO("skipped memory warming\n");
	}

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

	return hpb;
}

#ifdef DBG_MALLOC
void *hp_pkg_malloc(struct hp_block *hpb, unsigned long size,
						const char* file, const char* func, unsigned int line)
#else
void *hp_pkg_malloc(struct hp_block *hpb, unsigned long size)
#endif
{
	struct hp_frag *frag;
	unsigned int hash;

	/* size must be a multiple of ROUNDTO */
	size = ROUNDUP(size);

	/* search for a suitable free frag */
	for (hash = GET_HASH(size); hash < HP_HASH_SIZE; hash++) {
		frag = hpb->free_hash[hash].first;

		for (; frag; frag = frag->u.nxt_free)
			if (frag->size >= size)
				goto found;

		/* try in a bigger bucket */
	}

	/* out of memory... we have to shut down */
#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_ERR(oom_errorf, hpb->name, hpb->size - hpb->real_used,
			hpb->name[0] == 'p' ? "M" : "m");
#else
	LM_ERR(oom_nostats_errorf, hpb->name, hpb->name[0] == 'p' ? "M" : "m");
#endif
	LM_INFO("Safely shutting down OpenSIPS (aborting) ...\n");
	abort();

found:
	hp_frag_detach(hpb, frag);
	update_stats_pkg_frag_detach(hpb, frag);

#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	/* mark fragment as "busy" */
	frag->is_free = 0;
#endif
#ifndef STATISTICS
	hpb->used += frag->size;
	hpb->real_used += frag->size + FRAG_OVERHEAD;
#endif

	/* split the fragment if possible */
#ifdef DBG_MALLOC
	pkg_frag_split(hpb, frag, size, file, "fragm. from hp_malloc", line);
	frag->file=file;
	frag->func=func;
	frag->line=line;
#else
	pkg_frag_split(hpb, frag, size);
#endif

	if (hpb->real_used > hpb->max_real_used)
		hpb->max_real_used = hpb->real_used;

	pkg_threshold_check();

	return (char *)frag + sizeof *frag;
}

/*
 * although there is a lot of duplicate code, we get the best performance:
 *
 * - the _unsafe version will not be used too much anyway (usually at startup)
 * - hp_shm_malloc is faster (no 3rd parameter, no extra if blocks)
 */
#ifdef DBG_MALLOC
void *hp_shm_malloc_unsafe(struct hp_block *hpb, unsigned long size,
							const char* file, const char* func, unsigned int line)
#else
void *hp_shm_malloc_unsafe(struct hp_block *hpb, unsigned long size)
#endif
{
	struct hp_frag *frag;
	unsigned int init_hash, hash, sec_hash;
	int i;

	/* size must be a multiple of ROUNDTO */
	size = ROUNDUP(size);

	/*search for a suitable free frag*/

	for (hash = GET_HASH(size), init_hash = hash; hash < HP_HASH_SIZE; hash++) {
		if (!hpb->free_hash[hash].is_optimized) {
			frag = hpb->free_hash[hash].first;

			for (; frag; frag = frag->u.nxt_free)
				if (frag->size >= size)
					goto found;

		} else {
			/* optimized size. search through its own hash! */
			for (i = 0, sec_hash = HP_HASH_SIZE +
			                       hash * shm_secondary_hash_size +
				                   optimized_get_indexes[hash];
				 i < shm_secondary_hash_size;
				 i++, sec_hash = (sec_hash + 1) % shm_secondary_hash_size) {

				frag = hpb->free_hash[sec_hash].first;
				for (; frag; frag = frag->u.nxt_free)
					if (frag->size >= size) {
						/* free fragments are detached in a simple round-robin manner */
						optimized_get_indexes[hash] =
						    (optimized_get_indexes[hash] + i + 1)
						     % shm_secondary_hash_size;
						hash = sec_hash;
						goto found;
					}
			}
		}

		/* try in a bigger bucket */
	}

	/* out of memory... we have to shut down */
#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_ERR(oom_errorf, hpb->name, hpb->size - hpb->real_used,
			hpb->name[0] == 'p' ? "M" : "m");
#else
	LM_ERR(oom_nostats_errorf, hpb->name, hpb->name[0] == 'p' ? "M" : "m");
#endif
	abort();

found:
	hp_frag_detach(hpb, frag);

	if (stats_are_ready()) {
		update_stats_shm_frag_detach(frag);
#if defined(DBG_MALLOC) || defined(STATISTICS)
		hpb->used += frag->size;
		hpb->real_used += frag->size + FRAG_OVERHEAD;
#endif
	} else {
		hpb->used += frag->size;
		hpb->real_used += frag->size + FRAG_OVERHEAD;
	}

#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	/* mark it as "busy" */
	frag->is_free = 0;
#endif

#ifdef DBG_MALLOC
	/* split the fragment if possible */
	shm_frag_split_unsafe(hpb, frag, size, file, "fragm. from hp_malloc", line);
	frag->file=file;
	frag->func=func;
	frag->line=line;
#else
	shm_frag_split_unsafe(hpb, frag, size);
#endif

#ifndef HP_MALLOC_FAST_STATS
	if (stats_are_ready()) {
		unsigned long real_used;

		real_used = get_stat_val(shm_rused);
		if (real_used > hpb->max_real_used)
			hpb->max_real_used = real_used;
	} else
		if (hpb->real_used > hpb->max_real_used)
			hpb->max_real_used = hpb->real_used;
#endif

	if (mem_hash_usage)
		mem_hash_usage[init_hash]++;

	return (char *)frag + sizeof *frag;
}

/*
 * Note: as opposed to hp_shm_malloc_unsafe(),
 *       hp_shm_malloc() assumes that the core statistics are initialized
 */
#ifdef DBG_MALLOC
void *hp_shm_malloc(struct hp_block *hpb, unsigned long size,
						const char* file, const char* func, unsigned int line)
#else
void *hp_shm_malloc(struct hp_block *hpb, unsigned long size)
#endif
{
	struct hp_frag *frag;
	unsigned int init_hash, hash, sec_hash;
	int i;

	/* size must be a multiple of ROUNDTO */
	size = ROUNDUP(size);

	/*search for a suitable free frag*/

	for (hash = GET_HASH(size), init_hash = hash; hash < HP_HASH_SIZE; hash++) {
		if (!hpb->free_hash[hash].is_optimized) {
			SHM_LOCK(hash);
			frag = hpb->free_hash[hash].first;

			for (; frag; frag = frag->u.nxt_free)
				if (frag->size >= size)
					goto found;

			SHM_UNLOCK(hash);
		} else {
			/* optimized size. search through its own hash! */
			for (i = 0, sec_hash = HP_HASH_SIZE +
			                       hash * shm_secondary_hash_size +
				                   optimized_get_indexes[hash];
				 i < shm_secondary_hash_size;
				 i++, sec_hash = (sec_hash + 1) % shm_secondary_hash_size) {

				SHM_LOCK(sec_hash);
				frag = hpb->free_hash[sec_hash].first;
				for (; frag; frag = frag->u.nxt_free)
					if (frag->size >= size) {
						/* free fragments are detached in a simple round-robin manner */
						optimized_get_indexes[hash] =
						    (optimized_get_indexes[hash] + i + 1)
						     % shm_secondary_hash_size;
						hash = sec_hash;
						goto found;
					}

				SHM_UNLOCK(sec_hash);
			}
		}

		/* try in a bigger bucket */
	}

	/* out of memory... we have to shut down */
#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_ERR(oom_errorf, hpb->name, hpb->size - hpb->real_used,
			hpb->name[0] == 'p' ? "M" : "m");
#else
	LM_ERR(oom_nostats_errorf, hpb->name, hpb->name[0] == 'p' ? "M" : "m");
#endif
	abort();

found:
	hp_frag_detach(hpb, frag);

	update_stats_shm_frag_detach(frag);

#if defined(DBG_MALLOC) || defined(STATISTICS)
	hpb->used += (frag)->size;
	hpb->real_used += (frag)->size + FRAG_OVERHEAD;
#endif

#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	/* mark fragment as "busy" */
	frag->is_free = 0;
#endif

#ifdef DBG_MALLOC
	/* split the fragment if possible */
	shm_frag_split(hpb, frag, size, hash, file, "fragm. from hp_malloc", line);
	frag->file=file;
	frag->func=func;
	frag->line=line;
#else
	shm_frag_split(hpb, frag, size, hash);
#endif

	SHM_UNLOCK(hash);

#ifndef HP_MALLOC_FAST_STATS
	unsigned long real_used;

	real_used = get_stat_val(shm_rused);
	if (real_used > hpb->max_real_used)
		hpb->max_real_used = real_used;
#endif

	/* ignore concurrency issues, simply obtaining an estimate is enough */
	mem_hash_usage[init_hash]++;

	return (char *)frag + sizeof *frag;
}

#ifdef DBG_MALLOC
void hp_pkg_free(struct hp_block *hpb, void *p,
					const char* file, const char* func, unsigned int line)
#else
void hp_pkg_free(struct hp_block *hpb, void *p)
#endif
{
	struct hp_frag *f, *next;

	if (!p) {
		LM_WARN("free(0) called\n");
		return;
	}

	f = FRAG_OF(p);

	/*
	 * for private memory, coalesce as many consecutive fragments as possible
	 * The same operation is not performed for shared memory, because:
	 *		- performance penalties introduced by additional locking logic
	 *		- the allocator itself actually favours fragmentation and reusage
	 */
	for (;;) {
		next = FRAG_NEXT(f);
		if (next >= hpb->last_frag || !next->prev)
			break;

		hp_frag_detach(hpb, next);
		update_stats_pkg_frag_detach(hpb, next);

#ifdef DBG_MALLOC
#ifndef STATISTICS
		hpb->used += next->size;
		hpb->real_used += next->size + FRAG_OVERHEAD;
#endif
		hpb->used += FRAG_OVERHEAD;
#endif

		f->size += next->size + FRAG_OVERHEAD;
		update_stats_pkg_frag_merge(hpb);

#if defined(DBG_MALLOC) && !defined(STATISTICS)
		hpb->real_used -= FRAG_OVERHEAD;
		hpb->total_fragments--;
#endif
	}

	hp_frag_attach(hpb, f);
	update_stats_pkg_frag_attach(hpb, f);

#if defined(DBG_MALLOC) && !defined(STATISTICS)
	hpb->used -= f->size;
	hpb->real_used -= f->size + FRAG_OVERHEAD;
#endif
}

#ifdef DBG_MALLOC
void hp_shm_free_unsafe(struct hp_block *hpb, void *p,
							const char* file, const char* func, unsigned int line)
#else
void hp_shm_free_unsafe(struct hp_block *hpb, void *p)
#endif
{
	struct hp_frag *f;

	if (!p) {
		LM_WARN("free(0) called\n");
		return;
	}

	f = FRAG_OF(p);

	hp_frag_attach(hpb, f);
	update_stats_shm_frag_attach(f);

#if defined(DBG_MALLOC) || defined(STATISTICS)
	hpb->used -= f->size;
	hpb->real_used -= f->size + FRAG_OVERHEAD;
#endif
}

#ifdef DBG_MALLOC
void hp_shm_free(struct hp_block *hpb, void *p,
							const char* file, const char* func, unsigned int line)
#else
void hp_shm_free(struct hp_block *hpb, void *p)
#endif
{
	struct hp_frag *f;
	unsigned int hash;

	if (!p) {
		LM_WARN("free(0) called\n");
		return;
	}

	f = FRAG_OF(p);

	hash = PEEK_HASH_RR(hpb, f->size);

	SHM_LOCK(hash);
	hp_frag_attach(hpb, f);
	SHM_UNLOCK(hash);

	update_stats_shm_frag_attach(f);

#if defined(DBG_MALLOC) || defined(STATISTICS)
	hpb->used -= f->size;
	hpb->real_used -= f->size + FRAG_OVERHEAD;
#endif
}

#ifdef DBG_MALLOC
void *hp_pkg_realloc(struct hp_block *hpb, void *p, unsigned long size,
						const char* file, const char* func, unsigned int line)
#else
void *hp_pkg_realloc(struct hp_block *hpb, void *p, unsigned long size)
#endif
{
	struct hp_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct hp_frag *next;
	void *ptr;
	
	if (size == 0) {
		if (p)
			#ifdef DBG_MALLOC
			hp_pkg_free(hpb, p, file, func, line);
			#else
			hp_pkg_free(hpb, p);
			#endif

		return NULL;
	}

	if (!p)
		#ifdef DBG_MALLOC
		return hp_pkg_malloc(hpb, size, file, func, line);
		#else
		return hp_pkg_malloc(hpb, size);
		#endif
	f = FRAG_OF(p);

	size = ROUNDUP(size);
	orig_size = f->size;

	/* shrink operation */
	if (orig_size > size) {
		#ifdef DBG_MALLOC
		pkg_frag_split(hpb, f, size, file, "fragm. from hp_realloc", line);
		#else
		pkg_frag_split(hpb, f, size);
		#endif
	/* grow operation */
	} else if (orig_size < size) {
		
		diff = size - orig_size;
		next = FRAG_NEXT(f);

		/* try to join with a large enough adjacent free fragment */
		if (next < hpb->last_frag && next->prev &&
		    (next->size + FRAG_OVERHEAD) >= diff) {

			hp_frag_detach(hpb, next);
			update_stats_pkg_frag_detach(hpb, next);

			#ifdef DBG_MALLOC
			#ifndef STATISTICS
			hpb->used += next->size;
			hpb->real_used += next->size + FRAG_OVERHEAD;
			#endif
			hpb->used += FRAG_OVERHEAD;
			#endif

			f->size += next->size + FRAG_OVERHEAD;

			/* split the result if necessary */
			if (f->size > size)
				#ifdef DBG_MALLOC
				pkg_frag_split(hpb, f, size, file, "fragm. from hp_realloc", line);
				#else
				pkg_frag_split(hpb, f, size);
				#endif

		} else {
			/* could not join => realloc */
			#ifdef DBG_MALLOC
			ptr = hp_pkg_malloc(hpb, size, file, func, line);
			#else
			ptr = hp_pkg_malloc(hpb, size);
			#endif
			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);
				#ifdef DBG_MALLOC
				hp_pkg_free(hpb, p, file, func, line);
				#else
				hp_pkg_free(hpb, p);
				#endif
			}
			p = ptr;
		}

		if (hpb->real_used > hpb->max_real_used)
			hpb->max_real_used = hpb->real_used;
	}

	pkg_threshold_check();
	return p;
}

#ifdef DBG_MALLOC
void *hp_shm_realloc_unsafe(struct hp_block *hpb, void *p, unsigned long size,
								const char* file, const char* func, unsigned int line)
#else
void *hp_shm_realloc_unsafe(struct hp_block *hpb, void *p, unsigned long size)
#endif
{
	struct hp_frag *f;
	unsigned long orig_size;
	void *ptr;

	if (size == 0) {
		if (p)
			#ifdef DBG_MALLOC
			hp_shm_free_unsafe(hpb, p, file, func, line);
			#else
			hp_shm_free_unsafe(hpb, p);
			#endif

		return NULL;
	}

	if (!p)
		#ifdef DBG_MALLOC
		return hp_shm_malloc_unsafe(hpb, size, file, func, line);
		#else
		return hp_shm_malloc_unsafe(hpb, size);
		#endif

	f = FRAG_OF(p);
	size = ROUNDUP(size);

	orig_size = f->size;

	/* shrink operation? */
	if (orig_size > size)
		#ifdef DBG_MALLOC
		shm_frag_split_unsafe(hpb, f, size, file, "fragm. from hp_realloc", line);
		#else
		shm_frag_split_unsafe(hpb, f, size);
		#endif
	else if (orig_size < size) {
		#ifdef DBG_MALLOC
		ptr = hp_shm_malloc_unsafe(hpb, size, file, func, line);
		#else
		ptr = hp_shm_malloc_unsafe(hpb, size);
		#endif
		if (ptr) {
			/* copy, need by libssl */
			memcpy(ptr, p, orig_size);
			#ifdef DBG_MALLOC
			hp_shm_free_unsafe(hpb, p, file, func, line);
			#else
			hp_shm_free_unsafe(hpb, p);
			#endif
		}

		p = ptr;
	}

	return p;
}

#ifdef DBG_MALLOC
void *hp_shm_realloc(struct hp_block *hpb, void *p, unsigned long size,
						const char* file, const char* func, unsigned int line)
#else
void *hp_shm_realloc(struct hp_block *hpb, void *p, unsigned long size)
#endif
{
	struct hp_frag *f;
	unsigned long orig_size;
	unsigned int hash;
	void *ptr;

	if (size == 0) {
		if (p)
			#ifdef DBG_MALLOC
			hp_shm_free(hpb, p, file, func, line);
			#else
			hp_shm_free(hpb, p);
			#endif

		return NULL;
	}

	if (!p)
		#ifdef DBG_MALLOC
		return hp_shm_malloc(hpb, size, file, func, line);
		#else
		return hp_shm_malloc(hpb, size);
		#endif

	f = FRAG_OF(p);
	size = ROUNDUP(size);

	hash = PEEK_HASH_RR(hpb, f->size);

	SHM_LOCK(hash);
	orig_size = f->size;

	if (orig_size > size) {
		/* shrink */
		#ifdef DBG_MALLOC
		shm_frag_split_unsafe(hpb, f, size, file, "fragm. from hp_realloc", line);
		#else
		shm_frag_split_unsafe(hpb, f, size);
		#endif

	} else if (orig_size < size) {
		SHM_UNLOCK(hash);

		#ifdef DBG_MALLOC
		ptr = hp_shm_malloc(hpb, size, file, func, line);
		#else
		ptr = hp_shm_malloc(hpb, size);
		#endif
		if (ptr) {
			/* copy, need by libssl */
			memcpy(ptr, p, orig_size);
			#ifdef DBG_MALLOC
			hp_shm_free(hpb, p, file, func, line);
			#else
			hp_shm_free(hpb, p);
			#endif
		}

		return ptr;
	}

	SHM_UNLOCK(hash);
	return p;
}

#ifdef SHM_EXTRA_STATS
void set_indexes(int core_index) {

	struct hp_frag* f;
	for (f=shm_block->first_frag; (char*)f<(char*)shm_block->last_frag; f=FRAG_NEXT(f))
		if (!f->is_free)
			f->statistic_index = core_index;
}
#endif

void hp_status(struct hp_block *hpb)
{
	struct hp_frag *f;
	int i, j, si, t = 0;
	int h;

#ifdef DBG_MALLOC
	mem_dbg_htable_t allocd;
	struct mem_dbg_entry *it;
#endif

#if HP_MALLOC_FAST_STATS && (defined(DBG_MALLOC) || defined(STATISTICS))
	if (hpb == shm_block)
		update_shm_stats(hpb);
#endif

	LM_GEN1(memdump, "hp_status (%p, ROUNDTO=%ld):\n", hpb, ROUNDTO);
	if (!hpb)
		return;

	LM_GEN1(memdump, "%20s : %ld\n", "HP_HASH_SIZE", HP_HASH_SIZE);
	LM_GEN1(memdump, "%20s : %ld\n", "HP_EXTRA_HASH_SIZE", HP_HASH_SIZE);
	LM_GEN1(memdump, "%20s : %ld\n", "HP_TOTAL_SIZE", HP_HASH_SIZE);

	LM_GEN1(memdump, "%20s : %ld\n", "total_size", hpb->size);

#if defined(STATISTICS) || defined(DBG_MALLOC)
	LM_GEN1(memdump, "%20s : %lu\n%20s : %lu\n%20s : %lu\n",
			"used", hpb->used,
			"used+overhead", hpb->real_used,
			"free", hpb->size - hpb->used);

	LM_GEN1(memdump, "%20s : %lu\n\n", "max_used (+overhead)", hpb->max_real_used);
#endif

#ifdef DBG_MALLOC
	dbg_ht_init(allocd);

	for (f=hpb->first_frag; (char*)f<(char*)hpb->last_frag; f=FRAG_NEXT(f))
		if (!f->is_free)
			if (dbg_ht_update(allocd, f->file, f->func, f->line, f->size) < 0) {
				LM_ERR("Unable to update alloc'ed. memory summary\n");
				dbg_ht_free(allocd);
				return;
			}

	LM_GEN1(memdump, "dumping summary of all alloc'ed. fragments:\n");
	for(i=0; i < DBG_HASH_SIZE; i++) {
		it = allocd[i];
		while (it) {
			LM_GEN1(memdump, " %10lu : %lu x [%s: %s, line %lu]\n",
				it->size, it->no_fragments, it->file, it->func, it->line);
			it = it->next;
		}
	}

	dbg_ht_free(allocd);
#endif

	LM_GEN1(memdump, "Dumping free fragments:\n");

	for (h = 0; h < HP_HASH_SIZE; h++) {
		if (hpb->free_hash[h].is_optimized) {
			LM_GEN1(memdump, "[ %4d ][ %5d B ][ frags: ", h, h * (int)ROUNDTO);

			for (si = HP_HASH_SIZE + h * shm_secondary_hash_size, j = 0;
				 j < shm_secondary_hash_size; j++, si++, t++) {

				SHM_LOCK(si);
				for (i=0, f=hpb->free_hash[si].first; f; f=f->u.nxt_free, i++, t++)
					;
				SHM_UNLOCK(si);

				LM_GEN1(memdump, "%s%5d ", j == 0 ? "" : "| ", i);
			}

			LM_GEN1(memdump, "]\n");

		} else {
			SHM_LOCK(h);
				for (i=0, f=hpb->free_hash[h].first; f; f=f->u.nxt_free, i++, t++)
					;
			SHM_UNLOCK(h);

			if (i == 0)
				continue;

			if (h > HP_LINEAR_HASH_SIZE) {
				LM_GEN1(memdump, "[ %4d ][ %8d B -> %7d B ][ frags: %5d ]\n",
						h, (int)UN_HASH(h), (int)UN_HASH(h+1) - (int)ROUNDTO, i);
			} else
				LM_GEN1(memdump, "[ %4d ][ %5d B ][ frags: %5d ]\n",
						h, h * (int)ROUNDTO, i);
		}
	}

	LM_GEN1(memdump, "TOTAL: %6d free fragments\n", t);
	LM_GEN1(memdump, "TOTAL: %ld large bytes\n", hpb->large_space );
	LM_GEN1(memdump, "TOTAL: %u overhead\n", (unsigned int)FRAG_OVERHEAD );
	LM_GEN1(memdump, "-----------------------------\n");
}

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
