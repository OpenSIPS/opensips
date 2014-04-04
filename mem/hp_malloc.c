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

#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../locking.h"

#include "hp_malloc.h"

extern unsigned long *mem_hash_usage;

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
#define pkg_frag_split(blk, frag, sz) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__pkg_frag_split(blk, frag, sz); \
			update_stats_pkg_frag_split(blk); \
		} \
	} while (0)

#define shm_frag_split_unsafe(blk, frag, sz) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__shm_frag_split_unsafe(blk, frag, sz); \
			if (stats_are_ready()) { \
				update_stats_shm_frag_split(); \
			} else { \
				(blk)->real_used += FRAG_OVERHEAD; \
				(blk)->total_fragments++; \
			} \
		} \
	} while (0)

/* Note: the shm lock on "hash" must be acquired when this is called */
#define shm_frag_split(blk, frag, sz, hash) \
	do { \
		if (can_split_frag(frag, sz)) { \
			__shm_frag_split(blk, frag, sz, hash); \
			update_stats_shm_frag_split(); \
		} \
	} while (0)

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

static inline void hp_frag_attach(struct hp_block *qm, struct hp_frag *frag)
{
	struct hp_frag **f;
	unsigned int hash;

	hash = GET_HASH_RR(qm, frag->size);
	f = &(qm->free_hash[hash].first);

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

	*f = frag;

#ifdef HP_MALLOC_FAST_STATS
	qm->free_hash[hash].no++;
#endif
}

static inline void hp_frag_detach(struct hp_block *qm, struct hp_frag *frag)
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

	hash = GET_HASH_RR(qm, frag->size);
	qm->free_hash[hash].no--;
#endif
};

void __pkg_frag_split(struct hp_block *qm, struct hp_frag *frag,
							 unsigned long size)
{
	unsigned long rest;
	struct hp_frag *n;

	rest = frag->size - size;
	frag->size = size;

	/* split the fragment */
	n = FRAG_NEXT(frag);
	n->size = rest - FRAG_OVERHEAD;

	hp_frag_attach(qm, n);
	update_stats_pkg_frag_attach(qm, n);
}

void __shm_frag_split_unsafe(struct hp_block *qm, struct hp_frag *frag,
							unsigned long size)
{
	unsigned long rest;
	struct hp_frag *n;

#ifdef HP_MALLOC_FAST_STATS
	qm->free_hash[PEEK_HASH_RR(qm, frag->size)].total_no--;
	qm->free_hash[PEEK_HASH_RR(qm, size)].total_no++;
#endif

	rest = frag->size - size;
	frag->size = size;

	/* split the fragment */
	n = FRAG_NEXT(frag);
	n->size = rest - FRAG_OVERHEAD;

#ifdef HP_MALLOC_FAST_STATS
	qm->free_hash[PEEK_HASH_RR(qm, n->size)].total_no++;
#endif

	hp_frag_attach(qm, n);

	if (stats_are_ready())
		update_stats_shm_frag_attach(n);
	else {
		qm->used -= n->size;
		qm->real_used -= n->size;
	}
}

 /* size should already be rounded-up */
void __shm_frag_split(struct hp_block *qm, struct hp_frag *frag,
					 unsigned long size, unsigned int old_hash)
{
	unsigned long rest, hash;
	struct hp_frag *n;

#ifdef HP_MALLOC_FAST_STATS
	qm->free_hash[PEEK_HASH_RR(qm, frag->size)].total_no--;
	qm->free_hash[PEEK_HASH_RR(qm, size)].total_no++;
#endif

	rest = frag->size - size;
	frag->size = size;

	/* split the fragment */
	n = FRAG_NEXT(frag);
	n->size = rest - FRAG_OVERHEAD;

	/* insert the newly obtained hp_frag in its free list */
	hash = PEEK_HASH_RR(qm, n->size);

	if (hash != old_hash)
		SHM_LOCK(hash);

	hp_frag_attach(qm, n);

#ifdef HP_MALLOC_FAST_STATS
	qm->free_hash[hash].total_no++;
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
int hp_mem_warming(struct hp_block *qm)
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
			sf->fragments = sf->amount * qm->size / (ROUNDTO * i);

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
		qm->free_hash[sf->hash_index].is_optimized = 1;
		sf = sf->next;
	}

	big_frag = qm->first_frag;

	/* populate each free hash bucket with proper number of fragments */
	for (sf = sorted_sf; sf; sf = sf->next) {
		LM_INFO("[%d][%s] fraction: %.12lf total mem: %llu, %lu\n", sf->hash_index,
		         qm->free_hash[sf->hash_index].is_optimized ? "X" : " ",
				 sf->amount, (unsigned long long) (sf->amount *
				 qm->size * mem_warming_percentage / 100),
				 ROUNDTO * sf->hash_index);

		current_frag_size = ROUNDTO * sf->hash_index;
		bucket_mem = sf->amount * qm->size * mem_warming_percentage / 100;

		/* create free fragments worth of 'bucket_mem' memory */
		while (bucket_mem >= FRAG_OVERHEAD + current_frag_size) {
			hp_frag_detach(qm, big_frag);
			if (stats_are_ready())
				update_stats_shm_frag_detach(big_frag);
			else {
				qm->used += big_frag->size;
				qm->real_used += big_frag->size + FRAG_OVERHEAD;
			}

			/* trim-insert operation on the big free fragment */
			shm_frag_split_unsafe(qm, big_frag, current_frag_size);

			/*
			 * "big_frag" now points to a smaller, free and detached frag.
			 *
			 * With optimized buckets, inserts will be automagically
			 * balanced within their dedicated hashes
			 */
			hp_frag_attach(qm, big_frag);
			if (stats_are_ready())
				update_stats_shm_frag_attach(big_frag);
			else {
				qm->used -= big_frag->size;
				qm->real_used -= big_frag->size + FRAG_OVERHEAD;
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
static struct hp_block *hp_malloc_init(char *address, unsigned long size)
{
	char *start;
	char *end;
	struct hp_block *qm;
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
	qm = (struct hp_block *)start;
	memset(qm, 0, sizeof(struct hp_block));
	qm->size = size;

	qm->used = 0;
	qm->real_used = init_overhead;
	qm->max_real_used = init_overhead;
	gettimeofday(&qm->last_updated, NULL);

	qm->first_frag = (struct hp_frag *)(start + ROUNDUP(sizeof(struct hp_block)));
	qm->last_frag = (struct hp_frag *)(end - sizeof(struct hp_frag));
	/* init initial fragment*/
	qm->first_frag->size = size - init_overhead;
	qm->last_frag->size = 0;

	qm->last_frag->prev  = NULL;
	qm->first_frag->prev = NULL;

	/* link initial fragment into the free list*/

	qm->large_space = 0;
	qm->large_limit = qm->size / 100 * HP_MALLOC_DEFRAG_PERCENT;

	if (qm->large_limit < HP_MALLOC_DEFRAG_LIMIT)
		qm->large_limit = HP_MALLOC_DEFRAG_LIMIT;

	return qm;
}

struct hp_block *hp_pkg_malloc_init(char *address, unsigned long size)
{
	struct hp_block *hpb;
	
	hpb = hp_malloc_init(address, size);
	if (!hpb) {
		LM_ERR("failed to initialize shm block\n");
		return NULL;
	}

	hp_frag_attach(hpb, hpb->first_frag);

	/* first fragment attach is the equivalent of a split  */
	update_stats_pkg_frag_split(hpb, hpb->first_frag);

	return hpb;
}

struct hp_block *hp_shm_malloc_init(char *address, unsigned long size)
{
	struct hp_block *hpb;
	
	hpb = hp_malloc_init(address, size);
	if (!hpb) {
		LM_ERR("failed to initialize shm block\n");
		return NULL;
	}

#ifdef HP_MALLOC_FAST_STATS
	hpb->free_hash[PEEK_HASH_RR(hpb, hpb->first_frag->size)].total_no++;
#endif 

	hp_frag_attach(hpb, hpb->first_frag);

	/* first fragment attach is the equivalent of a split  */
	if (stats_are_ready())
		update_stats_shm_frag_split(hpb, hpb->first_frag);
	else {
		hpb->real_used += FRAG_OVERHEAD;
		hpb->total_fragments++;
	}

	/* if memory warming is on, pre-populate the hash with free fragments */
	if (mem_warming_enabled) {
		if (hp_mem_warming(hpb) != 0)
			LM_INFO("skipped memory warming\n");
	}

	hp_stats_lock = hp_shm_malloc_unsafe(hpb, sizeof *hp_stats_lock);
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


void *hp_pkg_malloc(struct hp_block *qm, unsigned long size)
{
	struct hp_frag *frag;
	unsigned int hash;

	/* size must be a multiple of ROUNDTO */
	size = ROUNDUP(size);

	/* search for a suitable free frag */
	for (hash = GET_HASH(size); hash < HP_HASH_SIZE; hash++) {
		frag = qm->free_hash[hash].first;

		for (; frag; frag = frag->u.nxt_free)
			if (frag->size >= size)
				goto found;

		/* try in a bigger bucket */
	}

	/* out of memory... we have to shut down */
	LM_CRIT("not enough memory, please increase the \"-M\" parameter!\n");
	abort();

found:
	hp_frag_detach(qm, frag);
	update_stats_pkg_frag_detach(qm, frag);

	/* split the fragment if possible */
	pkg_frag_split(qm, frag, size);

	if (qm->real_used > qm->max_real_used)
		qm->max_real_used = qm->real_used;

	pkg_threshold_check();

	return (char *)frag + sizeof *frag;
}

/*
 * although there is a lot of duplicate code, we get the best performance:
 *
 * - the _unsafe version will not be used too much anyway (usually at startup)
 * - hp_shm_malloc is faster (no 3rd parameter, no extra if blocks)
 */
void *hp_shm_malloc_unsafe(struct hp_block *qm, unsigned long size)
{
	struct hp_frag *frag;
	unsigned int init_hash, hash, sec_hash;
	int i;

	/* size must be a multiple of ROUNDTO */
	size = ROUNDUP(size);

	/*search for a suitable free frag*/

	for (hash = GET_HASH(size), init_hash = hash; hash < HP_HASH_SIZE; hash++) {
		if (!qm->free_hash[hash].is_optimized) {
			frag = qm->free_hash[hash].first;

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

				frag = qm->free_hash[sec_hash].first;
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
	LM_CRIT("not enough shared memory, please increase the \"-m\" parameter!\n");
	abort();

found:
	hp_frag_detach(qm, frag);
	if (stats_are_ready())
		update_stats_shm_frag_detach(frag);
	else {
		qm->used += frag->size;
		qm->real_used += frag->size + FRAG_OVERHEAD;
	}

	/* split the fragment if possible */
	shm_frag_split_unsafe(qm, frag, size);

#ifndef HP_MALLOC_FAST_STATS
	if (stats_are_ready()) {
		unsigned long real_used;

		real_used = get_stat_val(shm_rused);
		if (real_used > qm->max_real_used)
			qm->max_real_used = real_used;
	} else
		if (qm->real_used > qm->max_real_used)
			qm->max_real_used = qm->real_used;
#endif

	if (mem_hash_usage)
		mem_hash_usage[init_hash]++;

	return (char *)frag + sizeof *frag;
}

/*
 * Note: as opposed to hp_shm_malloc_unsafe(),
 *       hp_shm_malloc() assumes that the core statistics are initialized
 */
void *hp_shm_malloc(struct hp_block *qm, unsigned long size)
{
	struct hp_frag *frag;
	unsigned int init_hash, hash, sec_hash;
	int i;

	/* size must be a multiple of ROUNDTO */
	size = ROUNDUP(size);

	/*search for a suitable free frag*/

	for (hash = GET_HASH(size), init_hash = hash; hash < HP_HASH_SIZE; hash++) {
		if (!qm->free_hash[hash].is_optimized) {
			SHM_LOCK(hash);
			frag = qm->free_hash[hash].first;

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
				frag = qm->free_hash[sec_hash].first;
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
	LM_CRIT("not enough shared memory, please increase the \"-m\" parameter!\n");
	abort();

found:
	hp_frag_detach(qm, frag);

	/* split the fragment if possible */
	shm_frag_split(qm, frag, size, hash);

	SHM_UNLOCK(hash);

	update_stats_shm_frag_detach(frag);

#ifndef HP_MALLOC_FAST_STATS
	unsigned long real_used;

	real_used = get_stat_val(shm_rused);
	if (real_used > qm->max_real_used)
		qm->max_real_used = real_used;
#endif

	/* ignore concurrency issues, simply obtaining an estimate is enough */
	mem_hash_usage[init_hash]++;

	return (char *)frag + sizeof *frag;
}

void hp_pkg_free(struct hp_block *qm, void *p)
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
		if (next >= qm->last_frag || !next->prev)
			break;

		hp_frag_detach(qm, next);
		update_stats_pkg_frag_detach(qm, next);

		f->size += next->size + FRAG_OVERHEAD;
		update_stats_pkg_frag_merge(qm);
	}

	hp_frag_attach(qm, f);
	update_stats_pkg_frag_attach(qm, f);
}

void hp_shm_free_unsafe(struct hp_block *qm, void *p)
{
	struct hp_frag *f;

	if (!p) {
		LM_WARN("free(0) called\n");
		return;
	}

	f = FRAG_OF(p);

	hp_frag_attach(qm, f);
	update_stats_shm_frag_attach(f);
}

void hp_shm_free(struct hp_block *qm, void *p)
{
	struct hp_frag *f;
	unsigned int hash;

	if (!p) {
		LM_WARN("free(0) called\n");
		return;
	}

	f = FRAG_OF(p);
	hash = PEEK_HASH_RR(qm, f->size);

	SHM_LOCK(hash);
	hp_frag_attach(qm, f);
	SHM_UNLOCK(hash);

	update_stats_shm_frag_attach(f);
}


void *hp_pkg_realloc(struct hp_block *qm, void *p, unsigned long size)
{
	struct hp_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct hp_frag *next;
	void *ptr;
	
	if (size == 0) {
		if (p)
			hp_pkg_free(qm, p);

		return NULL;
	}

	if (!p)
		return hp_pkg_malloc(qm, size);

	f = FRAG_OF(p);

	size = ROUNDUP(size);
	orig_size = f->size;

	/* shrink operation */
	if (orig_size > size) {
		pkg_frag_split(qm, f, size);

	/* grow operation */
	} else if (orig_size < size) {
		
		diff = size - orig_size;
		next = FRAG_NEXT(f);

		/* try to join with a large enough adjacent free fragment */
		if (next < qm->last_frag && next->prev &&
		    (next->size + FRAG_OVERHEAD) >= diff) {

			hp_frag_detach(qm, next);
			update_stats_pkg_frag_detach(qm, next);

			f->size += next->size + FRAG_OVERHEAD;

			/* split the result if necessary */
			if (f->size > size)
				pkg_frag_split(qm, f, size);

		} else {
			/* could not join => realloc */
			ptr = hp_pkg_malloc(qm, size);
			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);
				hp_pkg_free(qm, p);
			}
			p = ptr;
		}

		if (qm->real_used > qm->max_real_used)
			qm->max_real_used = qm->real_used;
	}

	pkg_threshold_check();
	return p;
}

void *hp_shm_realloc_unsafe(struct hp_block *qm, void *p, unsigned long size)
{
	struct hp_frag *f;
	unsigned long orig_size;
	void *ptr;
	
	if (size == 0) {
		if (p)
			hp_shm_free_unsafe(qm, p);

		return NULL;
	}

	if (!p)
		return hp_shm_malloc_unsafe(qm, size);

	f = FRAG_OF(p);
	size = ROUNDUP(size);

	orig_size = f->size;

	/* shrink operation? */
	if (orig_size > size)
		shm_frag_split_unsafe(qm, f, size);
	else if (orig_size < size) {
		ptr = hp_shm_malloc_unsafe(qm, size);
		if (ptr) {
			/* copy, need by libssl */
			memcpy(ptr, p, orig_size);
			hp_shm_free_unsafe(qm, p);
		}

		p = ptr;
	}

	return p;
}

void *hp_shm_realloc(struct hp_block *qm, void *p, unsigned long size)
{
	struct hp_frag *f;
	unsigned long orig_size;
	unsigned int hash;
	void *ptr;

	if (size == 0) {
		if (p)
			hp_shm_free(qm, p);

		return NULL;
	}

	if (!p)
		return hp_shm_malloc(qm, size);

	f = FRAG_OF(p);
	size = ROUNDUP(size);

	hash = PEEK_HASH_RR(qm, f->size);

	SHM_LOCK(hash);
	orig_size = f->size;

	if (orig_size > size) {
		/* shrink */
		shm_frag_split_unsafe(qm, f, size);

	} else if (orig_size < size) {
		SHM_UNLOCK(hash);

		ptr = hp_shm_malloc(qm, size);
		if (ptr) {
			/* copy, need by libssl */
			memcpy(ptr, p, orig_size);
			hp_shm_free(qm, p);
		}

		return ptr;
	}

	SHM_UNLOCK(hash);
	return p;
}



void hp_status(struct hp_block *qm)
{
	struct hp_frag* f;
	unsigned int i,j;
	unsigned int h;
	int unused;
	unsigned long size;

	LM_GEN1(memdump, "hp_status (%p):\n", qm);
	if (!qm) return;

	LM_GEN1(memdump, " heap size= %ld\n", qm->size);

#ifdef STATISTICS
	LM_GEN1(memdump, " used= %lu, used+overhead=%lu, free=%lu\n",
			qm->used, qm->real_used, qm->size-qm->used);
	LM_GEN1(memdump, " max used (+overhead)= %lu\n", qm->max_real_used);
#endif

	LM_GEN1(memdump, "dumping free list:\n");
	for(h=0,i=0,size=0;h<HP_HASH_SIZE;h++){
		unused=0;
		for (f=qm->free_hash[h].first,j=0; f;
				size+=f->size,f=f->u.nxt_free,i++,j++){ }
		if (j) LM_GEN1(memdump,"hash = %3d fragments no.: %5d, unused: %5d\n\t\t"
							" bucket size: %9lu - %9lu (first %9lu)\n",
							h, j, unused, UN_HASH(h),
						((h<=HP_MALLOC_OPTIMIZE/ROUNDTO)?1:2)* UN_HASH(h),
							qm->free_hash[h].first->size
				);
		if (j!=qm->free_hash[h].no){
			LM_CRIT("different free frag. count: %d!=%ld"
					" for hash %3d\n", j, qm->free_hash[h].no, h);
		}

	}
	LM_GEN1(memdump, "TOTAL: %6d free fragments = %6lu free bytes\n", i, size);
	LM_GEN1(memdump, "TOTAL: %ld large bytes\n", qm->large_space );
	LM_GEN1(memdump, "TOTAL: %u overhead\n", (unsigned int)FRAG_OVERHEAD );
	LM_GEN1(memdump, "-----------------------------\n");
}



/* fills a malloc info structure with info about the memory block */
void hp_info(struct hp_block *qm, struct mem_info *info)
{
	memset(info, 0, sizeof *info);

	info->total_size = qm->size;
	info->min_frag = MIN_FRAG_SIZE;

#ifdef HP_MALLOC_FAST_STATS
	if (stats_are_expired(qm))
		update_shm_stats(qm);
#endif

	info->used = qm->used;
	info->real_used = qm->real_used;
	info->free = qm->size - qm->real_used;
	info->total_frags = qm->total_fragments;

	LM_DBG("mem_info: (sz: %ld | us: %ld | rus: %ld | free: %ld | frags: %ld)\n",
	        info->total_size, info->used, info->real_used, info->free,
	        info->total_frags);
}

#endif
