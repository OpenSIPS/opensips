/*
 * slab allocator with elastic arenas
 *
 * Copyright (C) 2026 Yury Kirsanov
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

#ifndef hg_malloc_h
#define hg_malloc_h

#include <stdio.h>
#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "meminfo.h"
#include "common.h"
#include "hg_san.h"
/* process_no: a cross-compiler build gets it through no other header */
#include "../globals.h"

#include "hg_cell.h"
#include "hg_block.h"

static inline unsigned long hg_leaves_per_page(const struct hg_block *hb)
{
	return 1UL << (hb->hps_shift - HG_LEAF_SHIFT);
}

static inline int hg_in_pages(const struct hg_block *hb, const void *p)
{
	return (const char *)p >= hb->pbase &&
	       (const char *)p <  hb->pbase + (hb->npages << hb->hps_shift);
}

/* only meaningful when hg_in_pages() */
static inline unsigned long hg_page_of(const struct hg_block *hb, const void *p)
{
	return (unsigned long)((const char *)p - hb->pbase) >> hb->hps_shift;
}

static inline char *hg_page_base(const struct hg_block *hb, const void *p)
{
	return hb->pbase + (hg_page_of(hb, p) << hb->hps_shift);
}

static inline unsigned long hg_leaf_of(const struct hg_block *hb, const void *p)
{
	unsigned long off = (unsigned long)((const char *)p - hb->pbase);

	return (off & ((1UL << hb->hps_shift) - 1)) >> HG_LEAF_SHIFT;
}

/* HG_INIT_INHERITED: the pre-fork pkg arena, which every child inherits COW */
#define HG_INIT_INHERITED  (1U << 0)

struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared,
		const char *proc_desc, unsigned int flags);
void hg_malloc_destroy(struct hg_block *hb);

/* the -m/-M caps (globals.h): 0 = fixed; pkg's is PER PROCESS, cap x nproc */

/* called WITHOUT hb->lock: merge @cp_ns under it */
int hg_mem_commit(struct hg_block *hb, unsigned long off, unsigned long delta,
		unsigned long cp_ns[HG_CP_PHASES], int *collapse_later);
int hg_mem_collapse(struct hg_block *hb, char *base, unsigned long len);
void hg_collapse_deferred(struct hg_block *hb);


const char *hg_grow_refusal_str(unsigned int why);

/* Why mlock() refused @delta bytes, from the limit, VmLck and hugetlb pool
 * figures given (negative: unreadable); pure, so unit tests can call it */
enum hg_grow_refusal hg_mlock_refusal_why(unsigned long lim, long locked_kb,
		unsigned long delta, int hugetlb, long free_pg, long rsvd_pg,
		long page_kb);

/* refuse process counts the host cannot hold, before the OOM killer does:
 * hg_capacity_check() pre-fork (-1: no fit), hg_fork_fits() per fork (0: no) */
int hg_capacity_check(unsigned int start_procs, unsigned int max_procs);
int hg_fork_fits(void);

/* under hb->lock; hg_oom_take() returns the failures since its last call */
static inline int hg_oom_first(struct hg_block *hb, unsigned long req)
{
	hb->oom_fails++;
	if (req > hb->oom_max_req)
		hb->oom_max_req = req;
	if (hb->oom_episode)
		return 0;
	hb->oom_episode = 1;
	return 1;
}

static inline unsigned long hg_oom_take(struct hg_block *hb,
		unsigned long *max_req)
{
	unsigned long n = hb->oom_fails - hb->oom_fails_said;

	*max_req = hb->oom_max_req;
	hb->oom_fails_said = hb->oom_fails;
	hb->oom_max_req = 0;
	if (!n)
		hb->oom_episode = 0;
	return n;
}

void hg_oom_report(struct hg_block *hb, unsigned long n, unsigned long max_req);
void hg_oom_report_shared(void);
void hg_sample_live_peaks(void);

/* pkg grow refusals are per process: each publishes its own to a shared
 * array at each sweep, and hgmem: sums them */
int hg_pkg_pub_init(unsigned int nproc);
void hg_pkg_publish(struct hg_block *hb);
void hg_pkg_pub_reset(int proc);
unsigned long hg_pkg_pub_stat(void *ctx);

/* Release the backing of [hbase+off, +len): MADV_REMOVE punches the shmem
 * object for every mapper, pkg uses MADV_DONTNEED; -1: shrink_unsupported */
int hg_mem_release(struct hg_block *hb, unsigned long off, unsigned long len);
int hg_mem_repin(struct hg_block *hb, unsigned long off, unsigned long len,
                 int tier);
/* whole-free pages counted in the bitmap, to compare with nfree[top] */
unsigned long hg_buddy_top_reachable(struct hg_block *hb);

/* Resolve the auto-scaling profiles once the config is parsed; fails LOUDLY on
 * one that cannot act (names nothing, exceeds -m/-M, no growth room) */
int hg_autoscale_post_cfg(void);

/* after fork(): the inherited private free-stack/bump state must be
 * discarded, not kept or donated */
void hg_malloc_child_init(struct hg_block *hb);
void hg_malloc_child_init_all(void);

/* sizes the DBG_MALLOC history pool like fm_get_dbg_pool_size(); best-effort:
 * a wrong estimate wastes a little of -m or fails a carve loudly */
unsigned long hg_get_dbg_pool_size(unsigned int hist_size);

#ifdef DBG_MALLOC
void *hg_malloc(struct hg_block *hb, unsigned long size,
                const char *file, const char *func, unsigned int line);
void hg_free(struct hg_block *hb, void *p, const char *file,
             const char *func, unsigned int line);
void *hg_realloc(struct hg_block *hb, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line);
#ifndef INLINE_ALLOC
void *hg_malloc_dbg(struct hg_block *hb, unsigned long size,
                    const char *file, const char *func, unsigned int line);
void hg_free_dbg(struct hg_block *hb, void *p, const char *file,
                 const char *func, unsigned int line);
void *hg_realloc_dbg(struct hg_block *hb, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line);
#endif
#else
void *hg_malloc(struct hg_block *hb, unsigned long size);
void hg_free(struct hg_block *hb, void *p);
void *hg_realloc(struct hg_block *hb, void *p, unsigned long size);
#endif

void hg_status(struct hg_block *hb);
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void hg_status_dbg(struct hg_block *hb);
#endif
void hg_info(struct hg_block *hb, struct mem_info *info);

/* table lookup, no lock needed (immutable) */
unsigned int hg_cell_total_size(unsigned char cls);

/* @frag is HG_HDR(p) - HG_LFRAG_HDR_SIZE, opaque so this header need not
 * include hg_large.h, which includes it */
unsigned long hg_large_frag_size_at(const void *frag);

static inline int hg_owns(struct hg_block *hb, void *cell_start)
{
	return (char *)cell_start >= hb->hbase &&
	       (char *)cell_start < hb->hbase + hb->hcap;
}

extern const char * const hg_lk_reason_str[HG_LK_REASONS];
extern const char * const hg_cp_phase_str[HG_CP_PHASES];

static inline hg_ns_t hg_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (hg_ns_t)ts.tv_sec * 1000000000ULL + (hg_ns_t)ts.tv_nsec;
}

/* saturated: past 4.29 s on a 32-bit build it reads as huge, not wrapped */
static inline unsigned long hg_ns_ul(hg_ns_t ns)
{
	return ns > ~0UL ? ~0UL : (unsigned long)ns;
}

static inline void hg_lkstat_add(struct hg_lkstat *s, hg_ns_t ns)
{
	hg_ns_t us = ns / 1000;
	unsigned int b = 0;

	if (us) {
		/* b = floor(log2(us)) + 1, capped at the overflow bucket */
		while (us > 1 && b < HG_LK_BUCKETS - 2) {
			us >>= 1;
			b++;
		}
		b++;
	}
	s->n++;
	s->total_ns += ns;
	if (ns > s->max_ns)
		s->max_ns = ns;
	s->hist[b]++;
}

/* out of line, so this header stays free of dprint */
void hg_lock_stall_note(struct hg_block *hb, int reason, unsigned long held_ns);

static inline void hg_lock_enter(struct hg_block *hb, enum hg_lock_reason r)
{
	hg_ns_t t0 = hg_now_ns(), t1;

	lock_get(&hb->lock);
	HG_TSAN_ACQUIRE(&hb->lock);
	t1 = hg_now_ns();
	hg_lkstat_add(&hb->lk_wait[r], t1 - t0);
	hb->lk_t0 = t1;
	hb->lk_cur = r;
}

static inline void hg_lock_leave(struct hg_block *hb)
{
	unsigned long held = hg_ns_ul(hg_now_ns() - hb->lk_t0);
	int r = hb->lk_cur;
	int stalled = 0;

	hg_lkstat_add(&hb->lk_hold[r], held);
	if (held > hb->lk_worst_ns) {
		hb->lk_worst_ns = held;
		hb->lk_worst_reason = r;
		hb->lk_worst_proc = process_no;
	}
	if (hg_lock_stall_us > 0 && held >= (unsigned long)hg_lock_stall_us * 1000UL) {
		hb->lk_hold[r].stalls++;
		hb->lk_stalls++;
		hb->lk_last_stall_ns = held;
		hb->lk_last_stall_reason = r;
		hb->lk_last_stall_proc = process_no;
		hb->lk_stall_event_due = 1;
		stalled = 1;
	}
	/* mark the lock free BEFORE releasing it, so a callee that must
	 * return with the lock held can be checked (hg_lock_assert_held) */
	hb->lk_cur = HG_LK_NONE;
	HG_TSAN_RELEASE(&hb->lock);
	lock_release(&hb->lock);
	if (stalled)
		hg_lock_stall_note(hb, r, held);
}

/* for the *_unlocks functions, which drop and re-take hb->lock */
void hg_lock_assert_held(struct hg_block *hb, const char *where);

#define HG_ARENA_REG_MAX 8
struct hg_arena_range {
	char             *base;
	unsigned long     size;
	struct hg_block  *hb;
};
/* process-local on purpose: a child inherits the parent's entries (same
 * shm) and adds its own private pkg arena */
extern struct hg_arena_range hg_arena_reg[HG_ARENA_REG_MAX];

extern unsigned long hg_xarena_frees;

/* Which arena owns @p? A child may free what its parent allocated pre-fork,
 * so the free goes to that owner; only a pointer NO arena owns is a defect */
static inline struct hg_block *hg_owner(const void *p)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		if (!hg_arena_reg[i].base)
			continue;
		if ((const char *)p >= hg_arena_reg[i].base &&
		    (const char *)p <  hg_arena_reg[i].base + hg_arena_reg[i].size)
			return hg_arena_reg[i].hb;
	}
	return NULL;
}

static inline int hg_owns_any(const void *p)
{
	return hg_owner(p) != NULL;
}

int hg_backed_slow(const struct hg_block *hb, const void *p);

/* may @p, inside @hb's reservation, be read? Lock-free; only a stale
 * pointer leads to an unbacked page */
static inline int hg_backed(const struct hg_block *hb, const void *p)
{
	if ((unsigned long)((const char *)p - hb->hbase) <
	    __atomic_load_n(&hb->backed_fast, __ATOMIC_ACQUIRE))
		return 1;
	return hg_backed_slow(hb, p);
}

/* under hb->lock, after every change of grow_inflight, punched_pages or
 * span_end, and at init */
static inline void backed_fast_update(struct hg_block *hb)
{
	__atomic_store_n(&hb->backed_fast,
		(hb->punched_pages || hb->grow_inflight) ? 0 : hb->span_end,
		__ATOMIC_RELEASE);
}

static inline struct hg_block *hg_owner_backed(const void *p)
{
	struct hg_block *hb = hg_owner(p);

	return hb && hg_backed(hb, p) ? hb : NULL;
}

static inline unsigned long hg_frag_size(void *p)
{
	unsigned char c;

	if (!p)
		return 0;

	/* the header may be unmapped or no longer backed; 0 = unknown size */
	if (!hg_owner_backed(HG_HDR(p)))
		return 0;

	c = HG_CLASS(p);
	if (c == HG_LARGE_MARKER)
		return hg_large_frag_size_at(HG_HDR(p) - HG_LFRAG_HDR_SIZE);
	if (c >= HG_NCLASSES)
		return 0;

	return hg_cell_total_size(c);
}

#define HG_FRAG_OVERHEAD (HG_CELL_HDR)

#ifdef SHM_EXTRA_STATS
void hg_stats_core_init(struct hg_block *hb, int core_index);
unsigned long hg_stats_get_index(void *ptr);
void hg_stats_set_index(void *ptr, unsigned long idx);

#ifdef DBG_MALLOC
static inline const char *hg_frag_file(void *p)
{
	if (!hg_owner_backed(HG_HDR(p)))
		return NULL;
	return HG_CELL(p)->file;
}
static inline const char *hg_frag_func(void *p)
{
	if (!hg_owner_backed(HG_HDR(p)))
		return NULL;
	return HG_CELL(p)->func;
}
static inline unsigned long hg_frag_line(void *p)
{
	if (!hg_owner_backed(HG_HDR(p)))
		return 0;
	return HG_CELL(p)->line;
}
#else
static inline const char *hg_frag_file(void *p) { return NULL; }
static inline const char *hg_frag_func(void *p) { return NULL; }
static inline unsigned long hg_frag_line(void *p) { return 0; }
#endif
#endif

/* a thread's own stats slot (TCP main's IO pool), else -1: the process's */
extern __thread int hg_pstat_slot;

/* process_no + 1, as the attendant's is -1 */
static inline struct hg_pstat *hg_pstat_mine(struct hg_block *hb)
{
	int s = hg_pstat_slot;

	if (s < 0)
		s = (int)(((unsigned int)(process_no + 1)) % HG_STAT_SLOTS);
	return &hb->pstat[s];
}

/* set when a slot can have two writers (more processes than slots, or a
 * thread with no slot of its own); per process, inherited at fork */
extern int hg_pstat_shared;

/* checked once the process count is known, before anything forks */
void hg_pstat_slots_check(unsigned int nprocs);

static inline void hg_pstat_add(struct hg_pstat *ps, long used, long frags,
		long cell)
{
	if (__builtin_expect(hg_pstat_shared, 0)) {
		__atomic_fetch_add(&ps->used, used, __ATOMIC_RELAXED);
		__atomic_fetch_add(&ps->fragments, frags, __ATOMIC_RELAXED);
		if (cell)
			__atomic_fetch_add(&ps->cell_live, cell, __ATOMIC_RELAXED);
		return;
	}
	ps->used += used;
	ps->fragments += frags;
	ps->cell_live += cell;
}

void hg_thread_stats_init(void);

/* clamped at 0: a torn sum over the signed slots can dip below it */
static inline unsigned long hg_used(struct hg_block *hb)
{
	long total = 0;
	int i;

	for (i = 0; i < HG_STAT_SLOTS; i++)
		total += hb->pstat[i].used;
	return total < 0 ? 0 : (unsigned long)total;
}

static inline unsigned long hg_fragments(struct hg_block *hb)
{
	long total = 0;
	int i;

	for (i = 0; i < HG_STAT_SLOTS; i++)
		total += hb->pstat[i].fragments;
	return total < 0 ? 0 : (unsigned long)total;
}

/* carved-but-idle cell capacity */
unsigned long hg_slab_recycled(struct hg_block *hb);

/* from init_stats_collector(); a no-op unless shm is HG_MALLOC */
#ifdef HG_MALLOC
int hg_register_stats(void);

#define HG_CAP_BY_NAME (~0UL)   /* @cap_req: take the cap from -m/-M */
struct hg_block *hg_malloc_init_cap(unsigned long size, unsigned long cap_req,
		char *name, int shared, const char *proc_desc, unsigned int flags);
/* @name must outlive the block; NULL = refused (logged) */
struct hg_block *hg_arena_create(char *name, unsigned long init_bytes,
		unsigned long cap_bytes);
int hg_arena_set_profile(struct hg_block *hb, const char *profile_name);
#else
static inline int hg_register_stats(void) { return 0; }
#endif

void hg_corrupt_abort(struct hg_block *hb, enum hg_corrupt_kind k)
	__attribute__ ((noreturn, cold));

/* @hb may be NULL; every site calls it after its own LM_CRIT, so
 * hg_mem_check = 2 aborts with the details logged */
static inline void hg_corrupt(struct hg_block *hb, enum hg_corrupt_kind k)
{
	if (hb)
		hb->corrupt[k]++;
	else
		hg_corrupt_noarena[k]++;
	if (hg_mem_check > 1)
		hg_corrupt_abort(hb, k);
}

void hg_guard_bad(struct hg_block *hb, const void *cs, unsigned long cap,
                  unsigned long size) __attribute__ ((cold));

static inline unsigned long hg_corrupt_total(struct hg_block *hb)
{
	unsigned long t = 0;
	int i;

	for (i = 0; i < HG_CORRUPT_KINDS; i++)
		t += hb->corrupt[i];
	return t;
}

static inline unsigned long hg_cell_live(struct hg_block *hb)
{
	long total = 0;
	int i;

	for (i = 0; i < HG_STAT_SLOTS; i++)
		total += hb->pstat[i].cell_live;
	return total < 0 ? 0 : (unsigned long)total;
}

static inline unsigned long hg_free_to_carve(const struct hg_block *hb)
{
	unsigned long size = hb->size, carved = hb->real_used;

	return size > carved ? size - carved : 0;
}

#ifdef STATISTICS
static inline unsigned long hg_get_size(struct hg_block *hb)
{
	return hb->size;
}
static inline unsigned long hg_get_used(struct hg_block *hb)
{
	return hg_used(hb);
}
static inline unsigned long hg_get_free(struct hg_block *hb)
{
	/* headroom left to CARVE, not size minus live: recycled cells serve
	 * only their own class; so free + real_used != size, unlike q_malloc */
	return hg_free_to_carve(hb);
}
static inline unsigned long hg_large_recycled(struct hg_block *hb)
{
	return hb->large_backing > hb->large_live ?
	       hb->large_backing - hb->large_live : 0;
}
/* atomic: two processes' sweeps may sample a shared arena's peak at once */
static inline void hg_live_peak(struct hg_block *hb, unsigned long live)
{
	unsigned long m = __atomic_load_n(&hb->max_live_used, __ATOMIC_RELAXED);

	while (live > m && !__atomic_compare_exchange_n(&hb->max_live_used,
	        &m, live, 1, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		;
}

static inline unsigned long hg_get_real_used(struct hg_block *hb)
{
	unsigned long recycled = hg_slab_recycled(hb) + hg_large_recycled(hb);
	unsigned long live = hb->real_used > recycled ?
	                     hb->real_used - recycled : 0;

	hg_live_peak(hb, live);
	return live;
}
static inline unsigned long hg_get_max_real_used(struct hg_block *hb)
{
	/* refresh the mark first, so reading max on its own is not stale */
	(void)hg_get_real_used(hb);
	return hb->max_live_used;
}
static inline unsigned long hg_get_frags(struct hg_block *hb)
{
	return hg_fragments(hb);
}
#endif /* STATISTICS */

#endif /* hg_malloc_h */
