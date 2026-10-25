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
#include <stddef.h>   /* offsetof, for the header-layout pins */
#include <stdint.h>   /* uint64_t: 64-bit free-map words on every ABI */
#include <string.h>   /* memcpy/memset, for the tail guard (hg_cell.h) */
#include "meminfo.h"
#include "common.h"
#include "hg_san.h"
/* process_no, for hg_pstat_mine(); included explicitly because a
 * cross-compiler build does not get it through other headers */
#include "../globals.h"

#include "hg_cell.h"
#include "hg_block.h"

/*
 * Address -> page/leaf (see HG_LEAF_SHIFT). pages_init() in hg_arena.c
 * checks they round-trip on real addresses at every arena init, and refuses
 * the arena if not.
 */

/* how many leaves tile one huge page */
static inline unsigned long hg_leaves_per_page(const struct hg_block *hb)
{
	return 1UL << (hb->hps_shift - HG_LEAF_SHIFT);
}

/* is @p in the page-addressable region? Arena memory before pbase (the block
 * header; on a non-Linux fallback also the unaligned head) is not buddy
 * memory, so it must answer NO */
static inline int hg_in_pages(const struct hg_block *hb, const void *p)
{
	return (const char *)p >= hb->pbase &&
	       (const char *)p <  hb->pbase + (hb->npages << hb->hps_shift);
}

/* page index of @p; only meaningful when hg_in_pages() */
static inline unsigned long hg_page_of(const struct hg_block *hb, const void *p)
{
	return (unsigned long)((const char *)p - hb->pbase) >> hb->hps_shift;
}

/* first byte of the page holding @p */
static inline char *hg_page_base(const struct hg_block *hb, const void *p)
{
	return hb->pbase + (hg_page_of(hb, p) << hb->hps_shift);
}

/* leaf index of @p WITHIN its own page */
static inline unsigned long hg_leaf_of(const struct hg_block *hb, const void *p)
{
	unsigned long off = (unsigned long)((const char *)p - hb->pbase);

	return (off & ((1UL << hb->hps_shift) - 1)) >> HG_LEAF_SHIFT;
}

/*
 * Reserve a huge-page-backed (or degraded) region of @size bytes and lay out
 * the block control structure at its start. Unlike fm_malloc_init() it takes
 * no pre-reserved address: HG_MALLOC runs its own huge-page tier ladder to
 * get the mapping (see hg_backing.c). Returns NULL on total failure; the
 * caller aborts startup (no silent fallback to another allocator).
 *
 * @shared: 1 for shm/shm_dbg (MAP_SHARED, one arena for every worker), 0 for
 * pkg (MAP_PRIVATE, each forked worker gets its own copy-on-write arena, lock
 * and free pools); hg_mem_reserve() in hg_backing.c says why getting this
 * wrong for pkg is a correctness AND a performance bug.
 *
 * @flags: HG_INIT_INHERITED marks the ONE arena every child inherits
 * copy-on-write: the pre-fork (attendant) pkg arena. It must never be
 * hugetlb-backed: a COW fault in a hugetlb VMA needs a huge page (no 4K
 * fallback) and a forked child holds no reservation on its parent's mapping,
 * so an empty pool makes the fault a silent SIGBUS at fork time. THP falls
 * back: the COW fault splits the huge PMD and copies one 4K page. Per-child
 * arenas are never inherited (children do not fork) and keep the full ladder.
 */
#define HG_INIT_INHERITED  (1U << 0)

struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared,
		const char *proc_desc, unsigned int flags);
void hg_malloc_destroy(struct hg_block *hb);

/*
 * The admin caps live in globals.h/globals.c (-m INIT:CAP / -M INIT:CAP, set
 * before any arena exists; 0 = fixed). The pkg cap is PER PROCESS, so the
 * host-RAM exposure is cap x nproc (applied by hg_grow_ram_refused()).
 */

/*
 * Commit [off, off+delta) of the reservation (both hps-rounded, @off the
 * committed end): populate, pin, VERIFY the backing the kernel gave (and
 * retrofit huge pages where the host needs it). Returns the achieved tier
 * (>= 1), or -1 with everything rolled back - a refusal, not a degradation,
 * so no worker SIGBUSes on half-committed memory. Called by
 * hg_buddy_grow_unlocks() WITHOUT hb->lock: it touches no allocator state
 * but locked_mb (atomically) and the once-per-episode refusal flag; phase
 * timings come back in @cp_ns for the caller to merge under the lock.
 * @collapse_later non-NULL: a worker waits on this grow, so a delta needing
 * the MADV_COLLAPSE retrofit is published on 4 KB pages and *collapse_later
 * set; hg_collapse_deferred() collapses it later.
 */
int hg_mem_commit(struct hg_block *hb, unsigned long off, unsigned long delta,
		unsigned long cp_ns[HG_CP_PHASES], int *collapse_later);
int hg_mem_collapse(struct hg_block *hb, char *base, unsigned long len);
void hg_collapse_deferred(struct hg_block *hb);

/*
 * Host-RAM limb of the growth ceiling: would committing @delta more bytes
 * leave the host under the configured floor of available memory? Nonzero
 * = REFUSE. Tier 1 always passes: a hugetlb mapping reserved its whole cap
 * from the pool at map time. For pkg the delta is multiplied by the process
 * count (every worker grows its own arena). Called by
 * hg_buddy_grow_unlocks() under hb->lock.
 */
int hg_grow_ram_refused(struct hg_block *hb, unsigned long delta);

const char *hg_grow_refusal_str(unsigned int why);

/*
 * Why mlock() refused @delta bytes: @lim the binding RLIMIT_MEMLOCK in bytes
 * (0: none), @locked_kb the process's VmLck, and on hugetlb (@hugetlb) the
 * pool's free and reserved pages of @page_kb each (negative: unreadable).
 * Pure, so unit tests can check it without changing the real limits.
 */
enum hg_grow_refusal hg_mlock_refusal_why(unsigned long lim, long locked_kb,
		unsigned long delta, int hugetlb, long free_pg, long rsvd_pg,
		long page_kb);

/*
 * Host-memory checks for every process's private arena, so a process count
 * or auto-scaler maximum the host cannot hold is refused or stopped instead
 * of ending in the OOM killer. hg_capacity_check() runs once before anything
 * forks: -1 when the startup processes cannot fit (warns for the
 * auto-scaling maximum and caps beyond MemTotal). hg_fork_fits() runs before
 * each fork: 0 = do not fork this one. Both count the hugetlb pool and RAM
 * above the floor.
 */
int hg_capacity_check(unsigned int start_procs, unsigned int max_procs);
int hg_fork_fits(void);

/* allocation-failure throttle, hb->lock held: hg_oom_first() counts a
 * failure and says whether to log it in full; hg_oom_take() returns the
 * failures since the last call (and the largest request), ending the
 * episode after a quiet interval. hg_oom_report_shared() logs the shared
 * arenas' summaries once per sweep interval. */
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

/*
 * Private-arena growth refusals, published per process into a shared array
 * (hg_pkg_pub_init(), pre-fork) at each cache sweep (hg_pkg_publish()), read
 * as hgmem:hg_pkg_grow_refused (sum) and hgmem:hg_pkg_grow_blocked
 * (processes blocked now) via hg_pkg_pub_stat(). hg_pkg_pub_reset() clears
 * the slot of a process that is gone.
 */
int hg_pkg_pub_init(unsigned int nproc);
void hg_pkg_publish(struct hg_block *hb);
void hg_pkg_pub_reset(int proc);
unsigned long hg_pkg_pub_stat(void *ctx);

/*
 * Release the backing of [hbase+off, +len), the shrink primitive (kernel
 * behaviour verified on 5.4, the oldest tested):
 *
 *   shared (shm):  madvise(MADV_REMOVE) punches the shmem OBJECT, so every
 *                  mapper is affected, even while another process holds
 *                  the pages VM_LOCKED; the range recommits cleanly. NOT
 *                  mmap(PROT_NONE|MAP_FIXED): it rebinds only the caller's
 *                  mapping and leaves other workers reading the old bytes.
 *   shared tier 1: same call; hugetlb hole punch returns the pages to
 *                  HugePages_Free.
 *   private (pkg): madvise(MADV_DONTNEED); next touch refaults zero.
 *
 * munlock first: it drops only THIS process's VM_LOCKED accounting (the
 * worker that grew the range keeps a stale VmLck until exit, cosmetic); the
 * punch frees the memory regardless. Returns 0, or -1 with
 * shrink_unsupported latched (nothing to retry).
 */
int hg_mem_release(struct hg_block *hb, unsigned long off, unsigned long len);
int hg_mem_repin(struct hg_block *hb, unsigned long off, unsigned long len,
                 int tier);
/* whole-free pages counted in the bitmap, to compare with nfree[top] */
unsigned long hg_buddy_top_reachable(struct hg_block *hb);

/*
 * Resolve and validate the auto-scaling profiles once, after the config is
 * parsed (from init_shm_post_yyparse()). Attaches the policy to the LIVE shm
 * arena and stashes the pkg policy for the per-child arenas pt.c creates
 * after fork; the pre-fork parent pkg arena predates the config and gets no
 * profile (it keeps its -M cap and grows on exhaustion). Fails LOUDLY on a
 * profile that names nothing, exceeds the -m/-M reservation, or sits on an
 * arena with no growth room: a policy that cannot act is a misconfiguration.
 */
int hg_autoscale_post_cfg(void);

/* re-sync per-process state after fork(): the inherited private
 * free-stack/bump state must be discarded, not kept or donated (hg_arena.c) */
void hg_malloc_child_init(struct hg_block *hb);
/* fork reset for every SHARED arena in the registry (core + module) */
void hg_malloc_child_init_all(void);

/* sizes the DBG_MALLOC allocation-history pool (shm_hist / struct_hist) like
 * fm_get_dbg_pool_size(), with a HG_CELL_HDR-based estimate for FRAG_OVERHEAD.
 * Best-effort: a wrong estimate wastes a little of -m or fails a chunk carve
 * loudly - no correctness risk, as chunks are carved dynamically. */
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

/* defined in hg_arena.c; table lookup, no lock needed (immutable) */
unsigned int hg_cell_total_size(unsigned char cls);

/* defined in hg_large.c; @frag is HG_HDR(p) - HG_LFRAG_HDR_SIZE (the struct
 * hg_lfrag at the start of the block), opaque so this header need not
 * include hg_large.h, which includes it */
unsigned long hg_large_frag_size_at(const void *frag);

/*
 * Arena ownership tests. Everything hg hands out lies inside some block's
 * hbase reservation, fixed at init. For a pointer from outside it (foreign
 * arena, stale, corrupted) the "class byte" at HG_HDR(p) is garbage or
 * unmapped, and reading it can fault.
 *
 *   hg_owns()     - the caller knows the block: one exact range test.
 *   hg_owns_any() - it does not: hg_frag_size() is installed as the shared
 *                   shm_frag_size(void *) hook next to fm_/qm_/hp_/
 *                   parallel_frag_size(), so it cannot take an hb and walks
 *                   a registry of live arenas. This is on the free fast path
 *                   (_shm_free() calls shm_frag_size() on every free); the
 *                   cost is below noise, so the registry stays a plain
 *                   linear walk. Revisit only if HG_ARENA_REG_MAX grows.
 *
 * Both are advisory: they turn "dereference and die" into "decline and carry
 * on". They do not make a bad pointer good.
 */
static inline int hg_owns(struct hg_block *hb, void *cell_start)
{
	/* against the CAP, not the span: nothing in [span_end, hcap) was handed
	 * out, and hcap never changes after init, which keeps this fast path
	 * off the slow path's cache lines (as hg_arena_reg does) */
	return (char *)cell_start >= hb->hbase &&
	       (char *)cell_start < hb->hbase + hb->hcap;
}

/* --- lock instrumentation helpers -------------------------------------- */
/* hg_lock_stall_us (cfg, default 1000 us) is declared in globals.h */
extern const char * const hg_lk_reason_str[HG_LK_REASONS];
extern const char * const hg_cp_phase_str[HG_CP_PHASES];

static inline unsigned long hg_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long)ts.tv_sec * 1000000000UL + (unsigned long)ts.tv_nsec;
}

static inline void hg_lkstat_add(struct hg_lkstat *s, unsigned long ns)
{
	unsigned long us = ns / 1000;
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

/* the stall bookkeeping + rate-limited WARN; out of line (hg_stats.c) so
 * the header stays free of dprint */
void hg_lock_stall_note(struct hg_block *hb, int reason, unsigned long held_ns);

static inline void hg_lock_enter(struct hg_block *hb, enum hg_lock_reason r)
{
	unsigned long t0 = hg_now_ns(), t1;

	lock_get(&hb->lock);
	HG_TSAN_ACQUIRE(&hb->lock);
	t1 = hg_now_ns();
	hg_lkstat_add(&hb->lk_wait[r], t1 - t0);
	hb->lk_t0 = t1;
	hb->lk_cur = r;
}

static inline void hg_lock_leave(struct hg_block *hb)
{
	unsigned long held = hg_now_ns() - hb->lk_t0;
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

/*
 * Contract check for the functions that drop and re-take hb->lock inside
 * (the *_unlocks family in hg_grow.c and hg_shrink.c and the ticks calling
 * them): the lock is held on entry and again on return. Out of line
 * (hg_stats.c) so the header stays free of dprint.
 */
void hg_lock_assert_held(struct hg_block *hb, const char *where);

#define HG_ARENA_REG_MAX 8
struct hg_arena_range {
	char             *base;
	unsigned long     size;
	struct hg_block  *hb;
};
/* defined in hg_malloc.c; maintained by hg_malloc_init/destroy. Process-local
 * on purpose - a forked child inherits the parent's entries (its shm mapping
 * really is the same memory) and adds its own private pkg arena on top. */
extern struct hg_arena_range hg_arena_reg[HG_ARENA_REG_MAX];

/* count of frees redirected to their true owner; reported by hg_stats */
extern unsigned long hg_xarena_frees;

/*
 * Which arena does this pointer belong to, if any? A child may free what
 * its parent allocated pre-fork (cachedb_redis and other modules do it in
 * child_init()), supported with every allocator through the COW-inherited
 * pkg arena. HG_MALLOC gives each child a fresh arena (pt.c), so such frees
 * reach an arena that never issued them: resolve the owner and free there.
 * Only a pointer owned by NO arena is a defect.
 */
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

static inline unsigned long hg_frag_size(void *p)
{
	unsigned char c;

	if (!p)
		return 0;

	/* the header may not be mapped - check before reading it; 0 is the
	 * "unknown size" answer, as for an out-of-range class */
	if (!hg_owns_any(HG_HDR(p)))
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
	if (!hg_owns_any(HG_HDR(p)))
		return NULL;
	return HG_CELL(p)->file;
}
static inline const char *hg_frag_func(void *p)
{
	if (!hg_owns_any(HG_HDR(p)))
		return NULL;
	return HG_CELL(p)->func;
}
static inline unsigned long hg_frag_line(void *p)
{
	if (!hg_owns_any(HG_HDR(p)))
		return 0;
	return HG_CELL(p)->line;
}
#else
static inline const char *hg_frag_file(void *p) { return NULL; }
static inline const char *hg_frag_func(void *p) { return NULL; }
static inline unsigned long hg_frag_line(void *p) { return 0; }
#endif
#endif

/*
 * Fast-path stats helpers. hg_pstat_mine() picks this process's slot:
 * process_no is -1 in the attendant and 0 in main before fork, so it is
 * biased by one and wrapped. Two processes sharing a slot would only race
 * on its counters, never corrupt anything.
 */
/* a thread of a threaded process (TCP main's IO pool) has its own slot,
 * claimed at thread start by hg_thread_stats_init(); -1 = the process slot */
extern __thread int hg_pstat_slot;

static inline struct hg_pstat *hg_pstat_mine(struct hg_block *hb)
{
	int s = hg_pstat_slot;

	if (s < 0)
		s = (int)(((unsigned int)(process_no + 1)) % HG_STAT_SLOTS);
	return &hb->pstat[s];
}

/* give the calling thread its own slot (idempotent; TCP IO pool threads
 * call it first). Thread slots come from the top of the array, processes
 * use the bottom; the counter is in the shm arena, so an index is unique
 * across every process that could start a thread. */
void hg_thread_stats_init(void);

/* summed on read; clamped at 0 because slots go negative when one process
 * frees another's cells, and a torn sum could underflow the return */
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

/* carved-but-idle cell capacity; defined in hg_stats.c (declared here too,
 * since hg_arena.h includes THIS header and cannot be included back) */
unsigned long hg_slab_recycled(struct hg_block *hb);

/*
 * Register the SHM arena's statistics with the statistics collector, so they
 * are scrapeable and not only via the hg_stats MI command. Called from
 * init_stats_collector(); a no-op unless HG_MALLOC is the shm allocator in
 * use. Returns 0 on success. SHM only: pkg memory already shows through the
 * generic struct mem_info route (pkmem: and proc_ statistics), and
 * per-process allocator statistics would need extending
 * signal_pkg_status()/pkg_status[][], as a pkg arena is private memory.
 */
#ifdef HG_MALLOC
int hg_register_stats(void);

/* --- module arenas (see hg_arena_create() in hg_malloc.c) --------------- */
#define HG_CAP_BY_NAME (~0UL)   /* hg_malloc_init_cap: take the cap from -m/-M */
struct hg_block *hg_malloc_init_cap(unsigned long size, unsigned long cap_req,
		char *name, int shared, const char *proc_desc, unsigned int flags);
/* a shared, elastic arena of the module's own; @name must outlive the block;
 * pre-fork only. NULL = refused (logged) */
struct hg_block *hg_arena_create(char *name, unsigned long init_bytes,
		unsigned long cap_bytes);
int hg_arena_set_profile(struct hg_block *hb, const char *profile_name);
#else
/* no-op without the allocator, so callers (statistics.c) need no #ifdef: the
 * definition is in mem/hg_stats.c, entirely inside "#ifdef HG_MALLOC" */
static inline int hg_register_stats(void) { return 0; }
#endif

/* hg_mem_check = 2: log and abort() - in hg_arena.c */
void hg_corrupt_abort(struct hg_block *hb, enum hg_corrupt_kind k)
	__attribute__ ((noreturn, cold));

/*
 * Bump a corruption counter; hb may be NULL where no arena is in scope.
 * Every site calls it after its own LM_CRIT, so with hg_mem_check = 2 the
 * process aborts with the details already in the log.
 */
static inline void hg_corrupt(struct hg_block *hb, enum hg_corrupt_kind k)
{
	if (hb)
		hb->corrupt[k]++;
	else
		hg_corrupt_noarena[k]++;
	if (hg_mem_check > 1)
		hg_corrupt_abort(hb, k);
}

/* a guarded cell failed hg_guard_ok(): logged and counted - in hg_arena.c */
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

/* total cell-slot bytes handed out across every process */
static inline unsigned long hg_cell_live(struct hg_block *hb)
{
	long total = 0;
	int i;

	for (i = 0; i < HG_STAT_SLOTS; i++)
		total += hb->pstat[i].cell_live;
	return total < 0 ? 0 : (unsigned long)total;
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
/* these feed the shmem: and pkgmem: statistics (SHM_GET_/PKG_GET_ in
 * shm_mem.h and mem.h), a different path from hg_info(), so the recycled
 * subtraction is applied here too */
static inline unsigned long hg_get_free(struct hg_block *hb)
{
	/* headroom left to CARVE, not size minus live: recycled cells serve
	 * only their own class, so counting them free would report plenty
	 * until an allocation of another size fails. Hence free + real_used !=
	 * size here (real_used is live), unlike q_malloc; free + carve == size
	 * holds. used = live payload, real_used / max_used = live commitment
	 * and its peak, free = room left to carve. */
	return hb->size - hb->real_used;
}
/* the large tier's counterpart to hg_slab_recycled(): buddy backing not
 * handed out as a fragment. O(1): both terms are kept under hb->lock. */
static inline unsigned long hg_large_recycled(struct hg_block *hb)
{
	return hb->large_backing > hb->large_live ?
	       hb->large_backing - hb->large_live : 0;
}
static inline unsigned long hg_get_real_used(struct hg_block *hb)
{
	/* real_used is the carve footprint of BOTH tiers (slab blocks plus
	 * whole large chunks), so both tiers' idle-but-held bytes come out */
	unsigned long recycled = hg_slab_recycled(hb) + hg_large_recycled(hb);
	unsigned long live = hb->real_used > recycled ?
	                     hb->real_used - recycled : 0;

	if (live > hb->max_live_used)
		hb->max_live_used = live;
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
