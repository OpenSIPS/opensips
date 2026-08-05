/*
 * hugepage-backed slab allocator
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
#include "meminfo.h"
#include "common.h"
/* for process_no, used by hg_pstat_mine() below to pick this process's
 * stats slot. Included explicitly rather than relied on to arrive via
 * some other header - it does on a native build, and does not under a
 * cross-compiler. */
#include "../globals.h"

#undef ROUNDTO

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
	#define ROUNDTO		sizeof(long long)
#else
	#define ROUNDTO		sizeof(void *)
#endif

#define HG_NCLASSES  21
#define HG_CELL_MAX  65536  /* largest cell; bigger allocs fail (Phase 1) */

/* the four-tier huge-page ladder, best first (ported from cachedb_perf) */
enum hg_mem_tier {
	HG_MEM_HUGETLB = 1,   /* mmap MAP_HUGETLB */
	HG_MEM_THP_ADVISE,    /* shmem THP via MADV_HUGEPAGE, huge at fault */
	HG_MEM_THP_COLLAPSE,  /* shmem THP via MADV_COLLAPSE, post-fill */
	HG_MEM_4K,            /* plain pages - always works */
};

const char *hg_mem_tier_str(enum hg_mem_tier tier);

/*
 * Cell header, hidden before every returned pointer (like FM_FRAG(p) in
 * f_malloc) - unlike cachedb_perf, HG_MALLOC hands pointers to arbitrary
 * caller code via shm_malloc()/pkg_malloc(), so the class tag can NOT live
 * in-band at the front of the payload the way cachedb_perf's records do.
 *
 * Composable layout - DBG_MALLOC and SHM_EXTRA_STATS are INDEPENDENT build
 * flags (a plain non-DBG build can still have SHM_EXTRA_STATS on for
 * mem-group accounting), so each contributes its own slice rather than one
 * replacing the other, mirroring how f_malloc's fm_frag has both the
 * DBG_MALLOC file/func/line fields AND the SHM_EXTRA_STATS
 * statistic_index field as separate #ifdef'd struct members:
 *
 *   offset 0                          : class id (immutable, stamped at
 *                                        chunk-carve time)
 *   offset ROUNDTO           (DBG)    : file
 *   offset ROUNDTO*2         (DBG)    : func
 *   offset ROUNDTO*3         (DBG)    : line
 *   offset ROUNDTO+HG_CELL_HDR_DBG
 *          (SHM_EXTRA_STATS)          : statistic_index (mem-group index)
 *   offset HG_CELL_HDR                : payload starts here; while a cell
 *                                        is FREE, the first ROUNDTO*2 bytes
 *                                        of payload double as the free-list
 *                                        link (cell_next()/cell_set_next()
 *                                        in hg_arena.c) - safe, since
 *                                        nobody reads payload of a free cell.
 */
#ifdef DBG_MALLOC
#define HG_CELL_HDR_DBG (ROUNDTO * 3)  /* file ptr + func ptr + line */
#else
#define HG_CELL_HDR_DBG 0
#endif

#ifdef SHM_EXTRA_STATS
#define HG_CELL_HDR_STATS (ROUNDTO)    /* statistic_index */
#else
#define HG_CELL_HDR_STATS 0
#endif

/*
 * Payloads must be aligned for the widest scalar a caller may store in
 * them; 8 covers uint64_t/double everywhere we build. This is NOT implied
 * by ROUNDTO: on 32-bit ARM ROUNDTO is 4, so the raw header below would be
 * 4 bytes in a plain build, and since cells always start 32-byte aligned
 * EVERY payload would land at 4 mod 8 - misaligned for any 64-bit field,
 * and an outright fault for the LDREXD/STREXD that gen_lock_t and the
 * 64-bit atomics in shared structs compile down to. (f_malloc does not hit
 * this only because its header is a struct that happens to be 8-aligned.)
 *
 * The padding goes at the END of the header, so every field offset below
 * stays exactly where it was and only the header's total size grows.
 */
#define HG_PAYLOAD_ALIGN 8
#define HG_CELL_HDR_RAW  (ROUNDTO + HG_CELL_HDR_DBG + HG_CELL_HDR_STATS)
#define HG_CELL_HDR \
	(((HG_CELL_HDR_RAW + HG_PAYLOAD_ALIGN - 1) / HG_PAYLOAD_ALIGN) \
	 * HG_PAYLOAD_ALIGN)

/* offset of the statistic_index field, valid only when SHM_EXTRA_STATS */
#define HG_CELL_STATS_OFF (ROUNDTO + HG_CELL_HDR_DBG)

#define HG_HDR(p)   ((char *)(p) - HG_CELL_HDR)
#define HG_CLASS(p) (*(unsigned char *)HG_HDR(p))

/* valid only when SHM_EXTRA_STATS; uniform for small cells AND large frags,
 * since the tag region (and thus this offset) always sits immediately
 * before payload regardless of what precedes it (fixed chunk cell vs.
 * hg_lfrag boundary-tag header) */
#ifdef SHM_EXTRA_STATS
#define HG_STATS_IDX(p) (*(unsigned long *)(HG_HDR(p) + HG_CELL_STATS_OFF))
#endif

/* tag-byte value marking a cell as belonging to the large-object tier
 * (hg_large.c) rather than a fixed size class - valid classes are
 * [0, HG_NCLASSES), so this is the first value past them, still
 * distinguishable from genuine corruption (any other out-of-range byte) */
#define HG_LARGE_MARKER HG_NCLASSES

struct hg_large_chunk;   /* opaque here, defined in hg_large.c */
struct hg_lfrag;         /* opaque here, defined in hg_large.h */

/* manifest sizeof(struct hg_lfrag): needed here (opaque type, can't call
 * sizeof() on it) to locate a large frag's header from a payload pointer.
 * hg_large.c static_asserts this matches the real struct, so any future
 * field change there fails the build here instead of drifting silently. */
#define HG_LFRAG_HDR_SIZE (4 * ROUNDTO)

struct hg_chunk {
	struct hg_chunk *next;    /* global registry, append-only */
	unsigned int cls;         /* immutable */
	unsigned int cell_size;   /* total slot size, header included */
	unsigned int cells;
} __attribute__ ((aligned (64)));

struct hg_region {
	struct hg_region *next;
	unsigned long size;
};

/* per-process private allocation state for ONE hg_block instance. Several
 * hg_block instances can be live in the same process at once (shm, shm_dbg,
 * pkg all selecting HG_MALLOC simultaneously) so this is looked up per-block,
 * not a single global - see hg_get_palloc() in hg_arena.c */
struct hg_palloc {
	struct hg_block *owner;   /* which block this state belongs to */
	struct {
		char *bump;            /* next unused cell in own chunk */
		unsigned int left;
		void *free_head;       /* private LIFO free stack */
		unsigned int nfree;
	} cls[HG_NCLASSES];
};

/*
 * Per-process counters for the two stats the lock-free fast path has to
 * touch on every single allocation and free.
 *
 * Keeping them as plain fields in hg_block would make every worker do an
 * unsynchronized read-modify-write on the same shared words - a data race
 * on every architecture (x86 TSO does not make "x += y" atomic either;
 * a weakly-ordered machine just loses more updates), whose symptom is
 * silently under-reported memory in /info. Making them atomic instead
 * would be correct but would put a contended shared cache line back on
 * the fast path - exactly what the per-process free stacks exist to
 * avoid. So each process gets its own cache-line-isolated slot and
 * readers sum the slots.
 *
 * Both fields are SIGNED on purpose: a cell allocated by one process can
 * be freed by another (that is what the shared pool is for), so an
 * individual slot legitimately goes negative. Only the sum is meaningful.
 */
#define HG_STAT_SLOTS     256
#define HG_STAT_LINE      64

struct hg_pstat {
	long used;       /* payload bytes handed out by this process */
	long fragments;  /* live cells handed out by this process */
	char _pad[HG_STAT_LINE - 2 * sizeof(long)];
} __attribute__ ((aligned (HG_STAT_LINE)));

struct hg_block {
	char *name; /* purpose of this memory block */

	gen_lock_t lock;          /* slow paths only: gpool + chunk carve */

	struct hg_chunk *chunks;
	unsigned int nchunks;
	/* upper bound on one chunk, derived from the arena size at init -
	 * see chunk_size_for() in hg_arena.c */
	unsigned int chunk_max;
	struct hg_region *regions;
	void *gpool[HG_NCLASSES];       /* global free cells, per class */
	unsigned int gpool_n[HG_NCLASSES];
	unsigned long lo, hi;           /* extent watermarks */

	/* large-object tier (hg_large.c): list of independently-carved
	 * chunks, each an f_malloc-style boundary-tag heap, sharing ONE free
	 * list across all of them; hb->lock guards all of it (slow path
	 * already, no separate lock needed) */
	struct hg_large_chunk *large_chunks;
	struct hg_lfrag *large_free;

	/* Bytes carved from the reservation into chunks/regions, i.e. the
	 * arena's own footprint. Only ever changed while holding hb->lock
	 * (carve_chunk, hg_region_alloc, the large tier), never on the
	 * lock-free fast path, so a plain field is safe here. */
	unsigned long real_used;
	unsigned long max_real_used;

	/* the fast-path counters - see struct hg_pstat above. Summed by
	 * hg_used()/hg_fragments(); never read directly. */
	struct hg_pstat pstat[HG_STAT_SLOTS];
	unsigned long size;        /* total arena size */

	/* the huge-page reservation this block owns: a pre-fork (or per-process,
	 * for PKG), never-unmapped, 2M-aligned MAP_SHARED (or private, for PKG)
	 * region. Chunks bump from it lock-free (atomic hoff) */
	char                 *hbase;
	unsigned long         hsize;
	volatile unsigned long hoff;
	enum hg_mem_tier      tier;
	unsigned long         locked_mb;

	unsigned char size2class[(HG_CELL_MAX / ROUNDTO) + 1];
} __attribute__ ((aligned (ROUNDTO)));

/*
 * Reserves its own huge-page-backed (or gracefully degraded) region of
 * @size bytes and lays out the block control structure at its start.
 *
 * Unlike fm_malloc_init(), this does NOT take a pre-reserved address: every
 * other allocator receives memory that shm_getmem() already mmap'd (a plain,
 * non-huge anonymous mapping), but HG_MALLOC always needs to run its own
 * hugepage tier ladder to get the mapping in the first place, so it owns the
 * whole reservation step itself (see hg_malloc.c). Returns NULL on total
 * failure (caller logs and aborts startup, per the "no silent fallback to a
 * different allocator" design decision).
 */
/* @shared: 1 for shm/shm_dbg (MAP_SHARED - one arena for every worker),
 * 0 for pkg (MAP_PRIVATE - each forked worker gets its own copy-on-write
 * arena, lock and free pools). See hg_mem_reserve() in hg_malloc.c for why
 * getting this wrong for pkg is a correctness AND a performance bug. */
struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared);
void hg_malloc_destroy(struct hg_block *hb);

/* re-sync per-process state after fork(): see hg_arena.c for why the
 * inherited private free-stack/bump state must be discarded, not kept or
 * donated (ported from cachedb_perf's pcache_arena_child_init reasoning) */
void hg_malloc_child_init(struct hg_block *hb);

/* sizes the DBG_MALLOC allocation-history pool (shm_hist / struct_hist),
 * same purpose and shape as fm_get_dbg_pool_size() - a HG_CELL_HDR-based
 * estimate substituted for f_malloc's FRAG_OVERHEAD. Best-effort: under- or
 * over-estimating just wastes a bit of the -m reservation or fails a chunk
 * carve loudly (logged, not corrupting) - no correctness risk either way,
 * since chunks are carved dynamically rather than packed into one fixed
 * region the way f_malloc's frag allocator is. */
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

/* defined in hg_large.c; @frag is HG_HDR(p) - HG_LFRAG_HDR (the struct
 * hg_lfrag* at the very start of the block). Declared here taking an
 * opaque pointer rather than struct hg_lfrag* to avoid hg_malloc.h needing
 * to depend on hg_large.h, which itself includes hg_malloc.h. */
unsigned long hg_large_frag_size_at(const void *frag);

static inline unsigned long hg_frag_size(void *p)
{
	unsigned char c;

	if (!p)
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
	return *(const char **)(HG_HDR(p) + ROUNDTO);
}
static inline const char *hg_frag_func(void *p)
{
	return *(const char **)(HG_HDR(p) + ROUNDTO * 2);
}
static inline unsigned long hg_frag_line(void *p)
{
	return *(unsigned long *)(HG_HDR(p) + ROUNDTO * 3);
}
#else
static inline const char *hg_frag_file(void *p) { return NULL; }
static inline const char *hg_frag_func(void *p) { return NULL; }
static inline unsigned long hg_frag_line(void *p) { return 0; }
#endif
#endif

/*
 * Fast-path stats helpers.
 *
 * hg_pstat_mine() picks this process's slot. process_no is -1 in the
 * attendant and 0 in the main process before fork, so it is biased by one
 * and wrapped: two processes sharing a slot would only reintroduce the
 * lost-update race for those two, never corrupt anything, and with
 * HG_STAT_SLOTS slots that needs a genuinely enormous process table.
 */
static inline struct hg_pstat *hg_pstat_mine(struct hg_block *hb)
{
	return &hb->pstat[((unsigned int)(process_no + 1)) % HG_STAT_SLOTS];
}

/* summed on read; clamped at 0 because individual slots go negative when
 * one process frees another's cells and a torn sum could otherwise
 * underflow an unsigned return */
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
	return hb->size - hb->real_used;
}
static inline unsigned long hg_get_real_used(struct hg_block *hb)
{
	return hb->real_used;
}
static inline unsigned long hg_get_max_real_used(struct hg_block *hb)
{
	return hb->max_real_used;
}
static inline unsigned long hg_get_frags(struct hg_block *hb)
{
	return hg_fragments(hb);
}
#endif /* STATISTICS */

#endif /* hg_malloc_h */
