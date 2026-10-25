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
#include "meminfo.h"
#include "common.h"
#include "hg_san.h"
/* process_no, for hg_pstat_mine(); included explicitly because a
 * cross-compiler build does not get it through other headers */
#include "../globals.h"

#undef HG_ROUNDTO

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
	#define HG_ROUNDTO		sizeof(long long)
#else
	#define HG_ROUNDTO		sizeof(void *)
#endif

#define HG_NCLASSES  21
#define HG_CELL_MAX  65536  /* largest cell; larger go to the large tier */

/* the four-tier huge-page ladder, best first */
enum hg_mem_tier {
	HG_MEM_HUGETLB = 1,   /* mmap MAP_HUGETLB */
	HG_MEM_THP_ADVISE,    /* shmem THP via MADV_HUGEPAGE, huge at fault */
	HG_MEM_THP_COLLAPSE,  /* shmem THP via MADV_COLLAPSE, post-fill */
	HG_MEM_4K,            /* plain pages - always works */
};

const char *hg_mem_tier_str(enum hg_mem_tier tier);

/*
 * Cell header, hidden before every returned pointer (like FM_FRAG(p) in
 * f_malloc): pointers go to arbitrary callers via shm_malloc()/pkg_malloc(),
 * so the class can NOT live in-band in the payload. DBG_MALLOC and
 * SHM_EXTRA_STATS are independent build flags; each adds its own slice:
 *
 *   offset 0                          : class id (stamped at carve, immutable)
 *   offset HG_ROUNDTO           (DBG) : file
 *   offset HG_ROUNDTO*2         (DBG) : func
 *   offset HG_ROUNDTO*3         (DBG) : line
 *   offset HG_ROUNDTO+HG_CELL_HDR_DBG
 *          (SHM_EXTRA_STATS)          : statistic_index (mem-group index)
 *   offset HG_CELL_HDR                : payload; while the cell is FREE its
 *                                       first pointer is the free-list link
 *                                       (cell_next() in hg_arena.c)
 */
#ifdef DBG_MALLOC
#define HG_CELL_HDR_DBG (HG_ROUNDTO * 3)  /* file ptr + func ptr + line */
#else
#define HG_CELL_HDR_DBG 0
#endif

#ifdef SHM_EXTRA_STATS
#define HG_CELL_HDR_STATS (HG_ROUNDTO)    /* statistic_index */
#else
#define HG_CELL_HDR_STATS 0
#endif

/*
 * Payload alignment: 8 covers uint64_t/double. HG_ROUNDTO does not imply it:
 * it is 4 on 32-bit ARM, and with cells 32-byte aligned a 4-byte header puts
 * every payload at 4 mod 8 - a fault for the LDREXD/STREXD of gen_lock_t
 * and 64-bit atomics. The padding goes at the END of the header, so no
 * field offset moves.
 */
#define HG_PAYLOAD_ALIGN 8

/*
 * The header as a struct, so sites name a field instead of computing
 * HG_ROUNDTO * n. The _Static_asserts below pin it to the layout above on
 * every ABI and build configuration.
 */
struct hg_cell_hdr {
	/* the first HG_ROUNDTO bytes: class, state and a checksum over both
	 * and the cell's address (hg_hdr_set()) */
	union {
		struct {
			unsigned char  cls;           /* class id, or HG_LARGE_MARKER */
			unsigned char  state;         /* HG_ST_FRESH / _FREE / _LIVE */
			unsigned short check;         /* hg_hdr_sum() */
		};
		unsigned int   hw;            /* the three as one word, for the
		                               * atomic LIVE -> FREE */
		unsigned char  _slot0[HG_ROUNDTO];
	};
#ifdef DBG_MALLOC
	const char    *file;                  /* HG_ROUNDTO */
	const char    *func;                  /* HG_ROUNDTO * 2 */
	unsigned long  line;                  /* HG_ROUNDTO * 3 */
#endif
#ifdef SHM_EXTRA_STATS
	unsigned long  stat_idx;              /* HG_ROUNDTO + HG_CELL_HDR_DBG */
#endif
};

#define HG_CELL_HDR_RAW  sizeof(struct hg_cell_hdr)
#define HG_CELL_HDR \
	(((HG_CELL_HDR_RAW + HG_PAYLOAD_ALIGN - 1) / HG_PAYLOAD_ALIGN) \
	 * HG_PAYLOAD_ALIGN)

/* offset of the statistic_index field, valid only when SHM_EXTRA_STATS */
#define HG_CELL_STATS_OFF (HG_ROUNDTO + HG_CELL_HDR_DBG)

/* C++ modules include this header too */
#ifdef __cplusplus
#define HG_STATIC_ASSERT static_assert
#else
#define HG_STATIC_ASSERT _Static_assert
#endif

/* the pins: the documented offsets, and the raw size the arithmetic gave */
HG_STATIC_ASSERT(HG_CELL_HDR_RAW == HG_ROUNDTO + HG_CELL_HDR_DBG + HG_CELL_HDR_STATS,
	"struct hg_cell_hdr is not the documented header layout");
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, cls) == 0,
	"the class byte must be the first byte of the header");
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, state) == 1 &&
	offsetof(struct hg_cell_hdr, check) == 2,
	"the state byte and the checksum must follow the class byte");
HG_STATIC_ASSERT(sizeof(unsigned int) == 4 && HG_ROUNDTO >= 4,
	"class, state and checksum must make up one 32-bit word");
#ifdef DBG_MALLOC
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, file) == HG_ROUNDTO &&
	offsetof(struct hg_cell_hdr, func) == HG_ROUNDTO * 2 &&
	offsetof(struct hg_cell_hdr, line) == HG_ROUNDTO * 3,
	"the DBG_MALLOC fields moved");
#endif
#ifdef SHM_EXTRA_STATS
HG_STATIC_ASSERT(offsetof(struct hg_cell_hdr, stat_idx) == HG_CELL_STATS_OFF,
	"the statistic_index field moved");
#endif

#define HG_HDR(p)   ((char *)(p) - HG_CELL_HDR)
/* the header of a payload pointer / of a cell-start pointer */
#define HG_CELL(p)     ((struct hg_cell_hdr *)(void *)HG_HDR(p))
#define HG_CELL_AT(cs) ((struct hg_cell_hdr *)(void *)(cs))
#define HG_CLASS(p) (HG_CELL(p)->cls)

/*
 * Cell state, in the header and covered by its checksum: whether a CALLER
 * holds the cell, not where the allocator keeps it.
 *
 *   carve                 -> FRESH   (hg_arena.c carve_chunk())
 *   FRESH or FREE -> LIVE            an allocation, the only way in
 *   LIVE          -> FREE            a free, by any process - the only way out
 *
 * Moving a cell between private list, shared pool, quarantine (HG_MALLOC_DBG)
 * or exit drain leaves it FREE (or FRESH). A free requires LIVE and an
 * allocation FRESH or FREE, so a double free is always refused and no cell
 * is handed out twice. A small cell's LIVE -> FREE is one CAS of the header
 * word (hg_hdr_claim_free()): of two racing frees exactly one wins; a large
 * fragment's runs under the arena lock. The values differ from 0x00/0xff
 * and each other, so a zeroed or scribbled header is caught even before the
 * checksum.
 */
#define HG_ST_FRESH  0x3c
#define HG_ST_FREE   0x5a
#define HG_ST_LIVE   0xa5

/* per-run secret mixed into every header checksum, set before the first
 * arena is created (so it is the same in every process) */
extern unsigned long long hg_hdr_secret;

/*
 * 16-bit check over the cell's address, class and state. Not cryptographic:
 * it catches a neighbour's overflow, a pointer into the middle of a cell and
 * a header copied to another address. base(address, class) XOR key(state)
 * costs one multiply per alloc or free (the hottest path): a state change is
 * a constant XOR, and a checked header is re-stamped from the check's base.
 */
#define HG_ST_KEY(st)  ((unsigned short)((st) * 0x0101u))

static inline unsigned short hg_hdr_base(const void *cs, unsigned int cls)
{
	/* cells are at least 32-aligned, so the class lands in bits the
	 * address leaves to the secret; the multiply carries every input bit
	 * into the top 16 */
	unsigned long long x = ((unsigned long long)(unsigned long)cs ^
		hg_hdr_secret ^ cls) * 0x9e3779b97f4a7c15ULL;

	return (unsigned short)(x >> 48);
}

static inline unsigned short hg_hdr_sum(const void *cs, unsigned int cls,
                                        unsigned int st)
{
	return hg_hdr_base(cs, cls) ^ HG_ST_KEY(st);
}

/* the header's first word, as the fields struct hg_cell_hdr lays out */
union hg_hdr_w {
	struct {
		unsigned char  cls, state;
		unsigned short check;
	} f;
	unsigned int w;
};

HG_STATIC_ASSERT(sizeof(union hg_hdr_w) == 4,
	"the header word must be exactly class, state and checksum");

/* the header word of a cell of class @cls in state @st, from its @base */
static inline unsigned int hg_hdr_make(unsigned int cls, unsigned int st,
                                       unsigned short base)
{
	union hg_hdr_w h;

	h.f.cls = (unsigned char)cls;
	h.f.state = (unsigned char)st;
	h.f.check = (unsigned short)(base ^ HG_ST_KEY(st));
	return h.w;
}

/* one store, so a racing hg_hdr_claim_free() never sees half a header */
static inline void hg_hdr_set_base(void *cs, unsigned int cls, unsigned int st,
                                   unsigned short base)
{
	__atomic_store_n(&HG_CELL_AT(cs)->hw, hg_hdr_make(cls, st, base),
		__ATOMIC_RELAXED);
}

static inline void hg_hdr_set(void *cs, unsigned int cls, unsigned int st)
{
	hg_hdr_set_base(cs, cls, st, hg_hdr_base(cs, cls));
}

/*
 * Read the header word once (never torn) and check it: the state, or -1 if
 * it fails. @w and @base come back for re-stamping without hashing again.
 */
static inline int hg_hdr_read(const void *cs, union hg_hdr_w *w,
                              unsigned short *base)
{
	w->w = __atomic_load_n(&((const struct hg_cell_hdr *)cs)->hw,
		__ATOMIC_RELAXED);
	*base = hg_hdr_base(cs, w->f.cls);
	if (w->f.check != (unsigned short)(*base ^ HG_ST_KEY(w->f.state)))
		return -1;
	return w->f.state;
}

static inline int hg_hdr_state(const void *cs)
{
	union hg_hdr_w w;
	unsigned short base;

	return hg_hdr_read(cs, &w, &base);
}

/*
 * LIVE -> FREE in one compare-and-swap, from the @live word and @base that
 * hg_hdr_read() returned: 1 if this free took the cell, 0 if another free
 * got there first - the caller must then touch nothing (no list, no counter).
 *
 * Relaxed is enough, by the protocol rather than by any CPU's ordering:
 *   1. the CAS alone decides the winner; the loser writes nothing;
 *   2. the winner's later writes (free-list link, HG_MALLOC_DBG poison) go
 *      to its private list or quarantine, read only by its own thread;
 *   3. a FREE cell becomes visible to another process or thread only in
 *      gpool_push(), which always runs with hb->lock held;
 *   4. hb->lock (in the shared mapping) orders, by its release/acquire,
 *      this word and the link before the next owner's gpool_pop().
 * Past this point exactly-once needs no CAS: private lists and quarantine
 * have one owning thread each, and the shared pool is under the lock.
 */
static inline int hg_hdr_claim_free(void *cs, unsigned int live,
                                    unsigned int cls, unsigned short base)
{
	return __atomic_compare_exchange_n(&HG_CELL_AT(cs)->hw, &live,
		hg_hdr_make(cls, HG_ST_FREE, base), 0, __ATOMIC_RELAXED,
		__ATOMIC_RELAXED);
}

/* valid only when SHM_EXTRA_STATS; the same for small cells and large frags,
 * since the tag always sits right before the payload */
#ifdef SHM_EXTRA_STATS
#define HG_STATS_IDX(p) (HG_CELL(p)->stat_idx)
#endif

/* class byte of a large-tier fragment (hg_large.c): the first value past the
 * valid classes [0, HG_NCLASSES), so any other out-of-range byte is still
 * corruption */
#define HG_LARGE_MARKER HG_NCLASSES


struct hg_large_chunk;   /* opaque here, defined in hg_large.c */

/*
 * The large tier's boundary-tag fragment header (hg_large.c), visible here
 * so a payload's frag header is HG_HDR(p) - sizeof(struct hg_lfrag) at
 * every site.
 */
struct hg_lfrag {
	unsigned long size;         /* bytes after this header: tag + payload */
	struct hg_lfrag *nxt_free;  /* NULL if allocated */
	struct hg_lfrag **prev;     /* NULL if allocated - f_malloc-style
	                              * free-list back-link for O(1) removal */
	struct hg_lfrag *pf;        /* physical previous frag in this chunk,
	                              * NULL if first frag of its chunk */
} __attribute__ ((aligned (HG_ROUNDTO)));   /* == f_malloc's ROUNDTO */

#define HG_LFRAG_HDR_SIZE (sizeof(struct hg_lfrag))

/*
 * A chunk is one buddy block dedicated to one cell class; its header sits in
 * the FIRST bytes OF THAT BLOCK. A side array would cost ~20 MB on a 5 GB
 * arena; in-block costs one cell and shares a line with the block. This
 * works because hg_cell_free() reads the class from the cell's own header,
 * so a page can host blocks of different classes.
 */
/*
 * Fullness grades: enough to sort "fullest partial" meaningfully, few enough
 * that a block rarely changes grade and the source-block scan is eight
 * pointer tests.
 */
#define HG_GRADES         8
#define HG_GRADE_NONE     0xffffffffu   /* no free cells, on no list */
#define HG_GRADE_DRAINED  0xfffffffeu   /* every cell free, on drained[] */

/* a block whose cells are ALL in the global pool - the GC's work queue */
#define HG_CHUNK_DRAINED    (1u << 0)
/* selected by this GC pass; its cells are being unlinked right now */
#define HG_CHUNK_RECLAIMING (1u << 1)

#define HG_CHUNK_MAP_WORDS 2                /* 128 cells per block, at most */
#define HG_CHUNK_MAP_BITS  64               /* bits per map word, every ABI */
#define HG_CHUNK_MAX_CELLS (HG_CHUNK_MAP_WORDS * HG_CHUNK_MAP_BITS)

struct hg_chunk {
	/*
	 * Global registry, doubly linked: hg_slab_recycled() and the DBG dump
	 * walker traverse it, so a reclaimed block MUST be unlinked, or the
	 * first counts capacity that is gone and the second reads a block the
	 * buddy has handed to another class.
	 */
	struct hg_chunk *next;
	struct hg_chunk *prev;
	unsigned int cls;         /* immutable */
	unsigned int cell_size;   /* total slot size, header included */
	unsigned int cells;

	/*
	 * Cells of this block in the GLOBAL pool (free, reachable by anyone).
	 * Changed only by gpool_push/gpool_pop, under hb->lock; a free into a
	 * thread's private LIFO does not touch it, so a privately cached cell
	 * counts as live - this can delay a reclaim, never cause a premature
	 * one (the idle sweep flushes those caches). in_gpool == cells is the
	 * condition the GC acts on.
	 */
	unsigned int in_gpool;
	unsigned int flags;       /* HG_CHUNK_DRAINED / _RECLAIMING */
	unsigned int order;       /* buddy order, so the GC can hand it back */

	/*
	 * This block's OWN free cells, and the fullness list it is on. A refill
	 * takes from ONE block, the fullest partial, so emptier blocks are left
	 * to drain to zero for the GC (one mixed list per class would top every
	 * block up a little). Only donation/refill, under hb->lock, touches it;
	 * the lock-free fast path never does.
	 */
	void        *free_head;
	unsigned int grade;       /* HG_GRADE_NONE / _DRAINED, or 0..HG_GRADES-1 */

	/* links on the list this block is on: bucket[cls][grade], or
	 * drained[cls] (the empty bucket, the GC's work queue) */
	struct hg_chunk *fnext;
	struct hg_chunk *fprev;

	/*
	 * Which cells are in the GLOBAL pool, one bit per cell: gpool_push
	 * sets, gpool_pop clears, the lock-free fast path never touches it. It
	 * makes a double free exact when the second copy reaches the pool,
	 * checks every link the pool follows, and tells the live-cell walker
	 * which cells are pool-free. At most 126 cells per block (8 KB of
	 * 64-byte cells; checked at carve): two words, in spare header bytes.
	 */
	uint64_t gfree[HG_CHUNK_MAP_WORDS];
} __attribute__ ((aligned (64)));

/* two cache lines on LP64 with the map in the spare bytes; smaller on ILP32,
 * where the pointers shrink - never more */
HG_STATIC_ASSERT(sizeof(struct hg_chunk) <= 128,
	"struct hg_chunk must not exceed two cache lines");

/*
 * Buddy geometry: how an address maps to its block and page. The leaf is the
 * minimum buddy order; 8 KB is a deliberate floor, as the leaf array is one
 * byte per leaf per page (1 KB would make it 8x larger). Leaves per page
 * derive from hb->hps_shift, since the huge page size is probed.
 */
#define HG_LEAF_SHIFT  13
#define HG_LEAF_SIZE   (1UL << HG_LEAF_SHIFT)

/*
 * Ceiling on buddy orders, for the fixed free-list arrays in struct hg_block.
 * The real count is hps_shift - HG_LEAF_SHIFT per arena: 8 on 2 MB pages,
 * 16 on 512 MB arm64 pages. 24 leaves room for 128 GB pages.
 */
#define HG_MAX_ORDERS  24

struct hg_page;      /* hg_buddy.h */
struct hg_free_blk;  /* hg_buddy.h */

/* the address -> page/leaf accessors follow struct hg_block, which they
 * dereference */

/* per-thread private allocation state (TLS) for ONE hg_block. Several blocks
 * can be live in one process (shm, shm_dbg, pkg, module arenas), so it is
 * looked up per block - see hg_get_palloc() in hg_arena.c */
struct hg_quar;  /* hg_dbg.c: the HG_MALLOC_DBG quarantine */

struct hg_palloc {
	struct hg_block *owner;   /* which block this state belongs to */
	/* this thread's quarantine for the block, mapped on the first free
	 * under HG_MALLOC_DBG; NULL otherwise */
	struct hg_quar *quar;
	struct {
		char *bump;            /* next unused cell in own chunk */
		unsigned int left;
		void *free_head;       /* private LIFO free stack */
		unsigned int nfree;
		/* set by every allocation, cleared by the sweep flush: a class
		 * used since the last sweep keeps a residue through it, an
		 * unused one gives every cell back. Fits the padding. */
		unsigned int touched;
	} cls[HG_NCLASSES];
};

/*
 * Per-process counters for the stats the lock-free fast path touches on
 * every allocation and free. Plain shared fields would race (lost updates,
 * under-reported memory) and atomics would put a contended line back on the
 * fast path, so each process has its own cache-line slot and readers sum
 * the slots. SIGNED on purpose: a cell allocated by one process can be freed
 * by another, so a slot goes negative; only the sum is meaningful. A thread
 * gets its own slot too (hg_thread_stats_init()), so TCP main's IO pool
 * threads do not race on the process's slot.
 */
#define HG_STAT_SLOTS     256
#define HG_STAT_LINE      64

struct hg_pstat {
	long used;       /* payload bytes handed out by this process */
	long fragments;  /* live cells handed out by this process */
	/* set by this process's free fast path (a store into a line it is
	 * already writing), cleared when its flush starts; the sweep dispatcher
	 * skips a clean slot - nothing taken since the last flush */
	long dirty;
	/* cell-slot bytes (header + payload + class round-up) handed out by
	 * this process: hg_slab_recycled() needs them to find idle carved
	 * capacity, which "used" cannot (a 100-byte request fills a 128-byte
	 * slot). Same private line as the counters above: no extra traffic. */
	long cell_live;
	char _pad[HG_STAT_LINE - 3 * sizeof(long)];
} __attribute__ ((aligned (HG_STAT_LINE)));

/*
 * What kind of corruption a check caught, grouped by what an operator would
 * do about it, not by which site found it, so a recurrence reads as one
 * repeated event rather than several unrelated ones.
 */
enum hg_corrupt_kind {
	HG_C_CLASS_MISMATCH = 0, /* cell resolves to a block of another class */
	HG_C_DOUBLE_FREE,        /* block already all free, or buddy re-freed */
	HG_C_NFREE_UNDERFLOW,    /* free list shorter than nfree claims */
	HG_C_BAD_CLASS,          /* cell header has an impossible class id */
	HG_C_FOREIGN_PTR,        /* pointer belongs to no live arena */
	HG_C_BUDDY_BAD_FREE,     /* outside the grid, misaligned, wrong order */
	HG_C_INTERNAL,           /* API use that would double-allocate, or the
	                          * arena's size accounting out of step (see
	                          * span_check) - a bug here, not in a peer */
	HG_C_HEADER,             /* cell header fails its checksum: a
	                          * neighbour's overflow, or not a cell */
	HG_C_USE_AFTER_FREE,     /* HG_MALLOC_DBG: freed cell written to */
	HG_C_OVERFLOW,           /* HG_MALLOC_DBG: written past the request */
	HG_CORRUPT_KINDS
};

/* for the two checks that fire where no arena pointer exists */
extern unsigned long hg_corrupt_noarena[HG_CORRUPT_KINDS];


/*
 * Lock-hold / lock-wait instrumentation. Every hb->lock section is a slow
 * path already, so two clock_gettime(CLOCK_MONOTONIC) reads (vDSO) per
 * section are noise; the fast path never comes here. All of it is written
 * UNDER the lock it measures, so no atomics: wait is recorded after the
 * acquire, hold before the release.
 *
 * Histograms are log2 us: bucket 0 is < 1 us, bucket k is [2^(k-1), 2^k) us,
 * the last >= 64 ms. A hold >= hg_lock_stall_us is a stall: counted per
 * reason, kept as the latest stall for the deferred E_CORE_HG_LOCK_STALL
 * event (raised from the sweep timer, never under the lock), and logged at
 * most once per second per process.
 */
enum hg_lock_reason {
	HG_LK_REFILL = 0,   /* class refill: gpool pop, chunk carve, grow */
	HG_LK_RETURN,       /* cell return: gpool push, donate, gc_class */
	HG_LK_FLUSH,        /* per-process cell-cache flush (sweep / floor) */
	HG_LK_LARGE,        /* large tier alloc / free */
	HG_LK_POLICY,       /* grow/shrink tick, profile apply */
	HG_LK_STATS,        /* statistics walks, live-cell enumeration */
	HG_LK_OTHER,
	HG_LK_REASONS
};
#define HG_LK_NONE (-1)   /* lk_cur while hb->lock is not held */
#define HG_LK_BUCKETS 18           /* <1us, 1,2,4,...,32ms, >=64ms */

struct hg_lkstat {
	unsigned long n;
	unsigned long total_ns;
	unsigned long max_ns;
	unsigned long stalls;              /* holds >= hg_lock_stall_us */
	unsigned long hist[HG_LK_BUCKETS];
};

/* phases of hg_mem_commit() on the THP path, timed apart so a slow grow
 * names the slow part: /proc/meminfo read, madvise, populating mlock,
 * backing check (a meminfo delta), MADV_COLLAPSE retrofit (second read) */
enum hg_commit_phase {
	HG_CP_MEMINFO = 0, HG_CP_ADVISE, HG_CP_MLOCK, HG_CP_VERIFY, HG_CP_COLLAPSE,
	HG_CP_PHASES
};

enum hg_grow_why {
	HG_GROW_EXHAUSTION = 0,   /* a request found nothing to carve */
	HG_GROW_PROACTIVE         /* the profile's tick, ahead of demand */
};

/* what refused a grow - hg_stats' last_grow_refusal, hg_grow_refusal_str() */
enum hg_grow_refusal {
	HG_GR_NONE = 0,         /* never refused */
	HG_GR_CAP,              /* the -m/-M reservation is spent */
	HG_GR_PROFILE,          /* the profile's scale-up target is reached */
	HG_GR_DRY_RUN,          /* hg_autoscale_dry_run: growth never acts */
	HG_GR_WAIT_TIMEOUT,     /* another grow stayed in flight too long */
	HG_GR_HOST_FLOOR,       /* the host would drop under the RAM floor */
	HG_GR_CGROUP,           /* the cgroup would drop under its floor */
	HG_GR_MEMLOCK,          /* RLIMIT_MEMLOCK cannot cover the mlock() */
	HG_GR_HUGETLB_POOL,     /* the hugetlb pool has too few free pages */
	HG_GR_MLOCK,            /* mlock() failed, neither of the above */
	HG_GR_HOLE_REPIN,       /* no punched hugetlb page could be re-pinned */
	HG_GR_REASONS
};

struct hg_block {
	/*
	 * What the LOCK-FREE fast path reads, grouped first on cache lines the
	 * slow path never writes. Every field here is set once
	 * (hg_malloc_init_cap(), private_caps_init()), so these lines stay
	 * shared-clean in every process. hg_cell_free() reads priv_max[c] on
	 * every call, so the lock must not share its line: the lock sits alone
	 * with the section bookkeeping only its holder writes, and the
	 * slow-path state starts on the line after it.
	 */
	char *name; /* purpose of this memory block */
	/* the huge-page reservation this block owns: a pre-fork (or
	 * per-process, for PKG), never-unmapped MAP_SHARED (or
	 * private, for PKG) region, huge-page aligned on Linux (only
	 * page-aligned on the non-Linux fallback, see pbase); hb itself lives
	 * at its start */
	char                 *hbase;
	unsigned long         hcap;   /* VA reserved, >= span_end; immutable */
	/* per-THREAD private free-cache bound in CELLS, per class: the byte
	 * budget from the arena size expressed per class (private_caps_init()
	 * in hg_arena.c). 0 = never cache this class privately: one cell
	 * exceeds a thread's whole share, so the shared pool serves it. */
	unsigned int priv_max[HG_NCLASSES];
	unsigned int priv_donate[HG_NCLASSES];
	/* upper bound on one chunk, derived from the arena size at init -
	 * see chunk_size_for() in hg_arena.c */
	unsigned int chunk_max;
	/* HG_MALLOC_DBG serves this arena: tail red zones, poisoned frees and
	 * a quarantine (see hg_dbg.h). Set at creation, never changed. */
	unsigned int dbg;
	/* bytes of freed cells one thread may hold in quarantine, when dbg */
	unsigned long quar_bytes;

	/* slow paths only: gpool + chunk carve. Alone on its line (see above);
	 * lk_t0/lk_cur are the section in progress, valid only while the lock
	 * is held and written by the holder alone. */
	gen_lock_t    lock __attribute__ ((aligned (64)));
	unsigned long lk_t0;
	int           lk_cur;

	/* --- everything from here on is written under hb->lock --- */
	struct hg_chunk *chunks __attribute__ ((aligned (64)));
	unsigned int nchunks;
	/* sum of cells * cell_size over the registered chunks, kept at carve
	 * and gc time so hg_slab_recycled() is O(1), not a walk of every chunk
	 * under hb->lock on every shmem: stat scrape */
	unsigned long slab_capacity;
	/*
	 * Shared free cells per class, as BLOCKS graded by fullness.
	 * bucket[c][0] holds the blocks with the fewest free cells, so a scan
	 * from 0 finds the fullest partial in O(HG_GRADES). A block with no
	 * free cells is on no list; one with every cell free is on drained[].
	 */
	struct hg_chunk *bucket[HG_NCLASSES][HG_GRADES];
	unsigned int gpool_n[HG_NCLASSES];   /* free cells of the class, total */
	unsigned long lo, hi;           /* extent watermarks, not read */

	/* large-object tier (hg_large.c): independently carved chunks, each an
	 * f_malloc-style boundary-tag heap, sharing ONE free list; all of it
	 * under hb->lock */
	struct hg_large_chunk *large_chunks;
	struct hg_lfrag *large_free;
	/*
	 * Backing the large tier holds from the buddy grid, and how much of it
	 * is handed out. A chunk is taken whole and sub-allocated, so
	 * large_backing is charged to real_used at chunk acquisition (live
	 * fragments alone would hide the chunks' slack); hg_large_recycled(),
	 * backing minus live, is subtracted back out for the live figure.
	 */
	unsigned long large_backing;
	unsigned long large_live;
	/* chunk churn: a chunk returns to the buddy when its last fragment is
	 * freed, so carved far ahead of returned means alloc/free thrash */
	unsigned long large_chunks_carved;
	unsigned long large_chunks_returned;

	/* bytes carved from the reservation into chunks/regions (the arena's
	 * footprint); changed only under hb->lock, never on the fast path */
	unsigned long real_used;
	unsigned long max_real_used;
	/* peak of the LIVE figure hg_get_real_used() reports (max_real_used is
	 * the peak CARVE, a different quantity). Sampled: refreshed on every
	 * stats read, each second by the sweep timer for a shared arena
	 * (hg_sample_live_peaks()) and at each sweep flush for a private one.
	 * The unsynchronized update is a benign race: it can only
	 * under-report. */
	unsigned long max_live_used;

	/* the fast-path counters - see struct hg_pstat above. Summed by
	 * hg_used()/hg_fragments(); never read directly. */
	struct hg_pstat pstat[HG_STAT_SLOTS];
	unsigned int thread_slot_next;   /* next thread slot, counts down */
	unsigned long size;        /* total arena size */

	/* span_end is the ADDRESS EXTENT of the published page grid, in bytes
	 * from hbase; committed_bytes is the COUNT of bytes backed
	 * (pre-faulted, pinned, usable). Equal until a page is punched
	 * mid-span. Address tests (ownership, page grid, bump carve, release)
	 * use span_end; memory figures (floor, profile, statistics) use
	 * committed_bytes. */
	unsigned long         span_end;
	unsigned long         committed_bytes;
	volatile unsigned long hoff;
	enum hg_mem_tier      tier;
	unsigned long         locked_mb;
	/* init could not mlock the arena (RLIMIT_MEMLOCK) and went on
	 * unpinned; growth then populates unpinned too instead of refusing */
	unsigned int          unpinned;
	/* MAP_SHARED vs MAP_PRIVATE, as passed to hg_malloc_init(): a pkg
	 * delta is per PROCESS, so the ceiling check multiplies it by nproc */
	int                   shared;

	/*
	 * Elastic arena. committed_bytes is COMMITTED (pre-faulted, pinned,
	 * published to the buddy); hcap is RESERVED virtual address space. The
	 * WHOLE cap is mapped once, before fork, and growth only commits more
	 * of it: mmap()/mprotect() edit one process's page tables, so a delta
	 * mapped after fork would SIGSEGV in every already-forked worker. One
	 * VMA over one shmem object lets a committed page fault in wherever it
	 * is next touched. hcap == committed_bytes is a fixed arena (default).
	 */
	unsigned long         committed_min; /* shrink's floor: committed_bytes
	                                     * at init (-m/-M), or the
	                                     * profile's scale-down size */
	unsigned long         grow_granule; /* bytes per grow step, hps multiple */
	unsigned long         shrink_step;  /* max bytes released per drain
	                                     * tick, hps multiple, decoupled
	                                     * from the granule */
	unsigned long         grows;        /* successful commits */
	unsigned long         grow_bytes;   /* their total */
	unsigned long         grow_refused; /* refusals (cap or resource) */
	/* allocation-failure log throttle: the first failure of an episode is
	 * logged in full, the rest are counted and summarised at the sweep
	 * (hg_oom_take()); a quiet interval ends the episode */
	unsigned long         oom_fails;
	unsigned long         oom_fails_said;
	unsigned long         oom_max_req;
	unsigned int          oom_episode;
	unsigned long         shrinks;      /* successful releases */
	unsigned long         shrink_bytes; /* their total */
	/*
	 * Interior release. A shrink RETRACTS the span from the top; a punch
	 * gives back a whole-free page from anywhere inside it without moving
	 * span_end. A punched page carved again must be re-mlock()ed BY THE
	 * CARVING PROCESS: mlock is per-VMA and not inherited across fork.
	 * repin_failed makes a broken pin visible.
	 */
	unsigned long         punches;       /* interior pages released */
	unsigned long         punch_bytes;
	unsigned long         punched_pages; /* gauge: currently punched */
	unsigned long         repins;        /* punched pages carved again */
	unsigned long         repin_bytes;
	unsigned long         repin_failed;  /* ...and could not be re-pinned */
	unsigned int          repin_said;    /* one warning per episode */
	unsigned long         hole_regrows;  /* grow events served from holes */
	unsigned long         top_carves;    /* whole pages by hg_buddy_alloc */
	/*
	 * The attached auto-scaling POLICY: numbers copied from a config
	 * auto_scaling_profile at attach time, never a pointer (the profile is
	 * process-local; this block may be shared). active == 0: no profile -
	 * growth still works up to hcap on exhaustion, shrink keeps its
	 * built-in gate. "scale up to N" is N MB, hps-rounded: the ADMIN
	 * CEILING within the -m INIT:CAP reservation, never above hcap (the
	 * reservation predates the config). "down to M" is the shrink floor
	 * and MAY sit below the initial size: with a profile, -m is only the
	 * start.
	 */
	struct {
		unsigned int   active;
		unsigned long  up_bytes;      /* admin ceiling, <= hcap */
		unsigned long  down_bytes;    /* shrink floor */
		unsigned int   up_pct;        /* grow when usage >= this... */
		unsigned int   up_need;       /* ...for this many ticks... */
		unsigned int   up_window;     /* ...out of this window */
		unsigned int   down_pct;      /* shrink when usage <= this... */
		unsigned int   down_cycles;   /* ...for this many consecutive */
		unsigned short cooldown;      /* post-grow shrink hold-off */
	} pol;
	unsigned int          pol_up_hits;   /* ticks over up_pct in window */
	unsigned int          pol_up_ticks;  /* window position */
	unsigned int          pol_cooldown;  /* ticks left before shrink counts */
	unsigned int          pol_dry_said;  /* one advise line per episode */
	/* consecutive quiet sweep ticks, the down-slow gate; reset by any grow
	 * and any tick failing the abundance test, so a shrink needs a full
	 * uninterrupted quiet window */
	unsigned int          shrink_quiet;
	/* the quiet window is established: the drain releases one step per
	 * maintenance tick while the gates hold. Cleared by any grow, a failed
	 * gate, or a tick that finds nothing to take. */
	unsigned int          draining;
	/* set once when hg_mem_release() fails structurally (e.g. no hugetlb
	 * hole punch): shrink is off for this arena's lifetime */
	unsigned int          shrink_unsupported;
	/* one log line per refusal EPISODE (a full arena refuses every
	 * allocation; grow_refused has the count). Set when a refusal is
	 * logged, cleared by the next successful grow. */
	unsigned int          grow_refuse_said;
	/* what refused the most recent grow (enum hg_grow_refusal), kept after
	 * the episode so hg_stats names the last cause; grow_blocked says if it
	 * is current. grow_refuse_mlock: an mlock() refusal's cause, classified
	 * once per episode (it reads /proc, and a full arena retries on every
	 * exhausted request). */
	unsigned int          grow_refuse_why;
	unsigned int          grow_refuse_mlock;
	/* lock instrumentation - see enum hg_lock_reason. The section in
	 * progress (lk_t0/lk_cur) sits with the lock itself, at the top. */
	struct hg_lkstat      lk_hold[HG_LK_REASONS];
	struct hg_lkstat      lk_wait[HG_LK_REASONS];
	struct hg_lkstat      lk_commit;      /* hg_mem_commit() inside a grow */
	struct hg_lkstat      lk_release;     /* hg_mem_release() in a trim or a
	                                       * punch, lock released */
	struct hg_lkstat      lk_gc;          /* gc_class() block returns */
	struct hg_lkstat      lk_cphase[HG_CP_PHASES]; /* commit, by phase */
	/* three-phase commit: a grow RESERVES [span_end, span_pending) under
	 * the lock, populates it with the lock released, then publishes it
	 * under the lock. One grow in flight at a time; a worker that exhausts
	 * meanwhile waits for the publish without the lock (lk_grow_wait). */
	unsigned long         span_pending;   /* span_end + in-flight delta */
	/* the maintenance process is alive and owns the proactive ticks */
	unsigned int          maint_active;
	int                   maint_proc;
	unsigned int          grow_inflight;  /* 0/1 */
	/* bumped, under the lock, by every grow and hole re-grow that
	 * published pages - what a waiting grower compares: a trim or a punch
	 * also holds grow_inflight and moves committed_bytes, the other way */
	unsigned long         grow_gen;
	unsigned long         grow_waits;     /* workers that waited for a grow */
	unsigned long         grow_wait_timeouts; /* ...and gave up (refused) */
	struct hg_lkstat      lk_grow_wait;   /* their unlocked wait times */
	unsigned long         lk_worst_ns;    /* longest hold ever, and whose */
	int                   lk_worst_reason;
	int                   lk_worst_proc;
	unsigned long         lk_stalls;      /* sum over reasons */
	unsigned long         lk_last_stall_ns; /* most recent stall, for the */
	int                   lk_last_stall_reason; /* deferred event */
	int                   lk_last_stall_proc;
	unsigned int          lk_stall_event_due;
	/* growth attribution: the tick or an exhausted request */
	unsigned long         grows_proactive;
	unsigned long         grows_exhaustion;
	/* deferred collapse (tier 3): pages a worker's grow published on 4 KB,
	 * for the maintenance process to collapse (hg_collapse_deferred()) */
	unsigned int          collapse_pending;
	unsigned long         collapse_wanting;       /* pages still flagged */
	unsigned long         collapse_scan;          /* next page to look at */
	unsigned long         collapse_deferred;      /* pages handed over */
	unsigned long         collapsed_late;         /* pages it collapsed */
	unsigned long         collapse_retries;       /* failed tries, retried */
	unsigned long         collapse_late_failed;   /* pages left on 4 KB */
	unsigned int          collapse_fail_said;     /* first failure logged */
	/*
	 * The alertable grow-blocked state, RESOURCE refusals only (an admin
	 * cap is policy and never latches). Two-step, like below_floor: the
	 * first resource refusal sets grow_blocked_mark = gc_passes + 1; the
	 * latch arms when a refusal recurs at gc_passes >= mark, i.e. a full GC
	 * pass did not help, so a spike one reclaim absorbs never alerts.
	 * Cleared by a successful grow or by free space recovering above the
	 * reserve floor (reusing its hysteresis). grow_blocked is the exported
	 * gauge; grow_event_due hands the E_CORE_SHM_GROW_BLOCKED raise to the
	 * sweep timer, which holds no arena lock: evi_raise_event() allocates
	 * shm and must not run under hb->lock in an arena that just refused.
	 */
	unsigned int          grow_blocked;
	unsigned long         grow_blocked_mark;
	/* grow_refused at arming time. On a full arena with nothing to reclaim
	 * gc_passes never moves, so the sweep timer is the fallback: a full
	 * sweep interval with the episode armed and refusals still rising
	 * latches it. A spike ending before the next sweep never alerts. */
	unsigned long         grow_blocked_refuse0;
	unsigned int          grow_event_due;
	/* bytes per ACHIEVED backing tier, indexed by enum hg_mem_tier (slot 0
	 * unused): hb->tier cannot describe a grown arena, as each THP delta
	 * may land on 4K next to 2M from init */
	unsigned long         tier_bytes[HG_MEM_4K + 1];

	/*
	 * Buddy substrate (geometry at HG_LEAF_SHIFT): "which block owns this
	 * address" is two shifts and a mask from an aligned origin. hbase is
	 * not reliably aligned (the Linux reserve paths align it, the non-Linux
	 * fallback mmap() gives only page alignment), so page 0 is pbase, hbase
	 * rounded up to a huge page. hps is PROBED: 2M on x86_64 and arm64 with
	 * 4K base pages, 32M with 16K, 512M with 64K - never hardcode ">> 21".
	 */
	unsigned long hps;         /* huge page size, probed at reserve time */
	unsigned int  hps_shift;   /* log2(hps), so page-of is a shift */
	char         *pbase;       /* page 0 - hbase rounded up to hps */
	unsigned long npages;      /* whole pages from pbase to the span end
	                            * (hbase+span_end); grows with the arena */
	unsigned long npages_cap;  /* whole pages to hbase+hcap, the grid's
	                            * true extent; descriptors exist for all
	                            * from init, so growth never relocates
	                            * metadata */

	/* buddy state (hg_buddy.c): written only under hb->lock; the buddy is
	 * slow path only (carve_chunk(), the large tier) */
	struct hg_page     *pages;                    /* npages descriptors */
	struct hg_free_blk *bfree[HG_MAX_ORDERS + 1]; /* free list per order */
	unsigned long       nfree[HG_MAX_ORDERS + 1]; /* its length, per order */
	/*
	 * Whole-free pages, one bit per page (1 = whole-free, backed, on
	 * offer). A bitmap, not a list: an address-ordered list walks cold page
	 * heads on every push, and a punch discards its nodes (each page's
	 * first bytes). bfree[top] is always NULL and nfree[top] is this
	 * bitmap's popcount; lower orders keep their lists.
	 */
	unsigned long      *wfree;
	unsigned long       wfree_words;
	unsigned long       buddy_free_leaves;        /* free leaves, whole arena */
	unsigned int        buddy_top;                /* whole-page order, cached */
	unsigned int        buddy_ready;              /* 0 until hg_buddy_init() */

	/* GC work queue, per class: blocks whose every cell is in the global
	 * pool, accumulated so one free-list walk reclaims them all */
	struct hg_chunk    *drained[HG_NCLASSES];
	/* the OLDEST drained block: gc_class_run() returns from the tail (the
	 * head, most recently drained, is the one kept if gc_keep[c] != 0) */
	struct hg_chunk    *drained_tail[HG_NCLASSES];
	unsigned int        ndrained[HG_NCLASSES];
	unsigned long       gc_blocks_returned;       /* lifetime, for stats */
	unsigned long       gc_passes;
	/*
	 * Per-class hysteresis: gc_keep[c] drained blocks of class c are KEPT
	 * (carved, empty) instead of returned to the buddy; gpool_pop() takes
	 * one before it carves. Fed by the class's carves per policy cycle
	 * (carves_cycle, halving when demand stops), capped by a per-class byte
	 * budget (arena >> HG_GC_KEEP_BUDGET_SHIFT) and HG_GC_KEEP_MAX blocks.
	 */
	unsigned int        gc_keep[HG_NCLASSES];
	unsigned int        carves_cycle[HG_NCLASSES];
	unsigned int        gc_next_class;       /* tick's round-robin start */
	/* who returned the blocks: the maintenance tick (budgeted, off the
	 * request path) or a trigger site (pressure or sweep flush, or the
	 * emergency threshold on the donate path) */
	unsigned long       gc_tick_blocks;
	unsigned long       gc_inline_blocks;
	unsigned long       sweeps_skipped;        /* clean, not dispatched */
	unsigned long       cache_flushes;            /* sweeps run */
	unsigned long       cells_flushed;            /* cells recovered from TLS */
	unsigned long       pressure_flushes;         /* self-flushes at carve exhaustion */
	unsigned long       pressure_cells;           /* cells those handed back */
	/*
	 * Corruption counters, one per kind. Each check also logs LM_CRIT, but
	 * a number can be alerted on and graphed (the log may not reach
	 * journald, and CRITICAL carries unrelated failures too). They count
	 * DETECTIONS, not repairs: the site has already refused the operation
	 * or leaked the cell. Non-zero is never routine.
	 */
	unsigned long       corrupt[HG_CORRUPT_KINDS];
	unsigned long       buddy_splits;             /* blocks split down an order */
	/*
	 * RUNTIME merges only. hg_buddy_init() publishes the page the header
	 * and metadata straddle leaf by leaf through the normal free path, so
	 * it coalesces; that total goes to buddy_merges_init and this counter
	 * is rebased to 0, so splits and merges share a zero point.
	 */
	unsigned long       buddy_merges;             /* blocks merged with a buddy */
	unsigned long       buddy_merges_init;        /* coalesces done building the tree */
	unsigned long       blocks_carved;            /* class blocks cut, lifetime */
	/* set while a flush walks a cache chain: pushing a cell can reclaim its
	 * block, and the next cell on the chain may live in that same block */
	unsigned int        gc_deferred;
	/*
	 * Reserve floor: free leaves below which the arena is under pressure;
	 * set once at init as a fraction of the grid. Crossing it triggers a
	 * sweep BEFORE an allocation fails, the warning an operator can act on.
	 */
	unsigned long       reserve_floor;
	unsigned int        below_floor;      /* hysteresis: already reported */
	unsigned int        floor_warned;     /* this crossing was a WARN */
	unsigned long       floor_crossings;

	unsigned char size2class[(HG_CELL_MAX / HG_ROUNDTO) + 1];
} __attribute__ ((aligned (HG_ROUNDTO)));

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
 * get the mapping (see hg_malloc.c). Returns NULL on total failure; the
 * caller aborts startup (no silent fallback to another allocator).
 *
 * @shared: 1 for shm/shm_dbg (MAP_SHARED, one arena for every worker), 0 for
 * pkg (MAP_PRIVATE, each forked worker gets its own copy-on-write arena, lock
 * and free pools); hg_mem_reserve() in hg_malloc.c says why getting this
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

/* the stall bookkeeping + rate-limited WARN; out of line (hg_arena.c) so
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
 * (the *_unlocks family in hg_buddy.c and the ticks calling them): the lock
 * is held on entry and again on return. Out of line (hg_arena.c) so the
 * header stays free of dprint.
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

/* carved-but-idle cell capacity; defined in hg_arena.c (declared here too,
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
 * definition is in mem/hg_arena.c, entirely inside "#ifdef HG_MALLOC" */
static inline int hg_register_stats(void) { return 0; }
#endif

/* bump a corruption counter; hb may be NULL where no arena is in scope */
static inline void hg_corrupt(struct hg_block *hb, enum hg_corrupt_kind k)
{
	if (hb)
		hb->corrupt[k]++;
	else
		hg_corrupt_noarena[k]++;
}

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
