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
#include <time.h>
#include <stddef.h>   /* offsetof, for the header-layout pins */
#include <stdint.h>   /* uint64_t: the per-block free map is 64 bits a word on every ABI */
#include "meminfo.h"
#include "common.h"
/* for process_no, used by hg_pstat_mine() below to pick this process's
 * stats slot. Included explicitly rather than relied on to arrive via
 * some other header - it does on a native build, and does not under a
 * cross-compiler. */
#include "../globals.h"

#undef HG_ROUNDTO

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
	#define HG_ROUNDTO		sizeof(long long)
#else
	#define HG_ROUNDTO		sizeof(void *)
#endif

#define HG_NCLASSES  21
#define HG_CELL_MAX  65536  /* largest cell; bigger allocs fail (Phase 1) */

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
 * f_malloc) - unlike a single module's private arena, HG_MALLOC hands
 * pointers to arbitrary caller code via shm_malloc()/pkg_malloc(), so the
 * class tag can NOT live in-band at the front of the payload the way such
 * an arena's records can.
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
 *   offset HG_ROUNDTO           (DBG)    : file
 *   offset HG_ROUNDTO*2         (DBG)    : func
 *   offset HG_ROUNDTO*3         (DBG)    : line
 *   offset HG_ROUNDTO+HG_CELL_HDR_DBG
 *          (SHM_EXTRA_STATS)          : statistic_index (mem-group index)
 *   offset HG_CELL_HDR                : payload starts here; while a cell
 *                                        is FREE, the first HG_ROUNDTO*2 bytes
 *                                        of payload double as the free-list
 *                                        link (cell_next()/cell_set_next()
 *                                        in hg_arena.c) - safe, since
 *                                        nobody reads payload of a free cell.
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
 * Payloads must be aligned for the widest scalar a caller may store in
 * them; 8 covers uint64_t/double everywhere we build. This is NOT implied
 * by HG_ROUNDTO: on 32-bit ARM HG_ROUNDTO is 4, so the raw header below would be
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

/*
 * The header as a struct, so every site names a field instead of
 * re-deriving "HG_ROUNDTO * n" by hand. The layout is the one documented
 * above and is PINNED by the _Static_asserts below: the struct may not move
 * a field without the build saying so, on every ABI and build configuration.
 * The class byte sits alone in the first HG_ROUNDTO bytes.
 */
struct hg_cell_hdr {
	unsigned char  cls;                   /* class id, or HG_LARGE_MARKER */
	unsigned char  _pad0[HG_ROUNDTO - 1];
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

/* valid only when SHM_EXTRA_STATS; uniform for small cells AND large frags,
 * since the tag region (and thus this offset) always sits immediately
 * before payload regardless of what precedes it (fixed chunk cell vs.
 * hg_lfrag boundary-tag header) */
#ifdef SHM_EXTRA_STATS
#define HG_STATS_IDX(p) (HG_CELL(p)->stat_idx)
#endif

/* tag-byte value marking a cell as belonging to the large-object tier
 * (hg_large.c) rather than a fixed size class - valid classes are
 * [0, HG_NCLASSES), so this is the first value past them, still
 * distinguishable from genuine corruption (any other out-of-range byte) */
#define HG_LARGE_MARKER HG_NCLASSES

struct hg_large_chunk;   /* opaque here, defined in hg_large.c */

/*
 * The large tier's boundary-tag fragment header (hg_large.c). Visible here
 * so that "the frag header of a payload pointer" is HG_HDR(p) -
 * sizeof(struct hg_lfrag) at every site, not a manifest constant that
 * hg_large.c had to static_assert against the real struct.
 */
struct hg_lfrag {
	unsigned long size;         /* total frag size: hdr + tag + payload */
	struct hg_lfrag *nxt_free;  /* NULL if allocated */
	struct hg_lfrag **prev;     /* NULL if allocated - f_malloc-style
	                              * free-list back-link for O(1) removal */
	struct hg_lfrag *pf;        /* physical previous frag in this chunk,
	                              * NULL if first frag of its chunk */
} __attribute__ ((aligned (HG_ROUNDTO)));   /* == f_malloc's ROUNDTO everywhere */

#define HG_LFRAG_HDR_SIZE (sizeof(struct hg_lfrag))

/*
 * A chunk is one buddy block dedicated to one cell class, and its header sits
 * in the FIRST bytes OF THAT BLOCK.
 *
 * In-block rather than in a side array, and the arithmetic is the whole
 * argument: at ~32 bytes per block, a separate array over a 5 GB arena would
 * be 20 MB - twenty times every other piece of metadata combined - where
 * in-block costs nothing external, shares a cache line with the block being
 * touched anyway, and gives up exactly one cell.
 *
 * The enabler: hg_cell_free() reads the class from the CELL's own header
 * byte rather than from the chunk, so a page can host blocks of different
 * classes with no fast-path change.
 */
/*
 * Fullness grades. Eight is the design's figure: enough that "fullest
 * partial" is meaningfully sorted, few enough that a block changes grade
 * rarely rather than on every cell, and that the scan for a source block is
 * eight pointer tests.
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
	 * Global registry. Doubly linked, which it did not need to be while
	 * chunks were immortal: hg_slab_recycled() and the DBG dump walker both
	 * traverse it, so a reclaimed block MUST come out of it - otherwise the
	 * first keeps counting capacity that no longer exists and the second
	 * reads a block the buddy has already handed to another class.
	 */
	struct hg_chunk *next;
	struct hg_chunk *prev;
	unsigned int cls;         /* immutable */
	unsigned int cell_size;   /* total slot size, header included */
	unsigned int cells;

	/*
	 * Cells of this block currently parked in the GLOBAL pool, i.e.
	 * definitively free and reachable by anyone. Maintained only at
	 * cache/block transitions (gpool_push/gpool_pop), which are 1-3% of
	 * operations and already under hb->lock - a free that lands in a
	 * thread's private LIFO does not touch this, by design.
	 *
	 * A cell sitting in some thread's private cache therefore still counts
	 * as live. That is deliberately conservative: it can only delay a
	 * reclaim, never cause a premature one, and flushing those caches is
	 * exactly what the idle sweep is for.
	 *
	 * in_gpool == cells means every cell of this block is free and globally
	 * visible, which is the condition the GC acts on.
	 */
	unsigned int in_gpool;
	unsigned int flags;       /* HG_CHUNK_DRAINED / _RECLAIMING */
	unsigned int order;       /* buddy order, so the GC can hand it back */

	/*
	 * This block's OWN free cells, and which fullness list it currently sits
	 * on. One mixed list per class would make a 32-cell refill skim cells
	 * from whichever blocks happened to be at its head and top every block
	 * up a little - measured, that leaves blocks stalled at 88% drained and
	 * the GC with nothing to collect.
	 *
	 * Per block, a refill takes all 32 from ONE block, and the
	 * fullness grading makes it the FULLEST partial - so that block is used
	 * up while emptier ones are left alone to reach zero.
	 *
	 * This costs the fast path nothing: hg_cell_free() still pushes to the
	 * thread-private TLS LIFO with no lock, and only the donation/refill
	 * path - already under hb->lock, 1-3% of operations - touches this.
	 */
	void        *free_head;
	unsigned int grade;       /* HG_GRADE_NONE / _DRAINED, or 0..HG_GRADES-1 */

	/*
	 * The list this block is currently on. Today that is only the per-class
	 * drained queue; the allocation policy generalises it into fullness
	 * buckets, of which "drained" is simply the empty one - which is why
	 * the design calls the empty bucket the GC's work queue.
	 */
	struct hg_chunk *fnext;
	struct hg_chunk *fprev;

	/*
	 * Which of this block's cells are in the GLOBAL pool, one bit per
	 * cell, maintained only at the pool boundary (gpool_push sets, gpool_pop
	 * clears) - so the lock-free fast path never touches it. It makes a
	 * double free exact the moment the second copy reaches the pool, lets
	 * every link the pool follows be checked against it, and tells the
	 * live-cell walker which cells are pool-free without a hash set. Blocks
	 * hold at most 126 cells (an 8 KB block of 64-byte cells; checked at
	 * carve), so two words cover any block. Fits the header's spare bytes.
	 */
	uint64_t gfree[HG_CHUNK_MAP_WORDS];
} __attribute__ ((aligned (64)));

/* two cache lines on LP64 with the map in the spare bytes; smaller on ILP32,
 * where the pointers shrink - never more */
HG_STATIC_ASSERT(sizeof(struct hg_chunk) <= 128,
	"struct hg_chunk must not exceed two cache lines");

/*
 * buddy geometry - how an address maps to its block and page.
 *
 * The leaf is the minimum buddy order. 8 KB is a deliberate floor: the leaf
 * array is one byte per leaf per page, so dropping to 1 KB would multiply that
 * array by eight for no measured gain. Do not lower it without evidence.
 *
 * Leaves per page is NOT a constant, because the huge page size is probed -
 * 256 leaves on a 2M page, 65536 on a 512M arm64 page - so it is derived from
 * hb->hps_shift rather than baked in.
 */
#define HG_LEAF_SHIFT  13
#define HG_LEAF_SIZE   (1UL << HG_LEAF_SHIFT)

/*
 * Ceiling on the number of buddy orders, for the fixed free-list array in
 * struct hg_block. The REAL count is derived per arena as
 * hps_shift - HG_LEAF_SHIFT: 8 on a 2 MB page with 8 KB leaves, 16 on a
 * 512 MB arm64 page. 24 leaves room for a 128 GB page that does not exist yet
 * and costs 25 pointers in one struct.
 */
#define HG_MAX_ORDERS  24

struct hg_page;      /* hg_buddy.h */
struct hg_free_blk;  /* hg_buddy.h */

/* the accessors that turn an address into a page and a leaf live just after
 * struct hg_block below - they dereference it, so they cannot precede it */

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
		/* set by every allocation, cleared by the sweep flush. A class
		 * allocated from since the last sweep keeps a residue through it;
		 * one that was not gives every cell back. Fits the padding. */
		unsigned int touched;
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
	/* Cell-slot bytes (header + payload + size-class round-up) currently
	 * handed out by this process. "used" alone cannot tell how much ARENA
	 * a process is holding, because a 100-byte request occupies a whole
	 * 128-byte slot; hg_slab_recycled() needs the slot figure to work out
	 * how much carved capacity is sitting idle. Lives on the same
	 * already-private cache line as the two counters above, so maintaining
	 * it costs no extra cache traffic on the fast path. */
	long cell_live;
	char _pad[HG_STAT_LINE - 3 * sizeof(long)];
} __attribute__ ((aligned (HG_STAT_LINE)));

/*
 * What kind of corruption a check caught. Grouped by what an operator would do
 * about it rather than by which line found it: several sites detect the same
 * defect from different angles, and splitting them would make a recurrence
 * look like several unrelated rare events instead of one repeated one.
 */
enum hg_corrupt_kind {
	HG_C_CLASS_MISMATCH = 0, /* cell resolves to a block of another class   */
	HG_C_DOUBLE_FREE,        /* block already fully free, or buddy re-freed */
	HG_C_NFREE_UNDERFLOW,    /* free list shorter than nfree claims - THIS  */
	                         /* is the __thread palloc_slots signature      */
	HG_C_BAD_CLASS,          /* cell header carries an impossible class id  */
	HG_C_FOREIGN_PTR,        /* pointer belongs to no live arena            */
	HG_C_BUDDY_BAD_FREE,     /* outside the grid, misaligned, wrong order   */
	HG_C_INTERNAL,           /* allocator API used in a way that would      */
	                         /* double-allocate, or the arena's own size  */
	                         /* accounting out of step (see span_check)   */
	                         /* - a bug here, not in a peer               */
	HG_CORRUPT_KINDS
};

/* for the two checks that fire where no arena pointer exists */
extern unsigned long hg_corrupt_noarena[HG_CORRUPT_KINDS];

/*
 * Lock-hold / lock-wait instrumentation. Every hb->lock section is a
 * slow path already (refill, return, flush, large, region, policy, stats),
 * so two clock_gettime(CLOCK_MONOTONIC) reads per section - ~20 ns each via
 * the vDSO - are noise next to the work they bracket, and the fast path
 * (cache hits) never comes here. Everything below is written UNDER the lock
 * it measures, so it needs no atomics: the wait figure is recorded after
 * the acquire, the hold figure before the release.
 *
 * Histograms are log2 in microseconds: bucket 0 is "< 1 us", bucket k is
 * [2^(k-1), 2^k) us, the last bucket collects everything >= 64 ms. A hold
 * at or above hg_lock_stall_us counts as a stall: it is tallied per reason,
 * remembered as the most recent stall for the deferred E_CORE_HG_LOCK_STALL
 * event (raised from the sweep timer, never under the lock), and logged
 * once per second per process at most.
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
#define HG_LK_BUCKETS 18           /* <1us, 1,2,4,...,32ms, >=64ms */

struct hg_lkstat {
	unsigned long n;
	unsigned long total_ns;
	unsigned long max_ns;
	unsigned long stalls;              /* holds >= hg_lock_stall_us */
	unsigned long hist[HG_LK_BUCKETS];
};

/* the phases of hg_mem_commit() on the THP path, timed separately so a
 * slow grow says WHICH part of the commit is slow: the /proc/meminfo read,
 * the madvise, the populating mlock, the backing verification (a meminfo
 * counter delta), the MADV_COLLAPSE retrofit (with its second meminfo read) */
enum hg_commit_phase {
	HG_CP_MEMINFO = 0, HG_CP_ADVISE, HG_CP_MLOCK, HG_CP_VERIFY, HG_CP_COLLAPSE,
	HG_CP_PHASES
};

enum hg_grow_why {
	HG_GROW_EXHAUSTION = 0,   /* a request found nothing to carve */
	HG_GROW_PROACTIVE         /* the profile's tick, ahead of demand */
};

struct hg_block {
	/*
	 * What the LOCK-FREE fast path reads, grouped first and kept on
	 * cache lines nothing on the slow path ever writes. Every field here
	 * is set once - hg_malloc_init_cap(), private_caps_init() - and never
	 * again, so these lines stay shared-clean in every process.
	 *
	 * Measured before this (offsetof() on a release build): the lock
	 * word sat at offset 8 and priv_max[] at offset 44, on the same
	 * 64-byte line. hg_cell_free() reads priv_max[c] on every call in
	 * every worker, and every lock_get()/lock_release() by ANY of them
	 * invalidated that line in all the others - a coherence miss per
	 * free whenever any slow path ran anywhere. The lock now sits alone
	 * on its own line, with the section bookkeeping only its holder
	 * writes; the slow-path state starts on the line after it.
	 */
	char *name; /* purpose of this memory block */
	/* the huge-page reservation this block owns: a pre-fork (or
	 * per-process, for PKG), never-unmapped, 2M-aligned MAP_SHARED (or
	 * private, for PKG) region; hb itself lives at its start */
	char                 *hbase;
	unsigned long         hcap;   /* VA reserved, >= span_end; immutable */
	/* Per-THREAD private free-cache bound, in CELLS, one entry per class,
	 * derived from the arena size at init - see private_caps_init() in
	 * hg_arena.c.  A flat cell count cannot bound anything, because the
	 * same count means 16 KB in class 64 and 16 MB in class 65536; these
	 * are the byte budget expressed per class.  priv_max may legitimately
	 * be 0, which means "never cache this class privately" - the class is
	 * large enough that one cell already exceeds a thread's whole share,
	 * and such allocations are rare enough that the shared pool is the
	 * right home for them. */
	unsigned int priv_max[HG_NCLASSES];
	unsigned int priv_donate[HG_NCLASSES];
	/* upper bound on one chunk, derived from the arena size at init -
	 * see chunk_size_for() in hg_arena.c */
	unsigned int chunk_max;

	/* slow paths only: gpool + chunk carve. Alone on its line - see the
	 * note above. lk_t0/lk_cur are the section in progress,
	 * valid only while the lock is held and written by the holder alone,
	 * so they share the holder's line and never a reader's. */
	gen_lock_t    lock __attribute__ ((aligned (64)));
	unsigned long lk_t0;
	int           lk_cur;

	/* --- everything from here on is written under hb->lock --- */
	struct hg_chunk *chunks __attribute__ ((aligned (64)));
	unsigned int nchunks;
	/* sum of cells * cell_size over the registered chunks, kept at carve
	 * and gc time so hg_slab_recycled() is an O(1) read instead of a walk
	 * of every chunk under hb->lock on every shmem: stat scrape (measured
	 * that walk at 7 ms mean / 30 ms max on a 1.8 GB arena, with SIP
	 * workers waiting up to 46 ms behind it) */
	unsigned long slab_capacity;
	/*
	 * Shared free cells, per class, held as BLOCKS graded by fullness
	 * rather than as one mixed cell list. bucket[c][0] holds the blocks
	 * with the fewest free cells, so scanning from 0 up finds the fullest
	 * partial in O(HG_GRADES) - the "concentration" the design requires.
	 * A block with no free cells is on no list; one with every cell free is
	 * on drained[] instead, which is the GC's queue.
	 */
	struct hg_chunk *bucket[HG_NCLASSES][HG_GRADES];
	unsigned int gpool_n[HG_NCLASSES];   /* free cells of the class, total */
	unsigned long lo, hi;           /* extent watermarks */

	/* large-object tier (hg_large.c): list of independently-carved
	 * chunks, each an f_malloc-style boundary-tag heap, sharing ONE free
	 * list across all of them; hb->lock guards all of it (slow path
	 * already, no separate lock needed) */
	struct hg_large_chunk *large_chunks;
	struct hg_lfrag *large_free;
	/*
	 * Backing the large tier holds from the buddy grid, and how much of it
	 * is handed out right now.  Both are needed because the two answer
	 * different questions and only the first one is what the grid lost:
	 * a chunk is taken whole from the buddy, then sub-allocated, so
	 * charging only the live fragments would leave real_used
	 * under-reporting the arena's true footprint by the chunks' unused
	 * slack - and free_to_carve over-reporting what was left,
	 * monotonically.  large_backing is charged to real_used at chunk
	 * acquisition; large_recycled() = large_backing - large_live is the
	 * large tier's analogue of hg_slab_recycled() and is subtracted back
	 * out to get the live figure.
	 */
	unsigned long large_backing;
	unsigned long large_live;
	/* chunk churn: a chunk goes back to the buddy the moment its last
	 * fragment is freed, so carved climbing far faster than returned is
	 * the signature of alloc/free thrash in this tier */
	unsigned long large_chunks_carved;
	unsigned long large_chunks_returned;

	/* Bytes carved from the reservation into chunks/regions, i.e. the
	 * arena's own footprint. Only ever changed while holding hb->lock
	 * (carve_chunk, the large tier), never on the
	 * lock-free fast path, so a plain field is safe here. */
	unsigned long real_used;
	unsigned long max_real_used;
	/* High-water mark of the LIVE figure that hg_get_real_used() reports, as
	 * opposed to max_real_used above, which is the peak CARVE. They are
	 * different quantities: carve only ever grows (chunks are never
	 * un-carved), so reporting it as max_used made max_used drift away from
	 * real_used forever instead of meaning "the peak real_used reached" -
	 * unlike every other allocator. Sampled, not exact: refreshed whenever
	 * the stats are read, so a spike between two reads can be missed. The
	 * unsynchronized max update is a benign race - a lost update can only
	 * under-report, never over-report. */
	unsigned long max_live_used;

	/* the fast-path counters - see struct hg_pstat above. Summed by
	 * hg_used()/hg_fragments(); never read directly. */
	struct hg_pstat pstat[HG_STAT_SLOTS];
	unsigned long size;        /* total arena size */

	/* Two sizes for two questions: span_end is the ADDRESS EXTENT of
	 * the published page grid, in bytes from hbase; committed_bytes is
	 * the COUNT of bytes backed - pre-faulted, pinned, usable. Equal
	 * until a page is punched from the middle of the span. Address tests
	 * (ownership, the page grid, the bump carve, the release primitive)
	 * use span_end; every figure that counts memory (floor, profile,
	 * statistics) uses committed_bytes. */
	unsigned long         span_end;
	unsigned long         committed_bytes;
	volatile unsigned long hoff;
	enum hg_mem_tier      tier;
	unsigned long         locked_mb;
	/* init could not mlock the arena (RLIMIT_MEMLOCK) and went on
	 * unpinned; growth then populates without pinning too instead of
	 * refusing every grow */
	unsigned int          unpinned;
	/* MAP_SHARED vs MAP_PRIVATE, as passed to hg_malloc_init(). Stored
	 * because growth policy depends on it: a pkg delta is per PROCESS,
	 * so its host-RAM cost is delta x nproc, and the ceiling check must
	 * know which multiplication to apply. */
	int                   shared;

	/*
	 * Elastic arena.
	 *
	 * committed_bytes is what is COMMITTED - pre-faulted, pinned, and
	 * published to the buddy (span_end, above, is the address extent
	 * those bytes occupy). hcap is what is RESERVED in virtual address
	 * space. The WHOLE cap is mapped once, before fork; growth only
	 * commits more of what is already mapped.
	 *
	 * That split is forced, not stylistic. mmap() and mprotect() edit ONE
	 * process's page tables, and the shm arena is shared by ~30 workers
	 * that forked before any growth happens. A delta mapped into a
	 * PROT_NONE reservation after fork is invisible to every one of them:
	 * measured, the grower reads its new page fine and a forked worker
	 * SIGSEGVs on the same address. Mapping the cap up front gives every
	 * worker one VMA over one shmem object, so a page the grower commits
	 * simply faults in wherever it is next touched.
	 *
	 * hcap == committed_bytes is a fixed arena, the default until an admin
	 * asks for more.
	 */
	unsigned long         committed_min; /* committed_bytes at init -
	                                     * shrink's floor. The admin asked
	                                     * for -m/-M of memory; growth
	                                     * above it is elastic, the base
	                                     * is not. */
	unsigned long         grow_granule; /* bytes per grow step, hps multiple */
	unsigned long         shrink_step;  /* max bytes released per drain
	                                     * tick, hps multiple, decoupled
	                                     * from the granule */
	unsigned long         grows;        /* successful commits */
	unsigned long         grow_bytes;   /* their total */
	unsigned long         grow_refused; /* refusals (cap or resource) */
	unsigned long         shrinks;      /* successful releases */
	unsigned long         shrink_bytes; /* their total */
	/*
	 * Interior release. A shrink RETRACTS the span from the
	 * top; a punch takes a whole-free page from anywhere inside it and
	 * gives the backing back without moving span_end - which is why
	 * committed_bytes had to stop being the same number as the span.
	 *
	 * repins are the other half of the promise: a punched page that is
	 * carved again must be re-mlock()ed BY THE CARVING PROCESS. mlock is
	 * not inherited across fork and is per-vma, so the puncher's lock says
	 * nothing about the carver's address space - measured, not assumed.
	 * repin_failed is the number that makes a broken pinning
	 * promise visible instead of silent.
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
	 * The attached auto-scaling POLICY - numbers copied out of
	 * a config auto_scaling_profile at attach time, never a pointer (the
	 * profile struct lives in process-local memory; this block may be
	 * shared). active==0 means no profile: growth still works up to hcap
	 * on exhaustion, shrink keeps its conservative built-in gate.
	 *
	 * The profile's worker-count fields map onto bytes: "scale up to N"
	 * is N MB, hps-rounded, and becomes the ADMIN CEILING within the
	 * -m INIT:CAP reservation (it can never raise hcap - the reservation
	 * happened before the config was even parsed, which is the whole
	 * reason the cap lives on the command line). "down to M" is the
	 * shrink floor and MAY sit below the initial size: with a profile
	 * attached, the profile is what the admin asked for, -m is just the
	 * starting point.
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
	/* consecutive quiet sweep ticks - the down-slow gate. Reset by any
	 * grow and by any tick that fails the abundance test, so a shrink
	 * needs a full uninterrupted quiet window. */
	unsigned int          shrink_quiet;
	/* the quiet window has been established: the drain releases one step
	 * per maintenance tick for as long as the gates keep holding. Cleared
	 * by any grow, a failed gate, or a tick that finds nothing to take. */
	unsigned int          draining;
	/* set once when hg_mem_release() fails structurally (e.g. a kernel
	 * without hugetlb hole punch): shrink is disabled for this arena's
	 * lifetime rather than re-attempted and re-logged every window */
	unsigned int          shrink_unsupported;
	/*
	 * One line per refusal EPISODE, not per refusal: a full arena refuses
	 * on every subsequent allocation (measured: 239k NOTICEs in 4s on the
	 * first at-cap soak), and the counter above already carries the
	 * magnitude. Set when a refusal is logged, cleared by the next
	 * successful grow.
	 */
	unsigned int          grow_refuse_said;
	/* lock instrumentation - see enum hg_lock_reason. The section in
	 * progress (lk_t0/lk_cur) sits with the lock itself, at the top. */
	struct hg_lkstat      lk_hold[HG_LK_REASONS];
	struct hg_lkstat      lk_wait[HG_LK_REASONS];
	struct hg_lkstat      lk_commit;      /* hg_mem_commit() inside a grow */
	struct hg_lkstat      lk_release;     /* hg_mem_release() in a trim or a
	                                       * punch, lock released */
	struct hg_lkstat      lk_gc;          /* gc_class() block returns */
	struct hg_lkstat      lk_cphase[HG_CP_PHASES]; /* commit, by phase */
	/* two-phase commit: a grow RESERVES [span_end, span_pending) under
	 * the lock, populates it with the lock released, then publishes it
	 * under the lock. One grow in flight at a time; a worker that exhausts
	 * meanwhile waits for the publish without the lock (lk_grow_wait). */
	unsigned long         span_pending;   /* span_end + in-flight delta */
	/* the maintenance process is alive and owns the proactive ticks */
	unsigned int          maint_active;
	int                   maint_proc;
	unsigned int          grow_inflight;  /* 0/1 */
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
	/* growth attribution: which path asked - the tick or an exhausted
	 * request */
	unsigned long         grows_proactive;
	unsigned long         grows_exhaustion;
	/*
	 * The alertable grow-blocked state, RESOURCE refusals only - an admin
	 * cap doing its job is policy, not an incident, and never latches.
	 *
	 * Latching is two-step, modelled on below_floor: the first resource
	 * refusal only records the GC-pass count it must outlive
	 * (grow_blocked_mark = gc_passes + 1); the latch arms when a refusal
	 * recurs at gc_passes >= that mark, i.e. a full GC pass ran in
	 * between and the arena STILL cannot grow - so a transient spike that
	 * one reclaim pass absorbs never alerts. Cleared by a successful
	 * grow (the resource came back) or by free space recovering above
	 * the reserve floor (the demand went away) - the design's "clear
	 * when demand falls below a lower mark", reusing the floor's own
	 * hysteresis threshold rather than inventing a second one.
	 *
	 * grow_blocked is the gauge the statistics export; grow_event_due
	 * hands the E_CORE_SHM_GROW_BLOCKED raise to the sweep timer, which
	 * runs with no arena lock held - evi_raise_event() allocates shm,
	 * and raising it here, under hb->lock, inside the allocator that
	 * just refused, would be re-entry into a full arena at best.
	 */
	unsigned int          grow_blocked;
	unsigned long         grow_blocked_mark;
	/*
	 * grow_refused at arming time. The gc_passes route above assumes GC
	 * RUNS; on the state that matters most - a full arena where nothing
	 * is reclaimable - gc_passes sits at zero forever and the latch
	 * would never arm (measured: 5M refusals, gc_passes 0, no latch).
	 * So the sweep timer is the fallback promoter: if a full sweep
	 * interval passes with the episode still armed and refusals still
	 * accumulating, it latches from there. A spike that ends before the
	 * next sweep still never alerts.
	 */
	unsigned long         grow_blocked_refuse0;
	unsigned int          grow_event_due;
	/*
	 * Bytes of the arena per ACHIEVED backing tier, indexed by
	 * enum hg_mem_tier (slot 0 unused; the enum starts at 1). hb->tier
	 * alone cannot describe a grown arena: every THP delta is a fresh
	 * negotiation with the kernel and may land on 4K next to an arena
	 * that got 2M at init. Page backing is an outcome per range, never
	 * an attribute of the arena - report it as such.
	 */
	unsigned long         tier_bytes[HG_MEM_4K + 1];

	/*
	 * buddy substrate - geometry at HG_LEAF_SHIFT above.
	 *
	 * The whole design turns "which block owns this address" into two shifts
	 * and a mask, which needs a known-aligned origin. hbase is NOT reliably
	 * that origin: all three Linux reserve paths align it (MAP_HUGETLB is
	 * aligned by the kernel, the THP tiers align explicitly at
	 * hg_malloc.c:301), but the non-Linux fallback takes a plain
	 * mmap(NULL, ...) and gets only page alignment. So page 0 starts at
	 * pbase, hbase rounded up to a huge page - equal to hbase everywhere it
	 * matters, and correct where it is not.
	 *
	 * hps is PROBED, not assumed: it is 2M on x86_64 and on arm64 with 4K
	 * base pages, but 32M with 16K pages and 512M with 64K. A hardcoded
	 * ">> 21" would mis-address every block on those machines, which is the
	 * same trap hg_hps() already exists to avoid for the mapping itself.
	 */
	unsigned long hps;         /* huge page size, probed at reserve time */
	unsigned int  hps_shift;   /* log2(hps), so page-of is a shift */
	char         *pbase;       /* page 0 - hbase rounded up to hps */
	unsigned long npages;      /* whole pages from pbase to the span end
	                            * (hbase+span_end); grows when the arena
	                            * does */
	unsigned long npages_cap;  /* whole pages to the reservation end
	                            * (hbase+hcap) - the grid's true extent.
	                            * Descriptors exist for all of these from
	                            * init, so growth publishes pages instead of
	                            * relocating metadata */

	/*
	 * Buddy state (hg_buddy.c). Every field here is written only while
	 * holding hb->lock - the buddy is entirely slow path, reached from
	 * carve_chunk() and the large tier, never from the cell fast path.
	 */
	struct hg_page     *pages;                    /* npages descriptors */
	struct hg_free_blk *bfree[HG_MAX_ORDERS + 1]; /* free list per order */
	unsigned long       nfree[HG_MAX_ORDERS + 1]; /* its length, per order */
	/*
	 * Whole-free pages, one bit per page: 1 = whole-free, backed and
	 * on offer. Not an intrusive list: one kept in address order needs a
	 * walk over cold page heads on every push, and its nodes - the first
	 * bytes of each page - are discarded by a punch, orphaning the rest of
	 * the list. Push, pop and "lowest free page" are word operations on
	 * metadata; bfree[top] is always NULL and nfree[top] is
	 * this bitmap's population count. Lower orders keep their lists.
	 */
	unsigned long      *wfree;
	unsigned long       wfree_words;
	unsigned long       buddy_free_leaves;        /* free leaves, whole arena */
	unsigned int        buddy_top;                /* whole-page order, cached */
	unsigned int        buddy_ready;              /* 0 until hg_buddy_init() */

	/*
	 * GC work queue: blocks whose every cell is in the global pool, per
	 * class. Reclaiming one means unlinking its cells from that class's
	 * free list, which is a walk - so drained blocks accumulate here and a
	 * single walk serves all of them, rather than one walk per block.
	 */
	struct hg_chunk    *drained[HG_NCLASSES];
	/* the OLDEST drained block, O(1). gc_class_run() returns from
	 * the tail (the head is the most recently drained, the one to keep if
	 * HG_GC_KEEP is ever raised); without it, finding the tail is a walk
	 * of the whole list per block returned, O(n^2) per pass. */
	struct hg_chunk    *drained_tail[HG_NCLASSES];
	unsigned int        ndrained[HG_NCLASSES];
	unsigned long       gc_blocks_returned;       /* lifetime, for stats */
	unsigned long       gc_passes;
	unsigned long       cache_flushes;            /* sweeps run */
	unsigned long       cells_flushed;            /* cells recovered from TLS */
	unsigned long       pressure_flushes;         /* self-flushes at carve exhaustion */
	unsigned long       pressure_cells;           /* cells those handed back */
	/*
	 * Corruption counters, one per kind.
	 *
	 * Every consistency check also emits LM_CRIT, but a log grep is a poor
	 * detector: the log sink may be a file that journalctl does not see,
	 * and OpenSIPS also logs unrelated failures at CRITICAL. These make
	 * corruption numeric, so it can be alerted on and graphed.
	 *
	 * They count DETECTIONS, not repairs: every site that bumps one has
	 * already decided to refuse the operation or leak the cell. A non-zero
	 * value means memory was corrupted and the allocator noticed - it is
	 * never routine.
	 */
	unsigned long       corrupt[HG_CORRUPT_KINDS];
	unsigned long       buddy_splits;             /* blocks split down an order */
	/*
	 * RUNTIME merges only.  hg_buddy_init() publishes the one page that the
	 * block header and buddy metadata straddle leaf by leaf, through the
	 * ordinary free path, so the tree is built by the normal rules - and
	 * every one of those is a coalesce.  Counted here, they would give it
	 * an arbitrary startup offset with no relation to fragmentation (an
	 * idle 8 MB pkg arena: 7 splits against 244 merges purely from init).
	 * The init total is snapshotted into buddy_merges_init and this
	 * counter is rebased to 0, so splits and merges share a zero point and
	 * their difference means something.
	 */
	unsigned long       buddy_merges;             /* blocks merged with a buddy */
	unsigned long       buddy_merges_init;        /* coalesces done building the tree */
	unsigned long       blocks_carved;            /* class blocks cut, lifetime */
	/* set while a flush walks a cache chain: pushing a cell can reclaim its
	 * block, and the next cell on the chain may live in that same block */
	unsigned int        gc_deferred;
	/*
	 * Reserve floor: free leaves below which the arena is treated as under
	 * pressure. Set once at init as a fraction of the grid. Not consumable
	 * by an expanding class in the sense that crossing it triggers a sweep
	 * BEFORE the failure, which is the only warning an operator can act on.
	 */
	unsigned long       reserve_floor;
	unsigned int        below_floor;      /* hysteresis: already reported */
	unsigned long       floor_crossings;

	unsigned char size2class[(HG_CELL_MAX / HG_ROUNDTO) + 1];
} __attribute__ ((aligned (HG_ROUNDTO)));

/*
 * Address -> page/leaf, the arithmetic the whole buddy layer rests on.
 * See the HG_LEAF_SHIFT block above.
 * pages_init() in hg_arena.c verifies these against real addresses at every
 * arena init, and refuses to start the arena if they do not round-trip.
 */

/* how many leaves tile one huge page */
static inline unsigned long hg_leaves_per_page(const struct hg_block *hb)
{
	return 1UL << (hb->hps_shift - HG_LEAF_SHIFT);
}

/* Is @p inside the page-addressable region? Everything before pbase (the
 * block header, and on a non-Linux fallback the unaligned head) is arena
 * memory but not buddy memory, so it must answer NO. */
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
 * getting this wrong for pkg is a correctness AND a performance bug.
 *
 * @flags: HG_INIT_INHERITED marks the ONE arena that outlives fork() as a
 * copy-on-write inheritance: the pre-fork (attendant) pkg arena. Every
 * child holds a private COW view of it for life - it reads module state
 * the parent parsed into it, and any write it makes there is a COW fault.
 * Such an arena must never be hugetlb-backed: a COW fault inside a
 * hugetlb VMA can only be satisfied by a huge page (no 4K fallback), and
 * a forked child holds no reservation on its parent's mapping, so with
 * the pool momentarily empty the fault is a SIGBUS - silent, at fork
 * time (measured: it is exactly how the last no-script child, TCP main,
 * died at startup on a short pool). THP has the fallback: a COW fault
 * splits the huge PMD and copies one 4K page. Per-child arenas are never
 * inherited (children do not fork) and keep the full ladder. */
#define HG_INIT_INHERITED  (1U << 0)

struct hg_block *hg_malloc_init(unsigned long size, char *name, int shared,
		const char *proc_desc, unsigned int flags);
void hg_malloc_destroy(struct hg_block *hb);

/*
 * The admin caps live in globals.h/globals.c (set by -m INIT:CAP /
 * -M INIT:CAP before any arena exists; 0 = fixed). The pkg
 * cap is PER PROCESS: every worker grows its own private arena, so the
 * host-RAM exposure is cap x nproc - hg_grow_ram_refused() applies that
 * multiplication.
 */

/*
 * Commit @delta more bytes at committed-end offset @off of the reservation
 * (both hps-rounded), populating and pinning them, and VERIFYING what
 * backing the kernel actually provided. Returns the achieved tier of the
 * delta (>= 1) or -1 with everything rolled back - a refusal, not a
 * degradation, so a worker never SIGBUSes on memory the allocator
 * half-committed. Defined in hg_malloc.c because the tier ladder and its
 * verification probes live there; called by hg_buddy_grow() under
 * hb->lock.
 */
/* Commit [off, off+delta) of the reservation: populate, pin, verify the
 * backing (and retrofit huge pages where the host needs it). Called WITHOUT
 * hb->lock held: it touches no allocator state except the locked_mb
 * total (atomically) and the once-per-episode refusal flag; the phase
 * timings come back in @cp_ns for the caller to merge under the lock. */
int hg_mem_commit(struct hg_block *hb, unsigned long off, unsigned long delta,
		unsigned long cp_ns[HG_CP_PHASES]);

/*
 * The host-RAM limb of the growth ceiling: would committing @delta more
 * bytes leave the host with less than the configured floor of available
 * memory? Returns nonzero to REFUSE. Tier 1 always passes - a hugetlb
 * mapping reserved its whole cap from the pool at map time (measured), so
 * its commits consume no new host RAM. For pkg arenas the delta is
 * multiplied by the process count first: every worker grows its own
 * private arena under the same workload, so the single-arena delta
 * understates the real cost ~30x on a gateway. Defined in hg_malloc.c
 * (it owns /proc/meminfo parsing); called by hg_buddy_grow() under
 * hb->lock.
 */
int hg_grow_ram_refused(struct hg_block *hb, unsigned long delta);

/*
 * Release the backing of [hbase+off, +len) - the shrink primitive, chosen
 * and verified by measurement on the oldest kernel tested (5.4):
 *
 *   shared (shm):  madvise(MADV_REMOVE) - punches the shmem OBJECT, so
 *                  every mapper is affected; measured to free pages even
 *                  while another process holds them VM_LOCKED, and the
 *                  range recommits cleanly afterwards. The one mechanism
 *                  that is NOT correct here is mmap(PROT_NONE|MAP_FIXED):
 *                  it rebinds only the caller's mapping and was measured
 *                  leaving other workers reading the old bytes.
 *   shared tier 1: same call; hugetlb hole punch works on 5.4 and the
 *                  pages return to HugePages_Free (measured), which is
 *                  where a static pool's shrink SHOULD put them.
 *   private (pkg): madvise(MADV_DONTNEED) - per-process arena, no
 *                  cross-process question; next touch refaults zero.
 *
 * munlock first: it releases only THIS process's VM_LOCKED accounting -
 * a range mlocked by the worker that grew it keeps its stale VmLck there
 * until exit, which is cosmetic; the punch frees the memory regardless.
 * Returns 0, or -1 with shrink_unsupported latched (nothing to retry).
 */
int hg_mem_release(struct hg_block *hb, unsigned long off, unsigned long len);
int hg_mem_repin(struct hg_block *hb, unsigned long off, unsigned long len,
                 int tier);
/* whole-free pages reachable from the top list's head, vs nfree[top] */
unsigned long hg_buddy_top_reachable(struct hg_block *hb);

/*
 * Resolve and validate the configured auto-scaling profiles, once, after
 * the config is parsed (called from init_shm_post_yyparse()). Attaches the
 * policy to the LIVE shm arena and stashes the pkg policy for the arenas
 * pt.c creates per child after fork - the pre-fork parent pkg arena
 * predates the config and stays fixed, which costs nothing (the attendant
 * barely allocates). Fails LOUDLY on a profile that names nothing, exceeds
 * the -m/-M reservation, or is attached to an arena with no growth room:
 * a policy that cannot act is a misconfiguration, not a default.
 */
int hg_autoscale_post_cfg(void);

/* re-sync per-process state after fork(): see hg_arena.c for why the
 * inherited private free-stack/bump state must be discarded, not kept or
 * donated */
void hg_malloc_child_init(struct hg_block *hb);
/* fork reset for every SHARED arena in the registry (core + module) -
 * see the definition for why coverage, not per-arena logic, is the fix */
void hg_malloc_child_init_all(void);

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

/*
 * Arena ownership tests.
 *
 * Everything hg hands out lives inside some block's hb->hbase reservation,
 * whose bounds are fixed at init. A pointer from outside it - a foreign
 * arena, a stale pointer, or a corrupted one - has a "class byte" at
 * HG_HDR(p) that is either garbage or, worse, unmapped, so simply reading it
 * faults. That is not hypothetical: it took a process down (in staging,
 * 2026-08-09, si_addr == p-32 inside hg_frag_size()).
 *
 * Two flavours, because the callers differ:
 *
 *   hg_owns()     - for code that already knows which block it is working on.
 *                   Exact, one range, no loop.
 *
 *   hg_owns_any() - for code that does NOT. hg_frag_size() is the reason this
 *                   exists: it is installed into the shared
 *                   "unsigned long (*shm_frag_size)(void *)" function pointer
 *                   next to fm_/qm_/hp_/parallel_frag_size(), so its signature
 *                   belongs to an interface we do not own and cannot grow an
 *                   hb parameter. It walks a registry of live arenas instead.
 *
 *                   This IS on the free fast path: _shm_free() calls
 *                   shm_frag_size() unconditionally on every free
 *                   (mem/shm_mem.h), so every shm_free walks the
 *                   registry. Measured anyway, three
 *                   alternating pairs at 800 cps on the bench harness:
 *                   2.747% allocator self-time without the checks, 2.807%
 *                   with, against a within-arm spread of ~0.2pp. The cost is
 *                   below the noise floor, so the registry stays a plain
 *                   linear walk - a cache here would be unmeasurable
 *                   complexity. Revisit only if HG_ARENA_REG_MAX grows.
 *
 * Both are advisory: they turn "dereference and die" into "decline and carry
 * on". They do not make a bad pointer good.
 */
static inline int hg_owns(struct hg_block *hb, void *cell_start)
{
	/* against the CAP, not the span. Both are correct - a pointer
	 * into [span_end, hcap) was never handed out, so it cannot be a live
	 * cell either way - but hcap never changes after init while span_end
	 * moves on every grow and shrink. Testing the immutable one keeps
	 * every word this fast path reads off the slow path's cache lines,
	 * and matches what the ownership registry (hg_arena_reg) already
	 * uses for the same reason. */
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
	lock_release(&hb->lock);
	if (stalled)
		hg_lock_stall_note(hb, r, held);
}

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
 * Which arena does this pointer belong to, if any?
 *
 * A child does NOT only ever free pointers from its current arena, and it is
 * not a bug when it does not. Every other allocator lets a child inherit the
 * parent's pkg arena COW, so freeing something the parent allocated pre-fork
 * is ordinary, supported behaviour - cachedb_redis and six sibling modules do
 * exactly that in child_init(), releasing the URL list mod_init() built.
 * HG_MALLOC hands each child a fresh arena instead (see pt.c), which broke
 * that assumption: those frees arrive addressed to an arena that never issued
 * them.
 *
 * So resolve the owner rather than judging by the caller's block. A pointer
 * that belongs to some other live arena is redirected there and freed
 * properly; only a pointer that belongs to NO arena is a real defect.
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

	/* the header may not be mapped at all - check before reading it.
	 * Returning 0 matches the "unknown size" answer this function already
	 * gives for an out-of-range class. */
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

/* carved-but-idle cell capacity; defined in hg_arena.c (declared here too,
 * since hg_arena.h includes THIS header and cannot be included back) */
unsigned long hg_slab_recycled(struct hg_block *hb);

/*
 * Register HG_MALLOC's SHM arena statistics with the statistics collector, so
 * the allocator's own state is scrapeable and not only reachable through the
 * hg_stats MI command.  Called from init_stats_collector(); a no-op unless
 * HG_MALLOC is the shm allocator actually in use.  Returns 0 on success.
 *
 * SHM ONLY, deliberately.  Every allocator (qm/fm/hp/f_parallel/hg) reports
 * through the same 7-field struct mem_info, and the core already turns that
 * into shmem: plus per-process pkmem: and proc_ statistics - so HG's pkg memory
 * is ALREADY visible by that generic route.  No allocator exposes
 * allocator-specific per-process statistics, and doing so would mean extending
 * the signal_pkg_status()/pkg_status[][] mechanism, since a pkg arena is
 * private memory that no other process can read.  The shm arena has no such
 * problem: there is exactly one, and it is shared.
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
/* No-op without the allocator, so callers (statistics.c) need no #ifdef of
 * their own. Building with -DHG_MALLOC removed previously failed at link with
 * an undefined reference here - the definition lives in mem/hg_arena.c, which
 * is entirely inside "#ifdef HG_MALLOC". */
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
/* These feed the shmem: and pkgmem: statistics (the SHM_GET_ and PKG_GET_
 * macros in shm_mem.h and mem.h) - a DIFFERENT path from hg_info(), so the
 * recycled
 * subtraction has to be applied here too or the published statistics still
 * report the raw carve footprint. */
static inline unsigned long hg_get_free(struct hg_block *hb)
{
	/* Headroom left to CARVE - deliberately NOT size minus the live figure.
	 * Carved-but-recycled cells are reusable only within their own size
	 * class, so counting them as free reports ~95% available right up until
	 * an allocation of a DIFFERENT size fails with "no more HG_MALLOC arena
	 * memory". hb->real_used is the carve footprint, so this is the number
	 * that actually predicts that failure.
	 *
	 * Consequence: free + real_used != size here (real_used is live), unlike
	 * q_malloc. The invariant that does hold is free + carve == size. Each
	 * figure answers a different question: used = live payload, real_used /
	 * max_used = live commitment and its peak, free = room left to carve. */
	return hb->size - hb->real_used;
}
/* The large tier's counterpart to hg_slab_recycled(): backing held from the
 * buddy grid that is not currently handed out as a fragment.  O(1), unlike the
 * slab version, because both terms are maintained under hb->lock as the
 * fragments come and go. */
static inline unsigned long hg_large_recycled(struct hg_block *hb)
{
	return hb->large_backing > hb->large_live ?
	       hb->large_backing - hb->large_live : 0;
}
static inline unsigned long hg_get_real_used(struct hg_block *hb)
{
	/* real_used is now the true carve footprint of BOTH tiers - slab blocks
	 * plus whole large chunks - so both tiers' idle-but-held bytes have to
	 * come back out to leave what is genuinely handed out. */
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
