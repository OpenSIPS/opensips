/*
 * slab allocator with elastic arenas - arena structures
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

/* included by hg_malloc.h, not on its own */

#ifndef HG_BLOCK_H
#define HG_BLOCK_H

struct hg_large_chunk;

/* the large tier's boundary-tag fragment header (hg_large.c), visible here so
 * every site finds it at HG_HDR(p) - sizeof(struct hg_lfrag) */
struct hg_lfrag {
	unsigned long size;         /* bytes after this header: tag + payload */
	struct hg_lfrag *nxt_free;
	struct hg_lfrag **prev;     /* free-list back-link, NULL if live */
	struct hg_lfrag *pf;        /* physical previous frag in this chunk,
	                              * NULL if first frag of its chunk */
} __attribute__ ((aligned (HG_ROUNDTO)));

#define HG_LFRAG_HDR_SIZE (sizeof(struct hg_lfrag))

/* fullness grades: enough to find a "fullest partial", few enough that a block
 * rarely changes grade and the source-block scan is eight pointer tests */
#define HG_GRADES         8
#define HG_GRADE_NONE     0xffffffffu   /* no free cells, on no list */
#define HG_GRADE_DRAINED  0xfffffffeu   /* every cell free, on drained[] */

#define HG_CHUNK_DRAINED    (1u << 0)
/* selected by this GC pass; its cells are being unlinked right now */
#define HG_CHUNK_RECLAIMING (1u << 1)

#define HG_CHUNK_MAP_WORDS 2
#define HG_CHUNK_MAP_BITS  64               /* bits per map word, every ABI */
#define HG_CHUNK_MAX_CELLS (HG_CHUNK_MAP_WORDS * HG_CHUNK_MAP_BITS)

/* a chunk: one buddy block of one cell class, its header in the block's first
 * bytes rather than a side array (that would cost ~20 MB on a 5 GB arena) */
struct hg_chunk {
	/* walked by hg_arena_walk_live(): a reclaimed block MUST be unlinked */
	struct hg_chunk *next;
	struct hg_chunk *prev;
	unsigned int cls;         /* immutable */
	unsigned int cell_size;   /* total slot size, header included */
	unsigned int cells;

	/* cells in the GLOBAL pool (under hb->lock); == cells is the GC's cue.
	 * A thread-cached cell counts as live, so a reclaim is never early */
	unsigned int in_gpool;
	unsigned int flags;       /* HG_CHUNK_DRAINED / _RECLAIMING */
	unsigned int order;       /* buddy order, so the GC can hand it back */

	void        *free_head;
	unsigned int grade;       /* HG_GRADE_NONE / _DRAINED, or 0..HG_GRADES-1 */

	/* links on bucket[cls][grade], or on drained[cls] */
	struct hg_chunk *fnext;
	struct hg_chunk *fprev;

	/* a bit per cell in the GLOBAL pool: makes a double free there exact,
	 * vets each pool link and marks pool-free cells for the live walker */
	uint64_t gfree[HG_CHUNK_MAP_WORDS];
} __attribute__ ((aligned (64)));

HG_STATIC_ASSERT(sizeof(struct hg_chunk) <= 128,
	"struct hg_chunk must not exceed two cache lines");

/* the buddy leaf, its minimum order: 8 KB is a deliberate floor, as the leaf
 * array is one byte per leaf (1 KB leaves would make it 8x larger) */
#define HG_LEAF_SHIFT  13
#define HG_LEAF_SIZE   (1UL << HG_LEAF_SHIFT)

/* ceiling for the fixed per-order arrays; an arena has hps_shift -
 * HG_LEAF_SHIFT orders (8 on 2 MB pages, 16 on arm64's 512 MB) */
#define HG_MAX_ORDERS  24

struct hg_page;
struct hg_free_blk;
struct hg_quar;

/* a thread's cache state in ONE hg_block: one per thread per arena */
struct hg_palloc {
	struct hg_block *owner;
	/* the HG_MALLOC_DBG quarantine, mapped on the first free; else NULL */
	struct hg_quar *quar;
	struct {
		char *bump;            /* next unused cell in own chunk */
		unsigned int left;
		void *free_head;       /* private LIFO free stack */
		unsigned int nfree;
		/* set on allocation, cleared by the sweep flush: an unused
		 * class gives every cell back, a used one keeps a residue */
		unsigned int touched;
	} cls[HG_NCLASSES];
};

/* per-process (and per-thread) slots for the fast-path stats, summed by
 * readers; SIGNED, as a cell freed by another process takes a slot below 0 */
#define HG_STAT_SLOTS     256
#define HG_STAT_LINE      64

struct hg_pstat {
	long used;       /* payload bytes handed out by this process */
	long fragments;  /* live cells handed out by this process */
	/* set by this process's free fast path, cleared when its flush starts:
	 * the sweep dispatcher skips a clean slot */
	long dirty;
	/* cell-slot bytes (header + payload + class round-up) handed out, so
	 * hg_slab_recycled() can find idle carved capacity, as "used" cannot */
	long cell_live;
	char _pad[HG_STAT_LINE - 4 * sizeof(long)];
} __attribute__ ((aligned (HG_STAT_LINE)));
HG_STATIC_ASSERT(sizeof(struct hg_pstat) == HG_STAT_LINE,
	"a stats slot is one cache line: resize _pad with the fields");

/* corruption kinds, grouped by what an operator would do, not by the site
 * that found it, so a recurrence reads as one repeated event */
enum hg_corrupt_kind {
	HG_C_CLASS_MISMATCH = 0, /* cell resolves to a block of another class */
	HG_C_DOUBLE_FREE,        /* block already all free, or buddy re-freed */
	HG_C_NFREE_UNDERFLOW,    /* free list shorter than nfree claims */
	HG_C_BAD_CLASS,          /* cell header has an impossible class id */
	HG_C_FOREIGN_PTR,        /* pointer belongs to no live arena */
	HG_C_BUDDY_BAD_FREE,     /* outside the grid, misaligned, wrong order */
	HG_C_INTERNAL,           /* API misuse, or size accounting out of step
	                          * (span_check): a bug here, not in a peer */
	HG_C_HEADER,             /* cell header fails its checksum: a
	                          * neighbour's overflow, or not a cell */
	HG_C_USE_AFTER_FREE,     /* HG_MALLOC_DBG: freed cell written to */
	HG_C_OVERFLOW,           /* written past the request: HG_MALLOC_DBG,
	                          * or a guard (hg_mem_check) */
	HG_CORRUPT_KINDS
};

/* for the two checks that fire where no arena pointer exists */
extern unsigned long hg_corrupt_noarena[HG_CORRUPT_KINDS];


/* lock hold/wait instrumentation, written UNDER the lock it measures (wait
 * after the acquire, hold before the release), so it needs no atomics */
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

/* nanoseconds of CLOCK_MONOTONIC: 64-bit on every ABI, as an unsigned long
 * of them wraps every 4.29 s on a 32-bit build */
typedef unsigned long long hg_ns_t;

struct hg_lkstat {
	unsigned long n;
	hg_ns_t total_ns;
	hg_ns_t max_ns;
	unsigned long stalls;              /* holds >= hg_lock_stall_us */
	unsigned long hist[HG_LK_BUCKETS];
};

/* phases of hg_mem_commit() on the THP path, timed apart so a slow grow
 * names its slow part (VERIFY: the backing check, a meminfo delta) */
enum hg_commit_phase {
	HG_CP_MEMINFO = 0, HG_CP_ADVISE, HG_CP_MLOCK, HG_CP_VERIFY, HG_CP_COLLAPSE,
	HG_CP_PHASES
};

enum hg_grow_why {
	HG_GROW_EXHAUSTION = 0,   /* a request found nothing to carve */
	HG_GROW_PROACTIVE         /* the profile's tick, ahead of demand */
};

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

/* parked whole private chains of one class, see hg_xfer.c */
#define HG_XFER_SLOTS 64
struct hg_xfer {
	void *head[HG_XFER_SLOTS];
	unsigned int len[HG_XFER_SLOTS];
	unsigned int n;
	unsigned int cap;     /* chains this class may park, 0 = off */
	unsigned int busy;    /* puts and gets since the last GC cycle */
};

struct hg_block {
	/* what the LOCK-FREE fast path reads: set once (backed_fast rarely),
	 * on lines the slow path never writes, so they stay shared-clean */
	char *name;
	/* all of hcap, mapped pre-fork (pkg: per process); growth only commits:
	 * a later map would SIGSEGV in workers. hb itself lives at its start */
	char                 *hbase;
	unsigned long         hcap;   /* VA reserved, >= span_end; immutable */
	/* hg_backed()'s fast test: all below it is backed; span_end, or 0
	 * while a page is punched or a grow, trim or punch runs unlocked */
	unsigned long         backed_fast;
	/* per-THREAD private cache bound in CELLS (private_caps_init()); 0:
	 * one cell exceeds a thread's share, so the shared pool serves it */
	unsigned int priv_max[HG_NCLASSES];
	unsigned int priv_donate[HG_NCLASSES];
	unsigned int chunk_max;
	/* HG_MALLOC_DBG checks on, see hg_dbg.h */
	unsigned int dbg;
	/* hg_mem_check without dbg: new allocations get a tail guard; a cell's
	 * state, not this flag, says whether it carries one */
	unsigned int guard;
	/* bytes of freed cells one thread may hold in quarantine, when dbg */
	unsigned long quar_bytes;

	/* the slow-path lock, alone on its line so fast-path lines stay clean;
	 * lk_t0/lk_cur: the section in progress, written by the holder alone */
	gen_lock_t    lock __attribute__ ((aligned (64)));
	hg_ns_t lk_t0;
	int           lk_cur;

	/* from here on: written under hb->lock, except the atomic fields,
	 * pstat[] (the fast path's) and corrupt[] */
	struct hg_chunk *chunks __attribute__ ((aligned (64)));
	unsigned int nchunks;
	/* sum of cells * cell_size over the chunks, kept at carve and GC so
	 * hg_slab_recycled() is O(1), not a chunk walk under hb->lock */
	unsigned long slab_capacity;
	/* shared free cells as BLOCKS graded by fullness: a refill scans from
	 * bucket[c][0], the fullest partial: emptier ones drain for the GC */
	struct hg_chunk *bucket[HG_NCLASSES][HG_GRADES];
	unsigned int gpool_n[HG_NCLASSES];   /* free cells of the class, total */
	struct hg_xfer xfer[HG_NCLASSES];

	struct hg_large_chunk *large_chunks;
	struct hg_lfrag *large_free;
	/* charged to real_used per whole chunk; backing minus live,
	 * hg_large_recycled(), is subtracted again for the live figure */
	unsigned long large_backing;
	unsigned long large_live;
	/* chunk churn: a chunk returns to the buddy when its last fragment is
	 * freed, so carved far ahead of returned means alloc/free thrash */
	unsigned long large_chunks_carved;
	unsigned long large_chunks_returned;

	/* bytes carved into chunks, slab and large: the arena's footprint */
	unsigned long real_used;
	unsigned long max_real_used;
	/* peak of hg_get_real_used()'s LIVE figure (max_real_used is the CARVE
	 * peak); sampled, unsynchronized - it can only under-report */
	unsigned long max_live_used;

	struct hg_pstat pstat[HG_STAT_SLOTS];
	unsigned int thread_slot_next;   /* next thread slot, counts down */
	unsigned long size;        /* the span's size, moved with span_end */

	/* span_end is the ADDRESS extent (address tests), committed_bytes the
	 * COUNT backed (memory figures); they differ once a page is punched */
	unsigned long         span_end;
	unsigned long         committed_bytes;
	volatile unsigned long hoff;
	enum hg_mem_tier      tier;
	unsigned long         locked_mb;
	/* init could not mlock the arena (RLIMIT_MEMLOCK) and went on
	 * unpinned; growth then populates unpinned too instead of refusing */
	unsigned int          unpinned;
	/* MAP_SHARED, else MAP_PRIVATE (pkg), as passed to hg_malloc_init() */
	int                   shared;
	/* a child's copy of the parent's pkg arena (COW): only pre-fork
	 * pointers are freed into it, so no grow, policy or publishing */
	int                   inherited;

	unsigned long         committed_min; /* shrink's floor: the -m/-M size,
	                                     * or profile's scale-down size */
	unsigned long         grow_granule; /* bytes per grow step, hps multiple */
	unsigned long         shrink_step;  /* max bytes released per drain
	                                     * tick, hps multiple */
	unsigned long         grows;        /* successful commits */
	unsigned long         grow_bytes;
	unsigned long         grow_refused; /* refusals (cap or resource) */
	/* allocation-failure throttle: an episode's first failure is logged,
	 * the rest summarised at the sweep (hg_oom_take()) */
	unsigned long         oom_fails;
	unsigned long         oom_fails_said;
	unsigned long         oom_max_req;
	unsigned int          oom_episode;
	unsigned long         shrinks;      /* successful releases */
	unsigned long         shrink_bytes;
	unsigned long         punches;       /* interior pages released */
	unsigned long         punch_bytes;
	unsigned long         punched_pages; /* gauge: currently punched */
	unsigned long         repins;        /* punched pages carved again */
	unsigned long         repin_bytes;
	unsigned long         repin_failed;  /* ...and could not be re-pinned */
	unsigned int          repin_said;    /* one warning per episode */
	unsigned long         hole_regrows;  /* grow events served from holes */
	unsigned long         top_carves;    /* whole pages by hg_buddy_alloc */
	/* the auto-scaling profile, copied (it is process-local, this block may
	 * be shared); down_bytes MAY sit below the initial size */
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
	/* consecutive quiet sweep ticks, the down-slow gate; any grow or tick
	 * failing the abundance test resets it */
	unsigned int          shrink_quiet;
	/* quiet window established: drain one step per maintenance tick until a
	 * grow, a failed gate or a tick that finds nothing to take */
	unsigned int          draining;
	/* set once when hg_mem_release() fails structurally (e.g. no hugetlb
	 * hole punch): shrink is off for this arena's lifetime */
	unsigned int          shrink_unsupported;
	/* one log line per refusal EPISODE (a full arena refuses every
	 * allocation); cleared by the next successful grow */
	unsigned int          grow_refuse_said;
	/* the last grow refusal's cause, kept after its episode; the mlock
	 * cause is classified once per episode (it reads /proc) */
	unsigned int          grow_refuse_why;
	unsigned int          grow_refuse_mlock;
	struct hg_lkstat      lk_hold[HG_LK_REASONS];
	struct hg_lkstat      lk_wait[HG_LK_REASONS];
	struct hg_lkstat      lk_commit;      /* hg_mem_commit() inside a grow */
	struct hg_lkstat      lk_release;     /* hg_mem_release() in a trim or a
	                                       * punch, lock released */
	struct hg_lkstat      lk_gc;          /* gc_class() block returns */
	struct hg_lkstat      lk_cphase[HG_CP_PHASES]; /* commit, by phase */
	unsigned long         span_pending;   /* span_end + in-flight delta */
	/* the maintenance process is alive and owns the proactive ticks */
	unsigned int          maint_active;
	int                   maint_proc;
	unsigned int          grow_inflight;  /* 0/1 */
	/* bumped by every grow that published pages: what a waiting grower
	 * compares, as a trim or punch also holds grow_inflight */
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
	unsigned long         grows_proactive;
	unsigned long         grows_exhaustion;
	/* deferred collapse (tier 3), see hg_page.want_collapse */
	unsigned int          collapse_pending;
	unsigned long         collapse_wanting;       /* pages still flagged */
	unsigned long         collapse_scan;          /* next page to look at */
	unsigned long         collapse_deferred;      /* pages handed over */
	unsigned long         collapsed_late;         /* pages it collapsed */
	unsigned long         collapse_retries;       /* failed tries, retried */
	unsigned long         collapse_late_failed;   /* pages left on 4 KB */
	unsigned int          collapse_fail_said;     /* first failure logged */
	/* latched when a RESOURCE refusal recurs after a full GC pass; the
	 * sweep timer raises the event, as evi_raise_event() allocates shm */
	unsigned int          grow_blocked;
	unsigned long         grow_blocked_mark;
	/* grow_refused at arming: with nothing to reclaim gc_passes stalls, so
	 * a sweep interval of rising refusals latches it instead */
	unsigned long         grow_blocked_refuse0;
	unsigned int          grow_event_due;
	/* bytes per ACHIEVED tier (slot 0 unused): hb->tier cannot describe a
	 * grown arena, as a THP delta may land on 4K next to 2M from init */
	unsigned long         tier_bytes[HG_MEM_4K + 1];

	/* buddy grid: hps is the probed huge page (2M, 32M, 512M on arm64) or
	 * 256 KB in small mode, so never hardcode ">> 21" */
	unsigned long hps;
	unsigned int  hps_shift;
	char         *pbase;       /* page 0 - hbase rounded up to hps */
	unsigned long npages;      /* whole pages from pbase to the span end
	                            * (hbase+span_end); grows with the arena */
	unsigned long npages_cap;  /* whole pages to hbase+hcap; descriptors
	                            * for all exist from init, never moved */

	struct hg_page     *pages;
	struct hg_free_blk *bfree[HG_MAX_ORDERS + 1];
	unsigned long       nfree[HG_MAX_ORDERS + 1];
	/* whole-free pages as a bitmap: a list walks cold page heads and loses
	 * nodes to punches; bfree[top] is NULL and nfree[top] the popcount */
	unsigned long      *wfree;
	unsigned long       wfree_words;
	unsigned long       buddy_free_leaves;
	unsigned int        buddy_top;                /* whole-page order, cached */
	unsigned int        buddy_ready;              /* 0 until hg_buddy_init() */

	/* GC work queue, per class: blocks whose every cell is in the global
	 * pool, accumulated so one free-list walk reclaims them all */
	struct hg_chunk    *drained[HG_NCLASSES];
	/* the oldest drained: the GC returns from the tail, keeps the head */
	struct hg_chunk    *drained_tail[HG_NCLASSES];
	unsigned int        ndrained[HG_NCLASSES];
	unsigned long       gc_blocks_returned;
	unsigned long       gc_passes;
	/* drained blocks of class c kept for gpool_pop() (hg_gc_cycle()) */
	unsigned int        gc_keep[HG_NCLASSES];
	unsigned int        carves_cycle[HG_NCLASSES];
	unsigned int        gc_next_class;       /* tick's round-robin start */
	/* blocks returned by the maintenance tick (budgeted) vs. inline by a
	 * trigger (pressure, sweep flush, the donate path's emergency) */
	unsigned long       gc_tick_blocks;
	unsigned long       gc_inline_blocks;
	unsigned long       sweeps_skipped;        /* clean, not dispatched */
	unsigned long       cache_flushes;            /* sweeps run */
	unsigned long       cells_flushed;            /* cells recovered from TLS */
	unsigned long       pressure_flushes;         /* self-flushes at carve exhaustion */
	unsigned long       pressure_cells;           /* cells those handed back */
	unsigned long       xfer_puts, xfer_gets;     /* chains parked, taken */
	unsigned long       xfer_full;                /* donations it refused */
	unsigned long       xfer_drained;             /* cells sent back to blocks */
	/* corruption DETECTIONS per kind (the site refused or leaked the cell),
	 * alongside LM_CRIT; non-zero is never routine */
	unsigned long       corrupt[HG_CORRUPT_KINDS];
	unsigned long       buddy_splits;
	/* RUNTIME merges only: hg_buddy_init()'s coalesces go to
	 * buddy_merges_init, so splits and merges share a zero point */
	unsigned long       buddy_merges;
	unsigned long       buddy_merges_init;
	unsigned long       blocks_carved;            /* class blocks cut, lifetime */
	/* set while a flush walks a cache chain: pushing a cell can reclaim its
	 * block, and the next cell on the chain may live in that same block */
	unsigned int        gc_deferred;
	/* free leaves below which the arena is under pressure:
	 * crossing it sweeps BEFORE an allocation fails, and warns */
	unsigned long       reserve_floor;
	unsigned int        below_floor;      /* hysteresis: already reported */
	unsigned int        floor_warned;     /* this crossing was a WARN */
	unsigned long       floor_crossings;

	unsigned char size2class[(HG_CELL_MAX / HG_ROUNDTO) + 1];
} __attribute__ ((aligned (HG_ROUNDTO)));

#endif /* HG_BLOCK_H */
