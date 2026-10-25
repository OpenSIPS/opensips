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

/* HG_MALLOC arena structures: chunks, per-thread caches, stats slots, struct hg_block; included by hg_malloc.h, not on its own */

#ifndef HG_BLOCK_H
#define HG_BLOCK_H

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
	char _pad[HG_STAT_LINE - 4 * sizeof(long)];
} __attribute__ ((aligned (HG_STAT_LINE)));
HG_STATIC_ASSERT(sizeof(struct hg_pstat) == HG_STAT_LINE,
	"a stats slot is one cache line: resize _pad with the fields");

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
	HG_C_OVERFLOW,           /* written past the request: HG_MALLOC_DBG,
	                          * or a guard (hg_mem_check) */
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
	/* hg_mem_check on an arena without dbg: new allocations get a tail
	 * guard (hg_guard_set()). Set at creation and after the config is
	 * read; a cell's state says whether it carries one, not this flag. */
	unsigned int guard;
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
	/* set in a child for each private arena it inherited at fork (the
	 * parent's pkg arena, COW): frees of pre-fork pointers still land in it,
	 * nothing allocates from it, so no grow or GROW-BLOCKED policy and no
	 * publishing (hg_cache_flush_self()); flush, GC and shrink still run */
	int                   inherited;

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

#endif /* HG_BLOCK_H */
