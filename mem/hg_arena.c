/*
 * slab allocator with elastic arenas - cells, per-thread caches, chunk carving
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

#ifdef HG_MALLOC

#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>   /* sysconf, for the IO-pool consumer count */

#include "hg_version.h"   /* HG_MALLOC_NAME */
#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_buddy.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_arena_int.h"

#define HG_CHUNK_SMALL    (256 * 1024)  /* ceiling on chunk_max, see below */
#define HG_CHUNK_MIN      (8 * 1024)    /* floor, however tiny the arena */
/*
 * GC policy. Drained blocks beyond a class's keep (hg_gc_cycle()) are
 * returned by the maintenance tick, HG_GC_TICK_BUDGET at a time, so the
 * request path never walks the drained list - except past HG_GC_EMERGENCY
 * beyond keep, where the donate path returns a batch itself. A returned
 * block sits on the buddy's free list at its own order, so carve_chunk() can
 * take it straight back with no split or merge.
 */
#define HG_REFILL_BATCH   32             /* cells pulled from the global pool */

/*
 * Private free-cache budget, in bytes (a flat cell count would mean 16 KB in
 * class 64 and 16 MB in class 65536), turned into per-class cell counts by
 * private_caps_init(): all private caches together may hold HG_PRIVATE_PCT
 * of the arena, split between the IO-pool threads, which share one pkg arena
 * in TCP main. HG_PRIVATE_CAP bounds the small classes on a large arena.
 */
#define HG_PRIVATE_PCT        25   /* of the arena, all threads, all classes */
#define HG_PRIVATE_CONSUMERS  16   /* fallback when the count is unknown     */
/* the divisor is the IO-pool thread count (tcp_threads, else online CPUs,
 * as tcp_init_children does), clamped so few CPUs do not give one thread the
 * whole share, nor many CPUs starve each cache */
#define HG_PRIVATE_CONSUMERS_MIN  4
#define HG_PRIVATE_CONSUMERS_MAX  64
#define HG_PRIVATE_CAP        256  /* cells per class, whatever the budget  */

/*
 * Per-thread private cache state, one slot per live hg_block (shm, shm_dbg
 * and pkg may all be HG_MALLOC at once). A static array: this bookkeeping
 * must not go through pkg_malloc()/shm_malloc(), which HG may itself back.
 *
 * __thread is a correctness requirement: the fast path is lock-free only
 * because this state is private, and TCP main's IO pool threads
 * (tcp_pool_init()) reach shm_malloc() too - per-process lists would lose
 * nfree updates and hand one cell to two callers. The shared pool stays
 * process-wide, under hb->lock. A thread that exits strands its cached
 * cells; IO pool threads live as long as the process.
 */
#define HG_MAX_INSTANCES 8   /* shm, pkg, shm_dbg + module arenas */
static __thread struct hg_palloc palloc_slots[HG_MAX_INSTANCES];

/*
 * One-entry cache of the slot this thread used last, so hg_get_palloc()
 * inlines as a TLS load and one compare on every alloc and free; the walk,
 * with its stack-protector prologue, stays out of line. Trusted only while
 * pl->owner matches; hg_arena_child_init() and hg_arena_destroy() also clear
 * it outright.
 */
static __thread struct hg_palloc *hg_last;

static void slot_reset(struct hg_palloc *pl);

static struct hg_palloc *hg_palloc_lookup(struct hg_block *hb)
{
	int i, free_slot = -1;

	for (i = 0; i < HG_MAX_INSTANCES; i++) {
		if (palloc_slots[i].owner == hb) {
			hg_last = &palloc_slots[i];
			return &palloc_slots[i];
		}
		if (free_slot < 0 && !palloc_slots[i].owner)
			free_slot = i;
	}

	if (free_slot < 0) {
		LM_CRIT("more than %d live HG_MALLOC instances in one process "
			"- raise HG_MAX_INSTANCES in hg_arena.c\n", HG_MAX_INSTANCES);
		return NULL;
	}

	slot_reset(&palloc_slots[free_slot]);
	palloc_slots[free_slot].owner = hb;
	hg_last = &palloc_slots[free_slot];
	return &palloc_slots[free_slot];
}

static inline struct hg_palloc *hg_get_palloc(struct hg_block *hb)
{
	struct hg_palloc *pl = hg_last;

	if (pl && pl->owner == hb)
		return pl;
	return hg_palloc_lookup(hb);
}

/*
 * A freed cell onto this thread's private list - its header already FREE,
 * the counters already moved - donating half the list to the shared pool
 * once it is over the class's bound.
 */
static inline void cell_push_private(struct hg_block *hb,
                                     struct hg_palloc *pl, unsigned int c,
                                     char *cell_start)
{
	unsigned int i;
	void *d;

	cell_set_next(cell_start, pl->cls[c].free_head);
	pl->cls[c].free_head = cell_start;
	pl->cls[c].nfree++;

	/* over the class's bound: donate half. A class with priv_max 0 trips
	 * on every free, so it is never cached privately */
	if (pl->cls[c].nfree > hb->priv_max[c]) {
		unsigned int claimed = pl->cls[c].nfree;
		unsigned int donate  = hb->priv_donate[c];

		hg_lock_enter(hb, HG_LK_RETURN);
		for (i = 0; i < donate; i++) {
			d = pl->cls[c].free_head;
			/* priv_donate is half priv_max, so NULL here means
			 * nfree drifted above the chain's real length;
			 * walking on would be cell_next(NULL) */
			if (!d)
				break;
			if (!cell_block(hb, c, d)) {
				/* an overwritten link: the chain ends here,
				 * the rest leaks; the resync records it */
				pl->cls[c].free_head = NULL;
				pl->cls[c].nfree = i;
				break;
			}
			pl->cls[c].free_head = cell_next(d);
			pl->cls[c].nfree--;
			if (hg_gpool_push(hb, c, d) < 0) {
				/* refused: trust the chain no further */
				pl->cls[c].free_head = NULL;
				pl->cls[c].nfree = i + 1;
				break;
			}
		}
		/* the chain ran dry: resync to zero, or every later free of
		 * this class re-enters here and logs again */
		if (i < donate)
			pl->cls[c].nfree = 0;
		hg_lock_leave(hb);

		if (i < donate) {
			LM_CRIT("%s: class %u free list ran dry after %u cells "
				"but nfree claimed %u - counter resynced to 0, "
				"pool accounting drifted\n",
				hb->name, c, i, claimed);
			hg_corrupt(hb, HG_C_NFREE_UNDERFLOW);
		}
	}
}

/* hg_dbg.c's quarantine releases a cell through this; the free path here
 * keeps the inlined copy */
void hg_cell_push_private(struct hg_block *hb, struct hg_palloc *pl,
                          unsigned int c, char *cell_start)
{
	cell_push_private(hb, pl, c, cell_start);
}

/*
 * Zero a private slot but keep its quarantine mapping, emptied. The cells
 * the ring held are forgotten, never released from here: after fork they
 * are the parent's, which still holds them in its own copy of the ring.
 */
static void slot_reset(struct hg_palloc *pl)
{
	struct hg_quar *q = pl->quar;

	memset(pl, 0, sizeof *pl);
	if (q) {
		hg_quar_reset(q);
		pl->quar = q;
	}
}

unsigned int hg_quarantine_drain(struct hg_block *hb)
{
	int i;

	for (i = 0; i < HG_MAX_INSTANCES; i++)
		if (palloc_slots[i].owner == hb)
			return hg_quar_drain(hb, &palloc_slots[i]);
	return 0;
}

/* the two checks that fire where no arena pointer is in scope */
unsigned long hg_corrupt_noarena[HG_CORRUPT_KINDS];

static const char * const hg_corrupt_str[HG_CORRUPT_KINDS] = {
	"class mismatch", "double free", "free count underflow", "bad class",
	"foreign pointer", "bad buddy free", "internal inconsistency",
	"damaged header", "use after free", "overflow"
};

void hg_corrupt_abort(struct hg_block *hb, enum hg_corrupt_kind k)
{
	LM_CRIT("%s: aborting on the %s above (hg_mem_check = 2)\n",
		hb ? hb->name : HG_MALLOC_NAME, hg_corrupt_str[k]);
	abort();
}

void hg_guard_bad(struct hg_block *hb, const void *cs, unsigned long cap,
                  unsigned long size)
{
	const unsigned char *pay = (const unsigned char *)cs + HG_CELL_HDR;
	unsigned long i = size;

	if (size < HG_GUARD_END(cap)) {
		while (i < HG_GUARD_END(cap) && pay[i] == HG_GUARD_BYTE)
			i++;
		LM_CRIT("%s: %p (%lu bytes) was written past the %lu bytes asked "
			"for (byte %lu)\n", hb->name, (const void *)pay, cap, size, i);
	} else {
		LM_CRIT("%s: %p (%lu bytes) was written past its size (the size "
			"field is lost)\n", hb->name, (const void *)pay, cap);
	}
	hg_corrupt(hb, HG_C_OVERFLOW);
}

unsigned long long hg_hdr_secret;

/*
 * Flush this thread's caches in every arena it holds state for: no arena
 * argument, palloc_slots[] already lists them. MUST run on the owning
 * thread, as the caches are __thread; a worker calls it inline for itself
 * rather than sending itself an IPC job (see signal_pkg_status()).
 */
void hg_cache_flush_self(void)
{
	int i, c;
	unsigned long oom_n, oom_req;

	for (i = 0; i < HG_MAX_INSTANCES; i++) {
		struct hg_palloc *pl = &palloc_slots[i];
		struct hg_block *hb = pl->owner;
		unsigned int n = 0;

		if (!hb)
			continue;
		/* clean before the walk, so a free during it is not lost */
		hg_pstat_mine(hb)->dirty = 0;
		for (c = 0; c < HG_NCLASSES; c++) {
			unsigned int keep = hg_flush_residue(hb, pl, c);

			pl->cls[c].touched = 0;
			/* nothing to hand back: empty, or at its residue */
			if (!pl->cls[c].free_head ||
			    (keep && pl->cls[c].nfree <= keep))
				continue;
			n += hg_cache_flush_class(hb, pl, c, keep);
		}
		hg_lock_enter(hb, HG_LK_FLUSH);
		hb->cache_flushes++;
		hb->cells_flushed += n;
		oom_n = hb->shared ? 0 : hg_oom_take(hb, &oom_req);
		/* a private arena's gates tick here, once per sweep: only its
		 * owner can release its memory. The shared arena is ticked by
		 * the sweep timer alone, or every worker would tick it */
		if (!hb->shared) {
			/* latches or disarms GROW-BLOCKED, as the sweep timer
			 * does for the shared arena - not for a copy inherited
			 * at fork, which nothing allocates from */
			if (!hb->inherited)
				hg_grow_blocked_tick(hb);
			/* a private arena has no maintenance process - its
			 * owner's sweep is its policy cycle and its GC tick */
			hg_gc_cycle(hb);
			hg_gc_tick(hb, HG_GC_TICK_BUDGET);
			/* an inherited copy is never grown: frees of pre-fork
			 * pointers are all that reach it. It still gives back
			 * what those frees empty */
			if (!hb->inherited)
				hg_grow_tick(hb);
			hg_shrink_tick(hb);
#ifdef STATISTICS
			/* the live peak, sampled once per sweep - see
			 * hg_sample_live_peaks() for the shared arenas */
			(void)hg_get_real_used(hb);
#endif
			/* the process's own pkg arena only: the copy has the
			 * same name, and its figures are the parent's */
			if (!hb->inherited && !strcmp(hb->name, "pkg"))
				hg_pkg_publish(hb);
		}
		hg_lock_leave(hb);
		if (oom_n)
			hg_oom_report(hb, oom_n, oom_req);
		if (n)
			LM_DBG("%s: idle sweep returned %u cached cells\n", hb->name, n);
	}
}

/*
 * Before the process leaves for good (auto-scaling down), hand back what this
 * thread holds in the shared arenas - the private lists and the unused rest
 * of every chunk it carved - or their blocks never drain. A private (pkg)
 * arena dies with the process and is skipped. The caller holds no arena lock.
 */
void hg_cache_drain_self(void)
{
	int i, c;

	for (i = 0; i < HG_MAX_INSTANCES; i++) {
		struct hg_palloc *pl = &palloc_slots[i];
		struct hg_block *hb = pl->owner;
		unsigned int n, unused = 0;

		if (!hb || !hb->shared)
			continue;

		/* the quarantine's cells onto the private lists, checked, so
		 * the flush below hands them back with the rest */
		hg_quar_drain(hb, pl);

		hg_lock_enter(hb, HG_LK_FLUSH);
		n = hg_cache_flush_locked(hb, pl);

		/* a bump cell was never handed out: it goes to the pool as is.
		 * Reclaim waits until all are pushed, as in the flush walk */
		hb->gc_deferred = 1;
		for (c = 0; c < HG_NCLASSES; c++) {
			while (pl->cls[c].left) {
				char *cell = pl->cls[c].bump;

				pl->cls[c].bump += cell_sizes[c];
				pl->cls[c].left--;
				if (hg_gpool_push(hb, c, cell) < 0) {
					pl->cls[c].left = 0;
					break;
				}
				unused++;
			}
		}
		hb->gc_deferred = 0;
		/* each class keeps its demand-sized reserve of drained blocks
		 * (gc_keep) and returns the rest, as after a flush */
		for (c = 0; c < HG_NCLASSES; c++)
			if (hb->ndrained[c] > hb->gc_keep[c])
				hb->gc_inline_blocks +=
					hg_gc_class(hb, c, hb->gc_keep[c], UINT_MAX);

		hb->cache_flushes++;
		hb->cells_flushed += n + unused;
		hg_lock_leave(hb);

		if (n || unused)
			LM_DBG("%s: leaving for good, returned %u cached and %u unused "
				"cells\n", hb->name, n, unused);
	}
}

/*
 * Bump the atomic offset within the block's own reservation. No fallback to
 * another allocator: exhaustion is a hard, loud failure (raise -m/-M).
 */
void *hg_chunk_backing(struct hg_block *hb, unsigned long size)
{
	unsigned long asz = (size + 63) & ~63UL;   /* keep 64-aligned */
	unsigned long off;

	/*
	 * Init only: hg_buddy_init() publishes everything above hoff as free,
	 * so a later bump would hand the same bytes to two owners. The one
	 * caller is the buddy carving its own metadata, before it is ready.
	 */
	if (hb->buddy_ready) {
		LM_CRIT("%s: bump carve of %lu bytes after the buddy owns the "
			"arena - refusing, this would double-allocate\n",
			hb->name, size);
		hg_corrupt(hb, HG_C_INTERNAL);
		return NULL;
	}

	off = __atomic_fetch_add(&hb->hoff, asz, __ATOMIC_RELAXED);

	if (off + asz <= hb->span_end)
		return hb->hbase + off;

	/* exhausted: an undo would race other bumpers, so hoff stays past the
	 * end and later bumps fail too; only the tail slack is lost */
	return NULL;
}

/*
 * As hg_chunk_backing(), but @align-aligned (a power of two), for the buddy's
 * whole pages. Bumps by the exact padded amount under a CAS, recomputing the
 * pad if another bumper wins, rather than wasting align-1 bytes. A failed
 * reservation never commits, so it does not consume the tail. The address is
 * aligned, not the offset: hbase may be unaligned on the non-Linux path.
 */
void *hg_backing_aligned(struct hg_block *hb, unsigned long size,
                         unsigned long align)
{
	unsigned long asz = (size + 63) & ~63UL;
	unsigned long cur, aligned_off, newoff;

	if (align < 64)
		align = 64;
	if (align & (align - 1)) {
		LM_ERR("%s: alignment %lu is not a power of two\n", hb->name, align);
		return NULL;
	}

	cur = __atomic_load_n(&hb->hoff, __ATOMIC_RELAXED);
	do {
		unsigned long addr = (unsigned long)hb->hbase + cur;

		aligned_off = cur + ((~addr + 1) & (align - 1));
		newoff = aligned_off + asz;
		if (newoff > hb->span_end)
			return NULL;
	} while (!__atomic_compare_exchange_n(&hb->hoff, &cur, newoff, 1,
	                                      __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	return hb->hbase + aligned_off;
}

/* carve a new chunk for class @c - hb->lock must be held, and may be dropped
 * and re-taken (hg_buddy_grow_unlocks()). The class byte of every cell's
 * hidden header is stamped here, before the chunk is reachable by anyone -
 * immutable from birth. */
static int carve_chunk(struct hg_block *hb, int c, struct hg_palloc *pl)
{
	struct hg_chunk *ch;
	unsigned int size = chunk_size_for(hb, c), i;
	char *cells;
	int ord;

	/* a chunk is a buddy block, so the size rounds up to an order: no
	 * waste, the bigger block just holds more cells */
	ord = hg_buddy_order_for(hb, size);
	if (ord < 0) {
		LM_ERR("%s: class %d wants a %u byte chunk, larger than the %lu byte "
			"page the buddy tops out at\n", hb->name, c, size,
			(unsigned long)hb->hps);
		return -1;
	}
	size = (unsigned int)(HG_LEAF_SIZE << ord);
	ch = hg_buddy_alloc(hb, (unsigned int)ord);
	/*
	 * No block of this order: before growing, flush this thread's caches so
	 * the GC can return blocks whose last cells sat there (the owner is the
	 * one asking: no IPC). Not before every carve, which would empty the
	 * cache whenever a class needs a block. Retried only if one came back.
	 */
	if (!ch) {
		unsigned long returned = hb->gc_blocks_returned;
		unsigned int n = hg_cache_flush_locked(hb, pl);

		hb->pressure_flushes++;
		hb->pressure_cells += n;
		if (hb->gc_blocks_returned != returned)
			ch = hg_buddy_alloc(hb, (unsigned int)ord);
	}
	/* exhaustion triggers a grow; one retry, as freshly published pages
	 * are whole and satisfy this order. The reserve floor is checked in
	 * the buddy layer (hg_reserve_floor_check()) */
	if (!ch && hg_buddy_grow_unlocks(hb, size, HG_GROW_EXHAUSTION) == 0)
		ch = hg_buddy_alloc(hb, (unsigned int)ord);

	if (!ch) {
		if (hg_oom_first(hb, size))
			LM_ERR("%s: no more HG_MALLOC arena memory for a %u byte "
				"chunk (class %d, order %d) - increase the arena size; "
				"further failures are summarised every 30 s\n",
				hb->name, size, c, ord);
		return -1;
	}

	/* the buddy's free-list linkage is left in the block's first bytes:
	 * every field is set here, none assumed zero */
	ch->in_gpool = 0;
	ch->flags = 0;
	ch->order = (unsigned int)ord;
	ch->free_head = NULL;
	ch->grade = HG_GRADE_NONE;
	ch->fnext = NULL;
	ch->fprev = NULL;
	ch->cls = c;
	ch->cell_size = cell_sizes[c];
	ch->cells = (size - sizeof(struct hg_chunk)) / cell_sizes[c];
	if (ch->cells > HG_CHUNK_MAX_CELLS) {
		/* cannot happen with the current class table (126 is the most);
		 * if it does, cap the block rather than overrun the map */
		LM_WARN("%s: class %d block would hold %u cells, capping at %lu - "
			"the per-block map is %lu bits\n", hb->name, c, ch->cells,
			(unsigned long)HG_CHUNK_MAX_CELLS, (unsigned long)HG_CHUNK_MAX_CELLS);
		ch->cells = HG_CHUNK_MAX_CELLS;
	}
	memset(ch->gfree, 0, sizeof ch->gfree);

	cells = (char *)ch + sizeof(struct hg_chunk);
	for (i = 0; i < ch->cells; i++) {
		struct hg_cell_hdr *h =
			HG_CELL_AT(cells + (unsigned long)i * cell_sizes[c]);

		hg_hdr_set(h, c, HG_ST_FRESH);
#ifdef DBG_MALLOC
		/* the block may be recycled: a never-used cell would carry old
		 * bytes as file/func, which hg_status_dbg dereferences */
		h->file = NULL;
		h->func = NULL;
		h->line = 0;
#endif
		hg_san_take(hb, h, cell_sizes[c] - HG_CELL_HDR);
	}

	ch->next = hb->chunks;
	ch->prev = NULL;
	if (ch->next)
		ch->next->prev = ch;
	hb->chunks = ch;
	hb->nchunks++;
	hb->slab_capacity += (unsigned long)ch->cells * ch->cell_size;
	hb->blocks_carved++;
	hb->carves_cycle[c]++;          /* this cycle's demand */
	hb->real_used += size;
	if (hb->real_used > hb->max_real_used)
		hb->max_real_used = hb->real_used;

	/* the whole chunk goes to the carving thread's bump region */
	pl->cls[c].bump = cells;
	pl->cls[c].left = ch->cells;

	LM_DBG("%s class %d: new %u byte chunk, %u cells of %u\n",
		hb->name, c, size, ch->cells, cell_sizes[c]);
	return 0;
}

/*
 * How many threads the private-cache share is divided between. tcp_threads
 * is 0 until the config is parsed, so at shm/pkg init this is the online-CPU
 * count; hg_private_caps_retune() re-runs it once the config is known.
 */
static unsigned int hg_io_consumers(void)
{
	int n = tcp_threads;

	if (n <= 0) {
		long cpus = sysconf(_SC_NPROCESSORS_ONLN);

		n = (cpus > 0) ? (int)cpus : HG_PRIVATE_CONSUMERS;
	}
	if (n < HG_PRIVATE_CONSUMERS_MIN)
		n = HG_PRIVATE_CONSUMERS_MIN;
	if (n > HG_PRIVATE_CONSUMERS_MAX)
		n = HG_PRIVATE_CONSUMERS_MAX;
	return (unsigned int)n;
}

/*
 * Turn the byte budget into per-class cell counts. A class whose single cell
 * exceeds a thread's per-class share gets priv_max 0: never cached privately,
 * every free goes to the shared pool (rare allocations, large memory).
 * priv_donate is half the cap, so a chain whose length matches nfree always
 * satisfies the donation loop.
 */
static void private_caps_init(struct hg_block *hb)
{
	unsigned int consumers = hg_io_consumers();
	unsigned long per_thread = (unsigned long)hb->size / 100 * HG_PRIVATE_PCT
	                           / consumers;
	unsigned long per_class  = per_thread / HG_NCLASSES;
	unsigned int c;

	for (c = 0; c < HG_NCLASSES; c++) {
		unsigned long n = per_class / cell_sizes[c];

		if (n > HG_PRIVATE_CAP)
			n = HG_PRIVATE_CAP;
		hb->priv_max[c]    = (unsigned int)n;
		hb->priv_donate[c] = (unsigned int)(n / 2);
		if (hb->priv_donate[c] == 0)
			hb->priv_donate[c] = 1;
	}

	LM_DBG("%s: private cache budget %lu B/thread over %u consumers (%lu B/class): "
		"class %u caches %u cells, class %u caches %u\n",
		hb->name, per_thread, consumers, per_class,
		cell_sizes[0], hb->priv_max[0],
		cell_sizes[HG_NCLASSES - 1], hb->priv_max[HG_NCLASSES - 1]);
}

/* re-derive the private caps once the config (tcp_threads) is known.
 * Runs pre-fork from hg_autoscale_post_cfg(), so children inherit the result.
 * The caps are set once and read on the fast path; this is the last write. */
void hg_private_caps_retune(struct hg_block *hb)
{
	if (hb)
		private_caps_init(hb);
}

/*
 * Lay out the page grid the buddy addresses through, and prove the
 * arithmetic on real addresses: an address resolves to its block by two
 * shifts and a mask (HG_LEAF_SHIFT, hg_malloc.h), and a wrong grid would
 * silently hand out another block's descriptor. Returns 0 when the grid is
 * usable, -1 when the arithmetic does not hold.
 */
static int pages_init(struct hg_block *hb)
{
	unsigned long hps = hb->hps, off;
	unsigned int shift = 0;
	const char *end;
	int i;

	if (!hps || (hps & (hps - 1))) {
		LM_ERR("%s: huge page size %lu is not a power of two - cannot "
			"build the page grid\n", hb->name, hps);
		return -1;
	}
	while ((1UL << shift) < hps)
		shift++;
	hb->hps_shift = shift;

	/* anchor the shift to the probed size: the probes below derive page
	 * indices from hps_shift, so a wrong shift would pass them all */
	if ((1UL << shift) != hps) {
		LM_ERR("%s: page shift %u describes %lu bytes, but the probed huge "
			"page is %lu\n", hb->name, shift, 1UL << shift, hps);
		return -1;
	}

	if (shift <= HG_LEAF_SHIFT) {
		LM_ERR("%s: huge page size %lu is not larger than the %lu byte "
			"buddy leaf\n", hb->name, hps, HG_LEAF_SIZE);
		return -1;
	}

	/* page 0 is the first aligned address at or after hbase: hbase itself
	 * on Linux; the non-Linux plain mmap() loses the unaligned head */
	hb->pbase = (char *)(((unsigned long)hb->hbase + hps - 1) & ~(hps - 1));
	end = hb->hbase + hb->span_end;
	hb->npages = (unsigned long)(end - hb->pbase) >> shift;
	/* the grid's full extent runs to the cap - descriptors for every page
	 * that could ever exist are laid out at init (hg_buddy_init), so a
	 * grow publishes pages instead of relocating metadata */
	hb->npages_cap = (unsigned long)(hb->hbase + hb->hcap - hb->pbase)
	                 >> shift;
	if (hb->npages_cap < hb->npages)    /* hcap==span_end or a tiny arena */
		hb->npages_cap = hb->npages;

	if (hb->pbase != hb->hbase)
		LM_INFO("%s: reservation base %p is not %lu-aligned, losing %lu "
			"bytes of head to align the page grid\n", hb->name,
			hb->hbase, hps, (unsigned long)(hb->pbase - hb->hbase));

	if (hb->npages == 0) {
		/* legitimate (a tiny -M on 512 MB arm64 pages): no buddy page,
		 * but the chunk allocator is unaffected, so not fatal */
		LM_INFO("%s: arena of %lu bytes holds no whole %lu byte page - "
			"buddy reclaim will be inactive\n",
			hb->name, hb->committed_bytes, hps);
		return 0;
	}

	/* the grid must not run past the reservation: an npages one too large
	 * keeps every internal relation intact and shows only here */
	if (hb->pbase + (hb->npages << shift) > end) {
		LM_ERR("%s: page grid of %lu pages ends at %p, past the %lu byte "
			"reservation ending at %p\n", hb->name, hb->npages,
			hb->pbase + (hb->npages << shift), hb->span_end, end);
		return -1;
	}

	/* --- the proof. Real addresses, spanning the whole grid. --- */
	for (i = 0; i < 5; i++) {
		unsigned long pg, leaf, want_pg;
		const char *probe, *pbase_of;

		switch (i) {
		case 0: want_pg = 0;               off = 0;                 break;
		case 1: want_pg = 0;               off = HG_LEAF_SIZE;      break;
		case 2: want_pg = hb->npages / 2;  off = hps / 2;           break;
		case 3: want_pg = hb->npages - 1;  off = 0;                 break;
		default:want_pg = hb->npages - 1;  off = hps - 1;           break;
		}
		probe = hb->pbase + (want_pg << shift) + off;

		if (!hg_in_pages(hb, probe)) {
			LM_ERR("%s: addressing self-test %d: %p should be inside the "
				"%lu-page grid at %p but is not\n",
				hb->name, i, probe, hb->npages, hb->pbase);
			return -1;
		}
		pg = hg_page_of(hb, probe);
		if (pg != want_pg) {
			LM_ERR("%s: addressing self-test %d: %p resolved to page %lu, "
				"expected %lu\n", hb->name, i, probe, pg, want_pg);
			return -1;
		}
		pbase_of = hg_page_base(hb, probe);
		if ((unsigned long)pbase_of & (hps - 1)) {
			LM_ERR("%s: addressing self-test %d: page base %p is not "
				"%lu-aligned\n", hb->name, i, pbase_of, hps);
			return -1;
		}
		if (probe - pbase_of != (long)off) {
			LM_ERR("%s: addressing self-test %d: %p is %ld bytes into its "
				"page, expected %lu\n", hb->name, i, probe,
				(long)(probe - pbase_of), off);
			return -1;
		}
		leaf = hg_leaf_of(hb, probe);
		if (leaf != off >> HG_LEAF_SHIFT ||
		    leaf >= hg_leaves_per_page(hb)) {
			LM_ERR("%s: addressing self-test %d: %p is leaf %lu, expected "
				"%lu of %lu\n", hb->name, i, probe, leaf,
				off >> HG_LEAF_SHIFT, hg_leaves_per_page(hb));
			return -1;
		}
	}

	/* the negative side: the unaligned head and the byte past the end must
	 * not classify as page memory, or a stray pointer resolves to a block
	 * that does not exist */
	if (hb->pbase != hb->hbase && hg_in_pages(hb, hb->hbase)) {
		LM_ERR("%s: addressing self-test: unaligned head %p classifies as "
			"page memory\n", hb->name, hb->hbase);
		return -1;
	}
	if (hg_in_pages(hb, hb->pbase + (hb->npages << shift))) {
		LM_ERR("%s: addressing self-test: the byte past the last page "
			"classifies as page memory\n", hb->name);
		return -1;
	}

	LM_DBG("%s page grid: %lu pages of %lu B at %p (shift %u), %lu leaves "
		"of %lu B per page; addressing verified\n",
		hb->name, hb->npages, hps, hb->pbase, shift,
		hg_leaves_per_page(hb), HG_LEAF_SIZE);
	return 0;
}

int hg_arena_init(struct hg_block *hb, unsigned long hdr_size)
{
	unsigned int idx, c, needed;

	if (pages_init(hb) < 0)
		return -1;

	/*
	 * Skip the block header and start on a leaf boundary: a buddy block is
	 * aligned to its own size, a multiple of the leaf, so an aligned first
	 * carve aligns them all and the address lookup can be a mask.
	 */
	hb->hoff = (hdr_size + HG_LEAF_SIZE - 1) & ~(HG_LEAF_SIZE - 1);
	if (hb->pbase != hb->hbase) {
		/* the grid does not start at hbase: the first carve must clear
		 * the discarded head too */
		unsigned long skip = (unsigned long)(hb->pbase - hb->hbase);

		if (hb->hoff < skip)
			hb->hoff = skip;
	}

	/* see chunk_size_for(): /64 keeps all 21 classes plus the large tier
	 * within a third of a small arena, even in the worst case */
	hb->thread_slot_next = HG_STAT_SLOTS - 1;   /* threads count down */
	hb->chunk_max = hb->size / 64;
	if (hb->chunk_max > HG_CHUNK_SMALL)
		hb->chunk_max = HG_CHUNK_SMALL;
	if (hb->chunk_max < HG_CHUNK_MIN)
		hb->chunk_max = HG_CHUNK_MIN;

	private_caps_init(hb);

	/* size -> class LUT: needed = requested payload + hidden header */
	for (idx = 0; idx <= HG_CELL_MAX / HG_ROUNDTO; idx++) {
		needed = idx * HG_ROUNDTO + HG_CELL_HDR;
		for (c = 0; c < HG_NCLASSES; c++)
			if (cell_sizes[c] >= needed)
				break;
		hb->size2class[idx] = (unsigned char)c;   /* HG_NCLASSES = oversize */
	}

	LM_DBG("%s arena ready: %d classes, %u B to %u B cells (header=%zu B)\n",
		hb->name, HG_NCLASSES, cell_sizes[0], cell_sizes[HG_NCLASSES-1],
		HG_CELL_HDR);

	/* last: it bump-carves its metadata and reserves everything below the
	 * resulting hoff; hg_chunk_backing() refuses once buddy_ready is set */
	if (hg_buddy_init(hb) < 0)
		return -1;
	return 0;
}

void hg_arena_destroy(struct hg_block *hb)
{
	int i;

	/* everything lives in one mapping (hb->hbase), unmapped whole by
	 * hg_malloc_destroy(); only this thread's palloc slot is dropped */
	for (i = 0; i < HG_MAX_INSTANCES; i++)
		if (palloc_slots[i].owner == hb)
			slot_reset(&palloc_slots[i]);
	hg_last = NULL;

	hg_large_destroy(hb);
}

void hg_arena_child_init(struct hg_block *hb)
{
	int i;

	/*
	 * After fork the child holds a COW copy of the parent's private state
	 * for @hb: the same bump pointer and free-list cells. It MUST NOT keep
	 * them (two processes would hand out the same cell) nor donate them
	 * (every child would push the same cells onto the shared pool).
	 * They are the parent's; the child starts empty. Only the calling
	 * thread's slots exist to clear, as fork() clones just that thread.
	 */
	for (i = 0; i < HG_MAX_INSTANCES; i++)
		if (palloc_slots[i].owner == hb)
			slot_reset(&palloc_slots[i]);
	hg_last = NULL;
}

unsigned int hg_cell_total_size(unsigned char cls)
{
	if (cls >= HG_NCLASSES)
		return 0;
	return cell_sizes[cls];
}

/*
 * The head of this thread's private list must be one of the arena's cells
 * before its link is followed: a scribbled link would otherwise send the
 * next pop to an arbitrary address. A bad head drops the whole list (the
 * cells on it leak) - nothing beyond it can be trusted.
 */
static inline int private_head_ok(struct hg_block *hb, struct hg_palloc *pl,
                                  int c)
{
	char *cs = pl->cls[c].free_head;

	if (hg_owns(hb, cs))
		return 1;
	LM_CRIT("%s: class %d private list leads to %p, outside the arena - "
		"dropping the list\n", hb->name, c, cs);
	hg_corrupt(hb, HG_C_FOREIGN_PTR);
	pl->cls[c].free_head = NULL;
	pl->cls[c].nfree = 0;
	return 0;
}

#ifdef DBG_MALLOC
void *hg_cell_alloc(struct hg_block *hb, unsigned long size,
                    const char *file, const char *func, unsigned int line)
#else
void *hg_cell_alloc(struct hg_block *hb, unsigned long size)
#endif
{
	struct hg_palloc *pl;
	char *cell_start, *payload;
	unsigned int got;
	unsigned long want = size;
	/* read once: the flag may change under a running allocation */
	unsigned int guard = hb->guard;
	int c;

	if (hb->dbg)
		want += HG_DBG_TAIL;     /* room for the DBG trailer */
	else if (guard)
		want += HG_GUARD_ROOM;   /* at least one guard byte */
	if (want + HG_CELL_HDR > HG_CELL_MAX) {
#ifdef DBG_MALLOC
		return hg_large_alloc(hb, size, file, func, line);
#else
		return hg_large_alloc(hb, size);
#endif
	}
	c = hb->size2class[(want + HG_ROUNDTO - 1) / HG_ROUNDTO];
	if (c >= HG_NCLASSES)
		return NULL;

	pl = hg_get_palloc(hb);
	if (!pl)
		return NULL;

again:
	/* fast paths: no locks, no shared lines */
	cell_start = pl->cls[c].free_head;
	if (cell_start) {
		if (!private_head_ok(hb, pl, c))
			goto again;
		pl->cls[c].free_head = cell_next(cell_start);
		pl->cls[c].nfree--;
		goto found;
	}
	if (pl->cls[c].left) {
		cell_start = pl->cls[c].bump;
		pl->cls[c].bump += cell_sizes[c];
		pl->cls[c].left--;
		goto found;
	}

	/* slow path: refill from the global pool, else carve a chunk */
	hg_lock_enter(hb, HG_LK_REFILL);
	for (got = 0; got < HG_REFILL_BATCH; got++) {
		cell_start = hg_gpool_pop(hb, c);
		if (!cell_start)
			break;
		cell_set_next(cell_start, pl->cls[c].free_head);
		pl->cls[c].free_head = cell_start;
		pl->cls[c].nfree++;
	}
	/* no pressure flush here (it is in carve_chunk()): class c's own chain
	 * is empty, and other classes' cells cannot feed a retry */
	if (!got && carve_chunk(hb, c, pl) < 0) {
		hg_lock_leave(hb);
		/* the quarantine never fails an allocation: let it go and look
		 * again - once, as the drain leaves it empty */
		if (hb->dbg && hg_quar_drain(hb, pl))
			goto again;
		return NULL;
	}
	hg_lock_leave(hb);

	cell_start = pl->cls[c].free_head;
	if (cell_start) {
		if (!private_head_ok(hb, pl, c))
			goto again;
		pl->cls[c].free_head = cell_next(cell_start);
		pl->cls[c].nfree--;
		goto found;
	}
	cell_start = pl->cls[c].bump;
	pl->cls[c].bump += cell_sizes[c];
	pl->cls[c].left--;

found:
	/*
	 * Only a FRESH or FREE cell with an intact header is handed out. A LIVE
	 * one was freed twice unseen (two processes at once), a damaged header
	 * is a scribbled list or a neighbour's overflow: leak it and take
	 * another, or one cell would go to two callers.
	 */
	{
		union hg_hdr_w w;
		unsigned short base;
		int st = hg_hdr_read(cell_start, &w, &base);

		if ((st != HG_ST_FRESH && st != HG_ST_FREE) || w.f.cls != c) {
			LM_CRIT("%s: class %d cell %p about to be handed out is %s - "
				"dropping it\n", hb->name, c, cell_start,
				st < 0 ? "damaged" : hg_st_live(st) ? "still in use" :
				"of another class");
			hg_corrupt(hb, st < 0 ? HG_C_HEADER : hg_st_live(st) ?
				HG_C_DOUBLE_FREE : HG_C_CLASS_MISMATCH);
			goto again;
		}
		if (guard) {
			hg_san_open(hb, cell_start, cell_sizes[c] - HG_CELL_HDR);
			hg_guard_set(cell_start, base, cell_sizes[c] - HG_CELL_HDR,
				size);
		}
		hg_hdr_set_base(cell_start, c, guard ? HG_ST_LIVE_G : HG_ST_LIVE,
			base);
	}
	payload = cell_start + HG_CELL_HDR;
	pl->cls[c].touched = 1;
	if (hb->dbg) {
		hg_san_open(hb, cell_start, cell_sizes[c] - HG_CELL_HDR);
		hg_dbg_tail_set(cell_start, cell_sizes[c] - HG_CELL_HDR, size);
	}
	hg_san_give(hb, cell_start, cell_sizes[c] - HG_CELL_HDR, size);
#ifdef DBG_MALLOC
	HG_CELL_AT(cell_start)->file = file;
	HG_CELL_AT(cell_start)->func = func;
	HG_CELL_AT(cell_start)->line = line;
#endif
	/* per-process slot: no lock, no shared cache line (see hg_pstat) */
	{
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used += cell_sizes[c] - HG_CELL_HDR;
		ps->fragments++;
		ps->cell_live += cell_sizes[c];
	}
	return payload;
}

/*
 * What every free checks before it trusts the header: intact, and LIVE.
 * Returns the class, or -1 when the free must be refused - counted and
 * logged here, and the cell left alone (leaked).
 */
static inline int free_check(struct hg_block *hb, char *cell_start, void *p,
                             union hg_hdr_w *w, unsigned short *base)
{
	int st = hg_hdr_read(cell_start, w, base);

	if (st == HG_ST_LIVE || st == HG_ST_LIVE_G) {
		unsigned int c = w->f.cls;
		unsigned long cap = 0, asked;

		/* a write past the request is reported and the free goes on: it
		 * stayed in the cell, or the neighbour's checksum catches it. A
		 * sanitizer gets the whole payload back first (hg_san.h); a
		 * large fragment's stays open while free */
		if (hb->dbg || HG_SAN_PRIVATE(hb) || st == HG_ST_LIVE_G) {
			if (c == HG_LARGE_MARKER)
				cap = ((struct hg_lfrag *)(void *)
					(cell_start - HG_LFRAG_HDR))->size - HG_CELL_HDR;
			else if (c < HG_NCLASSES)
				cap = cell_sizes[c] - HG_CELL_HDR;
		}
		if (cap) {
			hg_san_open(hb, cell_start, cap);
			if (hb->dbg)
				hg_dbg_tail_check(hb, cell_start, cap);
			else if (st == HG_ST_LIVE_G &&
			    !hg_guard_ok(cell_start, *base, cap, &asked))
				hg_guard_bad(hb, cell_start, cap, asked);
		}
		return c;
	}
	if (st < 0) {
		LM_CRIT("%s: %p has a damaged header - overwritten by a "
			"neighbour's overflow, or not a pointer this arena handed "
			"out - leaking it\n", hb->name, p);
		hg_corrupt(hb, HG_C_HEADER);
	} else {
		LM_CRIT("%s: %p is already free - double free, ignoring the "
			"second free\n", hb->name, p);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
	}
	return -1;
}

/*
 * The free's LIVE -> FREE (see hg_hdr_claim_free()). 0 when the header no
 * longer said LIVE: another free of the same cell, in another process or
 * thread, passed free_check() at the same moment and won - counted and
 * logged here, and this free does nothing.
 */
static inline int free_claim(struct hg_block *hb, char *cell_start,
                             unsigned int c, void *p, union hg_hdr_w *w,
                             unsigned short base)
{
	if (hg_hdr_claim_free(cell_start, w->w, c, base))
		return 1;
	LM_CRIT("%s: %p was freed twice at the same moment - ignoring the "
		"second free\n", hb->name, p);
	hg_corrupt(hb, HG_C_DOUBLE_FREE);
	return 0;
}

#ifdef DBG_MALLOC
void hg_cell_free(struct hg_block *hb, void *p, const char *file,
                  const char *func, unsigned int line)
#else
void hg_cell_free(struct hg_block *hb, void *p)
#endif
{
	struct hg_palloc *pl;
	char *cell_start;
	unsigned int c;
	int ci;
	union hg_hdr_w hw;
	unsigned short hbase;

	if (!p)
		return;

	cell_start = HG_HDR(p);

	/* before the class byte is even read: an out-of-arena pointer may
	 * not be mapped at all, and reading it would fault here rather
	 * than merely corrupt a pool. See hg_owns(). */
	if (!hg_owns(hb, cell_start)) {
		struct hg_block *owner = hg_owner(cell_start);

		if (!owner) {
			LM_CRIT("%s: %p belongs to no live arena - refusing to "
				"free it\n", hb->name, p);
			hg_corrupt(hb, HG_C_FOREIGN_PTR);
			return;
		}

		/*
		 * Another hg arena issued it - normal after fork, when modules
		 * free what the parent allocated pre-fork. Straight to the
		 * owner's global pool: this process never allocates from that
		 * arena again, so caching the cell would strand it.
		 */
		hg_xarena_frees++;
		hg_cell_free_global(owner, p);
		return;
	}

	/* no private slot: the shared pool takes it, checks and all - looked
	 * up first, so the checks below run once per free */
	pl = hg_get_palloc(hb);
	if (!pl) {
		hg_cell_free_global(hb, p);
		return;
	}

	ci = free_check(hb, cell_start, p, &hw, &hbase);
	if (ci < 0)
		return;
	c = (unsigned int)ci;

	if (c == HG_LARGE_MARKER) {
		hg_large_free(hb, (struct hg_lfrag *)(void *)(cell_start - HG_LFRAG_HDR));
		return;
	}

	if (c >= HG_NCLASSES) {
		/* a header that checks but names no class: a bug, not a
		 * scribble - leak the cell rather than corrupt the pools */
		LM_CRIT("%s: cell %p carries invalid class %u - leaking it\n",
			hb->name, p, c);
		hg_corrupt(hb, HG_C_BAD_CLASS);
		return;
	}

	if (!free_claim(hb, cell_start, c, p, &hw, hbase))
		return;

	{
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used -= cell_sizes[c] - HG_CELL_HDR;
		ps->fragments--;
		ps->cell_live -= cell_sizes[c];
		ps->dirty = 1;   /* this cache now holds something to sweep */
	}

#ifdef DBG_MALLOC
	if (hb->dbg) {
		/* the free's site replaces the allocation's: a write after the
		 * free is reported against it */
		HG_CELL_AT(cell_start)->file = file;
		HG_CELL_AT(cell_start)->func = func;
		HG_CELL_AT(cell_start)->line = line;
	}
#endif
	if (hb->dbg) {
		hg_quar_put(hb, pl, c, cell_start);
	} else {
		hg_san_take(hb, cell_start, cell_sizes[c] - HG_CELL_HDR);
		cell_push_private(hb, pl, c, cell_start);
	}
}

void hg_cell_free_global(struct hg_block *hb, void *p)
{
	char *cell_start;
	unsigned int c;
	int pushed, ci;
	union hg_hdr_w hw;
	unsigned short hbase;

	if (!p)
		return;

	cell_start = HG_HDR(p);
	if (!hg_owns(hb, cell_start)) {
		struct hg_block *owner = hg_owner(cell_start);

		/* see the matching comment in hg_cell_free() - reached both
		 * directly and by that function's redirect, so the redirect
		 * must not loop: it only ever passes the resolved owner. */
		if (!owner) {
			LM_CRIT("%s: %p belongs to no live arena - refusing to "
				"free it\n", hb->name, p);
			hg_corrupt(hb, HG_C_FOREIGN_PTR);
			return;
		}
		if (owner != hb) {
			hg_xarena_frees++;
			hb = owner;
		}
	}
	ci = free_check(hb, cell_start, p, &hw, &hbase);
	if (ci < 0)
		return;
	c = (unsigned int)ci;
	if (c == HG_LARGE_MARKER) {
		hg_large_free(hb, (struct hg_lfrag *)(void *)(cell_start - HG_LFRAG_HDR));
		return;
	}
	if (c >= HG_NCLASSES) {
		LM_CRIT("%s: cell %p carries invalid class %u - leaking it\n",
			hb->name, p, c);
		hg_corrupt(hb, HG_C_BAD_CLASS);
		return;
	}
	/* the counters move here: hg_cell_free() delegates without touching
	 * them. A push the pool refuses (a double free, counted there) freed
	 * nothing and must not move them */
	if (!free_claim(hb, cell_start, c, p, &hw, hbase))
		return;
	hg_san_take(hb, cell_start, cell_sizes[c] - HG_CELL_HDR);
	hg_lock_enter(hb, HG_LK_RETURN);
	pushed = hg_gpool_push(hb, c, cell_start);
	hg_lock_leave(hb);

	if (pushed == 0) {
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used -= cell_sizes[c] - HG_CELL_HDR;
		ps->fragments--;
		ps->cell_live -= cell_sizes[c];
	}
}

/*
 * The set of this thread's free cells for the live-cell walker, open
 * addressed in one plain calloc() (diagnostics must not depend on the
 * allocator they examine). The walker infers liveness by absence, so a
 * failed per-cell insert would report a free cell as live; with one table,
 * a failed allocation just skips the walk. Linear probing at load <= 0.5, so
 * a probe always ends on an empty slot.
 */
struct hg_free_set {
	void         **slots;    /* NULL = empty; power-of-two count */
	unsigned int   nslots;
	unsigned int   nused;
	unsigned int   overflow; /* inserts refused - must stay 0, see below */
};

static inline unsigned int hg_ptr_hash(const void *p, unsigned int nbuckets)
{
	unsigned long v = (unsigned long)p;

	v ^= v >> 16;
	v *= 2654435761UL;   /* Knuth multiplicative hash */
	v ^= v >> 13;
	return (unsigned int)(v & (nbuckets - 1));
}

static int hg_free_set_init(struct hg_free_set *set, unsigned int expected)
{
	unsigned int n = 64;

	while (n < expected * 2 && n < (1U << 24))
		n <<= 1;
	set->slots = calloc(n, sizeof(*set->slots));
	if (!set->slots)
		return -1;
	set->nslots   = n;
	set->nused    = 0;
	set->overflow = 0;
	return 0;
}

static void hg_free_set_add(struct hg_free_set *set, void *addr)
{
	unsigned int h = hg_ptr_hash(addr, set->nslots);

	/* refuse rather than probe forever: sized from a count under the same
	 * hb->lock, the table fills only if a list is longer than counted, and
	 * the caller then reports the set incomplete */
	if (set->nused * 2 >= set->nslots) {
		set->overflow++;
		return;
	}
	while (set->slots[h]) {
		if (set->slots[h] == addr)
			return;
		h = (h + 1) & (set->nslots - 1);
	}
	set->slots[h] = addr;
	set->nused++;
}

static int hg_free_set_has(struct hg_free_set *set, void *addr)
{
	unsigned int h = hg_ptr_hash(addr, set->nslots);

	while (set->slots[h]) {
		if (set->slots[h] == addr)
			return 1;
		h = (h + 1) & (set->nslots - 1);
	}
	return 0;
}

static void hg_free_set_destroy(struct hg_free_set *set)
{
	free(set->slots);
	set->slots = NULL;
}

/* exact number of free cells the set must hold, so the table is sized once
 * and never grown */
static unsigned int hg_free_set_count(struct hg_block *hb)
{
	struct hg_palloc *pl = hg_get_palloc(hb);
	struct hg_chunk *ch;
	unsigned int n = 0;
	void *cur;
	int c;

	/* the pool's free cells are read from each block's map by the
	 * walker itself; only this thread's private cells need the set */
	(void)ch;
	if (pl)
		for (c = 0; c < HG_NCLASSES; c++)
			for (cur = pl->cls[c].free_head; cur; cur = cell_next(cur))
				n++;
	return n;
}

static void hg_free_set_populate(struct hg_block *hb, struct hg_free_set *set)
{
	int c;
	void *cur;
	struct hg_chunk *ch;
	struct hg_palloc *pl = hg_get_palloc(hb);

	/* this thread's private chains only, as in hg_free_set_count() */
	(void)ch;
	for (c = 0; c < HG_NCLASSES; c++) {
		if (pl)
			for (cur = pl->cls[c].free_head; cur; cur = cell_next(cur))
				hg_free_set_add(set, cur);
	}
}

/*
 * Live-cell enumeration (mem-group stats_core_init, hg_status_dbg's dump):
 * a small cell is reported when its block's map does not have it in the
 * pool, its header says LIVE and it is not on this thread's private lists.
 */
void hg_arena_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx)
{
	struct hg_free_set set;
	struct hg_chunk *ch;
	unsigned int i, total_free = 0;
	char *cell_start;

	hg_lock_enter(hb, HG_LK_STATS);

	/* counted exactly, under the same hb->lock as the fill, so the table
	 * is sized once and the count cannot go stale */
	total_free = hg_free_set_count(hb);

	if (hg_free_set_init(&set, total_free) < 0) {
		hg_lock_leave(hb);
		LM_ERR("%s: out of memory building the live-cell diagnostic "
			"set - skipping the walk\n", hb->name);
		return;
	}
	hg_free_set_populate(hb, &set);

	/* must not happen (sized from a count under this lock); if it does,
	 * the walk may report free cells as live, so say so */
	if (set.overflow)
		LM_CRIT("%s: live-cell set overflowed by %u - the dump below "
			"may report free cells as live\n", hb->name, set.overflow);

	for (ch = hb->chunks; ch; ch = ch->next) {
		for (i = 0; i < ch->cells; i++) {
			cell_start = (char *)ch + sizeof(struct hg_chunk) +
				(unsigned long)i * ch->cell_size;
			/* pool-free by the block's own map, exact and free of
			 * any allocation; private-free by the set */
			if (map_test(ch, (long)i))
				continue;
			/* and only a LIVE header: cells in another
			 * process's cache, or never handed out, are not */
			if (!hg_st_live(hg_hdr_state(cell_start)))
				continue;
			if (!hg_free_set_has(&set, cell_start))
				cb(cell_start + HG_CELL_HDR, ctx);
		}
	}

	hg_free_set_destroy(&set);
	hg_lock_leave(hb);
}

#endif /* HG_MALLOC, statistics included */
