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

#include <unistd.h>
#include <sys/syscall.h>
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
#include "hg_xfer.h"

#define HG_CHUNK_SMALL    (256 * 1024)  /* ceiling on chunk_max */
#define HG_CHUNK_MIN      (8 * 1024)    /* floor, however tiny the arena */
#define HG_REFILL_BATCH   32

/* private free-cache budget in bytes, not cells (classes span 64..65472),
 * split over the threads sharing an arena by private_caps_init() */
#define HG_PRIVATE_PCT        25   /* of the arena, all threads, all classes */
#define HG_PRIVATE_CONSUMERS  16   /* a shared arena's sharers until counted */
#define HG_PRIVATE_CAP        256  /* cells per class, whatever the budget  */

/* static, as HG may back pkg/shm; __thread, as the fast path is lock-free and
 * IO-pool threads allocate */
#define HG_MAX_INSTANCES 8   /* shm, pkg, shm_dbg + module arenas */
static __thread struct hg_palloc palloc_slots[HG_MAX_INSTANCES];

/* the two slots this thread used last (pkg and shm calls interleave), so
 * hg_get_palloc() inlines to TLS loads and compares; trusted only while
 * pl->owner matches */
static __thread struct hg_palloc *hg_last, *hg_prev;

static void slot_reset(struct hg_palloc *pl);

static struct hg_palloc *hg_palloc_lookup(struct hg_block *hb)
{
	int i, free_slot = -1;

	for (i = 0; i < HG_MAX_INSTANCES; i++) {
		if (palloc_slots[i].owner == hb) {
			hg_prev = hg_last;
			hg_last = &palloc_slots[i];
			return &palloc_slots[i];
		}
		if (free_slot < 0 && !palloc_slots[i].owner)
			free_slot = i;
	}

	if (free_slot < 0) {
		static __thread int said;

		if (!said++)
			LM_CRIT("more than %d live HG_MALLOC instances in one "
				"process - raise HG_MAX_INSTANCES in hg_arena.c; small "
				"allocations fall back to the large tier\n",
				HG_MAX_INSTANCES);
		return NULL;
	}

	slot_reset(&palloc_slots[free_slot]);
	palloc_slots[free_slot].owner = hb;
#ifdef __OS_linux
	/* a library thread (not the process's main one) needs its own stats
	 * slot: it would update the process's without atomics */
	if (hg_pstat_slot < 0 && (pid_t)syscall(SYS_gettid) != getpid())
		hg_thread_stats_init();
#endif
	/* a new slot holds nothing: no flush owed for crossings before it */
	palloc_slots[free_slot].sweep_seen =
		__atomic_load_n(&hb->sweep_gen, __ATOMIC_RELAXED);
	hg_prev = hg_last;
	hg_last = &palloc_slots[free_slot];
	return &palloc_slots[free_slot];
}

static inline struct hg_palloc *hg_get_palloc(struct hg_block *hb)
{
	struct hg_palloc *pl = hg_last;

	if (pl && pl->owner == hb)
		return pl;
	pl = hg_prev;
	if (pl && pl->owner == hb) {
		hg_prev = hg_last;
		hg_last = pl;
		return pl;
	}
	return hg_palloc_lookup(hb);
}

/* a private-list cell, as private_head_ok() takes it: FREE or FRESH, of
 * class @c, in backed arena memory */
static inline int cell_link_ok(struct hg_block *hb, int c, char *cs)
{
	union hg_hdr_w w;
	unsigned short base;
	int st;

	if (!hg_owns(hb, cs) || !hg_backed(hb, cs))
		return 0;
	st = hg_hdr_read(cs, &w, &base);
	return (st == HG_ST_FRESH || st == HG_ST_FREE) && w.f.cls == c;
}

/* the first @donate cells to the transfer cache as one chain, its tail found
 * outside hb->lock; 0 = not parked, and the list is as it was */
static inline int xfer_donate(struct hg_block *hb, struct hg_palloc *pl,
                              unsigned int c, unsigned int donate)
{
	void *head = pl->cls[c].free_head, *tail = head, *rest;
	unsigned int i;
	int ok;

	/* a bad hop is left to the locked path, which checks every cell and
	 * drops the list */
	for (i = 1; i < donate && tail; i++) {
		tail = cell_next(tail);
		if (tail && !cell_link_ok(hb, c, tail))
			return 0;
	}
	if (!tail)
		return 0;
	rest = cell_next(tail);
	cell_set_next(tail, NULL);
	hg_lock_enter(hb, HG_LK_RETURN);
	ok = hg_xfer_put(hb, c, head, donate);
	hg_lock_leave(hb);
	if (!ok) {
		cell_set_next(tail, rest);
		return 0;
	}
	pl->cls[c].free_head = rest;
	pl->cls[c].nfree -= donate;
	return 1;
}

/* a freed cell (header already FREE, counters moved) onto this thread's list;
 * over the class's bound, half the list goes to the shared pool */
static inline void cell_push_private(struct hg_block *hb,
                                     struct hg_palloc *pl, unsigned int c,
                                     char *cell_start)
{
	unsigned int i;
	void *d;

	cell_set_next(cell_start, pl->cls[c].free_head);
	pl->cls[c].free_head = cell_start;
	pl->cls[c].nfree++;

	if (pl->cls[c].nfree > hb->priv_max[c]) {
		unsigned int claimed, donate;
		int refused = 0;

		/* a requested sweep flushes this list too: nothing to donate */
		if (hg_sweep_poll())
			return;
		claimed = pl->cls[c].nfree;
		donate = hb->priv_donate[c];
		if (hb->xfer[c].cap && xfer_donate(hb, pl, c, donate))
			return;
		hg_lock_enter(hb, HG_LK_RETURN);
		for (i = 0; i < donate; i++) {
			d = pl->cls[c].free_head;
			/* NULL: nfree drifted above the chain's real length */
			if (!d)
				break;
			/* refused (already logged and counted): the rest of the
			 * chain is not trusted, it leaks */
			if (!cell_block(hb, c, d)) {
				pl->cls[c].free_head = NULL;
				pl->cls[c].nfree = 0;
				refused = 1;
				break;
			}
			pl->cls[c].free_head = cell_next(d);
			pl->cls[c].nfree--;
			if (hg_gpool_push(hb, c, d) < 0) {
				pl->cls[c].free_head = NULL;
				pl->cls[c].nfree = 0;
				refused = 1;
				break;
			}
		}
		/* the chain ran dry: resync to zero, or every later free of
		 * this class re-enters here and logs again */
		if (i < donate)
			pl->cls[c].nfree = 0;
		hg_lock_leave(hb);

		if (i < donate && !refused) {
			LM_CRIT("%s: class %u free list ran dry after %u cells "
				"but nfree claimed %u - counter resynced to 0, "
				"pool accounting drifted\n",
				hb->name, c, i, claimed);
			hg_corrupt(hb, HG_C_NFREE_UNDERFLOW);
		}
	}
}

/* out-of-line copy for hg_dbg.c; the free path keeps the inlined one */
void hg_cell_push_private(struct hg_block *hb, struct hg_palloc *pl,
                          unsigned int c, char *cell_start)
{
	cell_push_private(hb, pl, c, cell_start);
}

/* zero a private slot but keep its quarantine mapping, emptied: after fork the
 * ring's cells are the parent's, so they are forgotten, never released */
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
		/* clean before the walk, so a free during it is not lost; not
		 * a shared slot: its other writer may hold cells unseen here */
		if (!hg_pstat_shared)
			__atomic_store_n(&hg_pstat_mine(hb)->dirty, 0,
				__ATOMIC_RELAXED);
		for (c = 0; c < HG_NCLASSES; c++) {
			unsigned int keep = hg_flush_residue(hb, pl, c);
			int idle = !pl->cls[c].touched;

			pl->cls[c].touched = 0;
			/* an idle class's never-used bump cells, else its block
			 * stays pinned until this process exits */
			if (idle && pl->cls[c].left) {
				hg_lock_enter(hb, HG_LK_FLUSH);
				n += hg_cache_bump_return(hb, pl, c);
				hg_lock_leave(hb);
			}
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
		 * owner can release its memory (shm ticks on the timer) */
		if (!hb->shared) {
			if (!hb->inherited)
				hg_grow_blocked_tick(hb);
			hg_gc_cycle(hb);
			hg_gc_tick(hb, HG_GC_TICK_BUDGET);
			/* an inherited copy still gives back what pre-fork frees
			 * empty */
			if (!hb->inherited)
				hg_grow_tick(hb);
			hg_shrink_tick(hb);
#ifdef STATISTICS
			/* the live peak, sampled once per sweep - see
			 * hg_sample_live_peaks() for the shared arenas */
			(void)hg_live_sample(hb);
#endif
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

void hg_cache_drain_self(void)
{
	int i;

	for (i = 0; i < HG_MAX_INSTANCES; i++) {
		struct hg_palloc *pl = &palloc_slots[i];
		struct hg_block *hb = pl->owner;
		unsigned int n;

		if (!hb || !hb->shared)
			continue;

		/* the quarantine's cells onto the private lists, checked, so
		 * the flush below hands them back with the rest */
		hg_quar_drain(hb, pl);

		/* cached and never-used (bump) cells alike, in batches */
		n = hg_cache_flush_all(hb, pl, -1);

		hg_lock_enter(hb, HG_LK_FLUSH);
		hb->cache_flushes++;
		hb->cells_flushed += n;
		hg_lock_leave(hb);

		if (n)
			LM_DBG("%s: leaving for good, returned %u cells\n", hb->name, n);
	}
}

void *hg_chunk_backing(struct hg_block *hb, unsigned long size)
{
	unsigned long asz = (size + 63) & ~63UL;
	unsigned long off;

	/* init only: hg_buddy_init() publishes everything above hoff as free,
	 * so a later bump would hand the same bytes to two owners */
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

/* as hg_chunk_backing(), @align-aligned (a power of two); CAS, so a failure
 * does not consume the tail. Aligns the address: hbase may be unaligned */
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

#define HG_CARVE_GROW_TRIES 4
/* parked chains drained per hold before the lock is let go for a moment */
#define HG_RECLAIM_CHAINS   4
#define HG_RECLAIM_BLOCKS   64

static inline void lock_breathe(struct hg_block *hb)
{
	enum hg_lock_reason r = (enum hg_lock_reason)hb->lk_cur;

	hg_lock_leave(hb);
	hg_lock_enter(hb, r);
}

/* class @c's drained blocks back to the buddy, a batch per hold */
static void reclaim_gc(struct hg_block *hb, int c)
{
	while (hb->ndrained[c] && hg_gc_class(hb, c, 0, HG_RECLAIM_BLOCKS))
		lock_breathe(hb);
}

/* Out of buddy blocks: the transfer cache's chains first, a few per hold, then
 * this thread's caches in HG_FLUSH_BATCH holds, until @bytes fit. hb->lock
 * held; dropped and re-taken. 1 if @bytes fit now */
static int hg_reclaim_locked(struct hg_block *hb, struct hg_palloc *pl,
                             unsigned long bytes)
{
	unsigned int n = 0, chains = 0;
	int c;

	hb->pressure_flushes++;
	for (c = 0; c < HG_NCLASSES; c++) {
		while (hb->xfer[c].n) {
			n += hg_xfer_drain_one(hb, c);
			if (++chains % HG_RECLAIM_CHAINS)
				continue;
			reclaim_gc(hb, c);
			if (hg_buddy_has(hb, bytes))
				goto done;
			lock_breathe(hb);
		}
		reclaim_gc(hb, c);
		if (hg_buddy_has(hb, bytes))
			goto done;
	}
	if (pl) {
		enum hg_lock_reason r = (enum hg_lock_reason)hb->lk_cur;

		hg_lock_leave(hb);
		n += hg_cache_flush_all(hb, pl, -1);
		hg_lock_enter(hb, r);
	}
	for (c = 0; c < HG_NCLASSES; c++)
		reclaim_gc(hb, c);
done:
	hb->pressure_cells += n;
	return hg_buddy_has(hb, bytes);
}

/* the arena's reclaim for a caller outside this file (the large tier) */
int hg_arena_reclaim_locked(struct hg_block *hb, unsigned long bytes)
{
	return hg_reclaim_locked(hb, hg_get_palloc(hb), bytes);
}

/* carve a new chunk for class @c; hb->lock held, may be dropped and re-taken.
 * Every cell's class byte is stamped here, before the chunk is reachable */
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
	/* no block of this order: reclaim parked and cached cells before a grow */
	if (!ch && hg_reclaim_locked(hb, pl, size))
		ch = hg_buddy_alloc(hb, (unsigned int)ord);
	/* a grow another thread made may be used up by its other waiters
	 * before this one gets the lock: retry, as the large tier does */
	for (i = 0; !ch && i < HG_CARVE_GROW_TRIES; i++) {
		if (hg_buddy_grow_unlocks(hb, size, HG_GROW_EXHAUSTION) != 0)
			break;
		ch = hg_buddy_alloc(hb, (unsigned int)ord);
	}

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
	ch->cells = (size - sizeof(struct hg_chunk) - HG_BLOCK_SLACK) / cell_sizes[c];
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
	hb->cls_chunks[c]++;
	hb->cls_cells[c] += ch->cells;
	hb->slab_capacity += (unsigned long)ch->cells * ch->cell_size;
	hb->blocks_carved++;
	hb->carves_cycle[c]++;
	hb->real_used += size;
	if (hb->real_used > hb->max_real_used)
		hb->max_real_used = hb->real_used;

	pl->cls[c].bump = cells;
	pl->cls[c].left = ch->cells;

	LM_DBG("%s class %d: new %u byte chunk, %u cells of %u\n",
		hb->name, c, size, ch->cells, cell_sizes[c]);
	return 0;
}

/* the budget is a share of the arena's current size over the threads that
 * cache in it; every class keeps at least one cell, or each of its
 * allocations and frees would take the lock. priv_donate is half priv_max,
 * so a donation never runs the chain dry. hb->lock held, or pre-fork */
static void private_caps_init(struct hg_block *hb)
{
	unsigned int sharers = hb->cache_sharers ? hb->cache_sharers : 1;
	unsigned long per_thread = (unsigned long)hb->size / 100 * HG_PRIVATE_PCT
	                           / sharers;
	unsigned long per_class  = per_thread / HG_NCLASSES;
	unsigned int c;

	for (c = 0; c < HG_NCLASSES; c++) {
		unsigned long n = per_class / cell_sizes[c];

		if (n > HG_PRIVATE_CAP)
			n = HG_PRIVATE_CAP;
		if (!n)
			n = 1;
		hb->priv_max[c]    = (unsigned int)n;
		hb->priv_donate[c] = (unsigned int)(n / 2);
		if (hb->priv_donate[c] == 0)
			hb->priv_donate[c] = 1;
	}
	hg_xfer_caps(hb);

	LM_DBG("%s: private cache budget %lu B/thread over %u sharers (%lu B/class): "
		"class %u caches %u cells, class %u caches %u\n",
		hb->name, per_thread, sharers, per_class,
		cell_sizes[0], hb->priv_max[0],
		cell_sizes[HG_NCLASSES - 1], hb->priv_max[HG_NCLASSES - 1]);
}

/* post-config, pre-fork: children inherit the caps */
void hg_private_caps_retune(struct hg_block *hb)
{
	if (hb)
		private_caps_init(hb);
}

/* after a grow, trim or punch changed the arena's size; hb->lock held */
void hg_private_caps_resize(struct hg_block *hb)
{
	private_caps_init(hb);
}

/* the threads caching in @hb are now @n; a shared arena's caps live in shm,
 * so any process may set them */
void hg_cache_sharers_set(struct hg_block *hb, unsigned int n)
{
	if (!hb)
		return;
	hg_lock_enter(hb, HG_LK_POLICY);
	hb->cache_sharers = n ? n : 1;
	private_caps_init(hb);
	hg_lock_leave(hb);
}

/* every process may cache in every shared arena: called once the process
 * count is final (pre-fork); TCP main adds its IO threads */
void hg_shared_sharers_set(unsigned int nproc)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++)
		if (hg_arena_reg[i].hb && hg_arena_reg[i].hb->shared)
			hg_cache_sharers_set(hg_arena_reg[i].hb, nproc);
}

void hg_shared_sharers_add(unsigned int n)
{
	int i;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		struct hg_block *hb = hg_arena_reg[i].hb;

		if (hb && hb->shared)
			hg_cache_sharers_set(hb, hb->cache_sharers + n);
	}
}

/* lay out the buddy's page grid and prove its shift-and-mask lookup on real
 * addresses: a wrong grid silently hands out another block's descriptor */
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

	/* pbase is hbase itself on Linux; the non-Linux plain mmap() loses the
	 * unaligned head */
	hb->pbase = (char *)(((unsigned long)hb->hbase + hps - 1) & ~(hps - 1));
	end = hb->hbase + hb->span_end;
	hb->npages = (unsigned long)(end - hb->pbase) >> shift;
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

	/* the unaligned head and the byte past the end must not classify as
	 * page memory, or a stray pointer resolves to a nonexistent block */
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

	/* skip the block header and start on a leaf boundary: an aligned first
	 * carve aligns every buddy block, so address lookup can be a mask */
	hb->hoff = (hdr_size + HG_LEAF_SIZE - 1) & ~(HG_LEAF_SIZE - 1);
	if (hb->pbase != hb->hbase) {
		unsigned long skip = (unsigned long)(hb->pbase - hb->hbase);

		if (hb->hoff < skip)
			hb->hoff = skip;
	}

	hb->thread_slot_next = HG_STAT_SLOTS - 1;
	/* /64 keeps all 21 classes plus the large tier within a third of a small
	 * arena, even in the worst case */
	hb->chunk_max = hb->size / 64;
	if (hb->chunk_max > HG_CHUNK_SMALL)
		hb->chunk_max = HG_CHUNK_SMALL;
	if (hb->chunk_max < HG_CHUNK_MIN)
		hb->chunk_max = HG_CHUNK_MIN;

	hb->cache_sharers = hb->shared ? HG_PRIVATE_CONSUMERS : 1;
	private_caps_init(hb);

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
	 * resulting hoff */
	if (hg_buddy_init(hb) < 0)
		return -1;
	return 0;
}

void hg_arena_destroy(struct hg_block *hb)
{
	int i;

	/* one mapping, unmapped whole by hg_malloc_destroy(): only this
	 * thread's slot and the large tier's bookkeeping to drop */
	for (i = 0; i < HG_MAX_INSTANCES; i++)
		if (palloc_slots[i].owner == hb)
			slot_reset(&palloc_slots[i]);
	hg_last = NULL;
	hg_prev = NULL;

	hg_large_destroy(hb);
}

void hg_arena_child_init(struct hg_block *hb)
{
	int i;

	/* the child's copy of the parent's bump pointer and free lists is the
	 * parent's: keeping or donating it would hand one cell out twice */
	for (i = 0; i < HG_MAX_INSTANCES; i++)
		if (palloc_slots[i].owner == hb)
			slot_reset(&palloc_slots[i]);
	hg_last = NULL;
	hg_prev = NULL;
}

unsigned int hg_cell_total_size(unsigned char cls)
{
	if (cls >= HG_NCLASSES)
		return 0;
	return cell_sizes[cls];
}

/* the private head must be a FREE or FRESH cell of class @c in arena memory
 * before its link is followed; a bad head drops (leaks) the whole list */
static inline int private_head_ok(struct hg_block *hb, struct hg_palloc *pl,
                                  int c, union hg_hdr_w *w,
                                  unsigned short *base)
{
	char *cs = pl->cls[c].free_head;
	int st;

	if (!hg_owns(hb, cs) || !hg_backed(hb, cs)) {
		/* dropped before logging: a log event may allocate this class */
		pl->cls[c].free_head = NULL;
		pl->cls[c].nfree = 0;
		LM_CRIT("%s: class %d private list leads to %p, outside the "
			"arena's memory - dropped the list\n", hb->name, c, cs);
		hg_corrupt(hb, HG_C_FOREIGN_PTR);
		return 0;
	}
	st = hg_hdr_read(cs, w, base);
	if ((st == HG_ST_FRESH || st == HG_ST_FREE) && w->f.cls == c)
		return 1;
	pl->cls[c].free_head = NULL;
	pl->cls[c].nfree = 0;
	LM_CRIT("%s: class %d private list head %p is %s - dropped the "
		"list\n", hb->name, c, cs, st < 0 ? "damaged" :
		hg_st_live(st) ? "still in use" : "of another class");
	hg_corrupt(hb, st < 0 ? HG_C_HEADER : hg_st_live(st) ?
		HG_C_DOUBLE_FREE : HG_C_CLASS_MISMATCH);
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
	void *chain;
	unsigned int got, batch;
	unsigned long want = size;
	/* read once: the flag may change under a running allocation */
	unsigned int guard = hb->guard;
	int c, st;
	union hg_hdr_w w;
	unsigned short base;

	/* refused before any arithmetic: near ULONG_MAX the additions below
	 * wrap to a small class the caller then writes past */
	if (size > hb->hcap) {
		hg_lock_enter(hb, HG_LK_REFILL);
		if (hg_oom_first(hb, size))
			LM_ERR("%s: a %lu byte request exceeds the arena's %lu byte "
				"cap - refused; further failures are summarised every "
				"30 s\n", hb->name, size, hb->hcap);
		hg_lock_leave(hb);
		return NULL;
	}

	if (hb->dbg)
		want += HG_DBG_TAIL;
	else if (guard)
		want += HG_GUARD_ROOM;
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
	if (!pl) {
		/* no private slot left: the large tier serves any size, and a
		 * free finds it by its marker */
#ifdef DBG_MALLOC
		return hg_large_alloc(hb, size, file, func, line);
#else
		return hg_large_alloc(hb, size);
#endif
	}

again:
	/* fast paths: no locks, no shared lines */
	cell_start = pl->cls[c].free_head;
	if (cell_start) {
		if (!private_head_ok(hb, pl, c, &w, &base))
			goto again;
		pl->cls[c].free_head = cell_next(cell_start);
		pl->cls[c].nfree--;
		goto checked;
	}
	if (pl->cls[c].left) {
		cell_start = pl->cls[c].bump;
		pl->cls[c].bump += cell_sizes[c];
		pl->cls[c].left--;
		goto found;
	}

	/* a sweep requested for a process the dispatcher cannot reach by IPC */
	hg_sweep_poll();
	/* a floor crossing since this thread last looked: give back what it
	 * holds of the other classes, in batches, before taking more */
	if (pl->sweep_seen != __atomic_load_n(&hb->sweep_gen, __ATOMIC_RELAXED)) {
		pl->sweep_seen = __atomic_load_n(&hb->sweep_gen, __ATOMIC_RELAXED);
		hg_cache_flush_all(hb, pl, c);
	}
	hg_lock_enter(hb, HG_LK_REFILL);
	/* cells reach the private list without a free: tell the sweep too */
	__atomic_store_n(&hg_pstat_mine(hb)->dirty, 1, __ATOMIC_RELAXED);
	if (hb->xfer[c].n && (chain = hg_xfer_get(hb, c, &got))) {
		hg_lock_leave(hb);
		pl->cls[c].free_head = chain;
		pl->cls[c].nfree = got;
		goto again;
	}
	batch = hb->priv_max[c] < HG_REFILL_BATCH ? hb->priv_max[c] :
		HG_REFILL_BATCH;
	if (!batch)
		batch = 1;
	for (got = 0; got < batch; got++) {
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
		if (!private_head_ok(hb, pl, c, &w, &base))
			goto again;
		pl->cls[c].free_head = cell_next(cell_start);
		pl->cls[c].nfree--;
		goto checked;
	}
	cell_start = pl->cls[c].bump;
	pl->cls[c].bump += cell_sizes[c];
	pl->cls[c].left--;

found:
	/* only a FRESH or FREE cell with an intact header is handed out; any
	 * other is leaked and another taken, or one cell goes to two callers */
	st = hg_hdr_read(cell_start, &w, &base);
	if ((st != HG_ST_FRESH && st != HG_ST_FREE) || w.f.cls != c) {
		LM_CRIT("%s: class %d cell %p about to be handed out is %s - "
			"dropping it\n", hb->name, c, cell_start,
			st < 0 ? "damaged" : hg_st_live(st) ? "still in use" :
			"of another class");
		hg_corrupt(hb, st < 0 ? HG_C_HEADER : hg_st_live(st) ?
			HG_C_DOUBLE_FREE : HG_C_CLASS_MISMATCH);
		goto again;
	}
checked:
	if (guard) {
		hg_san_open(hb, cell_start, cell_sizes[c] - HG_CELL_HDR);
		hg_guard_set(cell_start, base, cell_sizes[c] - HG_CELL_HDR,
			size);
	}
	hg_hdr_set_base(cell_start, c, guard ? HG_ST_LIVE_G : HG_ST_LIVE,
		base);
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
	hg_pstat_add(hg_pstat_mine(hb), cell_sizes[c] - HG_CELL_HDR, 1,
		cell_sizes[c]);
	return payload;
}

/* every free's header check (intact and LIVE): returns the class, or -1 to
 * refuse the free - counted and logged here, the cell leaked */
static inline int free_check(struct hg_block *hb, char *cell_start, void *p,
                             union hg_hdr_w *w, unsigned short *base)
{
	int st = hg_hdr_read(cell_start, w, base);

	if (st == HG_ST_LIVE || st == HG_ST_LIVE_G) {
		unsigned int c = w->f.cls;
		unsigned long cap = 0, asked;

		/* a write past the request is reported and the free goes on: it
		 * stayed in the cell, or the neighbour's checksum catches it */
		/* a large fragment's size is checked by hg_large_free() first,
		 * under the lock, and its tail there */
		if ((hb->dbg || HG_SAN_PRIVATE(hb) || st == HG_ST_LIVE_G) &&
		    c < HG_NCLASSES)
			cap = cell_sizes[c] - HG_CELL_HDR;
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

/* 0 when a concurrent free of the cell won: counted and logged here */
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

	if (!hg_owns(hb, cell_start)) {
		struct hg_block *owner = hg_owner(cell_start);

		if (!owner) {
			LM_CRIT("%s: %p belongs to no live arena - refusing to "
				"free it\n", hb->name, p);
			hg_corrupt(hb, HG_C_FOREIGN_PTR);
			return;
		}

		/* straight to its owner's pool: this process never allocates
		 * there, so caching strands it */
		hg_xarena_frees++;
		hg_cell_free_global(owner, p);
		return;
	}

	if (!hg_backed(hb, cell_start)) {
		LM_CRIT("%s: %p points into memory the arena gave back to the "
			"kernel - freed before, not touching it\n", hb->name, p);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
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

		hg_pstat_add(ps, -(long)(cell_sizes[c] - HG_CELL_HDR), -1,
			-(long)cell_sizes[c]);
		/* atomic: the sweep dispatcher reads it from another process */
		__atomic_store_n(&ps->dirty, 1, __ATOMIC_RELAXED);
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
	if (!hg_backed(hb, cell_start)) {
		LM_CRIT("%s: %p points into memory the arena gave back to the "
			"kernel - freed before, not touching it\n", hb->name, p);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
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
		LM_CRIT("%s: cell %p carries invalid class %u - leaking it\n",
			hb->name, p, c);
		hg_corrupt(hb, HG_C_BAD_CLASS);
		return;
	}
	/* the counters move here (hg_cell_free() delegates without touching
	 * them), and not for a push the pool refuses: it freed nothing */
	if (!free_claim(hb, cell_start, c, p, &hw, hbase))
		return;
	hg_san_take(hb, cell_start, cell_sizes[c] - HG_CELL_HDR);
	hg_lock_enter(hb, HG_LK_RETURN);
	pushed = hg_gpool_push(hb, c, cell_start);
	hg_lock_leave(hb);

	if (pushed == 0)
		hg_pstat_add(hg_pstat_mine(hb),
			-(long)(cell_sizes[c] - HG_CELL_HDR), -1,
			-(long)cell_sizes[c]);
}

void hg_arena_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx)
{
	struct hg_chunk *ch;
	unsigned int i;
	char *cell_start;

	/* from a signal handler that interrupted a locked section */
	if (hg_lock_depth) {
		LM_GEN1(memdump, "%s: live-cell walk skipped - this thread is "
			"inside the allocator\n", hb->name);
		return;
	}
	hg_lock_enter(hb, HG_LK_STATS);
	for (ch = hb->chunks; ch; ch = ch->next) {
		/* a damaged link ends the walk: an overrun is not followed */
		if (!chunk_links_ok(hb, ch) || !cell_block(hb, ch->cls < HG_NCLASSES ?
		    (int)ch->cls : 0, ch)) {
			LM_CRIT("%s: chunk list damaged at block %p - live-cell walk "
				"stopped\n", hb->name, (void *)ch);
			break;
		}
		for (i = 0; i < ch->cells; i++) {
			cell_start = (char *)ch + sizeof(struct hg_chunk) +
				(unsigned long)i * ch->cell_size;
			if (map_test(ch, (long)i))
				continue;
			/* FREE cells (private lists, quarantine) and FRESH ones are
			 * not LIVE: the header test alone excludes them */
			if (hg_st_live(hg_hdr_state(cell_start)))
				cb(cell_start + HG_CELL_HDR, ctx);
		}
	}
	hg_lock_leave(hb);
}

#endif /* HG_MALLOC, statistics included */
