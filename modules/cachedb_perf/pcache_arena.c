/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * cachedb_perf memory: where the cache's cells come from.
 *
 * Three backings, decided once in pcache_arena_init() (mod_init, pre-fork):
 *
 *   core    the core shm allocator is HG_MALLOC - every cell is an HG slab
 *           cell; classes, per-process caches, GC, growth and maintenance
 *           are HG's, nothing here but the class byte.
 *   own-hg  a dedicated arena on an HG_MALLOC build - created through the
 *           core's module-arena facade as an HG arena of our own.
 *   own     any other allocator: this file's slot allocator, below.
 *
 * THE OWN BACKING (DESIGN 3.3, reworked for reclaim - tasks C1..C9)
 *
 * Memory is cut into 256 KB SLOTS, each 256 KB-aligned.  A slot is one
 * CHUNK: a 64-byte header and cells of one size class.  A cell's chunk is
 * therefore a mask of its address - no per-cell back pointer, the record
 * header has no room for one.  Slots come from the dedicated reservation
 * (arena_hugepage_mb: 2 MB-aligned, huge-page backed, a bump frontier plus
 * the free lists) or from shm PAGES (16 slots carved out of one shm_malloc
 * block, plus one slot of alignment slack).
 *
 * Cells: byte 0 is the class id, stamped when the chunk is cut and never
 * written again while the chunk keeps that class (DESIGN 3.2 rule 1);
 * bytes 8..15 carry the free-list link.  A process allocates from a private
 * free stack, then from the bump of the chunk it cut, then - under the
 * arena lock - by pulling a batch of cells home on some chunk of the class.
 * A free goes to the private stack; past PCACHE_PRIVATE_MAX the surplus is
 * sent HOME: pushed on its own chunk's free list (lock-free), which is the
 * whole point - a chunk whose every cell is home is provably drained, no
 * process can hold a pointer it will later free.  Chunks with cells home
 * sit on a per-class "avail" stack (lock-free, one membership flag) where
 * the allocator finds them.
 *
 * Reclaim (the module's own process, one tick a second, never inline and
 * never a timer job): drained chunks beyond reclaim_keep per class are
 * RETIRED - the slot goes to the free lists and is re-cut for ANY class on
 * the next carve (cross-class reuse: the footprint follows the peak total,
 * not the sum of per-class peaks).  Free slots that form a whole 2 MB group
 * of the reservation, or a whole shm page, are given back to the host after
 * a quiet window and a cool-off since the last carve: MADV_REMOVE on the
 * reservation (the mapping stays, a later carve re-faults), shm_free of the
 * page.  Nothing is ever unmapped, so a lock-free reader still holding a
 * pointer into a retired, re-cut or punched-out slot reads mapped memory:
 * the copy-out chain (extents, class bound, hash, key, version re-check)
 * rejects what it finds there, exactly as for any stale pointer.
 */

#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../../dprint.h"
#include "../../locking.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../ipc.h"
#include "pcache_arena.h"
#include "pcache_mem.h"

/* the core's module-arena facade (HG_MALLOC v3 trees); older cores have no
 * such header - then only the own backing exists */
#if defined(__has_include)
# if __has_include("../../mem/mem_arena.h")
#  include "../../mem/mem_arena.h"
#  define PCACHE_HAVE_MEM_ARENA 1
# endif
#endif
#ifndef PCACHE_HAVE_MEM_ARENA
typedef void mem_arena_t;
static inline mem_arena_t *shm_arena_create(char *n, unsigned long i,
		unsigned long c) { return NULL; }
static inline int shm_arena_set_profile(mem_arena_t *a, const char *p)
{ return -1; }
static inline mem_arena_t *shm_arena_core(void) { return NULL; }
static inline void mem_arena_extents(const mem_arena_t *a, unsigned long *lo,
		unsigned long *hi) { *lo = 0; *hi = 0; }
static inline int mem_arena_tier(const mem_arena_t *a) { return 0; }
static inline void mem_arena_usage(mem_arena_t *a, unsigned long *c,
		unsigned long *k, unsigned long *l) { *c = 0; *k = 0; *l = 0; }
#define mem_arena_malloc(a, s)     ((void *)0)
#define mem_arena_free(a, p)       do { } while (0)
#endif

#ifndef MADV_REMOVE
#define MADV_REMOVE 9
#endif

char *pcache_backing_policy = "auto";
int pcache_arena_hugepage_cap_mb = 0;
char *pcache_arena_profile = NULL;
int pcache_reclaim_keep = 1;        /* drained chunks kept per class */
int pcache_reclaim_quiet_s = 5;     /* slots free this long before give-back */
int pcache_reclaim_cooloff_s = 10;  /* no give-back this long after a carve */
int pcache_reclaim_giveback = 1;    /* 0: retire and re-cut only, keep resident */

static int backing = PCACHE_BACKING_OWN;
static mem_arena_t *hg_handle;            /* CORE: the shm block; OWN_HG: ours */

/* CP-20: MB to reserve for the huge-page arena; 0 = disabled (shm_malloc).
 * Set by the cachedb_perf "arena_hugepage_mb" modparam. */
int pcache_arena_hugepage_mb = 0;

/* ~x1.5 ladder, all multiples of 32 so cells stay 8-aligned */
static const unsigned int cell_sizes[PCACHE_NCLASSES] = {
	64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048,
	3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536
};

#define PCACHE_SLOT_SHIFT     18
#define PCACHE_SLOT           (1UL << PCACHE_SLOT_SHIFT)   /* 256 KB */
#define PCACHE_SLOT_MASK      (~(PCACHE_SLOT - 1))
#define PCACHE_CHUNK_HDR      64
#define PCACHE_PAGE_SLOTS     16            /* slots per shm page (4 MB) */
#define PCACHE_GROUP_SLOTS    8             /* slots per 2 MB huge page */
#define PCACHE_HPS            (PCACHE_SLOT * PCACHE_GROUP_SLOTS)
#define PCACHE_REFILL_BATCH   32            /* cells pulled home per refill */
#define PCACHE_PRIVATE_MAX    256           /* private stack size that triggers */
#define PCACHE_DONATE         128           /*   sending this many cells home  */
#define PCACHE_CLS_FREE       0xffffffffU   /* chunk header: the slot is free */

typedef struct pcache_page pcache_page_t;

/* one slot = one chunk; the header is the slot's first 64 bytes */
typedef struct pcache_chunk {
	struct pcache_chunk *link;   /* class avail stack, or a free-slot list */
	void *free_head;             /* cells home on this chunk (lock-free push) */
	pcache_page_t *page;         /* owning shm page, NULL = the reservation */
	unsigned int cls;            /* class, or PCACHE_CLS_FREE */
	unsigned int cell_size;
	unsigned int cells;
	unsigned int nfree;          /* cells on free_head */
	unsigned int in_avail;       /* 1 while on (or heading to) the avail stack */
	unsigned int cold;           /* memory punched out; a carve re-faults it */
	unsigned int free_at;        /* reclaim tick the slot became free */
	unsigned int home_since;     /* reclaim tick the first cell came home */
	/* padded to PCACHE_CHUNK_HDR; cells follow */
} pcache_chunk_t;

/* a shm block holding PCACHE_PAGE_SLOTS aligned slots */
struct pcache_page {
	pcache_page_t *next;
	char *raw;                   /* the shm_malloc block */
	char *base;                  /* first slot (256 KB-aligned) */
	pcache_chunk_t *free;        /* this page's free slots */
	unsigned int nslots;
	unsigned int nfree;          /* slots on the free list */
};

typedef struct pcache_region {
	struct pcache_region *next;
	unsigned long size;
} pcache_region_t;

typedef struct pcache_arena {
	gen_lock_t lock;                        /* refill, carve, retire, stats */
	unsigned long bytes;                    /* memory held from the host */
	pcache_region_t *regions;               /* raw index regions (shm) */
	unsigned long regions_bytes;
	unsigned long lo, hi;                   /* extent watermarks */

	/* own backing: classes */
	pcache_chunk_t *avail[PCACHE_NCLASSES]; /* chunks with cells home (lock-free) */
	pcache_chunk_t *cur[PCACHE_NCLASSES];   /* the allocator's current chunk */
	unsigned int chunks_cls[PCACHE_NCLASSES];       /* chunks cut for the class */
	unsigned int chunks_peak_cls[PCACHE_NCLASSES];

	/* own backing: slots.  The reservation's free slots are bitmaps (one
	 * bit per slot; a carve takes the LOWEST free slot so the top groups
	 * drain), a page's free slots are its own list (a carve takes from
	 * the FULLEST page so whole pages drain).  Packing is what makes the
	 * give-back units - 2 MB groups, 4 MB pages - ever become empty. */
	unsigned long *rwarm;                   /* reservation: free, resident */
	unsigned long *rcold;                   /* reservation: free, punched out */
	unsigned int rslots;                    /* bits in each bitmap */
	unsigned int nfree_warm, nfree_cold;    /* reservation + pages / reservation */
	pcache_page_t *pages;
	unsigned int npages;
	unsigned int slots_total;               /* reservation slots cut + page slots */
	unsigned int chunks_used;               /* slots holding a chunk */
	unsigned int tick;                      /* reclaim ticks (1/s) */
	unsigned int carve_tick;                /* tick of the last carve */
	unsigned int giveback_off;              /* MADV_REMOVE refused: stay resident */
	unsigned long chunks_retired;           /* cumulative */
	unsigned long flush_broadcasts;         /* "send your hoard home" rounds */
	unsigned int flush_tick;                /* tick of the last broadcast */
	unsigned long pages_freed;              /* cumulative */
	unsigned long released_bytes;           /* cumulative give-back */
	unsigned long cold_bytes;               /* currently punched out */

	/* CP-20 huge-page reservation: a pre-fork, never-unmapped, 2M-aligned
	 * MAP_SHARED region; slots bump from it at hoff, regions too */
	char                 *hbase;
	unsigned long         hsize;
	unsigned long         hoff;             /* chunk frontier, grows UP (lock) */
	unsigned long         rtop;             /* region frontier, grows DOWN: the
	                                         * index tables never share a 2 MB
	                                         * group with chunks, so groups of
	                                         * retired chunks can be punched out */
	enum pcache_mem_tier  htier;
	unsigned long         hlocked_mb;
} pcache_arena_t;

/* per-process allocation state - pkg, lazily created, reset on fork */
struct pcache_palloc {
	struct {
		char *bump;                  /* next unused cell in own chunk */
		unsigned int left;
		void *free_head;             /* private free stack */
		unsigned int nfree;
	} cls[PCACHE_NCLASSES];
};

static pcache_arena_t *arena;                  /* shm, set pre-fork */
static struct pcache_palloc *my_palloc;        /* pkg, per process */
static unsigned char size2class[2049];         /* idx = ceil(size/32) */

/* free-list link: bytes 8..15, never byte 0 (the class id) */
static inline void *cell_next(void *cell)
{
	return *(void **)((char *)cell + 8);
}

static inline void cell_set_next(void *cell, void *next)
{
	*(void **)((char *)cell + 8) = next;
}

static inline pcache_chunk_t *cell_chunk(const void *cell)
{
	return (pcache_chunk_t *)((unsigned long)cell & PCACHE_SLOT_MASK);
}

/*
 * A cell goes home: onto its chunk's free list.  Lock-free, any number of
 * pushers; the only popper is the allocator under the arena lock, so the
 * pop side has no ABA (a cell cannot be pushed twice while it is on the
 * list).  The chunk is announced to the class the first time its count
 * leaves zero - one membership flag keeps it on the avail stack once.
 */
static void cell_home(void *cell)
{
	pcache_chunk_t *ch = cell_chunk(cell);
	unsigned int c = ch->cls;
	void *old;
	pcache_chunk_t *top;

	do {
		old = __atomic_load_n(&ch->free_head, __ATOMIC_RELAXED);
		cell_set_next(cell, old);
	} while (!__atomic_compare_exchange_n(&ch->free_head, &old, cell, 0,
	                                      __ATOMIC_RELEASE, __ATOMIC_RELAXED));

	if (__atomic_add_fetch(&ch->nfree, 1, __ATOMIC_ACQ_REL) != 1)
		return;
	__atomic_store_n(&ch->home_since, arena->tick, __ATOMIC_RELAXED);
	old = NULL;
	if (!__atomic_compare_exchange_n(&ch->in_avail, (unsigned int *)&old,
	        1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
		return;
	do {
		top = __atomic_load_n(&arena->avail[c], __ATOMIC_RELAXED);
		ch->link = top;
	} while (!__atomic_compare_exchange_n(&arena->avail[c], &top, ch, 0,
	                                      __ATOMIC_RELEASE, __ATOMIC_RELAXED));
}

/* pop one cell from a chunk - arena lock held (single popper) */
static void *chunk_pop(pcache_chunk_t *ch)
{
	void *old, *nxt;

	do {
		old = __atomic_load_n(&ch->free_head, __ATOMIC_ACQUIRE);
		if (!old)
			return NULL;
		nxt = cell_next(old);
	} while (!__atomic_compare_exchange_n(&ch->free_head, &old, nxt, 0,
	                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
	__atomic_sub_fetch(&ch->nfree, 1, __ATOMIC_RELAXED);
	return old;
}

/* pop a chunk from the class avail stack - arena lock held */
static pcache_chunk_t *avail_pop(int c)
{
	pcache_chunk_t *top, *nxt;

	do {
		top = __atomic_load_n(&arena->avail[c], __ATOMIC_ACQUIRE);
		if (!top)
			return NULL;
		nxt = top->link;
	} while (!__atomic_compare_exchange_n(&arena->avail[c], &top, nxt, 0,
	                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
	__atomic_store_n(&top->in_avail, 0, __ATOMIC_RELEASE);
	return top;
}

static void avail_push(int c, pcache_chunk_t *ch)
{
	pcache_chunk_t *top;

	do {
		top = __atomic_load_n(&arena->avail[c], __ATOMIC_RELAXED);
		ch->link = top;
	} while (!__atomic_compare_exchange_n(&arena->avail[c], &top, ch, 0,
	                                      __ATOMIC_RELEASE, __ATOMIC_RELAXED));
}

static inline void extents_add(unsigned long lo, unsigned long hi)
{
	if (lo < arena->lo)
		arena->lo = lo;
	if (hi > arena->hi)
		arena->hi = hi;
}

#define BITS_PER_LONG   (8 * sizeof(unsigned long))

static inline void bit_set(unsigned long *m, unsigned int i)
{
	m[i / BITS_PER_LONG] |= 1UL << (i % BITS_PER_LONG);
}

static inline void bit_clr(unsigned long *m, unsigned int i)
{
	m[i / BITS_PER_LONG] &= ~(1UL << (i % BITS_PER_LONG));
}

static inline int bit_get(const unsigned long *m, unsigned int i)
{
	return (m[i / BITS_PER_LONG] >> (i % BITS_PER_LONG)) & 1;
}

/* the lowest set bit below @n, or -1 */
static int bit_first(const unsigned long *m, unsigned int n)
{
	unsigned int w, words = (n + BITS_PER_LONG - 1) / BITS_PER_LONG;

	for (w = 0; w < words; w++)
		if (m[w])
			return w * BITS_PER_LONG + __builtin_ctzl(m[w]);
	return -1;
}

static inline unsigned int rslot_idx(const pcache_chunk_t *ch)
{
	return ((char *)ch - arena->hbase) >> PCACHE_SLOT_SHIFT;
}

static inline pcache_chunk_t *rslot_at(unsigned int i)
{
	return (pcache_chunk_t *)(arena->hbase + (unsigned long)i * PCACHE_SLOT);
}

/* a new shm page: PCACHE_PAGE_SLOTS aligned slots on its free list.
 * Arena lock held. */
static int page_add(void)
{
	pcache_page_t *pg;
	pcache_chunk_t *ch;
	unsigned long size = (PCACHE_PAGE_SLOTS + 1) * PCACHE_SLOT;
	unsigned int i;

	pg = shm_malloc(sizeof *pg);
	if (!pg) {
		LM_ERR("no more shm memory for a page descriptor\n");
		return -1;
	}
	pg->raw = shm_malloc(size);
	if (!pg->raw) {
		LM_ERR("no more shm memory for a %lu byte page\n", size);
		shm_free(pg);
		return -1;
	}
	pg->base = (char *)(((unsigned long)pg->raw + PCACHE_SLOT - 1)
	                    & PCACHE_SLOT_MASK);
	pg->nslots = PCACHE_PAGE_SLOTS;
	pg->nfree = PCACHE_PAGE_SLOTS;
	pg->next = arena->pages;
	arena->pages = pg;
	arena->npages++;
	arena->bytes += size;
	extents_add((unsigned long)pg->raw, (unsigned long)pg->raw + size);

	pg->free = NULL;
	for (i = 0; i < pg->nslots; i++) {
		ch = (pcache_chunk_t *)(pg->base + (unsigned long)i * PCACHE_SLOT);
		memset(ch, 0, PCACHE_CHUNK_HDR);
		ch->page = pg;
		ch->cls = PCACHE_CLS_FREE;
		ch->link = pg->free;
		pg->free = ch;
	}
	arena->nfree_warm += pg->nslots;
	arena->slots_total += pg->nslots;
	return 0;
}

/* a free slot for a new chunk, in packing order: the reservation's lowest
 * resident free slot, then its lowest punched-out one (re-faults, keeps
 * the used range tight), then its frontier, then the fullest page, then a
 * new page.  Arena lock held. */
static pcache_chunk_t *slot_take(void)
{
	pcache_chunk_t *ch = NULL;
	pcache_page_t *pg, *best = NULL;
	int i;

	if (arena->hbase && (i = bit_first(arena->rwarm, arena->rslots)) >= 0) {
		bit_clr(arena->rwarm, i);
		arena->nfree_warm--;
		ch = rslot_at(i);
	} else if (arena->hbase &&
	           (i = bit_first(arena->rcold, arena->rslots)) >= 0) {
		bit_clr(arena->rcold, i);
		arena->nfree_cold--;
		arena->cold_bytes -= PCACHE_SLOT;
		arena->bytes += PCACHE_SLOT;
		ch = rslot_at(i);
		ch->cold = 0;
	} else if (arena->hbase && arena->hoff + PCACHE_SLOT <= arena->rtop) {
		ch = (pcache_chunk_t *)(arena->hbase + arena->hoff);
		arena->hoff += PCACHE_SLOT;
		arena->slots_total++;
		arena->bytes += PCACHE_SLOT;
		memset(ch, 0, PCACHE_CHUNK_HDR);
	} else {
		for (pg = arena->pages; pg; pg = pg->next)
			if (pg->nfree && (!best || pg->nfree < best->nfree))
				best = pg;
		if (!best) {
			if (page_add() < 0)
				return NULL;
			best = arena->pages;
		}
		ch = best->free;
		best->free = ch->link;
		best->nfree--;
		arena->nfree_warm--;
	}
	arena->chunks_used++;
	arena->carve_tick = arena->tick;
	return ch;
}

/* cut a chunk for class @c and hand it to the carving process as its bump
 * source - arena lock held.  The class byte of every cell is stamped HERE,
 * before the chunk is reachable by anyone - immutable from birth, so a
 * stale reader can always trust it (DESIGN 3.2 copy-out rule 1). */
static int carve_chunk(int c, struct pcache_palloc *pl)
{
	pcache_chunk_t *ch;
	unsigned int i;
	char *cells;

	ch = slot_take();
	if (!ch) {
		LM_ERR("no more memory for a chunk (class %d)\n", c);
		return -1;
	}
	ch->link = NULL;
	ch->free_head = NULL;
	ch->cls = c;
	ch->cell_size = cell_sizes[c];
	ch->cells = (PCACHE_SLOT - PCACHE_CHUNK_HDR) / cell_sizes[c];
	ch->nfree = 0;
	ch->in_avail = 0;
	ch->free_at = 0;
	ch->home_since = 0;

	cells = (char *)ch + PCACHE_CHUNK_HDR;
	for (i = 0; i < ch->cells; i++)
		cells[(unsigned long)i * cell_sizes[c]] = (unsigned char)c;

	arena->chunks_cls[c]++;
	if (arena->chunks_cls[c] > arena->chunks_peak_cls[c])
		arena->chunks_peak_cls[c] = arena->chunks_cls[c];

	/* the whole chunk belongs to the carving process */
	pl->cls[c].bump = cells;
	pl->cls[c].left = ch->cells;

	LM_DBG("class %d: chunk %p, %u cells of %u\n", c, ch, ch->cells,
		cell_sizes[c]);
	return 0;
}

static struct pcache_palloc *get_palloc(void)
{
	if (!my_palloc) {
		my_palloc = pkg_malloc(sizeof *my_palloc);
		if (!my_palloc) {
			LM_ERR("no more pkg memory\n");
			return NULL;
		}
		memset(my_palloc, 0, sizeof *my_palloc);
	}
	return my_palloc;
}

/* send this process's bump remainder of class @c home */
static void bump_home(struct pcache_palloc *pl, int c)
{
	while (pl->cls[c].left) {
		cell_home(pl->cls[c].bump);
		pl->cls[c].bump += cell_sizes[c];
		pl->cls[c].left--;
	}
	pl->cls[c].bump = NULL;
}

int pcache_arena_init(void)
{
	int idx, c;

	arena = shm_malloc(sizeof *arena);
	if (!arena) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(arena, 0, sizeof *arena);
	arena->lo = ~0UL;
	if (!lock_init(&arena->lock)) {
		LM_ERR("failed to init the arena lock\n");
		shm_free(arena);
		arena = NULL;
		return -1;
	}

	/* size -> class LUT, built pre-fork and inherited */
	for (idx = 0; idx <= 2048; idx++) {
		for (c = 0; c < PCACHE_NCLASSES; c++)
			if (cell_sizes[c] >= (unsigned int)idx * 32)
				break;
		size2class[idx] = (unsigned char)c;   /* NCLASSES = impossible */
	}

	/*
	 * Which backing? An HG_MALLOC build can hand the whole job to HG: a
	 * dedicated arena becomes an HG arena of our own (own-hg), and with
	 * no arena asked for, cells go straight into the core shm arena when
	 * that allocator is HG (core). Only without HG does this file's
	 * slot allocator run (own). The policy modparam can force any.
	 */
	{
		const char *pol = pcache_backing_policy ? pcache_backing_policy : "auto";
		int want_arena = pcache_arena_hugepage_mb > 0;
		int try_own_hg = 0, try_core = 0;

		if (!strcasecmp(pol, "auto")) {
			try_own_hg = want_arena;
			try_core = !want_arena;
		} else if (!strcasecmp(pol, "own-hg")) {
			try_own_hg = 1;
		} else if (!strcasecmp(pol, "core")) {
			try_core = 1;
		} else if (strcasecmp(pol, "own")) {
			LM_ERR("memory_backing '%s' is not auto|core|own-hg|own\n", pol);
			return -1;
		}
		if (try_own_hg) {
			unsigned long init = (unsigned long)(pcache_arena_hugepage_mb > 0 ?
				pcache_arena_hugepage_mb : 64) << 20;
			unsigned long cap = (unsigned long)pcache_arena_hugepage_cap_mb << 20;

			hg_handle = shm_arena_create("cachedb_perf", init,
				cap > init ? cap : init);
			if (hg_handle) {
				backing = PCACHE_BACKING_OWN_HG;
				if (pcache_arena_profile &&
				    shm_arena_set_profile(hg_handle, pcache_arena_profile) < 0) {
					LM_ERR("arena_profile '%s' could not be attached\n",
						pcache_arena_profile);
					return -1;
				}
			} else if (strcasecmp(pol, "auto")) {
				LM_ERR("memory_backing=own-hg: no HG_MALLOC arena available "
					"(not an HG_MALLOC build, or the reservation failed)\n");
				return -1;
			}
		}
		if (backing == PCACHE_BACKING_OWN && try_core) {
			hg_handle = shm_arena_core();
			if (hg_handle) {
				backing = PCACHE_BACKING_CORE;
			} else if (strcasecmp(pol, "auto")) {
				LM_ERR("memory_backing=core: the shm allocator is not "
					"HG_MALLOC\n");
				return -1;
			}
		}
	}
	if (backing != PCACHE_BACKING_OWN) {
		LM_DBG("arena ready: %s\n", pcache_arena_backing_str());
		return 0;
	}

	if (pcache_reclaim_keep < 0 || pcache_reclaim_quiet_s < 0 ||
	    pcache_reclaim_cooloff_s < 0) {
		LM_ERR("reclaim_keep / reclaim_quiet_s / reclaim_cooloff_s must "
			"not be negative\n");
		return -1;
	}

	/* CP-20: reserve the huge-page arena, pre-fork, if requested */
	if (pcache_arena_hugepage_mb > 0) {
		arena->hsize = (unsigned long)pcache_arena_hugepage_mb << 20;
		arena->hbase = pcache_mem_reserve(arena->hsize, &arena->htier,
			&arena->hlocked_mb);
		if (!arena->hbase) {
			LM_WARN("huge-page arena reservation of %d MB failed; "
				"falling back to shm_malloc (4K)\n",
				pcache_arena_hugepage_mb);
			arena->hsize = 0;
		} else {
			arena->lo = (unsigned long)arena->hbase;
			arena->hi = (unsigned long)arena->hbase + arena->hsize;
			arena->rtop = arena->hsize;
			arena->rslots = arena->hsize >> PCACHE_SLOT_SHIFT;
			arena->rwarm = shm_malloc(2 * ((arena->rslots + BITS_PER_LONG - 1)
				/ BITS_PER_LONG) * sizeof(unsigned long));
			if (!arena->rwarm) {
				LM_ERR("no more shm memory for the slot bitmaps\n");
				return -1;
			}
			memset(arena->rwarm, 0, 2 * ((arena->rslots + BITS_PER_LONG - 1)
				/ BITS_PER_LONG) * sizeof(unsigned long));
			arena->rcold = arena->rwarm +
				(arena->rslots + BITS_PER_LONG - 1) / BITS_PER_LONG;
			LM_NOTICE("huge-page arena: %d MB on %s, %lu MB pinned from swapping\n",
				pcache_arena_hugepage_mb,
				pcache_mem_tier_str(arena->htier), arena->hlocked_mb);
		}
	}

	LM_DBG("arena ready: %d classes, %u B to %u B cells, %lu KB slots\n",
		PCACHE_NCLASSES, cell_sizes[0], cell_sizes[PCACHE_NCLASSES-1],
		PCACHE_SLOT >> 10);
	return 0;
}

/*
 * Raw memory for an index region (bucket segments).  64-aligned, never
 * freed (task C10: tables grow and never shrink - small and bounded).
 * From the reservation's frontier in whole slots when it has room, shm
 * otherwise.
 */
void *pcache_region_alloc(size_t size)
{
	pcache_region_t *rg;
	unsigned long need = size + sizeof(pcache_region_t) + 64, slots;
	char *aligned;

	if (backing != PCACHE_BACKING_OWN) {
		/* HG hands out whole regions too; nothing to register - the
		 * arena's extents and accounting are HG's */
		rg = mem_arena_malloc(hg_handle, need);
		if (!rg) {
			LM_ERR("no more arena memory for a %lu byte region\n", need);
			return NULL;
		}
		__atomic_fetch_add(&arena->bytes, need, __ATOMIC_RELAXED);
		return (char *)(((unsigned long)rg + sizeof(pcache_region_t) + 63)
		                & ~63UL);
	}

	lock_get(&arena->lock);
	slots = (need + PCACHE_SLOT - 1) >> PCACHE_SLOT_SHIFT;
	if (arena->hbase && arena->hoff + slots * PCACHE_SLOT <= arena->rtop) {
		arena->rtop -= slots * PCACHE_SLOT;
		rg = (pcache_region_t *)(arena->hbase + arena->rtop);
		arena->bytes += slots * PCACHE_SLOT;
		arena->regions_bytes += slots * PCACHE_SLOT;
		rg->size = 0;                       /* lives in the reservation */
		lock_release(&arena->lock);
		return (char *)(((unsigned long)rg + sizeof(pcache_region_t) + 63)
		                & ~63UL);
	}
	lock_release(&arena->lock);

	rg = shm_malloc(need);
	if (!rg) {
		LM_ERR("no more shm memory for a %lu byte region\n", need);
		return NULL;
	}
	rg->size = need;
	aligned = (char *)(((unsigned long)rg + sizeof(pcache_region_t) + 63)
	                   & ~63UL);
	lock_get(&arena->lock);
	rg->next = arena->regions;
	arena->regions = rg;
	arena->bytes += need;
	arena->regions_bytes += need;
	extents_add((unsigned long)rg, (unsigned long)rg + need);
	lock_release(&arena->lock);
	return aligned;
}

void pcache_arena_destroy(void)
{
	pcache_region_t *rg, *rnext;
	pcache_page_t *pg, *pnext;

	if (!arena)
		return;

	if (backing != PCACHE_BACKING_OWN) {
		/* the cells and regions are HG's; the arena mapping (ours or the
		 * core's) goes with the process */
		lock_destroy(&arena->lock);
		shm_free(arena);
		arena = NULL;
		return;
	}

	for (rg = arena->regions; rg; rg = rnext) {
		rnext = rg->next;
		shm_free(rg);
	}
	for (pg = arena->pages; pg; pg = pnext) {
		pnext = pg->next;
		shm_free(pg->raw);
		shm_free(pg);
	}
	if (arena->hbase)
		munmap(arena->hbase, arena->hsize);
	if (arena->rwarm)
		shm_free(arena->rwarm);
	lock_destroy(&arena->lock);
	shm_free(arena);
	arena = NULL;

	if (my_palloc) {
		pkg_free(my_palloc);
		my_palloc = NULL;
	}
}

void pcache_arena_child_init(void)
{
	struct pcache_palloc *pl = my_palloc;

	if (backing != PCACHE_BACKING_OWN || !pl)
		return;

	/*
	 * After fork every child holds a COW copy of the parent's private
	 * allocator state - the SAME bump pointer and the SAME free-list cell
	 * addresses.  A child must not keep them (two processes bumping one
	 * chunk would hand out the same cell), and it must NOT send them home
	 * either: every child inherited the identical copy, so each would push
	 * the same physical cells, landing one cell on a free list N times -
	 * later popped by several processes at once and written through
	 * concurrently (the CP-16 corruption: a value byte overwrites a
	 * neighbour's class id, and the next free reads an impossible class).
	 *
	 * The leftover cells belong to the parent.  The child simply discards
	 * its inherited copy and starts empty, carving its own chunk on first
	 * use.  The parent keeps its own small hoard.
	 *
	 * Bug fixed here (2026-08-07): this function's OWN comment already
	 * said "discards", but the code called pkg_free(pl) anyway - freeing
	 * pl (the pcache_palloc struct itself) is exactly the same class of
	 * mistake the comment warns about for its internal free-list cells:
	 * pl is COW-shared with the parent and every sibling child inherited
	 * the identical pointer, so pkg_free() is a WRITE into that shared
	 * page (hg_cell_free()/cell_set_next() links it into a free list).
	 * Under HG_MALLOC's hugepage-backed pkg arena this write-triggered
	 * COW fault reproducibly SIGBUSed (mem/hg_arena.c:98, always via
	 * cachedb_perf.c child_init -> here), first surfaced when a TCP-based
	 * protocol (proto_bin, for clusterer_controller) made this fork/free
	 * path run under HG_MALLOC for the first time. Fix: just drop the
	 * reference, exactly as documented - no free, no donation, nothing.
	 * pl's memory is reclaimed for free when the child process exits.
	 */
	my_palloc = NULL;
}

/* send every privately held cell of this process home: the free stacks
 * and the bump remainders.  For a process that is done allocating (and
 * for the selftest); the hot paths never call it. */
void pcache_arena_flush_private(void)
{
	struct pcache_palloc *pl = my_palloc;
	void *cell;
	int c;

	if (backing != PCACHE_BACKING_OWN || !pl)
		return;
	for (c = 0; c < PCACHE_NCLASSES; c++) {
		while ((cell = pl->cls[c].free_head) != NULL) {
			pl->cls[c].free_head = cell_next(cell);
			pl->cls[c].nfree--;
			cell_home(cell);
		}
		bump_home(pl, c);
	}
}

void *pcache_cell_alloc(unsigned int size)
{
	struct pcache_palloc *pl;
	pcache_chunk_t *ch;
	void *cell;
	unsigned int got;
	int c;

	if (size > PCACHE_CELL_MAX) {
		LM_DBG("%u bytes exceeds the largest cell (%d)\n",
			size, PCACHE_CELL_MAX);
		return NULL;
	}
	c = size2class[(size + 31) >> 5];

	if (backing != PCACHE_BACKING_OWN) {
		/* an HG slab cell, class-rounded so pcache_cell_bound() stays
		 * exact; byte 0 carries our class id exactly as in own chunks
		 * (HG's own header sits in front of the pointer it returns) */
		cell = mem_arena_malloc(hg_handle, cell_sizes[c]);
		if (!cell)
			return NULL;
		*(unsigned char *)cell = (unsigned char)c;
		__atomic_fetch_add(&arena->bytes, cell_sizes[c], __ATOMIC_RELAXED);
		return cell;
	}

	pl = get_palloc();
	if (!pl)
		return NULL;

	/* fast paths: no locks, no shared lines */
	cell = pl->cls[c].free_head;
	if (cell) {
		pl->cls[c].free_head = cell_next(cell);
		pl->cls[c].nfree--;
		return cell;
	}
	if (pl->cls[c].left) {
		cell = pl->cls[c].bump;
		pl->cls[c].bump += cell_sizes[c];
		pl->cls[c].left--;
		return cell;
	}

	/* slow path: pull a batch home from the class's chunks, else carve */
	lock_get(&arena->lock);
	for (got = 0; got < PCACHE_REFILL_BATCH; ) {
		ch = arena->cur[c];
		if (!ch) {
			ch = avail_pop(c);
			if (!ch)
				break;
			arena->cur[c] = ch;
		}
		cell = chunk_pop(ch);
		if (!cell) {
			arena->cur[c] = NULL;     /* empty; the next free re-announces it */
			continue;
		}
		cell_set_next(cell, pl->cls[c].free_head);
		pl->cls[c].free_head = cell;
		pl->cls[c].nfree++;
		got++;
	}
	if (!got && carve_chunk(c, pl) < 0) {
		lock_release(&arena->lock);
		return NULL;
	}
	lock_release(&arena->lock);

	cell = pl->cls[c].free_head;
	if (cell) {
		pl->cls[c].free_head = cell_next(cell);
		pl->cls[c].nfree--;
		return cell;
	}
	cell = pl->cls[c].bump;
	pl->cls[c].bump += cell_sizes[c];
	pl->cls[c].left--;
	return cell;
}

void pcache_cell_free(void *cell)
{
	struct pcache_palloc *pl;
	unsigned int c = *(unsigned char *)cell, i;
	void *d;

	if (c >= PCACHE_NCLASSES) {
		LM_CRIT("cell %p carries invalid class %u - leaking it\n",
			cell, c);
		return;
	}

	if (backing != PCACHE_BACKING_OWN) {
		__atomic_fetch_sub(&arena->bytes, cell_sizes[c], __ATOMIC_RELAXED);
		mem_arena_free(hg_handle, cell);
		return;
	}

	pl = get_palloc();
	if (!pl) {
		/* cannot even track it privately - send it home */
		cell_home(cell);
		return;
	}

	cell_set_next(cell, pl->cls[c].free_head);
	pl->cls[c].free_head = cell;
	pl->cls[c].nfree++;

	if (pl->cls[c].nfree > PCACHE_PRIVATE_MAX) {
		/* the surplus goes home, and so does an idle bump remainder -
		 * a process hoarding cells would otherwise pin their chunks */
		for (i = 0; i < PCACHE_DONATE; i++) {
			d = pl->cls[c].free_head;
			pl->cls[c].free_head = cell_next(d);
			pl->cls[c].nfree--;
			cell_home(d);
		}
		bump_home(pl, c);
	}
}

/* a free from a process that is not an allocator (the expiry sweep):
 * straight home, lock-free */
void pcache_cell_free_global(void *cell)
{
	unsigned int c = *(unsigned char *)cell;

	if (c >= PCACHE_NCLASSES) {
		LM_CRIT("cell %p carries invalid class %u - leaking it\n",
			cell, c);
		return;
	}
	if (backing != PCACHE_BACKING_OWN) {
		__atomic_fetch_sub(&arena->bytes, cell_sizes[c], __ATOMIC_RELAXED);
		mem_arena_free(hg_handle, cell);
		return;
	}
	cell_home(cell);
}

/* the largest size this cell can hold, from its class byte; 0 = not a cell */
unsigned int pcache_cell_bound(const void *cell)
{
	unsigned char c = *(const unsigned char *)cell;

	if (c >= PCACHE_NCLASSES)
		return 0;
	return cell_sizes[c];
}

void pcache_arena_extents(unsigned long *lo, unsigned long *hi)
{
	if (backing != PCACHE_BACKING_OWN) {
		/* the HG reservation (the whole cap): every pointer HG ever
		 * hands out from this arena lies inside it */
		mem_arena_extents(hg_handle, lo, hi);
		return;
	}
	/* unlocked on purpose: readers validate with these on every lookup.
	 * The watermarks only ever widen (a page is never unmapped), so a
	 * torn pair can only be narrower than the truth - a live record read
	 * through a stale pair is just a miss that the next retry serves. */
	*lo = __atomic_load_n(&arena->lo, __ATOMIC_RELAXED);
	*hi = __atomic_load_n(&arena->hi, __ATOMIC_RELAXED);
}

/* ---- reclaim: the module's own process, one tick a second ------------ */

/* retire a drained chunk: its slot goes to the warm list - arena lock held */
static void chunk_retire(pcache_chunk_t *ch)
{
	unsigned int c = ch->cls;

	if (arena->cur[c] == ch)
		arena->cur[c] = NULL;
	ch->free_head = NULL;
	ch->nfree = 0;
	ch->in_avail = 0;
	ch->cls = PCACHE_CLS_FREE;
	ch->free_at = arena->tick;
	if (ch->page) {
		ch->link = ch->page->free;
		ch->page->free = ch;
		ch->page->nfree++;
	} else {
		bit_set(arena->rwarm, rslot_idx(ch));
	}
	arena->nfree_warm++;
	arena->chunks_cls[c]--;
	arena->chunks_used--;
	arena->chunks_retired++;
}

/* is every slot of [lo, hi) a free, resident, quiet one?  Arena lock held. */
static int range_quiet(char *lo, char *hi)
{
	pcache_chunk_t *ch;
	char *p;

	for (p = lo; p < hi; p += PCACHE_SLOT) {
		ch = (pcache_chunk_t *)p;
		if (ch->cls != PCACHE_CLS_FREE || ch->cold ||
		    arena->tick - ch->free_at < (unsigned int)pcache_reclaim_quiet_s)
			return 0;
	}
	return 1;
}

/* give memory back to the host - arena lock held */
static void giveback_tick(void)
{
	pcache_page_t *pg, **ppg;
	pcache_chunk_t *ch;
	unsigned int g, i, keep_pages = 0;
	char *p;

	if (!pcache_reclaim_giveback || arena->giveback_off ||
	    arena->tick - arena->carve_tick < (unsigned int)pcache_reclaim_cooloff_s)
		return;

	/* the reservation: whole 2 MB groups of free resident slots, punched
	 * out with MADV_REMOVE - the mapping stays, the pages go (hugetlb ones
	 * back to the pool).  Bookkeeping first: the punch zeroes the slot
	 * headers, so nothing may still be read from them afterwards. */
	if (arena->hbase) {
		for (g = 0; (g + 1) * PCACHE_GROUP_SLOTS <= arena->hoff / PCACHE_SLOT; g++) {
			p = arena->hbase + (unsigned long)g * PCACHE_HPS;
			for (i = 0; i < PCACHE_GROUP_SLOTS; i++)
				if (!bit_get(arena->rwarm, g * PCACHE_GROUP_SLOTS + i))
					break;
			if (i < PCACHE_GROUP_SLOTS || !range_quiet(p, p + PCACHE_HPS))
				continue;
			for (i = 0; i < PCACHE_GROUP_SLOTS; i++) {
				bit_clr(arena->rwarm, g * PCACHE_GROUP_SLOTS + i);
				bit_set(arena->rcold, g * PCACHE_GROUP_SLOTS + i);
			}
			arena->nfree_warm -= PCACHE_GROUP_SLOTS;
			arena->nfree_cold += PCACHE_GROUP_SLOTS;
			if (madvise(p, PCACHE_HPS, MADV_REMOVE) < 0) {
				LM_WARN("MADV_REMOVE refused on the %s arena (%s) - "
					"free slots stay resident from now on\n",
					pcache_mem_tier_str(arena->htier), strerror(errno));
				arena->giveback_off = 1;
				/* still free, still resident: back to warm */
				for (i = 0; i < PCACHE_GROUP_SLOTS; i++) {
					bit_set(arena->rwarm, g * PCACHE_GROUP_SLOTS + i);
					bit_clr(arena->rcold, g * PCACHE_GROUP_SLOTS + i);
				}
				arena->nfree_warm += PCACHE_GROUP_SLOTS;
				arena->nfree_cold -= PCACHE_GROUP_SLOTS;
				return;
			}
			/* the headers went with the memory: rebuild them cold */
			for (i = 0; i < PCACHE_GROUP_SLOTS; i++) {
				ch = (pcache_chunk_t *)(p + (unsigned long)i * PCACHE_SLOT);
				memset(ch, 0, PCACHE_CHUNK_HDR);
				ch->cls = PCACHE_CLS_FREE;
				ch->cold = 1;
				ch->free_at = arena->tick;
			}
			arena->cold_bytes += PCACHE_HPS;
			arena->bytes -= PCACHE_HPS;
			arena->released_bytes += PCACHE_HPS;
		}
	}

	/* shm pages: a page whose every slot is free and quiet goes back to
	 * shm_free (keep reclaim_keep of them resident for the next growth) */
	for (ppg = &arena->pages; (pg = *ppg) != NULL; ) {
		if (pg->nfree < pg->nslots ||
		    !range_quiet(pg->base, pg->base + (unsigned long)pg->nslots * PCACHE_SLOT)) {
			ppg = &pg->next;
			continue;
		}
		if (keep_pages < (unsigned int)pcache_reclaim_keep) {
			keep_pages++;
			ppg = &pg->next;
			continue;
		}
		arena->nfree_warm -= pg->nslots;
		arena->slots_total -= pg->nslots;
		arena->bytes -= (PCACHE_PAGE_SLOTS + 1) * PCACHE_SLOT;
		arena->released_bytes += (PCACHE_PAGE_SLOTS + 1) * PCACHE_SLOT;
		*ppg = pg->next;
		arena->npages--;
		arena->pages_freed++;
		shm_free(pg->raw);
		shm_free(pg);
	}
}

/*
 * "Send your hoard home": runs in EVERY process through the core's IPC,
 * between its messages.  A process's private free stack and the remainder
 * of the slot it is carving from pin their chunks - a few hundred cells
 * scattered over as many chunks keep those chunks from ever draining - so
 * when chunks linger partially home the reclaim process asks everyone to
 * let go; the next allocation simply refills from the arena.
 */
static void pcache_flush_rpc(int sender, void *param)
{
	pcache_arena_flush_private();
}

/*
 * One reclaim tick.  Drained chunks live on the class avail stacks (a
 * chunk with cells home is always there, or the allocator's current one,
 * or on its way): take the stack, retire the drained ones beyond
 * reclaim_keep, put the rest back.  A chunk whose announcement is still in
 * flight (flag set, not found) is left for the next tick.
 */
void pcache_arena_reclaim_tick(void)
{
	pcache_chunk_t *ch, *next, *head;
	unsigned int kept, nfree, lingering = 0;
	int c;

	if (backing != PCACHE_BACKING_OWN)
		return;

	lock_get(&arena->lock);
	arena->tick++;
	for (c = 0; c < PCACHE_NCLASSES; c++) {
		kept = 0;
		head = __atomic_exchange_n(&arena->avail[c], NULL, __ATOMIC_ACQ_REL);
		for (ch = head; ch; ch = next) {
			next = ch->link;
			nfree = __atomic_load_n(&ch->nfree, __ATOMIC_ACQUIRE);
			if (nfree == ch->cells &&
			    kept++ >= (unsigned int)pcache_reclaim_keep) {
				chunk_retire(ch);
				continue;
			}
			/* partially home for a whole quiet window, nobody taking
			 * the cells and nobody bringing the rest: a hoard pins it */
			if (nfree && nfree < ch->cells &&
			    arena->tick - ch->home_since >= (unsigned int)pcache_reclaim_quiet_s)
				lingering++;
			avail_push(c, ch);
		}
		/* the allocator's current chunk is not on the stack */
		ch = arena->cur[c];
		if (ch && !__atomic_load_n(&ch->in_avail, __ATOMIC_ACQUIRE) &&
		    __atomic_load_n(&ch->nfree, __ATOMIC_ACQUIRE) == ch->cells &&
		    kept++ >= (unsigned int)pcache_reclaim_keep)
			chunk_retire(ch);
	}
	giveback_tick();
	if (lingering &&
	    arena->tick - arena->flush_tick >= (unsigned int)pcache_reclaim_quiet_s) {
		arena->flush_tick = arena->tick;
		arena->flush_broadcasts++;
		lock_release(&arena->lock);
		ipc_send_rpc_all(pcache_flush_rpc, NULL);
		return;
	}
	lock_release(&arena->lock);
}

/* ---- reporting --------------------------------------------------------- */

void pcache_arena_stats(unsigned int *nchunks, unsigned long *bytes)
{
	if (backing != PCACHE_BACKING_OWN) {
		*nchunks = 0;                  /* no chunks of ours: HG's cells */
		*bytes = __atomic_load_n(&arena->bytes, __ATOMIC_RELAXED);
		return;
	}
	lock_get(&arena->lock);
	*nchunks = arena->chunks_used;
	*bytes = arena->bytes;
	lock_release(&arena->lock);
}

/* the reclaim view for perf_stats "arena" - arena lock taken here */
int pcache_arena_mi(mi_item_t *aobj)
{
	char buf[PCACHE_NCLASSES * 24], *p = buf;
	pcache_page_t *pg;
	pcache_chunk_t *ch;
	unsigned long off, out[PCACHE_NCLASSES], strand = 0;
	unsigned int i, c;
	int rc;

	if (backing != PCACHE_BACKING_OWN)
		return 0;

	memset(out, 0, sizeof out);
	lock_get(&arena->lock);
	/* cells out (not home) per class: the reservation's cut slots and
	 * every page slot */
	for (off = 0; off < arena->hoff; off += PCACHE_SLOT) {
		ch = (pcache_chunk_t *)(arena->hbase + off);
		if (ch->cls < PCACHE_NCLASSES)
			out[ch->cls] += ch->cells - ch->nfree;
	}
	for (pg = arena->pages; pg; pg = pg->next)
		for (i = 0; i < pg->nslots; i++) {
			ch = (pcache_chunk_t *)(pg->base + (unsigned long)i * PCACHE_SLOT);
			if (ch->cls < PCACHE_NCLASSES)
				out[ch->cls] += ch->cells - ch->nfree;
		}
	for (c = 0; c < PCACHE_NCLASSES; c++) {
		if (!arena->chunks_cls[c] && !arena->chunks_peak_cls[c])
			continue;
		if (!out[c])
			strand += arena->chunks_cls[c];   /* held by a class with nothing live */
		p += snprintf(p, sizeof buf - (p - buf), "%s%u:%u/%u/%lu",
			p == buf ? "" : " ", cell_sizes[c], arena->chunks_cls[c],
			arena->chunks_peak_cls[c], out[c]);
	}
	rc = add_mi_number(aobj, MI_SSTR("slot_kb"), PCACHE_SLOT >> 10) < 0 ||
	     add_mi_number(aobj, MI_SSTR("slots_total"), arena->slots_total) < 0 ||
	     add_mi_number(aobj, MI_SSTR("slots_free_warm"), arena->nfree_warm) < 0 ||
	     add_mi_number(aobj, MI_SSTR("slots_free_cold"), arena->nfree_cold) < 0 ||
	     add_mi_number(aobj, MI_SSTR("chunks_strand"), strand) < 0 ||
	     add_mi_number(aobj, MI_SSTR("chunks_retired"), arena->chunks_retired) < 0 ||
	     add_mi_number(aobj, MI_SSTR("flush_broadcasts"), arena->flush_broadcasts) < 0 ||
	     add_mi_number(aobj, MI_SSTR("pages"), arena->npages) < 0 ||
	     add_mi_number(aobj, MI_SSTR("pages_freed"), arena->pages_freed) < 0 ||
	     add_mi_number(aobj, MI_SSTR("released_bytes"), arena->released_bytes) < 0 ||
	     add_mi_number(aobj, MI_SSTR("cold_bytes"), arena->cold_bytes) < 0 ||
	     add_mi_number(aobj, MI_SSTR("reclaim_ticks"), arena->tick) < 0 ||
	     add_mi_number(aobj, MI_SSTR("last_carve_age_s"),
	         arena->tick - arena->carve_tick) < 0 ||
	     add_mi_string(aobj, MI_SSTR("classes"), buf, p - buf) < 0;
	lock_release(&arena->lock);
	return rc ? -1 : 0;
}

int pcache_arena_tier(void)
{
	if (backing == PCACHE_BACKING_OWN_HG)
		return mem_arena_tier(hg_handle);     /* same enum values */
	if (backing == PCACHE_BACKING_CORE)
		return PCACHE_MEM_NO_ARENA;           /* the core arena's tier */
	return arena->hbase ? (int)arena->htier : PCACHE_MEM_NO_ARENA;
}

int pcache_arena_backing(void)
{
	return backing;
}

const char *pcache_arena_backing_str(void)
{
	switch (backing) {
	case PCACHE_BACKING_CORE:
		return "core (HG_MALLOC shm arena cells)";
	case PCACHE_BACKING_OWN_HG:
		return "own arena managed by HG_MALLOC";
	default:
		return arena && arena->hbase ? "own slots in a dedicated reservation"
		                             : "own slots in shm";
	}
}

void pcache_arena_backing_notice(void)
{
	unsigned long committed, cap, live;

	switch (backing) {
	case PCACHE_BACKING_CORE:
		LM_NOTICE("memory backing IN USE: the core HG_MALLOC shm arena - "
			"every cache cell is an HG slab cell (classes, per-process "
			"caches, GC and re-typing, growth and maintenance are HG's); "
			"counted in core's shmem: stats%s\n",
			pcache_arena_hugepage_mb > 0 ? " (arena_hugepage_mb ignored "
			"under memory_backing=core)" : "");
		break;
	case PCACHE_BACKING_OWN_HG:
		mem_arena_usage(hg_handle, &committed, &cap, &live);
		LM_NOTICE("memory backing IN USE: a dedicated arena managed by "
			"HG_MALLOC - %lu MB committed, can grow to %lu MB%s; see "
			"hg_stats 'cachedb_perf'\n", committed >> 20, cap >> 20,
			pcache_arena_profile ? " under its auto-scaling profile" : "");
		break;
	default:
		if (pcache_arena_hugepage_mb > 0)
			LM_NOTICE("memory backing IN USE: a separate %d MB reservation, "
				"OUTSIDE OpenSIPS shared memory (arena_hugepage_mb), "
				"cachedb_perf's own slot allocator with reclaim (keep %d "
				"drained chunks per class, give back after %d s quiet / "
				"%d s cool-off%s)\n", pcache_arena_hugepage_mb,
				pcache_reclaim_keep, pcache_reclaim_quiet_s,
				pcache_reclaim_cooloff_s,
				pcache_reclaim_giveback ? "" : ", give-back OFF");
		else
			LM_NOTICE("memory backing IN USE: OpenSIPS shared memory "
				"(shm_malloc), cachedb_perf's own slot allocator with "
				"reclaim (keep %d drained chunks per class, pages back to "
				"shm after %d s quiet / %d s cool-off%s) - NOT a separate "
				"reservation; counted in core's own shmem: stats. Set "
				"arena_hugepage_mb to reserve a dedicated arena.\n",
				pcache_reclaim_keep, pcache_reclaim_quiet_s,
				pcache_reclaim_cooloff_s,
				pcache_reclaim_giveback ? "" : ", give-back OFF");
	}
}

static void pcache_arena_hg_capacity(int *active, unsigned long *total,
		unsigned long *used, unsigned long *free)
{
	unsigned long committed, cap, live;

	mem_arena_usage(hg_handle, &committed, &cap, &live);
	*active = 1;
	*total = cap;
	*used = live;
	*free = cap > live ? cap - live : 0;
}

/* the dedicated reservation: used = slots holding a chunk plus the index
 * regions cut from it (task C9: live slots, not the bump frontier) */
void pcache_arena_hugepage_capacity(int *active, unsigned long *total,
		unsigned long *used, unsigned long *free)
{
	unsigned long off, n = 0;
	pcache_chunk_t *ch;

	if (backing == PCACHE_BACKING_OWN_HG) {
		pcache_arena_hg_capacity(active, total, used, free);
		return;
	}
	if (backing != PCACHE_BACKING_OWN || !arena->hbase) {
		*active = 0;
		*total = 0;
		*used = 0;
		*free = 0;
		return;
	}
	lock_get(&arena->lock);
	for (off = 0; off < arena->hoff; off += PCACHE_SLOT) {
		ch = (pcache_chunk_t *)(arena->hbase + off);
		if (ch->cls != PCACHE_CLS_FREE)
			n++;
	}
	*active = 1;
	*total = arena->hsize;
	*used = n * PCACHE_SLOT + (arena->hsize - arena->rtop);   /* + the tables */
	*free = arena->hsize - *used;
	lock_release(&arena->lock);
}

/*
 * startup selftest (modparam "arena_selftest"): exercises class mapping,
 * the stamp/bound contract, LIFO reuse, chunk growth, sending cells home,
 * refill, extents, the oversize edge, and reclaim: drained chunks retire
 * beyond reclaim_keep and their slots are re-cut for another class.  Ends
 * by dropping the private state through pcache_arena_child_init(), the
 * fork-reset path - so that gets exercised too.
 */
#define CHK(cond, ...) \
	do { \
		if (!(cond)) { \
			LM_ERR("arena selftest FAILED: " __VA_ARGS__); \
			return -1; \
		} \
	} while (0)

int pcache_arena_selftest(void)
{
	void *a, *b, **ptrs;
	unsigned long lo, hi, by0, by1, retired0, retired1;
	unsigned int n0, n1, n2, n3, i, used0, warm;
	const unsigned int N = 5000;
	int c;

	if (backing != PCACHE_BACKING_OWN) {
		LM_NOTICE("arena selftest: skipped (%s)\n", pcache_arena_backing_str());
		return 0;
	}

	/* class mapping, stamp, bound, LIFO reuse, boundary crossing */
	for (c = 0; c < PCACHE_NCLASSES; c++) {
		a = pcache_cell_alloc(cell_sizes[c]);
		CHK(a != NULL, "alloc(%u) failed\n", cell_sizes[c]);
		CHK(*(unsigned char *)a == c, "class stamp %d != %d\n",
			*(unsigned char *)a, c);
		CHK(pcache_cell_bound(a) == cell_sizes[c],
			"bound %u != %u\n", pcache_cell_bound(a), cell_sizes[c]);
		CHK(cell_chunk(a)->cls == (unsigned int)c,
			"cell %p of class %d not in a class %d chunk\n", a, c, c);
		memset((char *)a + 1, 0xAB, cell_sizes[c] - 1);
		pcache_cell_free(a);
		b = pcache_cell_alloc(cell_sizes[c]);
		CHK(b == a, "no LIFO reuse in class %d\n", c);
		pcache_cell_free(b);
		if (c < PCACHE_NCLASSES - 1) {
			a = pcache_cell_alloc(cell_sizes[c] + 1);
			CHK(*(unsigned char *)a == c + 1,
				"size %u not in class %d\n", cell_sizes[c] + 1, c + 1);
			pcache_cell_free(a);
		}
	}

	/* oversize and zero */
	CHK(pcache_cell_alloc(PCACHE_CELL_MAX + 1) == NULL, "oversize passed\n");
	a = pcache_cell_alloc(0);
	CHK(a && *(unsigned char *)a == 0, "zero-size alloc broken\n");
	pcache_cell_free(a);

	/* bulk: multiple chunks, uniqueness, extents */
	ptrs = pkg_malloc(N * sizeof *ptrs);
	CHK(ptrs != NULL, "no pkg for the pointer array\n");
	pcache_arena_stats(&n0, &by0);
	for (i = 0; i < N; i++) {
		ptrs[i] = pcache_cell_alloc(64);
		if (!ptrs[i]) {
			pkg_free(ptrs);
			CHK(0, "bulk alloc %u failed\n", i);
		}
		*(unsigned int *)((char *)ptrs[i] + 8) = i;
	}
	pcache_arena_stats(&n1, &by1);
	CHK(n1 > n0, "no chunk growth over %u allocs\n", N);
	pcache_arena_extents(&lo, &hi);
	for (i = 0; i < N; i++) {
		CHK(*(unsigned int *)((char *)ptrs[i] + 8) == i,
			"cell %u overlapped\n", i);
		CHK((unsigned long)ptrs[i] >= lo &&
			(unsigned long)ptrs[i] + 64 <= hi,
			"cell %u outside the extents\n", i);
		CHK(((unsigned long)ptrs[i] & ~PCACHE_SLOT_MASK) >= PCACHE_CHUNK_HDR,
			"cell %u inside a chunk header\n", i);
	}
	for (i = 0; i < N; i++)
		pcache_cell_free(ptrs[i]);
	/* the private stack must have sent cells home past the threshold */
	CHK(arena->avail[0] != NULL, "nothing went home after %u frees\n", N);

	/* full reuse: no new chunks on the second pass (refill path) */
	for (i = 0; i < N; i++) {
		ptrs[i] = pcache_cell_alloc(64);
		if (!ptrs[i]) {
			pkg_free(ptrs);
			CHK(0, "realloc %u failed\n", i);
		}
	}
	pcache_arena_stats(&n2, &by1);
	CHK(n2 == n1, "reuse pass grew chunks: %u -> %u\n", n1, n2);
	for (i = 0; i < N; i++)
		pcache_cell_free(ptrs[i]);
	pkg_free(ptrs);

	/* reclaim: with everything home, a tick retires the drained class-0
	 * chunks beyond reclaim_keep, and the next carve of ANOTHER class
	 * re-cuts one of the freed slots (cross-class reuse) */
	pcache_arena_flush_private();
	used0 = arena->chunks_used;
	retired0 = arena->chunks_retired;
	pcache_arena_reclaim_tick();
	retired1 = arena->chunks_retired;
	CHK(retired1 > retired0, "no chunk retired after a full drain "
		"(%u chunks in use, reclaim_keep %d)\n", used0, pcache_reclaim_keep);
	CHK(arena->chunks_used + (retired1 - retired0) == used0,
		"retire accounting: %u used + %lu retired != %u\n",
		arena->chunks_used, retired1 - retired0, used0);
	warm = arena->nfree_warm;
	CHK(warm >= retired1 - retired0, "retired slots not on the warm list "
		"(%u warm)\n", warm);
	/* the largest class holds 3 cells per slot and owns exactly one chunk
	 * here: the 4th allocation must cut a new chunk, and that cut must
	 * take a retired slot (warm count down by one), stamped for ITS class */
	{
		void *big[4];
		unsigned int bc = PCACHE_NCLASSES - 1;

		for (i = 0; i < 4; i++) {
			big[i] = pcache_cell_alloc(cell_sizes[bc]);
			CHK(big[i] != NULL, "alloc %u of %u after retire failed\n",
				i, cell_sizes[bc]);
			CHK(cell_chunk(big[i])->cls == bc &&
			    *(unsigned char *)big[i] == bc,
				"cell %u of class %u in a class %u chunk\n", i, bc,
				cell_chunk(big[i])->cls);
		}
		CHK(arena->nfree_warm == warm - 1, "the carve did not take a "
			"retired slot (%u -> %u warm)\n", warm, arena->nfree_warm);
		CHK(cell_chunk(big[3]) != cell_chunk(big[0]),
			"4th cell of %u came from the same chunk\n", cell_sizes[bc]);
		for (i = 0; i < 4; i++)
			pcache_cell_free(big[i]);
	}
	pcache_arena_stats(&n3, &by1);

	/* fork-reset path: drop the private state, then allocate fresh */
	pcache_arena_child_init();
	CHK(my_palloc == NULL, "child reset kept state\n");
	a = pcache_cell_alloc(64);
	CHK(a != NULL, "alloc after child reset failed\n");
	pcache_cell_free(a);

	LM_NOTICE("arena selftest: PASS (%u chunks after reclaim of %lu, "
		"%lu bytes, %d classes)\n", n3, retired1 - retired0, by1,
		PCACHE_NCLASSES);
	return 0;
}
