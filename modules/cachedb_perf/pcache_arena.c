/*
 * cachedb_perf - high-performance local memory cache
 *
 * Copyright (C) 2026 Yury Kirsanov
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <string.h>
#include <sys/mman.h>

#include "../../dprint.h"
#include "../../locking.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#include "pcache_arena.h"
#include "pcache_mem.h"

/* CP-20: MB to reserve for the huge-page arena; 0 = disabled (shm_malloc).
 * Set by the cachedb_perf "arena_hugepage_mb" modparam. */
int pcache_arena_hugepage_mb = 0;

/* ~x1.5 ladder, all multiples of 32 so cells stay 8-aligned */
static const unsigned int cell_sizes[PCACHE_NCLASSES] = {
	64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048,
	3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536
};

#define PCACHE_CHUNK_HDR      64
#define PCACHE_CHUNK_SMALL    (256 * 1024)  /* cells <= 8K share 256K chunks */
#define PCACHE_REFILL_BATCH   32            /* cells pulled from the global pool */
#define PCACHE_PRIVATE_MAX    256           /* private stack size that triggers */
#define PCACHE_DONATE         128           /*   donation of this many cells   */

typedef struct pcache_chunk {
	struct pcache_chunk *next;   /* global registry, append-only */
	unsigned int cls;            /* immutable */
	unsigned int cell_size;
	unsigned int cells;
	/* padded to PCACHE_CHUNK_HDR; cells follow */
} pcache_chunk_t;

typedef struct pcache_region {
	struct pcache_region *next;
	unsigned long size;
} pcache_region_t;

typedef struct pcache_arena {
	gen_lock_t lock;                        /* slow paths only */
	pcache_chunk_t *chunks;
	unsigned int nchunks;
	unsigned long bytes;
	pcache_region_t *regions;               /* raw index regions */
	void *gpool[PCACHE_NCLASSES];           /* global free cells */
	unsigned int gpool_n[PCACHE_NCLASSES];
	unsigned long lo, hi;                   /* extent watermarks */

	/* CP-20 huge-page reservation: a pre-fork, never-unmapped, 2M-aligned
	 * MAP_SHARED region.  Chunks bump from it lock-free (atomic hoff);
	 * shm_malloc is the fallback once it is exhausted or if reserve fails */
	char                 *hbase;
	unsigned long         hsize;
	volatile unsigned long hoff;
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

/* global pool ops - arena lock must be held */
static inline void gpool_push(int c, void *cell)
{
	cell_set_next(cell, arena->gpool[c]);
	arena->gpool[c] = cell;
	arena->gpool_n[c]++;
}

static inline void *gpool_pop(int c)
{
	void *cell = arena->gpool[c];

	if (cell) {
		arena->gpool[c] = cell_next(cell);
		arena->gpool_n[c]--;
	}
	return cell;
}

/*
 * THE CP-20 SEAM: every byte of arena memory funnels through here.
 * If a huge-page reservation exists, bump from it lock-free (the caller's
 * lock state varies - carve_chunk holds the arena lock, pcache_region_alloc
 * does not - so an atomic bump is the only safe choice here); otherwise, or
 * once it is exhausted, fall back to shm_malloc.  Memory is NEVER returned
 * while the server runs.
 */
static void *pcache_chunk_backing(size_t size)
{
	if (arena->hbase) {
		unsigned long asz = (size + 63) & ~63UL;   /* keep 64-aligned */
		unsigned long off = __atomic_fetch_add(&arena->hoff, asz,
			__ATOMIC_RELAXED);
		if (off + asz <= arena->hsize)
			return arena->hbase + off;
		/* exhausted: undo would race other bumpers, so just leave hoff
		 * past the end (further huge allocs also fall through) and use
		 * shm - correctness holds, we only lose the tail slack */
	}
	return shm_malloc(size);
}

static inline unsigned int chunk_size_for(int c)
{
	return cell_sizes[c] <= 8192 ? PCACHE_CHUNK_SMALL : cell_sizes[c] * 32;
}

/* carve a new chunk for class @c - arena lock must be held.
 * The class byte of every cell is stamped HERE, before the chunk is
 * reachable by anyone - immutable from birth, so a stale reader can
 * always trust it (DESIGN 3.2 copy-out rule 1). */
static int carve_chunk(int c, struct pcache_palloc *pl)
{
	pcache_chunk_t *ch;
	unsigned int size = chunk_size_for(c), i;
	char *cells;

	ch = pcache_chunk_backing(size);
	if (!ch) {
		LM_ERR("no more shm memory for a %u byte chunk (class %d)\n",
			size, c);
		return -1;
	}

	ch->cls = c;
	ch->cell_size = cell_sizes[c];
	ch->cells = (size - PCACHE_CHUNK_HDR) / cell_sizes[c];

	cells = (char *)ch + PCACHE_CHUNK_HDR;
	for (i = 0; i < ch->cells; i++)
		cells[(unsigned long)i * cell_sizes[c]] = (unsigned char)c;

	ch->next = arena->chunks;
	arena->chunks = ch;
	arena->nchunks++;
	arena->bytes += size;

	if ((unsigned long)ch < arena->lo)
		arena->lo = (unsigned long)ch;
	if ((unsigned long)ch + size > arena->hi)
		arena->hi = (unsigned long)ch + size;

	/* the whole chunk belongs to the carving process */
	pl->cls[c].bump = cells;
	pl->cls[c].left = ch->cells;

	LM_DBG("class %d: new %u byte chunk, %u cells of %u\n",
		c, size, ch->cells, cell_sizes[c]);
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
			LM_NOTICE("huge-page arena: %d MB on %s, %lu MB pinned\n",
				pcache_arena_hugepage_mb,
				pcache_mem_tier_str(arena->htier), arena->hlocked_mb);
		}
	}

	LM_DBG("arena ready: %d classes, %u B to %u B cells\n",
		PCACHE_NCLASSES, cell_sizes[0], cell_sizes[PCACHE_NCLASSES-1]);
	return 0;
}

void *pcache_region_alloc(size_t size)
{
	pcache_region_t *rg;
	unsigned long need = size + sizeof(pcache_region_t) + 64;
	char *aligned;

	rg = pcache_chunk_backing(need);
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
	if ((unsigned long)rg < arena->lo)
		arena->lo = (unsigned long)rg;
	if ((unsigned long)rg + need > arena->hi)
		arena->hi = (unsigned long)rg + need;
	lock_release(&arena->lock);

	return aligned;
}

void pcache_arena_destroy(void)
{
	pcache_chunk_t *ch, *next;
	pcache_region_t *rg, *rnext;

	if (!arena)
		return;

	/* blocks carved from the huge reservation are part of one mmap - they
	 * must be munmap'd as a whole (below), never shm_free'd individually */
#define IN_HARENA(_p) (arena->hbase && (char *)(_p) >= arena->hbase && \
	(char *)(_p) < arena->hbase + arena->hsize)

	for (rg = arena->regions; rg; rg = rnext) {
		rnext = rg->next;
		if (!IN_HARENA(rg))
			shm_free(rg);
	}
	for (ch = arena->chunks; ch; ch = next) {
		next = ch->next;
		if (!IN_HARENA(ch))
			shm_free(ch);
	}
	if (arena->hbase)
		munmap(arena->hbase, arena->hsize);
#undef IN_HARENA
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

	if (!pl)
		return;

	/*
	 * After fork every child holds a COW copy of the parent's private
	 * allocator state - the SAME bump pointer and the SAME free-list cell
	 * addresses.  A child must not keep them (two processes bumping one
	 * chunk would hand out the same cell), and it must NOT donate them to
	 * the global pool either: every child inherited the identical copy, so
	 * each would push the same physical cells, landing one cell on the free
	 * list N times - later popped by several processes at once and written
	 * through concurrently (the CP-16 corruption: a value byte overwrites a
	 * neighbour's class id, and the next free reads an impossible class).
	 *
	 * The leftover cells belong to the parent.  The child simply discards
	 * its inherited copy and starts empty, carving its own chunk on first
	 * use.  The parent keeps its own small hoard.
	 */
	my_palloc = NULL;
	pkg_free(pl);
}

void *pcache_cell_alloc(unsigned int size)
{
	struct pcache_palloc *pl;
	void *cell;
	unsigned int got;
	int c;

	if (size > PCACHE_CELL_MAX) {
		LM_DBG("%u bytes exceeds the largest cell (%d)\n",
			size, PCACHE_CELL_MAX);
		return NULL;
	}
	c = size2class[(size + 31) >> 5];

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

	/* slow path: refill from the global pool, else carve a chunk */
	lock_get(&arena->lock);
	for (got = 0; got < PCACHE_REFILL_BATCH; got++) {
		cell = gpool_pop(c);
		if (!cell)
			break;
		cell_set_next(cell, pl->cls[c].free_head);
		pl->cls[c].free_head = cell;
		pl->cls[c].nfree++;
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

	pl = get_palloc();
	if (!pl) {
		/* cannot even track it privately - hand it to the pool */
		pcache_cell_free_global(cell);
		return;
	}

	cell_set_next(cell, pl->cls[c].free_head);
	pl->cls[c].free_head = cell;
	pl->cls[c].nfree++;

	/* keep hoarding bounded: donate half once over the threshold */
	if (pl->cls[c].nfree > PCACHE_PRIVATE_MAX) {
		lock_get(&arena->lock);
		for (i = 0; i < PCACHE_DONATE; i++) {
			d = pl->cls[c].free_head;
			pl->cls[c].free_head = cell_next(d);
			pl->cls[c].nfree--;
			gpool_push(c, d);
		}
		lock_release(&arena->lock);
	}
}

void pcache_cell_free_global(void *cell)
{
	unsigned int c = *(unsigned char *)cell;

	lock_get(&arena->lock);
	gpool_push(c, cell);
	lock_release(&arena->lock);
}

unsigned int pcache_cell_bound(const void *cell)
{
	unsigned char c = *(const unsigned char *)cell;

	if (c >= PCACHE_NCLASSES)
		return 0;
	return cell_sizes[c];
}

void pcache_arena_extents(unsigned long *lo, unsigned long *hi)
{
	/* unlocked on purpose: both only ever grow outward.  A reader mixing
	 * a fresh lo with a stale hi sees a subset - the check then fails
	 * closed (treated as invalid) for a moment during a chunk carve */
	*lo = arena->lo;
	*hi = arena->hi;
}

void pcache_arena_stats(unsigned int *nchunks, unsigned long *bytes)
{
	lock_get(&arena->lock);
	*nchunks = arena->nchunks;
	*bytes = arena->bytes;
	lock_release(&arena->lock);
}

/* the tier the huge-page reservation actually got (CP-11 MEM_DEGRADED) -
 * distinct from pcache_mem.tier, which is the optimistic probe; with no
 * reservation (arena_hugepage_mb=0 or a failed reserve) the arena is plain
 * shm, reported as 4K */
int pcache_arena_tier(void)
{
	return arena->hbase ? (int)arena->htier : PCACHE_MEM_4K;
}


/*
 * startup selftest (modparam "arena_selftest"): exercises class mapping,
 * the stamp/bound contract, LIFO reuse, chunk growth, donation, refill,
 * extents and the oversize edge, on the pre-fork process.  Ends by
 * donating everything through pcache_arena_child_init(), which is the
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
	unsigned long lo, hi, by0, by1;
	unsigned int n0, n1, n2, i;
	const unsigned int N = 5000;
	int c;

	/* class mapping, stamp, bound, LIFO reuse, boundary crossing */
	for (c = 0; c < PCACHE_NCLASSES; c++) {
		a = pcache_cell_alloc(cell_sizes[c]);
		CHK(a != NULL, "alloc(%u) failed\n", cell_sizes[c]);
		CHK(*(unsigned char *)a == c, "class stamp %d != %d\n",
			*(unsigned char *)a, c);
		CHK(pcache_cell_bound(a) == cell_sizes[c],
			"bound %u != %u\n", pcache_cell_bound(a), cell_sizes[c]);
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
	}
	for (i = 0; i < N; i++)
		pcache_cell_free(ptrs[i]);

	/* the private stack must have donated past the threshold */
	CHK(arena->gpool_n[0] > 0, "no donation after %u frees\n", N);

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

	/* fork-reset path: donate everything, then allocate fresh */
	pcache_arena_child_init();
	CHK(my_palloc == NULL, "child reset kept state\n");
	a = pcache_cell_alloc(64);
	CHK(a != NULL, "alloc after child reset failed\n");
	pcache_cell_free(a);

	LM_NOTICE("arena selftest: PASS (%u chunks, %lu bytes, "
		"%d classes)\n", n2, by1, PCACHE_NCLASSES);
	return 0;
}
