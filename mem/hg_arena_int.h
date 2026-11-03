/*
 * slab allocator with elastic arenas - helpers shared by the arena files
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

#ifndef HG_ARENA_INT_H
#define HG_ARENA_INT_H

/* internal to hg_arena.c, hg_pool.c, hg_cache.c and hg_stats.c: the cell and
 * block helpers and the slow paths they share; include after their headers */

unsigned int hg_gc_class(struct hg_block *hb, int c, unsigned int keep,
                             unsigned int limit);

int hg_gpool_push(struct hg_block *hb, int c, void *cell_start);

void *hg_gpool_pop(struct hg_block *hb, int c);

unsigned int hg_cache_bump_return(struct hg_block *hb, struct hg_palloc *pl,
                                  int c);

unsigned int hg_cache_flush_all(struct hg_block *hb, struct hg_palloc *pl,
                                int skip);

unsigned int hg_flush_residue(struct hg_block *hb,
                                         struct hg_palloc *pl, int c);

unsigned int hg_cache_flush_class(struct hg_block *hb,
                                      struct hg_palloc *pl, int c,
                                      unsigned int keep);


/* ~x1.5 ladder, all multiples of 32 so cells stay HG_ROUNDTO-aligned; total
 * slot sizes (header + payload). The four top powers of two are trimmed so
 * every block they get (header and slack aside) holds a whole number of
 * cells: 65536 left 3 of 4 cells in a 256 KB block */
static const unsigned int cell_sizes[HG_NCLASSES] = {
	64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048,
	3072, 4096, 6144, 8128, 12288, 16320, 24576, 32704, 49152, 65472
};
/* target cells per block, the unit of reclaim: fewer drain sooner, more mean
 * fewer carves. Re-measure how many blocks reach empty before raising it */
#define HG_CELLS_PER_BLOCK 32
/* left unused at a block's end: an overrun of its last cell then cannot reach
 * the next block's header (chunk, free-block or large-chunk links) */
#define HG_BLOCK_SLACK 32

/* a free cell's list link, private stacks and pool alike; takes @cell_start */
static inline void *cell_next(void *cell_start)
{
	/* via void *: the link is pointer-aligned (HG_ROUNDTO cells, a
	 * HG_CELL_HDR multiple); keeps -Wcast-align quiet on strict targets */
	return *(void **)(void *)((char *)cell_start + HG_CELL_HDR);
}

static inline void cell_set_next(void *cell_start, void *next)
{
	*(void **)(void *)((char *)cell_start + HG_CELL_HDR) = next;
}

/* resolve a cell to its block, refusing anything not a chunk of class @c:
 * writing in_gpool into a large-tier block would corrupt the large heap */
static inline struct hg_chunk *cell_block(struct hg_block *hb, int c, void *p)
{
	struct hg_chunk *ch = hg_buddy_block_of(hb, p);

	if (!ch) {
		LM_CRIT("%s: cell %p (class %d) is not on the arena's page grid - "
			"not touching it\n", hb->name, p, c);
		hg_corrupt(hb, HG_C_FOREIGN_PTR);
		return NULL;
	}
	if (ch->cls != (unsigned int)c) {
		LM_CRIT("%s: cell %p resolves to block %p of class %u, expected "
			"class %d - not touching it\n",
			hb->name, p, (void *)ch, ch->cls, c);
		hg_corrupt(hb, HG_C_CLASS_MISMATCH);
		return NULL;
	}
	/* the map index and the cell walk trust these */
	if (ch->cell_size != cell_sizes[c] || !ch->cells ||
	    ch->cells > HG_CHUNK_MAX_CELLS || ch->order > hb->buddy_top ||
	    sizeof(struct hg_chunk) + (unsigned long)ch->cells * ch->cell_size >
	    (HG_LEAF_SIZE << ch->order)) {
		LM_CRIT("%s: block %p (class %d) has a damaged header - cell size "
			"%u, %u cells, order %u; not touching it\n", hb->name,
			(void *)ch, c, ch->cell_size, ch->cells, ch->order);
		hg_corrupt(hb, HG_C_OVERFLOW);
		return NULL;
	}
	return ch;
}

/* a chunk-list link: NULL, or the start of a block on the page grid */
static inline int chunk_link_ok(struct hg_block *hb, struct hg_chunk *x)
{
	return !x || hg_buddy_block_of(hb, x) == (void *)x;
}

/* @ch's chunk-list neighbours point back at it: checked before an unlink or a
 * walk follows them */
static inline int chunk_links_ok(struct hg_block *hb, struct hg_chunk *ch)
{
	if (!chunk_link_ok(hb, ch->prev) || !chunk_link_ok(hb, ch->next))
		return 0;
	if (ch->prev ? ch->prev->next != ch : hb->chunks != ch)
		return 0;
	return !ch->next || ch->next->prev == ch;
}

static inline int map_test(const struct hg_chunk *ch, long i)
{
	return (int)((ch->gfree[i / HG_CHUNK_MAP_BITS] >> (i % HG_CHUNK_MAP_BITS)) & 1);
}

/* a chunk is claimed whole on its class's first use, so hb->chunk_max caps it
 * at a small fraction of the arena (21 x 256 KB would sink an 8 MB pkg) */
static inline unsigned int chunk_size_for(struct hg_block *hb, int c)
{
	unsigned int want, least = sizeof(struct hg_chunk) + HG_BLOCK_SLACK +
		cell_sizes[c] * 2;

	want = cell_sizes[c] * HG_CELLS_PER_BLOCK;
	if (want < HG_LEAF_SIZE)
		want = HG_LEAF_SIZE;

	if (want > hb->chunk_max)
		want = hb->chunk_max;
	/* ...but always enough for the header plus a couple of cells, or the
	 * class could never be served at all */
	if (want < least)
		want = least;
	return want;
}

#endif /* HG_ARENA_INT_H */
