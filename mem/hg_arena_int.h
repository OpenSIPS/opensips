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

unsigned int hg_cache_flush_locked(struct hg_block *hb,
                                       struct hg_palloc *pl);

unsigned int hg_flush_residue(struct hg_block *hb,
                                         struct hg_palloc *pl, int c);

unsigned int hg_cache_flush_class(struct hg_block *hb,
                                      struct hg_palloc *pl, int c,
                                      unsigned int keep);


/* ~x1.5 ladder, all multiples of 32 so cells stay HG_ROUNDTO-aligned; total
 * slot sizes (header + payload) */
static const unsigned int cell_sizes[HG_NCLASSES] = {
	64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048,
	3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536
};
/*
 * Target cells per block. A block is the unit of reclaim: fewer cells drain
 * sooner, more mean fewer carves. Do not raise it without re-measuring how
 * many blocks reach empty.
 */
#define HG_CELLS_PER_BLOCK 32

/*
 * Free-list link, one convention for the private stacks and the shared pool:
 * both helpers take @cell_start (the hidden header) and keep the link at
 * cell_start + HG_CELL_HDR: in the payload, never in the header, whichever
 * list owns the cell.
 */
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

/*
 * Resolve a cell to its block; refuse anything that is not a chunk of this
 * class. Large-tier blocks start with a struct hg_large_chunk, and writing
 * in_gpool there would corrupt the large heap.
 */
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
	return ch;
}

static inline int map_test(const struct hg_chunk *ch, long i)
{
	return (int)((ch->gfree[i / HG_CHUNK_MAP_BITS] >> (i % HG_CHUNK_MAP_BITS)) & 1);
}

/*
 * Chunk size scales with the arena: a chunk is claimed whole the first time
 * its class is touched, so a fixed 256 KB would cost 21 x 256 KB before the
 * first byte is served, which an 8 MB pkg arena cannot afford. hb->chunk_max
 * caps a chunk at a small fraction of the arena.
 */
static inline unsigned int chunk_size_for(struct hg_block *hb, int c)
{
	unsigned int want, least = sizeof(struct hg_chunk) + cell_sizes[c] * 2;

	/* HG_CELLS_PER_BLOCK cells, at least one buddy leaf: a block comes back
	 * only when every cell is free, so a block of thousands of small cells
	 * would essentially never drain */
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
