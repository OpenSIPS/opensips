/*
 * HG_MALLOC fuzz test against an independent shadow model
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

/*
 * A seeded random sequence of malloc / free / realloc / read-back, checked
 * after every step against a model that knows nothing of the allocator's
 * insides: its own table of live blocks, a stamp written into every byte of
 * each one, and a set of the live addresses. What it checks:
 *
 *   identity      no address is handed out while it is still live
 *   alignment     every block is 8-aligned
 *   non-overlap   and data integrity: each block reads back its own stamp
 *                 at every free, realloc and read-back, and all blocks are
 *                 read back every HGF_CHECK steps - two live blocks that
 *                 overlap cannot both keep their stamps
 *   realloc       the prefix both sizes share survives a move; a NULL
 *                 leaves the old block valid; to 0 bytes it is a free
 *   accounting    this process's live-fragment count in the arena moves by
 *                 exactly the model's count; its used bytes cover the bytes
 *                 the model asked for (a bound only - size classes round up)
 *   failure       on a capped arena: allocations do fail, nothing already
 *                 handed out is damaged by the failures, and after frees the
 *                 arena serves again
 *
 * Each run is one seed in one child; a failure prints the seed, the step
 * and the last HGF_LOG steps, and HG_FUZZ_SEED / HG_FUZZ_OPS in the
 * environment replay it. A seed that ever found a bug goes into
 * hgf_seeds[] for good.
 */

#ifdef HG_MALLOC

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../pt.h"
#include "../../mem/shm_mem.h"
#include "../../mem/hg_malloc.h"
#include "../../mem/hg_arena.h"
#include "../../mem/mem_arena.h"
#include "test_hg_malloc.h"
#include "test_hg_fuzz.h"

#define HGF_SLOTS   1024
#define HGF_SET     4096        /* live-address set: open addressing, 4x slots */
#define HGF_OPS     20000       /* steps per seed, unless HG_FUZZ_OPS */
#define HGF_CHECK   1024        /* full read-back and accounting, every N steps */
#define HGF_LOG     32

/* the seeds every run takes; a seed that found a bug is added here */
static const unsigned long long hgf_seeds[] = { 1, 2, 0x5eedULL };

struct hgf_blk {
	char         *p;
	unsigned long size;
	unsigned int  tag;
};

struct hgf_op {
	unsigned long n;
	char          op;
	int           slot;
	unsigned long size;
	void         *p;
};

struct hgf {
	unsigned long long rng, seed;
	unsigned long n, ops;
	struct hgf_blk blk[HGF_SLOTS];
	void *set[HGF_SET];
	unsigned int live, tag;
	unsigned long req;           /* bytes asked for, over the live blocks */
	struct hgf_op log[HGF_LOG];
	/* the allocator under test */
	struct hg_block *hb;
	void *(*alloc)(unsigned long);
	void (*free)(void *);
	void *(*realloc)(void *, unsigned long);
	int capped;                  /* NULL is a legal answer */
	unsigned long nulls;
	long frag0, used0;
};

static struct hgf F;

static mem_arena_t *hgf_arena;

static void *hgf_shm_alloc(unsigned long s) { return shm_malloc(s); }
static void hgf_shm_free(void *p) { shm_free(p); }
static void *hgf_shm_realloc(void *p, unsigned long s) { return shm_realloc(p, s); }
static void *hgf_ar_alloc(unsigned long s) { return mem_arena_malloc(hgf_arena, s); }
static void hgf_ar_free(void *p) { mem_arena_free(hgf_arena, p); }
static void *hgf_ar_realloc(void *p, unsigned long s)
{
	return mem_arena_realloc(hgf_arena, p, s);
}

/* splitmix64 */
static unsigned long long hgf_rnd(struct hgf *f)
{
	unsigned long long z = (f->rng += 0x9e3779b97f4a7c15ULL);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static inline unsigned char hgf_byte(unsigned int tag, unsigned long i)
{
	return (unsigned char)(tag * 151u + i * 7u + (i >> 9));
}

static void hgf_stamp(char *p, unsigned long size, unsigned int tag)
{
	unsigned long i;

	for (i = 0; i < size; i++)
		p[i] = (char)hgf_byte(tag, i);
}

/* the first of @len bytes that is not the stamp, or @len */
static unsigned long hgf_unstamped(const char *p, unsigned long len,
                                   unsigned int tag)
{
	unsigned long i;

	for (i = 0; i < len; i++)
		if ((unsigned char)p[i] != hgf_byte(tag, i))
			break;
	return i;
}

static void hgf_note(struct hgf *f, char op, int slot, unsigned long size,
                     void *p)
{
	struct hgf_op *o = &f->log[f->n % HGF_LOG];

	o->n = f->n;
	o->op = op;
	o->slot = slot;
	o->size = size;
	o->p = p;
}

static int hgf_fail(struct hgf *f, const char *what, void *p, unsigned long x)
{
	unsigned long k, first;

	LM_ERR("hg fuzz: seed %llu step %lu of %lu: %s (%p, %lu) - replay with "
		"HG_FUZZ_SEED=%llu HG_FUZZ_OPS=%lu\n", f->seed, f->n, f->ops, what,
		p, x, f->seed, f->n + 1);
	first = f->n >= HGF_LOG ? f->n - HGF_LOG + 1 : 0;
	for (k = first; k <= f->n; k++) {
		struct hgf_op *o = &f->log[k % HGF_LOG];

		if (o->n == k)
			LM_ERR("hg fuzz:   step %lu: %c slot %d size %lu -> %p\n",
				o->n, o->op, o->slot, o->size, o->p);
	}
	return -1;
}

/* --- the live-address set ---------------------------------------------- */

static unsigned int hgf_hash(const void *p)
{
	unsigned long long x = (unsigned long long)(unsigned long)p;

	x = (x ^ (x >> 33)) * 0xff51afd7ed558ccdULL;
	return (unsigned int)(x ^ (x >> 29)) & (HGF_SET - 1);
}

/* 0 if added, -1 if already there */
static int hgf_set_add(struct hgf *f, void *p)
{
	unsigned int i = hgf_hash(p);

	for (; f->set[i]; i = (i + 1) & (HGF_SET - 1))
		if (f->set[i] == p)
			return -1;
	f->set[i] = p;
	return 0;
}

/* backward-shift deletion keeps the probe chains whole */
static void hgf_set_del(struct hgf *f, void *p)
{
	unsigned int i = hgf_hash(p), j, h;

	for (; f->set[i] != p; i = (i + 1) & (HGF_SET - 1))
		if (!f->set[i])
			return;
	for (j = i;;) {
		f->set[i] = NULL;
		do {
			j = (j + 1) & (HGF_SET - 1);
			if (!f->set[j])
				return;
			h = hgf_hash(f->set[j]);
		} while (i <= j ? (i < h && h <= j) : (i < h || h <= j));
		f->set[i] = f->set[j];
		i = j;
	}
}

/* --- the steps ---------------------------------------------------------- */

static unsigned long hgf_size(struct hgf *f)
{
	unsigned int r = hgf_rnd(f) % 100;

	if (r < 1)
		return 0;
	if (r < 41)
		return 1 + hgf_rnd(f) % 256;
	if (r < 71)
		return 257 + hgf_rnd(f) % 3840;
	if (r < 86)
		return 4097 + hgf_rnd(f) % (60 * 1024);
	if (r < 96) {
		/* a class edge, give or take a byte - only the input is chosen
		 * with the allocator in mind, never the verdict */
		long s = (long)hg_cell_total_size(hgf_rnd(f) % HG_NCLASSES) -
			(long)HG_CELL_HDR + (long)(hgf_rnd(f) % 3) - 1;

		return s > 0 ? (unsigned long)s : 1;
	}
	return 64 * 1024 + hgf_rnd(f) % (448 * 1024);
}

static int hgf_check_blk(struct hgf *f, int s, const char *when)
{
	struct hgf_blk *b = &f->blk[s];
	unsigned long i = hgf_unstamped(b->p, b->size, b->tag);

	if (i != b->size)
		return hgf_fail(f, when, b->p, i);
	return 0;
}

static int hgf_alloc(struct hgf *f, int s)
{
	struct hgf_blk *b = &f->blk[s];
	unsigned long size = hgf_size(f);
	char *p = f->alloc(size);

	hgf_note(f, 'a', s, size, p);
	if (!p) {
		if (!f->capped)
			return hgf_fail(f, "NULL from an arena with room", NULL, size);
		f->nulls++;
		return 0;
	}
	if ((unsigned long)p & 7)
		return hgf_fail(f, "block not 8-aligned", p, size);
	if (hgf_set_add(f, p) < 0)
		return hgf_fail(f, "address handed out while still live", p, size);
	b->p = p;
	b->size = size;
	b->tag = ++f->tag;
	hgf_stamp(p, size, b->tag);
	f->live++;
	f->req += size;
	return 0;
}

static int hgf_free(struct hgf *f, int s)
{
	struct hgf_blk *b = &f->blk[s];

	hgf_note(f, 'f', s, b->size, b->p);
	if (hgf_check_blk(f, s, "block changed while live (at its free)") < 0)
		return -1;
	hgf_set_del(f, b->p);
	f->free(b->p);
	f->live--;
	f->req -= b->size;
	b->p = NULL;
	return 0;
}

static int hgf_realloc(struct hgf *f, int s)
{
	struct hgf_blk *b = &f->blk[s];
	unsigned long size = hgf_size(f), keep, i;
	char *q;

	hgf_note(f, 'r', s, size, b->p);
	if (hgf_check_blk(f, s, "block changed while live (at its realloc)") < 0)
		return -1;
	q = f->realloc(b->p, size);
	if (!size) {
		/* realloc to nothing frees the block and returns NULL, as it does
		 * with every OpenSIPS allocator */
		if (q)
			return hgf_fail(f, "realloc to 0 bytes returned a block", q, 0);
		hgf_set_del(f, b->p);
		f->live--;
		f->req -= b->size;
		b->p = NULL;
		return 0;
	}
	if (!q) {
		if (!f->capped)
			return hgf_fail(f, "realloc NULL from an arena with room",
				b->p, size);
		f->nulls++;
		/* a failed realloc leaves the block as it was */
		return hgf_check_blk(f, s, "block changed by a failed realloc");
	}
	keep = b->size < size ? b->size : size;
	i = hgf_unstamped(q, keep, b->tag);
	if (i != keep)
		return hgf_fail(f, "realloc lost the shared prefix", q, i);
	if ((unsigned long)q & 7)
		return hgf_fail(f, "realloc block not 8-aligned", q, size);
	hgf_set_del(f, b->p);
	if (hgf_set_add(f, q) < 0)
		return hgf_fail(f, "realloc returned an address still live", q, size);
	f->req += size;
	f->req -= b->size;
	b->p = q;
	b->size = size;
	b->tag = ++f->tag;
	hgf_stamp(q, size, b->tag);
	return 0;
}

/* every live block reads back, and this process's share of the arena's
 * counters moved exactly as the model did */
static int hgf_audit(struct hgf *f)
{
	struct hg_pstat *ps = hg_pstat_mine(f->hb);
	long frags = ps->fragments - f->frag0, used = ps->used - f->used0;
	int s;

	for (s = 0; s < HGF_SLOTS; s++)
		if (f->blk[s].p &&
		    hgf_check_blk(f, s, "block changed while live (audit)") < 0)
			return -1;
	if (frags != (long)f->live)
		return hgf_fail(f, "live fragments counted by the arena differ "
			"from the model's", NULL, (unsigned long)frags);
	if (used < (long)f->req)
		return hgf_fail(f, "used bytes below the bytes asked for", NULL,
			(unsigned long)used);
	return 0;
}

/* f->ops steps, the blocks left live */
static int hgf_steps(struct hgf *f)
{
	unsigned int r;
	int s;

	f->frag0 = hg_pstat_mine(f->hb)->fragments;
	f->used0 = hg_pstat_mine(f->hb)->used;
	for (f->n = 0; f->n < f->ops; f->n++) {
		r = hgf_rnd(f) % 100;
		s = hgf_rnd(f) % HGF_SLOTS;
		if (!f->blk[s].p) {
			if (hgf_alloc(f, s) < 0)
				return -1;
		} else if (r < 45) {
			if (hgf_free(f, s) < 0 || hgf_alloc(f, s) < 0)
				return -1;
		} else if (r < 80) {
			if (hgf_free(f, s) < 0)
				return -1;
		} else if (r < 95) {
			if (hgf_realloc(f, s) < 0)
				return -1;
		} else {
			hgf_note(f, 'v', s, f->blk[s].size, f->blk[s].p);
			if (hgf_check_blk(f, s, "block changed while live") < 0)
				return -1;
		}
		if (f->n % HGF_CHECK == HGF_CHECK - 1 && hgf_audit(f) < 0)
			return -1;
	}
	return hgf_audit(f);
}

/* the steps, then every block freed: the counters back where they began */
static int hgf_run(struct hgf *f)
{
	int s;

	if (hgf_steps(f) < 0)
		return -1;
	for (s = 0; s < HGF_SLOTS; s++)
		if (f->blk[s].p && hgf_free(f, s) < 0)
			return -1;
	return hgf_audit(f);
}

static void hgf_init(struct hgf *f, unsigned long long seed, unsigned long ops)
{
	memset(f, 0, sizeof *f);
	f->seed = f->rng = seed;
	f->ops = ops;
}

static unsigned long hgf_ops(void)
{
	const char *e = getenv("HG_FUZZ_OPS");

	return e && *e ? strtoul(e, NULL, 0) : HGF_OPS;
}

static int hgf_child_shm(void *arg)
{
	struct hgf *f = &F;

	hgf_init(f, *(unsigned long long *)arg, hgf_ops());
	f->hb = shm_block;
	f->alloc = hgf_shm_alloc;
	f->free = hgf_shm_free;
	f->realloc = hgf_shm_realloc;
	return hgf_run(f);
}

/*
 * A capped arena run into its cap: allocations fail and nothing handed out
 * is damaged by the failures; then half is freed and the arena must serve
 * again - under HG_MALLOC_DBG this is also the quarantine's drain-on-failure
 * path. A run that never reaches the cap proves nothing and fails.
 */
static int hgf_child_capped(void *arg)
{
	struct hgf *f = &F;
	unsigned long nulls;
	int s;
	char *p;

	hgf_init(f, *(unsigned long long *)arg, hgf_ops() / 4);
	f->hb = (struct hg_block *)hgf_arena;
	f->alloc = hgf_ar_alloc;
	f->free = hgf_ar_free;
	f->realloc = hgf_ar_realloc;
	f->capped = 1;
	if (hgf_steps(f) < 0)
		return -1;
	nulls = f->nulls;
	if (!nulls)
		return hgf_fail(f, "the capped arena never refused an allocation",
			NULL, f->req);
	for (s = 0; s < HGF_SLOTS; s += 2)
		if (f->blk[s].p && hgf_free(f, s) < 0)
			return -1;
	p = f->alloc(1024);
	if (!p)
		return hgf_fail(f, "the arena serves nothing after frees", NULL,
			f->req);
	f->free(p);
	for (s = 0; s < HGF_SLOTS; s++)
		if (f->blk[s].p && hgf_free(f, s) < 0)
			return -1;
	return hgf_audit(f);
}

void test_hg_fuzz(void)
{
	static unsigned long long seeds[sizeof hgf_seeds / sizeof hgf_seeds[0] + 1];
	const char *e = getenv("HG_FUZZ_SEED");
	unsigned int n = 0, i;
	char desc[64];

	if (e && *e)
		seeds[n++] = strtoull(e, NULL, 0);
	else
		for (i = 0; i < sizeof hgf_seeds / sizeof hgf_seeds[0]; i++)
			seeds[n++] = hgf_seeds[i];

	for (i = 0; i < n; i++) {
		snprintf(desc, sizeof desc, "hg fuzz %llu", seeds[i]);
		ok(hgt_in_child(desc, hgf_child_shm, &seeds[i]),
			"fuzz, seed %llu, %lu steps on shm: no address handed out "
			"twice, every block keeps its bytes, realloc keeps the prefix, "
			"the arena's counters follow the model", seeds[i], hgf_ops());
	}

	/* the capped arena: created here, before the fork, as a module's is */
	if (!hgf_arena)
		hgf_arena = shm_arena_create("hgfuzz", 4UL << 20, 8UL << 20);
	ok(hgf_arena && hgt_in_child("hg fuzz capped", hgf_child_capped,
		&seeds[0]), "fuzz, seed %llu, on an 8 MB-capped arena: allocations "
		"fail at the cap without damaging live blocks, and the arena serves "
		"again after frees", seeds[0]);
}

#endif /* HG_MALLOC */
