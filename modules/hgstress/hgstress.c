/*
 * hgstress - multi-process shm allocator soak test
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

/*
 * A throwaway stress module (not for production) that hammers the *shared*
 * memory allocator from every forked worker at once and detects the failure
 * mode that unit-style tests miss: the same cell being handed to two
 * different processes.
 *
 * Method - each worker, after fork:
 *   1. allocates a block and stamps EVERY 8-byte word of it with a value
 *      derived from its own pid and the block's slot/size;
 *   2. keeps the block live in a slot table and, on later passes, re-reads
 *      those words and checks they are still its own stamp.
 *
 * If two processes are ever given the same address, the second one's stamp
 * overwrites the first's, and the first detects a foreign pid on its next
 * verify pass. That is reported as a "torn" block - the direct, in-process
 * signature of a double hand-out, rather than waiting for the eventual
 * downstream segfault in unrelated code.
 *
 * Sizes deliberately span the small-cell size classes AND cross the 64K cap
 * into the large/coalescing tier, so both allocator paths are exercised and
 * blocks are freed in a scattered order to force coalescing and reuse.
 *
 * Load with "modparam(hgstress, ...)" tuning and watch for the per-worker
 * PASS/FAIL notice; the run aborts startup with -1 on any failure so a
 * scripted test can just check the exit status.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"

#define HGS_MAX_SLOTS 4096

static int hgs_slots  = 512;      /* live blocks held per worker */
static int hgs_iters  = 200000;   /* alloc/free ops per worker */
static int hgs_verify = 2000;     /* full verify sweep every N ops */
static int hgs_large  = 64;       /* 1-in-N allocations exceed the cell cap */

struct hgs_shared {
	gen_lock_t lock;
	int workers;
	int failed;
	unsigned long long ops;
	unsigned long long torn;
};

static struct hgs_shared *shared;

struct hgs_blk {
	char *p;
	unsigned long len;
};

/* the stamp is per (pid, slot) so a foreign writer is identifiable, and it is
 * written to EVERY word - a partial overlap is caught as readily as a whole
 * one.
 *
 * Fixed at 64 bits (not "unsigned long") on purpose: the pid is packed into
 * the upper half and recovered with a >> 32 in hgs_check() below, which is
 * undefined behaviour the moment "unsigned long" is only 32 bits, as it is
 * on i386 - the shift silently loses the whole pid and the diagnostic prints
 * garbage instead of naming the foreign writer. uint64_t keeps the packing
 * well-defined on every width the allocator itself supports. */
static inline uint64_t hgs_stamp(int pid, int slot)
{
	return ((uint64_t)pid << 32) ^ (uint64_t)(slot * 2654435761u);
}

static void hgs_fill(struct hgs_blk *b, int pid, int slot)
{
	uint64_t v = hgs_stamp(pid, slot), *w = (uint64_t *)b->p;
	unsigned long i, n = b->len / sizeof(uint64_t);

	for (i = 0; i < n; i++)
		w[i] = v;
}

/* returns the number of corrupted words */
static unsigned long hgs_check(struct hgs_blk *b, int pid, int slot)
{
	uint64_t v = hgs_stamp(pid, slot), *w = (uint64_t *)b->p;
	unsigned long i, n = b->len / sizeof(uint64_t), bad = 0;

	for (i = 0; i < n; i++)
		if (w[i] != v) {
			if (bad == 0)
				LM_CRIT("torn block: slot %d len %lu word %lu: "
					"got 0x%"PRIx64" want 0x%"PRIx64
					" (foreign pid %"PRId64")\n",
					slot, b->len, i, w[i], v,
					(int64_t)(w[i] >> 32));
			bad++;
		}
	return bad;
}

static unsigned long hgs_pick_size(unsigned int *seed)
{
	/* small: spread across the size classes, incl. the sub-64B and the
	 * class-boundary sizes; large: past the 64K cell cap */
	if (hgs_large > 0 && (rand_r(seed) % hgs_large) == 0)
		return 65536 + (rand_r(seed) % (512 * 1024));
	return 8 + (rand_r(seed) % 8000);
}

static int hgs_run(int rank)
{
	struct hgs_blk *blk;
	unsigned int seed;
	unsigned long torn = 0, ops = 0;
	int i, slot, pid = getpid();

	blk = pkg_malloc(hgs_slots * sizeof *blk);
	if (!blk) {
		LM_ERR("no pkg memory for the slot table\n");
		return -1;
	}
	memset(blk, 0, hgs_slots * sizeof *blk);
	seed = (unsigned int)pid ^ (unsigned int)rank;

	for (i = 0; i < hgs_iters; i++) {
		slot = rand_r(&seed) % hgs_slots;

		if (blk[slot].p) {
			torn += hgs_check(&blk[slot], pid, slot);
			shm_free(blk[slot].p);
			blk[slot].p = NULL;
		} else {
			blk[slot].len = hgs_pick_size(&seed);
			blk[slot].p = shm_malloc(blk[slot].len);
			if (!blk[slot].p) {
				LM_ERR("shm_malloc(%lu) failed at op %d - increase -m\n",
					blk[slot].len, i);
				blk[slot].len = 0;
				continue;
			}
			hgs_fill(&blk[slot], pid, slot);
		}
		ops++;

		/* full sweep: catches a foreign write to a block this worker is
		 * holding but has not touched recently - the common case, since a
		 * double hand-out is usually noticed long after it happened */
		if (hgs_verify > 0 && (i % hgs_verify) == 0)
			for (slot = 0; slot < hgs_slots; slot++)
				if (blk[slot].p)
					torn += hgs_check(&blk[slot], pid, slot);
	}

	for (slot = 0; slot < hgs_slots; slot++)
		if (blk[slot].p) {
			torn += hgs_check(&blk[slot], pid, slot);
			shm_free(blk[slot].p);
		}
	pkg_free(blk);

	lock_get(&shared->lock);
	shared->workers++;
	shared->ops += ops;
	shared->torn += torn;
	if (torn)
		shared->failed = 1;
	lock_release(&shared->lock);

	if (torn) {
		LM_CRIT("hgstress worker %d (pid %d): FAIL - %lu torn words "
			"over %lu ops\n", rank, pid, torn, ops);
		return -1;
	}

	LM_NOTICE("hgstress worker %d (pid %d): PASS - %lu ops, 0 torn\n",
		rank, pid, ops);
	return 0;
}

static int mod_init(void)
{
	if (hgs_slots > HGS_MAX_SLOTS)
		hgs_slots = HGS_MAX_SLOTS;

	shared = shm_malloc(sizeof *shared);
	if (!shared) {
		LM_ERR("no shm memory for the shared result block\n");
		return -1;
	}
	memset(shared, 0, sizeof *shared);
	if (!lock_init(&shared->lock)) {
		LM_ERR("failed to init the result lock\n");
		return -1;
	}

	LM_NOTICE("hgstress armed: %d slots, %d iters, verify every %d, "
		"1-in-%d large\n", hgs_slots, hgs_iters, hgs_verify, hgs_large);
	return 0;
}

static int child_init(int rank)
{
	if (!is_worker_proc(rank))
		return 0;
	return hgs_run(rank);
}

static void mod_destroy(void)
{
	if (!shared)
		return;
	LM_NOTICE("hgstress TOTAL: %d workers, %llu ops, %llu torn -> %s\n",
		shared->workers, shared->ops, shared->torn,
		shared->failed ? "FAIL" : "PASS");
}

static const param_export_t params[] = {
	{ "slots",  INT_PARAM, &hgs_slots  },
	{ "iters",  INT_PARAM, &hgs_iters  },
	{ "verify", INT_PARAM, &hgs_verify },
	{ "large",  INT_PARAM, &hgs_large  },
	{ 0, 0, 0 }
};

struct module_exports exports = {
	"hgstress",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,           /* load function */
	NULL,        /* dependencies */
	NULL,        /* exported functions */
	NULL,        /* exported async functions */
	params,
	NULL,        /* exported statistics */
	NULL,        /* exported MI functions */
	NULL,        /* exported pseudo-variables */
	NULL,        /* exported transformations */
	NULL,        /* extra processes */
	NULL,        /* pre-init function */
	mod_init,
	NULL,        /* reply processing */
	mod_destroy,
	child_init,
	NULL         /* reload confirm */
};
