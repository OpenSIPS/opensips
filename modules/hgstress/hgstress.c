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
#include "../../timer.h"
#include "../../mi/mi.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"

#define HGS_MAX_SLOTS 4096

static int hgs_slots  = 512;      /* live blocks held per worker */
static int hgs_iters  = 200000;   /* alloc/free ops per worker */
static int hgs_verify = 2000;     /* full verify sweep every N ops */
static int hgs_large  = 64;       /* 1-in-N allocations exceed the cell cap */
/*
 * v3 growth driver. Each worker first allocates and HOLDS hold_mb MB of
 * stamped 128-512K blocks before the churn starts, and keeps them stamped
 * through it. Size workers x hold_mb past -m and a fixed arena MUST report
 * allocation failures (the fail-first arm), while a capped arena MUST grow
 * to absorb it - with every worker already forked, which is the exact
 * cross-process-visibility property the v3 mechanism was chosen for. A
 * worker that SIGSEGVs touching grown space is the failure signature of
 * the broken (per-process page table) growth design.
 */
static int hgs_hold_mb = 0;       /* 0 = the classic churn-only soak */
/*
 * Same driver for the PKG arena. pkg is MAP_PRIVATE and per-process, so
 * there is no cross-process question to prove here - what this arm proves
 * is that the growth path executes for the private arena at all: every
 * worker grows its OWN arena past -M independently, and the stamps verify
 * the grown pages hold data. (The pkg cap multiplies by nproc in real
 * RAM - a rig concern too: 5 workers x the cap.)
 */
static int hgs_hold_pkg_mb = 0;
/*
 * Second cycle, for the shrink rig: at again_s seconds after startup a
 * TIMER job re-runs one hold/verify/free cycle of hold_mb - in the timer
 * process, which is fine for shm (the arena is shared; any process can
 * drive it). The window between the workers' child_init soak ending
 * (holds freed) and this cycle is where the shrink gate finds its quiet
 * ticks; the cycle then proves the punched range recommits and serves
 * stamped data again. 0 = off.
 */
static int hgs_again_s = 0;

struct hgs_shared {
	gen_lock_t lock;
	int workers;
	int failed;
	unsigned long long ops;
	unsigned long long torn;
	unsigned long long alloc_failed;   /* shm_malloc refusals, all workers */
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
 * uint64_t, not unsigned long. The stamp packs the pid into the high 32 bits
 * and a hash of the slot into the low 32, which needs a 64-bit type to exist
 * at all: on ILP32 "(unsigned long)pid << 32" shifts a 32-bit value by 32,
 * which is UNDEFINED BEHAVIOUR, not a truncation. Whatever gcc emitted, the
 * pid half was gone - so every worker's stamp collapsed to the slot hash
 * alone, the detector could no longer tell a foreign writer from its own
 * data, and the "foreign pid" it printed came from a second UB shift in the
 * diagnostic itself. On LP64, where unsigned long is already 64-bit, this
 * changes nothing whatsoever. */
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
					"got 0x%" PRIx64 " want 0x%" PRIx64
					" (foreign pid %" PRIu64 ")\n",
					slot, b->len, i, w[i], v,
					w[i] >> 32);
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
	struct hgs_blk *blk, *hold = NULL;
	unsigned int seed;
	unsigned long torn = 0, ops = 0, alloc_failed = 0;
	unsigned long held = 0;
	int nhold = 0, maxhold = 0;
	int i, slot, pid = getpid();

	blk = pkg_malloc(hgs_slots * sizeof *blk);
	if (!blk) {
		LM_ERR("no pkg memory for the slot table\n");
		return -1;
	}
	memset(blk, 0, hgs_slots * sizeof *blk);
	seed = (unsigned int)pid ^ (unsigned int)rank;

	/*
	 * Hold phase: pile up hold_mb MB of stamped 128-512K blocks and KEEP
	 * them. This is what pushes total demand past the initial arena while
	 * every worker is alive, so growth (or, in the fail-first arm, the
	 * exhaustion it replaces) happens under the exact conditions the
	 * mechanism is claimed to survive. The blocks stay in the verify
	 * sweeps: a stamp that survives in a page committed after this
	 * process forked is the pass criterion, a SIGSEGV here is the
	 * signature of growth that edited only the grower's page tables.
	 */
	if (hgs_hold_mb > 0) {
		maxhold = hgs_hold_mb * 8 + 8;   /* 128K min -> at most 8/MB */
		hold = pkg_malloc(maxhold * sizeof *hold);
		if (!hold) {
			LM_ERR("no pkg memory for the hold table\n");
			pkg_free(blk);
			return -1;
		}
		memset(hold, 0, maxhold * sizeof *hold);

		while (held < (unsigned long)hgs_hold_mb << 20 &&
		       nhold < maxhold) {
			hold[nhold].len = (128 << 10) +
				(rand_r(&seed) % (384 << 10));
			hold[nhold].p = shm_malloc(hold[nhold].len);
			if (!hold[nhold].p) {
				alloc_failed++;
				hold[nhold].len = 0;
				break;   /* the arena is done growing or fixed */
			}
			/* the hold table reuses the slot-stamp scheme, offset so
			 * a hold block and a churn block never share a stamp */
			hgs_fill(&hold[nhold], pid, HGS_MAX_SLOTS + nhold);
			held += hold[nhold].len;
			nhold++;
		}
		LM_NOTICE("hgstress worker %d (pid %d): holding %lu KB in %d "
			"blocks (%s)\n", rank, pid, held >> 10, nhold,
			alloc_failed ? "STOPPED by allocation failure" : "target met");
	}

	/*
	 * PKG hold: same idea, per-process arena. Allocate-and-stamp past -M,
	 * verify at the end, free. Runs before the shm churn so a pkg-side
	 * crash is attributable at a glance.
	 */
	if (hgs_hold_pkg_mb > 0) {
		struct hgs_blk *ph;
		unsigned long pheld = 0;
		int np = 0, pmax = hgs_hold_pkg_mb * 8 + 8;
		unsigned long ptorn = 0;

		ph = pkg_malloc(pmax * sizeof *ph);
		if (!ph) {
			LM_ERR("no pkg memory for the pkg-hold table\n");
			pkg_free(blk);
			if (hold)
				pkg_free(hold);
			return -1;
		}
		memset(ph, 0, pmax * sizeof *ph);
		while (pheld < (unsigned long)hgs_hold_pkg_mb << 20 &&
		       np < pmax) {
			ph[np].len = (128 << 10) + (rand_r(&seed) % (384 << 10));
			ph[np].p = pkg_malloc(ph[np].len);
			if (!ph[np].p) {
				alloc_failed++;
				ph[np].len = 0;
				break;
			}
			hgs_fill(&ph[np], pid, 2 * HGS_MAX_SLOTS + np);
			pheld += ph[np].len;
			np++;
		}
		for (i = 0; i < np; i++) {
			ptorn += hgs_check(&ph[i], pid, 2 * HGS_MAX_SLOTS + i);
			pkg_free(ph[i].p);
		}
		pkg_free(ph);
		torn += ptorn;
		LM_NOTICE("hgstress worker %d (pid %d): pkg hold %lu KB in %d "
			"blocks, %lu torn (%s)\n", rank, pid, pheld >> 10, np,
			ptorn, np && pheld >= (unsigned long)hgs_hold_pkg_mb << 20
			? "target met" : "STOPPED by allocation failure");
	}

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
				alloc_failed++;
				blk[slot].len = 0;
				continue;
			}
			hgs_fill(&blk[slot], pid, slot);
		}
		ops++;

		/* full sweep: catches a foreign write to a block this worker is
		 * holding but has not touched recently - the common case, since a
		 * double hand-out is usually noticed long after it happened.
		 * The hold blocks are swept too - they are the ones living in
		 * grown pages. */
		if (hgs_verify > 0 && (i % hgs_verify) == 0) {
			for (slot = 0; slot < hgs_slots; slot++)
				if (blk[slot].p)
					torn += hgs_check(&blk[slot], pid, slot);
			for (slot = 0; slot < nhold; slot++)
				if (hold[slot].p)
					torn += hgs_check(&hold[slot], pid,
					                  HGS_MAX_SLOTS + slot);
		}
	}

	for (slot = 0; slot < hgs_slots; slot++)
		if (blk[slot].p) {
			torn += hgs_check(&blk[slot], pid, slot);
			shm_free(blk[slot].p);
		}
	pkg_free(blk);

	/* final verify + release of the held load - the stamps have now
	 * survived the whole churn in place */
	for (slot = 0; slot < nhold; slot++)
		if (hold[slot].p) {
			torn += hgs_check(&hold[slot], pid,
			                  HGS_MAX_SLOTS + slot);
			shm_free(hold[slot].p);
		}
	if (hold)
		pkg_free(hold);

	lock_get(&shared->lock);
	shared->workers++;
	shared->ops += ops;
	shared->torn += torn;
	shared->alloc_failed += alloc_failed;
	if (torn)
		shared->failed = 1;
	lock_release(&shared->lock);

	if (torn) {
		LM_CRIT("hgstress worker %d (pid %d): FAIL - %lu torn words "
			"over %lu ops\n", rank, pid, torn, ops);
		return -1;
	}

	LM_NOTICE("hgstress worker %d (pid %d): PASS - %lu ops, 0 torn, "
		"%lu alloc failures\n", rank, pid, ops, alloc_failed);
	return 0;
}

static void hgs_again(unsigned int ticks, void *param)
{
	struct hgs_blk *hold;
	unsigned long held = 0, torn = 0;
	int n = 0, i, maxhold = hgs_hold_mb * 8 + 8, pid = getpid();
	unsigned int seed = (unsigned int)pid ^ 0xa9a1u;

	hold = pkg_malloc(maxhold * sizeof *hold);
	if (!hold) {
		LM_ERR("again-cycle: no pkg for the hold table\n");
		return;
	}
	memset(hold, 0, maxhold * sizeof *hold);
	while (held < (unsigned long)hgs_hold_mb << 20 && n < maxhold) {
		hold[n].len = (128 << 10) + (rand_r(&seed) % (384 << 10));
		hold[n].p = shm_malloc(hold[n].len);
		if (!hold[n].p)
			break;
		hgs_fill(&hold[n], pid, 3 * HGS_MAX_SLOTS + n);
		held += hold[n].len;
		n++;
	}
	for (i = 0; i < n; i++) {
		torn += hgs_check(&hold[i], pid, 3 * HGS_MAX_SLOTS + i);
		shm_free(hold[i].p);
	}
	pkg_free(hold);
	LM_NOTICE("hgstress AGAIN-CYCLE (pid %d): held %lu KB in %d blocks, "
		"%lu torn -> %s\n", pid, held >> 10, n, torn,
		torn == 0 && held >= (unsigned long)hgs_hold_mb << 20
		? "PASS" : (torn ? "FAIL" : "SHORT"));
}

/*
 * MI-driven persistent hold, for the autoscaling rig: the child_init soak
 * blocks the timer processes (no sweep ticks until every child finishes),
 * so proving PROACTIVE growth needs load applied from a normal running
 * process - an MI worker. hgs_hold allocates and parks stamped blocks
 * until hgs_release; both verify stamps.
 */
#define HGS_MI_MAX 4096
static struct hgs_blk hgs_mi_held[HGS_MI_MAX];
static int hgs_mi_n;

static mi_response_t *mi_hgs_hold(const mi_params_t *params,
                                  struct mi_handler *async_hdl)
{
	int mb, pid = getpid();
	unsigned int seed;
	unsigned long want, held = 0;

	if (get_mi_int_param(params, "mb", &mb) < 0 || mb <= 0)
		return init_mi_param_error();
	want = (unsigned long)mb << 20;
	seed = (unsigned int)pid ^ 0x5eed;

	while (held < want && hgs_mi_n < HGS_MI_MAX) {
		struct hgs_blk *b = &hgs_mi_held[hgs_mi_n];

		b->len = (128 << 10) + (rand_r(&seed) % (384 << 10));
		b->p = shm_malloc(b->len);
		if (!b->p)
			break;
		hgs_fill(b, pid, 5 * HGS_MAX_SLOTS + hgs_mi_n);
		held += b->len;
		hgs_mi_n++;
	}
	LM_NOTICE("hgstress MI-HOLD: +%lu KB (%d blocks total held)\n",
		held >> 10, hgs_mi_n);
	return init_mi_result_string(MI_SSTR("OK"));
}

static mi_response_t *mi_hgs_release(const mi_params_t *params,
                                     struct mi_handler *async_hdl)
{
	unsigned long torn = 0;
	int i, pid = getpid();

	for (i = 0; i < hgs_mi_n; i++) {
		torn += hgs_check(&hgs_mi_held[i], pid, 5 * HGS_MAX_SLOTS + i);
		shm_free(hgs_mi_held[i].p);
		hgs_mi_held[i].p = NULL;
	}
	LM_NOTICE("hgstress MI-RELEASE: %d blocks freed, %lu torn\n",
		hgs_mi_n, torn);
	hgs_mi_n = 0;
	return torn ? init_mi_error(500, MI_SSTR("torn")) :
	              init_mi_result_string(MI_SSTR("OK"));
}

static const mi_export_t mi_cmds[] = {
	{ "hgs_hold", "allocate and park N MB of stamped shm", 0, 0, {
		{mi_hgs_hold, {"mb", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{ "hgs_release", "verify and free everything hgs_hold parked", 0, 0, {
		{mi_hgs_release, {0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
	{EMPTY_MI_EXPORT},
};

static int mod_init(void)
{
	if (hgs_slots > HGS_MAX_SLOTS)
		hgs_slots = HGS_MAX_SLOTS;

	if (hgs_again_s > 0 &&
	    register_timer("hgstress-again", hgs_again, NULL,
	                   (unsigned int)hgs_again_s,
	                   TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("failed to register the again-cycle timer\n");
		return -1;
	}

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
		"1-in-%d large, hold %d MB/worker\n",
		hgs_slots, hgs_iters, hgs_verify, hgs_large, hgs_hold_mb);
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
	LM_NOTICE("hgstress TOTAL: %d workers, %llu ops, %llu torn, "
		"%llu alloc failures -> %s\n",
		shared->workers, shared->ops, shared->torn,
		shared->alloc_failed, shared->failed ? "FAIL" : "PASS");
}

static const param_export_t params[] = {
	{ "slots",   INT_PARAM, &hgs_slots   },
	{ "iters",   INT_PARAM, &hgs_iters   },
	{ "verify",  INT_PARAM, &hgs_verify  },
	{ "large",   INT_PARAM, &hgs_large   },
	{ "hold_mb",     INT_PARAM, &hgs_hold_mb     },
	{ "hold_pkg_mb", INT_PARAM, &hgs_hold_pkg_mb },
	{ "again_s",     INT_PARAM, &hgs_again_s     },
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
	mi_cmds,     /* exported MI functions */
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
