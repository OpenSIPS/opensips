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

/* soak test, not for production: workers stamp every word of their shm
 * blocks and re-verify, so a cell handed to two processes shows as "torn" */

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
static int hgs_fill_on   = 1;     /* 0 = no stamps: the allocator cost alone */
static int hgs_max_small = 8000;  /* small sizes are 8 .. 8 + max_small - 1 */
/* KB of pkg the parent takes in mod_init and keeps: forks every child with
 * the parent's pkg arena that full, e.g. under its headroom line */
static int hgs_parent_pkg_kb = 0;
/* growth driver: each worker holds hold_mb MB of stamped blocks through the
 * churn - past -m a fixed arena must fail, a capped one must grow */
static int hgs_hold_mb = 0;       /* 0 = the classic churn-only soak */
/* the same for the private pkg arena: each worker grows its own past -M
 * (RAM cost is nproc x the cap) */
static int hgs_hold_pkg_mb = 0;
/* shrink rig: again_s seconds after startup a timer job re-runs one hold
 * cycle, proving punched ranges recommit and serve data; 0 = off */
static int hgs_again_s = 0;

struct hgs_shared {
	gen_lock_t lock;
	int workers;
	int failed;
	unsigned long long ops;
	unsigned long long torn;
	unsigned long long alloc_failed;
};

static struct hgs_shared *shared;

struct hgs_blk {
	char *p;
	unsigned long len;
};

/* pid in the high 32 bits, slot hash in the low, written to EVERY word;
 * uint64_t, as a 32-bit unsigned long << 32 is undefined on ILP32 */
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
	if (hgs_large > 0 && (rand_r(seed) % hgs_large) == 0)
		return 65536 + (rand_r(seed) % (512 * 1024));
	return 8 + (rand_r(seed) % hgs_max_small);
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

	/* hold phase: a SIGSEGV here means growth edited only the grower's
	 * tables */
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
				break;   /* arena done growing, or fixed */
			}
			/* slot stamps, offset so a hold block and a churn
			 * block never share a stamp */
			hgs_fill(&hold[nhold], pid, HGS_MAX_SLOTS + nhold);
			held += hold[nhold].len;
			nhold++;
		}
		LM_NOTICE("hgstress worker %d (pid %d): holding %lu KB in %d "
			"blocks (%s)\n", rank, pid, held >> 10, nhold,
			alloc_failed ? "STOPPED by allocation failure" : "target met");
	}

	/* pkg hold: before the shm churn, so a pkg-side crash is attributable
	 * at a glance */
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
			if (hgs_fill_on)
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
			if (hgs_fill_on)
				hgs_fill(&blk[slot], pid, slot);
		}
		ops++;

		/* full sweep, incl. the hold blocks in grown pages: a double
		 * hand-out is usually noticed long after it happened */
		if (hgs_fill_on && hgs_verify > 0 && (i % hgs_verify) == 0) {
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
			if (hgs_fill_on)
				torn += hgs_check(&blk[slot], pid, slot);
			shm_free(blk[slot].p);
		}
	pkg_free(blk);

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

/* MI hold for the autoscaling rig: the child_init soak blocks the timers,
 * so proactive growth needs load from a running MI worker */
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

/* fault injection in the MI worker (double_free, scribble, overrun*); the
 * damage is seen at the next flush, or at the free with hg_mem_check */
static mi_response_t *mi_hgs_fault(const mi_params_t *params,
                                   struct mi_handler *async_hdl)
{
	str kind;
	char *a, *b;

	if (get_mi_string_param(params, "kind", &kind.s, &kind.len) < 0)
		return init_mi_param_error();
	if (kind.len == 11 && !memcmp(kind.s, "double_free", 11)) {
		a = shm_malloc(100);
		if (!a)
			return init_mi_error(500, MI_SSTR("no shm"));
		shm_free(a);
		shm_free(a);
		LM_NOTICE("hgstress FAULT: %p freed twice\n", a);
	} else if (kind.len == 8 && !memcmp(kind.s, "scribble", 8)) {
		a = shm_malloc(100);
		b = shm_malloc(100);
		if (!a || !b)
			return init_mi_error(500, MI_SSTR("no shm"));
		shm_free(a);
		shm_free(b);
		memset(a, 0xa5, 2 * sizeof(void *));
		LM_NOTICE("hgstress FAULT: link of freed %p overwritten (chain %p -> %p -> garbage)\n", a, b, a);
	} else if (kind.len >= 7 && !memcmp(kind.s, "overrun", 7)) {
		unsigned long n = 100, at = 100;
		int pkg = 0, re = 0;

		if (kind.len == 13 && !memcmp(kind.s, "overrun_large", 13)) {
			n = at = 100000;
		} else if (kind.len == 11 && !memcmp(kind.s, "overrun_pkg", 11)) {
			pkg = 1;
		} else if (kind.len == 15 && !memcmp(kind.s, "overrun_realloc", 15)) {
			re = 1;
			at = 60;
		} else if (kind.len != 7) {
			return init_mi_param_error();
		}
		a = pkg ? pkg_malloc(n) : shm_malloc(n);
		if (a && re)
			a = shm_realloc(a, at);
		if (!a)
			return init_mi_error(500, MI_SSTR("no memory"));
		a[at] = 0x5a;
		LM_NOTICE("hgstress FAULT: byte %lu of %lu-byte %s %p written\n",
			at, at, pkg ? "pkg" : "shm", a);
		if (pkg)
			pkg_free(a);
		else
			shm_free(a);
	} else {
		return init_mi_param_error();
	}
	return init_mi_result_string(MI_SSTR("OK"));
}

static const mi_export_t mi_cmds[] = {
	{ "hgs_fault", "inject a double free, a scribbled link or a one-byte overrun", 0, 0, {
		{mi_hgs_fault, {"kind", 0}},
		{EMPTY_MI_RECIPE}}, {0}
	},
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
	if (hgs_max_small < 1)
		hgs_max_small = 1;
	if (hgs_parent_pkg_kb > 0) {
		struct mem_info info;
		long held = 0;

		while (held < (long)hgs_parent_pkg_kb << 10) {
			if (!pkg_malloc(16 << 10))
				break;
			held += 16 << 10;
		}
		memset(&info, 0, sizeof info);
#ifdef pkg_info
		pkg_info(&info);
#endif
		LM_NOTICE("hgstress parent pkg hold: %ld KB kept (asked %d KB); "
			"pkg %lu KB, %lu KB free\n", held >> 10, hgs_parent_pkg_kb,
			info.total_size >> 10, info.free >> 10);
	}

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
	{ "fill",      INT_PARAM, &hgs_fill_on   },
	{ "max_small", INT_PARAM, &hgs_max_small },
	{ "parent_pkg_kb", INT_PARAM, &hgs_parent_pkg_kb },
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
