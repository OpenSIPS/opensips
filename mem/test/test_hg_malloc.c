/*
 * HG_MALLOC unit tests
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

#include "test_hg_malloc.h"
#include "test_hg_fuzz.h"
#include "test_hg_memlimit.h"

#ifdef HG_MALLOC

#include <tap.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>

#include "../../dprint.h"
#include "../../pt.h"
#include "../../globals.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mem/hg_malloc.h"
#include "../../mem/hg_arena.h"
#include "../../mem/hg_buddy.h"
#include "../../mem/mem_arena.h"
#include "../../mem/hg_xfer.h"
#include "../../mem/hg_advise.h"
#include "../../mem/hg_large.h"
#include "../../mem/hg_dbg.h"
#include "../../shutdown.h"
#include "../../ipc.h"
#include "../../core_stats.h"
#include "../../lib/cJSON.h"
#include "../../mi/mi.h"
#include "../../mi/item.h"
#include "../../mi/mi_hg.h"

/* a fuzz seed has taken from 10 to over 30 s under an emulator (the qemu
 * cross-builds in CI); a child that dies is noticed as it exits, not here */
#define HGT_WAIT_US   (120 * 1000 * 1000)
#define HGT_STEP_US   (10 * 1000)

#define HGT_PASS  1
#define HGT_FAIL  2

static volatile int *hgt_verdict;
/* set by the parent once internal_fork() has returned, so a child that
 * exits early is not reported as "failed to initialize" */
static volatile int *hgt_go;

int hg_ut_selected(void)
{
	return (mem_allocator_pkg == MM_HG_MALLOC ||
	        mem_allocator_pkg == MM_HG_MALLOC_DBG) &&
	       (mem_allocator_shm == MM_HG_MALLOC ||
	        mem_allocator_shm == MM_HG_MALLOC_DBG);
}

static void hgt_fill(void *p, unsigned long len, unsigned char seed)
{
	unsigned char *c = p;
	unsigned long i;

	for (i = 0; i < len; i++)
		c[i] = (unsigned char)(seed + i * 31);
}

static int hgt_check(const void *p, unsigned long len, unsigned char seed)
{
	const unsigned char *c = p;
	unsigned long i;

	for (i = 0; i < len; i++)
		if (c[i] != (unsigned char)(seed + i * 31))
			return 0;
	return 1;
}

int hgt_in_child(char *desc, int (*fn)(void *), void *arg)
{
	const struct internal_fork_params ifp = {
		.proc_desc = desc,
		.flags = OSS_PROC_NO_IPC|OSS_PROC_NO_LOAD,
		.type = TYPE_NONE,
	};
	int idx, waited, gone = 0;
	pid_t pid;
	siginfo_t si;

	*hgt_verdict = 0;
	*hgt_go = 0;
	fflush(stdout);
	idx = internal_fork(&ifp);
	if (idx < 0) {
		LM_ERR("failed to fork the '%s' child\n", desc);
		return 0;
	}

	if (idx == 0) {
		for (waited = 0; !__atomic_load_n(hgt_go, __ATOMIC_ACQUIRE) &&
		        waited < HGT_WAIT_US; waited += HGT_STEP_US)
			usleep(HGT_STEP_US);
		/* release: all fn() wrote is visible before the verdict is */
		__atomic_store_n(hgt_verdict, fn(arg) == 0 ? HGT_PASS : HGT_FAIL,
			__ATOMIC_RELEASE);
		exit(0);
	}
	/* internal_fork() returns the child's process-table slot, not its pid;
	 * the child stored its pid there before its start-up completed */
	pid = pt[idx].pid;
	__atomic_store_n(hgt_go, 1, __ATOMIC_RELEASE);

	for (waited = 0; !__atomic_load_n(hgt_verdict, __ATOMIC_ACQUIRE) &&
	        waited < HGT_WAIT_US; waited += HGT_STEP_US) {
		/* exited (a zombie, WNOWAIT) or already reaped with SIGCHLD
		 * ignored; a verdict stored before exit() is visible below */
		si.si_pid = 0;
		if (pid > 0 &&
		        (waitid(P_PID, pid, &si, WEXITED|WNOHANG|WNOWAIT) < 0 ?
		        errno == ECHILD : si.si_pid == pid)) {
			gone = 1;
			break;
		}
		usleep(HGT_STEP_US);
	}

	if (__atomic_load_n(hgt_verdict, __ATOMIC_ACQUIRE) == 0) {
		if (gone) {
			LM_ERR("the '%s' child exited without a verdict - it crashed "
				"or aborted\n", desc);
		} else {
			/* or it goes on using the arenas during the next test, and
			 * its late verdict is taken for that test's */
			if (pid > 0) {
				kill(pid, SIGKILL);
				while (waitid(P_PID, pid, &si, WEXITED|WNOWAIT) < 0 &&
				        errno == EINTR)
					;
			}
			LM_ERR("the '%s' child gave no verdict within %d s%s\n", desc,
				HGT_WAIT_US / 1000000, pid > 0 ? " - killed it" : "");
		}
		/* it may have died holding an arena lock: the next allocation
		 * here would hang the job, so stop the run */
		ok(0, "the '%s' child crashed or hung - stopping the run", desc);
		fflush(stdout);
		shutdown_opensips(1);
	}

	return *hgt_verdict == HGT_PASS;
}

/* pkg memory allocated before fork() lives in the inherited arena, not
 * the child's own: the child must be able to realloc and free it */
#define HGT_PF_A  1000
#define HGT_PF_B  3000

struct hgt_prefork {
	void *a;
	void *b;
};

static int hgt_child_prefork(void *arg)
{
	struct hgt_prefork *pf = arg;
	char *q, *fresh;

	q = pkg_realloc(pf->a, 20000);
	if (!q) {
		LM_ERR("pkg_realloc() of a pre-fork pointer returned NULL\n");
		return -1;
	}
	if (!hgt_check(q, HGT_PF_A, 0x11)) {
		LM_ERR("pkg_realloc() of a pre-fork pointer lost its content\n");
		return -1;
	}
	pkg_free(q);

	pkg_free(pf->b);

	fresh = pkg_malloc(5000);
	if (!fresh) {
		LM_ERR("pkg_malloc() failed after freeing pre-fork pointers\n");
		return -1;
	}
	hgt_fill(fresh, 5000, 0x33);
	if (!hgt_check(fresh, 5000, 0x33))
		return -1;
	pkg_free(fresh);

	return 0;
}

static void test_hg_prefork_pkg(void)
{
	struct hgt_prefork pf;

	pf.a = pkg_malloc(HGT_PF_A);
	pf.b = pkg_malloc(HGT_PF_B);
	if (!pf.a || !pf.b) {
		ok(0, "pre-fork pkg allocations");
		return;
	}
	hgt_fill(pf.a, HGT_PF_A, 0x11);
	hgt_fill(pf.b, HGT_PF_B, 0x22);

	ok(hgt_in_child("hg pre-fork pkg", hgt_child_prefork, &pf),
		"a pkg pointer from before fork() can be realloc'ed and freed "
		"in the child");

	ok(hgt_check(pf.a, HGT_PF_A, 0x11) && hgt_check(pf.b, HGT_PF_B, 0x22),
		"the parent's pre-fork pkg memory is intact after the child freed "
		"its copies");

	pkg_free(pf.a);
	pkg_free(pf.b);
}

#define HGT_CELLS  2048

static void *hgt_cell[HGT_CELLS];
static unsigned long hgt_cell_len[HGT_CELLS];

static unsigned long hgt_size(int i)
{
	/* spread over 1 B .. 64 KB, every class boundary crossed */
	return 1 + ((unsigned long)i * 2654435761UL) % (64 * 1024);
}

static int hgt_alloc_cells(void)
{
	int i;

	for (i = 0; i < HGT_CELLS; i++) {
		hgt_cell_len[i] = hgt_size(i);
		hgt_cell[i] = shm_malloc(hgt_cell_len[i]);
		if (!hgt_cell[i]) {
			LM_ERR("shm_malloc(%lu) failed\n", hgt_cell_len[i]);
			while (--i >= 0)
				shm_free(hgt_cell[i]);
			return -1;
		}
		hgt_fill(hgt_cell[i], hgt_cell_len[i], (unsigned char)i);
	}
	return 0;
}

static int hgt_check_free_cells(void)
{
	int i, bad = 0;

	for (i = 0; i < HGT_CELLS; i++) {
		if (!hgt_check(hgt_cell[i], hgt_cell_len[i], (unsigned char)i))
			bad++;
		shm_free(hgt_cell[i]);
	}
	if (bad)
		LM_ERR("%d of %d shm cells lost their content\n", bad, HGT_CELLS);
	return bad ? -1 : 0;
}

static int hgt_child_free_cells(void *arg)
{
	int rc = hgt_check_free_cells();

	/* back to the pool before the verdict, so the parent can take them */
	hg_cache_drain_self();
	return rc;
}

static int hgt_ptr_cmp(const void *a, const void *b)
{
	const char *x = *(char * const *)a, *y = *(char * const *)b;

	return x < y ? -1 : x > y;
}

static void test_hg_cross_process_shm(void)
{
	static void *freed[HGT_CELLS];
	int i, reused = 0, intact;

	if (hgt_alloc_cells() != 0) {
		ok(0, "shm cells for the cross-process test");
		return;
	}
	memcpy(freed, hgt_cell, sizeof freed);
	qsort(freed, HGT_CELLS, sizeof *freed, hgt_ptr_cmp);

	ok(hgt_in_child("hg shm free", hgt_child_free_cells, NULL),
		"another process can free shm cells of every class");

	if (hgt_alloc_cells() != 0) {
		ok(0, "shm cells freed by another process are reused intact");
		return;
	}
	for (i = 0; i < HGT_CELLS; i++)
		if (bsearch(&hgt_cell[i], freed, HGT_CELLS, sizeof *freed,
		        hgt_ptr_cmp))
			reused++;
	intact = hgt_check_free_cells() == 0;
	ok(intact && reused > 0, "shm cells freed by another process are "
		"reused intact (%d of %d came back)", reused, HGT_CELLS);
}

static void test_hg_large(void)
{
	static const unsigned long sz[] = {
		128 * 1024, 1024 * 1024, 4 * 1024 * 1024 };
	unsigned int i, good = 0;
	char *p, *q;

	for (i = 0; i < sizeof sz / sizeof sz[0]; i++) {
		p = pkg_malloc(sz[i]);
		if (p) {
			hgt_fill(p, sz[i], (unsigned char)i);
			q = pkg_realloc(p, sz[i] * 2);
			if (q) {
				if (hgt_check(q, sz[i], (unsigned char)i))
					good++;
				pkg_free(q);
			} else {
				pkg_free(p);
			}
		}

		p = shm_malloc(sz[i]);
		if (p) {
			hgt_fill(p, sz[i], (unsigned char)(i + 7));
			q = shm_realloc(p, sz[i] * 2);
			if (q) {
				if (hgt_check(q, sz[i], (unsigned char)(i + 7)))
					good++;
				shm_free(q);
			} else {
				shm_free(p);
			}
		}
	}

	ok(good == 2 * sizeof sz / sizeof sz[0],
		"large pkg and shm allocations (128 KB - 8 MB) keep their content "
		"across realloc");
}

/* an INIT that is not a page multiple: the arena carves past INIT and its
 * size is the span, so "free" (size - carved) must not wrap */
#define HGT_FPI_INIT   (3UL << 20)
#define HGT_FPI_PIECE  (96 << 10)    /* the large tier, past 64 KB */
#define HGT_FPI_MAX    64

static void test_hg_free_past_init(void)
{
	static struct hg_block *a;
	struct mem_info mi;
	void *p[HGT_FPI_MAX];
	int n, i;

	if (!a)
		a = shm_arena_create("hgfpi", HGT_FPI_INIT, HGT_FPI_INIT);
	if (!a) {
		ok(0, "a %lu MB module arena", HGT_FPI_INIT >> 20);
		return;
	}
	if (a->span_end <= HGT_FPI_INIT) {
		skip(1, 1, "a %lu MB INIT is a page multiple here (%lu KB pages), "
			"nothing to carve past", HGT_FPI_INIT >> 20, a->hps >> 10);
		end_skip;
		return;
	}

	for (n = 0; n < HGT_FPI_MAX && a->real_used <= HGT_FPI_INIT; n++)
		if (!(p[n] = mem_arena_malloc(a, HGT_FPI_PIECE)))
			break;
	hg_info(a, &mi);
	ok(a->real_used > HGT_FPI_INIT && a->size == a->span_end &&
		mi.total_size == a->span_end && mi.free <= mi.total_size &&
		mi.free == a->span_end - a->real_used,
		"an arena with a %lu MB INIT on %lu KB pages carves past INIT "
		"(%lu KB carved), and its size is the %lu KB span, with free "
		"what is left of it", HGT_FPI_INIT >> 20, a->hps >> 10,
		a->real_used >> 10, a->span_end >> 10);
	for (i = 0; i < n; i++)
		if (p[i])
			mem_arena_free(a, p[i]);
}

/* the transfer-cache test's arena, reused by later tests: the registry has
 * few slots */
static struct hg_block *hgt_xfer_arena;

/* frees past priv_max park a chain, a refill after the private list runs dry
 * takes it, and a drain hands every parked cell back to its block */
#define HGT_XF_ARENA  (8UL << 20)
#define HGT_XF_SIZE   200
#define HGT_XF_MAX    1024

static void test_hg_xfer(void)
{
	struct hg_block *a;
	static unsigned int *p[HGT_XF_MAX];
	unsigned long puts0, gets0, drained0, gpool0;
	unsigned int c, n, i, bad = 0, parked, expect, left, k, j, none;

	if (!hgt_xfer_arena)
		hgt_xfer_arena = shm_arena_create("hgxfer", HGT_XF_ARENA,
			HGT_XF_ARENA);
	a = hgt_xfer_arena;
	if (!a) {
		ok(0, "a %lu MB module arena", HGT_XF_ARENA >> 20);
		return;
	}
	/* a class with no cell to cache takes the lock on every operation */
	for (none = 0, k = 0; k < HG_NCLASSES; k++)
		if (!a->priv_max[k])
			none++;
	ok(!none, "every class of a %lu MB shared arena keeps at least one cell "
		"in a thread's cache (%u classes had none)", HGT_XF_ARENA >> 20,
		none);
	c = a->size2class[(HGT_XF_SIZE + HG_ROUNDTO - 1) / HG_ROUNDTO];
	n = a->priv_max[c] * 3;
	if (!a->xfer[c].cap || n > HGT_XF_MAX || a->dbg || a->guard) {
		skip(1, 2, "class %u keeps %u cells, transfer cap %u: nothing to "
			"park here", c, a->priv_max[c], a->xfer[c].cap);
		end_skip;
		return;
	}
	puts0 = a->xfer_puts;
	gets0 = a->xfer_gets;
	drained0 = a->xfer_drained;

	for (i = 0; i < n; i++)
		p[i] = mem_arena_malloc(a, HGT_XF_SIZE);
	for (i = 0; i < n; i++)
		if (p[i])
			mem_arena_free(a, p[i]);
	for (i = 0; i < n; i++)
		if ((p[i] = mem_arena_malloc(a, HGT_XF_SIZE)))
			*p[i] = i;
	for (i = 0; i < n; i++)
		if (!p[i] || *p[i] != i)
			bad++;
	ok(!bad && a->xfer_puts > puts0 && a->xfer_gets > gets0,
		"%u frees and allocations of %u bytes go through the transfer "
		"cache (%lu chains parked, %lu taken), every cell distinct",
		n, HGT_XF_SIZE, a->xfer_puts - puts0, a->xfer_gets - gets0);
	for (i = 0; i < n; i++)
		if (p[i])
			mem_arena_free(a, p[i]);

	/* what is parked, counted from the slots before the drain: the drain's
	 * own return and counter move together and prove nothing */
	hg_lock_enter(a, HG_LK_STATS);
	for (expect = 0, k = 0; k < HG_NCLASSES; k++)
		for (j = 0; j < a->xfer[k].n; j++)
			expect += a->xfer[k].len[j];
	gpool0 = a->gpool_n[c];
	parked = hg_xfer_drain_all(a);
	for (left = 0, k = 0; k < HG_NCLASSES; k++)
		left += a->xfer[k].n;
	hg_lock_leave(a);
	ok(expect > 0 && parked == expect && !left &&
		a->xfer_drained - drained0 == parked && a->gpool_n[c] > gpool0,
		"a drain returns all %u parked cells to their blocks (%u parked "
		"by count)", parked, expect);
}

static void test_hg_size_bound(void)
{
	static const unsigned long sizes[] = {
		~0UL, ~0UL - 1, ~0UL / 2 + 1, ~0UL - 64 * 1024,
	};
	unsigned char *p, *q;
	unsigned int i, refused = 0, intact = 0, served = 0;

	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		if (!(q = shm_malloc(sizes[i])))
			refused++;
		else
			shm_free(q);
		if (!(q = pkg_malloc(sizes[i])))
			refused++;
		else
			pkg_free(q);
	}
	p = shm_malloc(100);
	if (p) {
		hgt_fill(p, 100, 0x5a);
		q = shm_realloc(p, ~0UL);
		if (!q) {
			refused++;
			intact = hgt_check(p, 100, 0x5a);
		} else {
			p = q;
		}
		shm_free(p);
	}
	p = pkg_malloc(100);
	if (p) {
		hgt_fill(p, 100, 0x6b);
		q = pkg_realloc(p, ~0UL);
		if (!q) {
			refused++;
			intact = intact && hgt_check(p, 100, 0x6b);
		} else {
			p = q;
		}
		pkg_free(p);
	}
	p = pkg_malloc(100);
	if (p) {
		served = 1;
		pkg_free(p);
	}
	ok(refused == 2 * sizeof sizes / sizeof sizes[0] + 2 && intact && served,
		"sizes near ULONG_MAX are refused by pkg and shm malloc and realloc, "
		"which leave the allocation intact (%u of %u refused), and the "
		"arenas serve normally after",
		refused, (unsigned int)(2 * sizeof sizes / sizeof sizes[0] + 2));
}

#define HGT_GROW_CHUNK  (1024 * 1024)
#define HGT_GROW_MAX    256

static void test_hg_grow(void)
{
	struct hg_block *hb = shm_block;
	void *p[HGT_GROW_MAX];
	unsigned long grows0, exh0, committed0;
	int i, n;

	if (!hg_shm_cap_bytes || hg_shm_cap_bytes <= hb->committed_min) {
		skip(1, 1, "shm arena is fixed (-m without INIT:CAP), growth not "
			"tested");
		end_skip;
		return;
	}

	grows0 = hb->grows;
	exh0 = hb->grows_exhaustion;
	committed0 = hb->committed_bytes;

	/* allocate until the arena grows; what is committed (more than INIT if
	 * the maintenance process grew it ahead) is used up first */
	for (n = 0; n < HGT_GROW_MAX; n++) {
		p[n] = shm_malloc(HGT_GROW_CHUNK);
		if (!p[n])
			break;
		hgt_fill(p[n], 64, (unsigned char)n);
		if (hb->grows_exhaustion != exh0)
			break;
	}
	if (n < HGT_GROW_MAX && p[n])
		n++;

	/* grows_exhaustion: the maintenance process's grow-ahead also moves
	 * grow_gen, and would pass for growth on demand */
	ok(hb->grows_exhaustion != exh0 && hb->committed_bytes > committed0,
		"an elastic shm arena grows on demand (%lu -> %lu MB, %lu grows, "
		"%lu on exhaustion)", committed0 >> 20, hb->committed_bytes >> 20,
		hb->grows - grows0, hb->grows_exhaustion - exh0);

	for (i = 0; i < n; i++)
		shm_free(p[i]);
}

#define HGT_SHRINK_BLK  (256UL * 1024)
#define HGT_SHRINK_MAX  512

static int hgt_child_pkg_shrink(void *arg)
{
	struct hg_block *pb = mem_block;
	void *p[HGT_SHRINK_MAX];
	unsigned long gen0, c0, grown, keep;
	int i, n;

	gen0 = pb->grow_gen;
	c0 = pb->committed_bytes;
	for (n = 0; n < HGT_SHRINK_MAX; n++) {
		p[n] = pkg_malloc(HGT_SHRINK_BLK);
		if (!p[n])
			break;
		if (pb->grow_gen != gen0) {
			n++;
			break;
		}
	}
	grown = pb->committed_bytes;
	if (pb->grow_gen == gen0 || grown <= c0) {
		LM_ERR("the pkg arena did not grow (%lu KB committed)\n", grown >> 10);
		for (i = 0; i < n; i++)
			pkg_free(p[i]);
		return -1;
	}
	keep = c0 * 5 / 8 / HGT_SHRINK_BLK;
	if (keep > (unsigned long)n)
		keep = n;
	for (i = keep; i < n; i++)
		pkg_free(p[i]);

	hg_lock_enter(pb, HG_LK_POLICY);
	for (i = 0; i < 16 && pb->committed_bytes >= grown; i++)
		hg_shrink_tick(pb);
	hg_lock_leave(pb);

	for (i = 0; i < (int)keep; i++)
		pkg_free(p[i]);
	if (pb->committed_bytes >= grown) {
		LM_ERR("the pkg arena did not shrink: %lu KB committed after growing "
			"from %lu KB, %lu KB live\n", pb->committed_bytes >> 10,
			c0 >> 10, (keep * HGT_SHRINK_BLK) >> 10);
		return -1;
	}
	return 0;
}

static void test_hg_pkg_shrink(void)
{
	struct hg_block *pb = mem_block;

	if (!pb || !hg_pkg_cap_bytes || hg_pkg_cap_bytes <= pb->committed_min) {
		skip(1, 1, "pkg arena is fixed (-M without INIT:CAP), shrink not "
			"tested");
		end_skip;
		return;
	}
	ok(hgt_in_child("hg pkg shrink", hgt_child_pkg_shrink, NULL),
		"a pkg arena that grew one step shrinks again with more live than "
		"a step plus four floors would leave room for");
}

static int hgt_child_inherited(void *arg)
{
	struct hg_block *own = mem_block, *copy = NULL;
	unsigned long committed, grows, floor;
	int i, fails = 0;

	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		struct hg_block *hb = hg_arena_reg[i].hb;

		if (hb && !hb->shared && hb != own)
			copy = hb;
	}
	if (!copy || !copy->inherited || own->inherited) {
		LM_ERR("no inherited pkg arena marked as such (copy %p, %d; own %d)\n",
			(void *)copy, copy ? copy->inherited : -1, own->inherited);
		return -1;
	}

	committed = copy->committed_bytes;
	grows = copy->grows;
	hg_lock_enter(copy, HG_LK_POLICY);
	floor = copy->reserve_floor;
	copy->reserve_floor = copy->buddy_free_leaves;
	hg_lock_leave(copy);
	hg_cache_flush_self();
	hg_lock_enter(copy, HG_LK_POLICY);
	copy->reserve_floor = floor;
	hg_lock_leave(copy);

	if (copy->committed_bytes != committed || copy->grows != grows) {
		LM_ERR("the inherited pkg arena grew: %lu -> %lu KB, %lu -> %lu "
			"grows\n", committed >> 10, copy->committed_bytes >> 10, grows,
			copy->grows);
		fails++;
	}
	return fails ? -1 : 0;
}

static void test_hg_inherited(void)
{
	struct hg_block *pb = mem_block;

	if (!pb || !hg_pkg_cap_bytes || hg_pkg_cap_bytes <= pb->committed_min) {
		skip(1, 1, "pkg arena is fixed (-M without INIT:CAP), inherited "
			"copy not tested");
		end_skip;
		return;
	}
	ok(hgt_in_child("hg inherited", hgt_child_inherited, NULL),
		"a child's copy of the parent's pkg arena is marked as inherited, "
		"and its sweep does not grow it even under its headroom line");
}

/* borrowed fields are restored under the lock: no other process sees them */
static void test_hg_grow_refusal_cause(void)
{
	struct hg_block *hb = shm_block;
	unsigned long refused = 0, up_bytes = 0;
	unsigned int why = 0, said = 0, dry_said = 0, active = 0;
	unsigned int why_dry = HG_GR_NONE, why_ceil = HG_GR_NONE;
	unsigned int want_ceil = HG_GR_PROFILE;
	int dry = 0, r_dry = 0, r_ceil = 0, skipped;

	hg_lock_enter(hb, HG_LK_OTHER);
	skipped = !hb->buddy_ready || hb->grow_inflight;
	if (!skipped) {
		refused = hb->grow_refused;
		why = hb->grow_refuse_why;
		said = hb->grow_refuse_said;
		dry_said = hb->pol_dry_said;
		active = hb->pol.active;
		up_bytes = hb->pol.up_bytes;
		dry = hg_autoscale_dry_run;

		hg_autoscale_dry_run = 1;
		hb->pol_dry_said = 1;          /* expected: no warning */
		r_dry = hg_buddy_grow_unlocks(hb, 4096, HG_GROW_EXHAUSTION);
		why_dry = hb->grow_refuse_why;
		hg_autoscale_dry_run = 0;

		hb->pol.active = 1;
		hb->pol.up_bytes = hb->committed_bytes;
		if (hb->committed_bytes == hb->hcap)
			want_ceil = HG_GR_CAP;
		hb->grow_refuse_said = 1;      /* expected: no notice */
		r_ceil = hg_buddy_grow_unlocks(hb, 4096, HG_GROW_EXHAUSTION);
		why_ceil = hb->grow_refuse_why;

		hg_autoscale_dry_run = dry;
		hb->pol.active = active;
		hb->pol.up_bytes = up_bytes;
		hb->pol_dry_said = dry_said;
		hb->grow_refuse_said = said;
		hb->grow_refuse_why = why;
		hb->grow_refused = refused;
	}
	hg_lock_leave(hb);

	skip(skipped, 1, "a grow was in flight: refusal causes not checked");
	ok(r_dry < 0 && why_dry == HG_GR_DRY_RUN && r_ceil < 0 &&
		why_ceil == want_ceil,
		"a refused grow records its cause: %s in dry-run mode (dry_run "
		"expected), %s at the ceiling (%s expected)",
		hg_grow_refusal_str(why_dry), hg_grow_refusal_str(why_ceil),
		hg_grow_refusal_str(want_ceil));
	end_skip;
}

#define MB(x) ((unsigned long)(x) << 20)

static void hgt_advise(struct hg_advice *a, int pkg, unsigned long init,
		unsigned long committed, unsigned long cap, unsigned long peak)
{
	memset(a, 0, sizeof *a);
	a->pkg = pkg;
	a->init = init;
	a->size = a->committed = committed;
	a->cap = cap;
	a->peak = peak;
	a->hps = MB(2);
}

static void test_hg_advise(void)
{
	struct hg_advice a;
	struct hg_block *hb = shm_block;

	/* an RGS on -m 128:512 that grew to 236 MB holding a 211 MB peak */
	hgt_advise(&a, 0, MB(128), MB(236), MB(512), 221618176UL);
	hg_advise_compute(&a);
	ok(a.elastic && a.peak_pct == 41 && !strcmp(a.verdict, "reasonable") &&
		a.rec_init_mb == 242 && a.rec_mb == 424,
		"hg_advise: an elastic arena is judged against its cap, not the "
		"committed size its growth follows (%u%%, %s, INIT %lu, cap %lu)",
		a.peak_pct, a.verdict, a.rec_init_mb, a.rec_mb);

	hgt_advise(&a, 0, MB(256), MB(256), MB(256), MB(200));
	hg_advise_compute(&a);
	ok(!a.elastic && a.peak_pct == 78 && a.rec_mb == 400 && !a.rec_init_mb &&
		!strcmp(a.verdict, "TIGHT - raise it before the next busy period"),
		"hg_advise: a fixed arena is judged against its size (%u%%, %s)",
		a.peak_pct, a.verdict);

	/* a profile shrank it below INIT; INIT is what stays pinned */
	hgt_advise(&a, 0, MB(192), MB(128), MB(384), MB(37));
	hg_advise_compute(&a);
	ok(a.elastic && a.peak_pct == 9 && a.rec_init_mb == 44 &&
		!strcmp(a.verdict, "INIT oversized - pinned from startup and never used"),
		"hg_advise: an elastic arena's INIT far above its peak is oversized, "
		"its unused cap is not (%s, INIT %lu)", a.verdict, a.rec_init_mb);

	/* a profile growing at 80% needs INIT = peak / 0.8 to stay put */
	hgt_advise(&a, 0, MB(64), MB(128), MB(512), MB(100));
	a.grow_pct = 80;
	hg_advise_compute(&a);
	ok(a.rec_init_mb == 126, "hg_advise: INIT clears the profile's grow "
		"line (%lu)", a.rec_init_mb);

	hgt_advise(&a, 1, MB(16), MB(24), MB(64), MB(20));
	a.nproc = 10;
	a.committed_all = MB(10 * 24);
	hg_advise_compute(&a);
	ok(a.margin == 3 && a.pinned_total_mb == 240 && a.rec_init_mb == 24 &&
		a.rec_total_mb == 240,
		"hg_advise: elastic pkg pins the sum of every process's arena "
		"(%lu MB) and recommends INIT per process (%lu MB)",
		a.pinned_total_mb, a.rec_init_mb);

	if (!hb)
		return;
	hg_advise_arena(hb, hb->max_real_used, 0, 0, 0, &a);
	ok(a.init == hb->init_bytes && a.committed == hb->committed_bytes &&
		a.cap == ((hb->pol.active && hb->pol.up_bytes) ? hb->pol.up_bytes :
		hb->hcap) && a.elastic == (a.cap > a.init),
		"hg_advise: the shm arena's INIT, committed size and cap reach the "
		"advice (%lu/%lu/%lu MB)", a.init >> 20, a.committed >> 20,
		a.cap >> 20);
}

/* a class only the exit test's child uses in the transfer-cache arena, so
 * its blocks drain exactly when that child's caches come back */
#define HGT_EXIT_SIZE   6000
#define HGT_EXIT_CELLS  100

static int hgt_child_exit(void *arg)
{
	struct hg_block *a = hgt_xfer_arena;
	void *p[HGT_EXIT_CELLS];
	int i;

	for (i = 0; i < HGT_EXIT_CELLS; i++) {
		p[i] = mem_arena_malloc(a, HGT_EXIT_SIZE);
		if (!p[i]) {
			LM_ERR("mem_arena_malloc(%d) failed\n", HGT_EXIT_SIZE);
			return -1;
		}
	}
	/* half back: cached cells, parked chains and a bump tail stay */
	for (i = 0; i < HGT_EXIT_CELLS; i += 2)
		mem_arena_free(a, p[i]);
	for (i = 1; i < HGT_EXIT_CELLS; i += 2)
		mem_arena_free(a, p[i]);
	/* the verdict first: the exit below does not return */
	__atomic_store_n(hgt_verdict, HGT_PASS, __ATOMIC_RELEASE);
	dynamic_process_final_exit();
	return 0;
}

/* every block of class @c in @a has all its cells pooled, the transfer
 * cache drained first (parked chains are the arena's, not a process's) */
static int hgt_class_pooled(struct hg_block *a, int c)
{
	struct hg_chunk *ch;
	int full = 1;

	hg_lock_enter(a, HG_LK_STATS);
	hg_xfer_drain_all(a);
	for (ch = a->chunks; ch; ch = ch->next)
		if ((int)ch->cls == c && ch->in_gpool != ch->cells)
			full = 0;
	hg_lock_leave(a);
	return full;
}

static void test_hg_exit_returns_cells(void)
{
	struct hg_block *a = hgt_xfer_arena;
	int waited, c, done = 0;

	if (!a) {
		ok(0, "a process leaving for good gives back its cells (no arena)");
		return;
	}
	c = a->size2class[(HGT_EXIT_SIZE + (a->dbg ? HG_DBG_TAIL : 0) +
		HG_ROUNDTO - 1) / HG_ROUNDTO];
	if (!hgt_in_child("hg exit", hgt_child_exit, NULL)) {
		ok(0, "a process leaving for good gives back its cells");
		return;
	}
	/* the drain runs after the verdict, as the child exits */
	for (waited = 0; !(done = hgt_class_pooled(a, c)) &&
	        waited < HGT_WAIT_US; waited += HGT_STEP_US)
		usleep(HGT_STEP_US);
	ok(done, "a process leaving for good gives back its cached cells and "
		"unused chunk tails: every block of its class is whole again");
}

/* every free large frag is on the list its size names, linked both ways,
 * and the map has a bit for each non-empty list and no other */
static int hgt_large_lists_ok(struct hg_block *hb, unsigned int *nfree)
{
	struct hg_lfrag *f, **pp;
	unsigned int b, want, n = 0;
	int good = 1;

	hg_lock_enter(hb, HG_LK_STATS);
	for (b = 0; b < HG_LARGE_BUCKETS; b++) {
		if (!!hb->large_free[b] != !!(hb->large_free_map & (1UL << b)))
			good = 0;
		for (pp = &hb->large_free[b], f = *pp; f && n < 100000;
		     pp = &f->nxt_free, f = *pp, n++) {
			want = (unsigned int)(HG_LARGE_BUCKETS - 1) -
			       (unsigned int)__builtin_clzl(f->size);
			if (f->prev != pp || want != b)
				good = 0;
		}
	}
	hg_lock_leave(hb);
	*nfree = n;
	return good;
}

/* frags of 70 KB with every other one freed, then requests that fit only
 * a higher list: each is served from the list its size needs */
#define HGT_LL_SMALL  (70 << 10)
#define HGT_LL_BIG    (300 << 10)
#define HGT_LL_N      12

static void test_hg_large_lists(void)
{
	struct hg_block *a = hgt_xfer_arena;
	void *p[HGT_LL_N], *q[3];
	unsigned int i, nfree = 0, mid_free = 0, bad = 0;
	int mid_ok, end_ok;

	if (!a) {
		ok(0, "large free lists (no module arena)");
		return;
	}
	for (i = 0; i < HGT_LL_N; i++)
		if ((p[i] = mem_arena_malloc(a, HGT_LL_SMALL)))
			hgt_fill(p[i], HGT_LL_SMALL, (unsigned char)i);
	for (i = 0; i < HGT_LL_N; i += 2)
		if (p[i]) {
			mem_arena_free(a, p[i]);
			p[i] = NULL;
		}
	for (i = 0; i < 3; i++)
		if ((q[i] = mem_arena_malloc(a, i ? HGT_LL_BIG : HGT_LL_SMALL / 2)))
			hgt_fill(q[i], i ? HGT_LL_BIG : HGT_LL_SMALL / 2,
				(unsigned char)(100 + i));
	mid_ok = hgt_large_lists_ok(a, &mid_free);

	for (i = 1; i < HGT_LL_N; i += 2)
		if (!p[i] || !hgt_check(p[i], HGT_LL_SMALL, (unsigned char)i))
			bad++;
	for (i = 0; i < 3; i++)
		if (!q[i] || !hgt_check(q[i], i ? HGT_LL_BIG : HGT_LL_SMALL / 2,
		        (unsigned char)(100 + i)))
			bad++;
	for (i = 0; i < HGT_LL_N; i++)
		if (p[i])
			mem_arena_free(a, p[i]);
	for (i = 0; i < 3; i++)
		if (q[i])
			mem_arena_free(a, q[i]);
	end_ok = hgt_large_lists_ok(a, &nfree);

	ok(mid_ok && mid_free > 0 && bad == 0 && end_ok && nfree == 0 &&
		!a->large_chunks && a->large_free_map == 0,
		"large free frags sit on the list their size names, a request "
		"above a list's frags is served from a higher one, and every chunk "
		"returns once all is freed (%u free mid-way, %u bad, %u left)",
		mid_free, bad, nfree);
}

/* shm/pkg_shrink_cooldown: 600 s at least, in hg_scaling_cycle for shm and
 * the 30 s sweep for pkg; a module arena ignores both */
#define HGT_CD_DELAY 30

static void test_hg_shrink_cooldown(void)
{
	static const struct {
		int cycle, shm, pkg;
		int want_shm, want_pkg;
	} c[] = {
		{    1,    -1, -1, HGT_CD_DELAY, HGT_CD_DELAY },
		{    1,   599, -1,           -1, HGT_CD_DELAY },
		{    1,   600, 20,          600,           20 },
		{    1, 65535, 19,        65535,           -1 },
		{    7,    85, -1,           -1, HGT_CD_DELAY },
		{    7,    86, 20,           86,           20 },
		{   30,    19, -1,           -1, HGT_CD_DELAY },
		{   30,    20, 20,           20,           20 },
		{  600,     1, 19,            1,           -1 },
		{ 1000,     1, 21,            1,           21 },
	};
	int cycle = hg_scaling_cycle, shm = hg_shm_shrink_cooldown;
	int pkg = hg_pkg_shrink_cooldown;
	int got_shm, got_pkg, got_mod;
	unsigned int i, bad = 0;

	if (!hgt_xfer_arena) {
		ok(0, "shrink cooldown (no module arena)");
		return;
	}
	for (i = 0; i < sizeof c / sizeof c[0]; i++) {
		hg_scaling_cycle = c[i].cycle;
		hg_shm_shrink_cooldown = c[i].shm;
		hg_pkg_shrink_cooldown = c[i].pkg;
		got_shm = hg_shrink_cooldown(shm_block, HGT_CD_DELAY);
		got_pkg = hg_shrink_cooldown(NULL, HGT_CD_DELAY);
		got_mod = hg_shrink_cooldown(hgt_xfer_arena, HGT_CD_DELAY);
		if (got_shm != c[i].want_shm || got_pkg != c[i].want_pkg ||
		        got_mod != HGT_CD_DELAY) {
			LM_ERR("cooldown case %u (cycle %d s, shm %d, pkg %d): shm %d, "
				"pkg %d, module %d; want %d, %d, %d\n", i, c[i].cycle,
				c[i].shm, c[i].pkg, got_shm, got_pkg, got_mod,
				c[i].want_shm, c[i].want_pkg, HGT_CD_DELAY);
			bad++;
		}
	}
	hg_scaling_cycle = cycle;
	hg_shm_shrink_cooldown = shm;
	hg_pkg_shrink_cooldown = pkg;

	ok(bad == 0, "shm_shrink_cooldown and pkg_shrink_cooldown replace the "
		"profile's delay, refuse less than 600 s (rounded up to whole "
		"cycles; pkg at 30 s whatever hg_scaling_cycle is), and a module "
		"arena keeps its profile's (%u of %u cases wrong)", bad,
		(unsigned int)(sizeof c / sizeof c[0]));
}

/* a process's pkg figures reach the shared table at each publish; its peak
 * stays the worst after its slot is reset, as when it exits */
struct hgt_pub {
	unsigned long want;
	unsigned long peak;
	unsigned long committed;
	int proc;
};

static int hgt_child_pkg_pub(void *arg)
{
	struct hgt_pub *r = arg;
	struct hg_block *hb = mem_block;
	char *p = pkg_malloc(r->want);

	if (!p) {
		LM_ERR("pkg_malloc(%lu) failed\n", r->want);
		return -1;
	}
	hgt_fill(p, r->want, 9);
	pkg_free(p);
	hg_pkg_publish(hb);
	r->peak = hb->max_real_used;
	r->committed = hb->committed_bytes;
	r->proc = process_no;
	return 0;
}

static void test_hg_pkg_pub(void)
{
	struct hgt_pub *r = shm_malloc(sizeof *r);
	struct hg_pkg_worst w0, w1, w2;
	int ran;

	if (!r) {
		ok(0, "shm for the pkg publish test");
		return;
	}
	memset(r, 0, sizeof *r);
	hg_pkg_publish(mem_block);
	hg_pkg_pub_worst(&w0);
	/* above every peak published so far, so the child's is the worst */
	r->want = w0.peak + (2UL << 20);
	ran = r->want < (128UL << 20) &&
	      hgt_in_child("hg pkg publish", hgt_child_pkg_pub, r);
	hg_pkg_pub_worst(&w1);
	if (ran)
		hg_pkg_pub_reset(r->proc);
	hg_pkg_pub_worst(&w2);

	skip(r->want >= (128UL << 20), 1, "published peak too high (%lu MB) for "
		"the pkg publish test", w0.peak >> 20);
	ok(ran && w0.nproc > 0 && w1.peak == r->peak && w1.peak > w0.peak &&
		w1.nproc >= w0.nproc && w2.nproc == w1.nproc - 1 &&
		w2.peak == w1.peak &&
		w2.committed_all == w1.committed_all - r->committed,
		"a process's published pkg peak becomes the worst, its slot counts "
		"until reset, and the worst peak outlives the reset (peaks %lu -> "
		"%lu -> %lu KB, processes %d -> %d -> %d)", w0.peak >> 10,
		w1.peak >> 10, w2.peak >> 10, w0.nproc, w1.nproc, w2.nproc);
	end_skip;
	shm_free(r);
}

/* the dispatcher: this process flushes itself at its own second; a process
 * without IPC gets a request it polls; one with IPC gets the flush RPC */
#define HGT_SW_SIZE    2000
#define HGT_SW_CELLS   16
#define HGT_SW_EVERY   120   /* HG_SWEEP_INTERVAL x HG_SWEEP_FORCE_EVERY */

static unsigned int hgt_sweep_tick(int proc, unsigned int round)
{
	return round * HGT_SW_EVERY +
	       (unsigned int)proc * 2654435761u % 30;
}

struct hgt_sweep {
	int target;
	int ipc;      /* 1: leave the target's pipe, 0: hide it */
};

static int hgt_child_sweep(void *arg)
{
	struct hgt_sweep *s = arg;
	int fd = IPC_FD_WRITE(s->target);

	if (!s->ipc)
		pt[s->target].ipc_pipe[1] = -1;
	hg_cache_sweep(hgt_sweep_tick(s->target, 1), NULL);
	pt[s->target].ipc_pipe[1] = fd;
	return 0;
}

static void test_hg_sweep_dispatch(void)
{
	struct hg_block *a = hgt_xfer_arena;
	struct hgt_sweep *s = shm_malloc(sizeof *s);
	void *p[HGT_SW_CELLS];
	unsigned long g0, g1, g2;
	int c, i, pooled_before, pooled_after, req, req_again, rpc = -1;

	if (!a || !s) {
		ok(0, "sweep dispatcher (no module arena or shm)");
		if (s)
			shm_free(s);
		return;
	}
	c = a->size2class[(HGT_SW_SIZE + (a->dbg ? HG_DBG_TAIL : 0) +
		HG_ROUNDTO - 1) / HG_ROUNDTO];
	for (i = 0; i < HGT_SW_CELLS; i++)
		p[i] = mem_arena_malloc(a, HGT_SW_SIZE);
	for (i = 0; i < HGT_SW_CELLS; i++)
		if (p[i])
			mem_arena_free(a, p[i]);
	/* HG_MALLOC_DBG: the frees sit in quarantine, which the sweep leaves */
	if (a->dbg)
		hg_quarantine_drain(a);
	pooled_before = hgt_class_pooled(a, c);
	/* the class was used: the first flush keeps a residue, the next not */
	hg_cache_sweep(hgt_sweep_tick(process_no, 0), NULL);
	hg_cache_sweep(hgt_sweep_tick(process_no, 1), NULL);
	pooled_after = hgt_class_pooled(a, c);
	ok(!pooled_before && pooled_after, "the sweep flushes the dispatching "
		"process's own caches at its second of the interval");

	/* a child dispatches to this process with its pipe hidden */
	s->target = process_no;
	s->ipc = 0;
	g0 = __atomic_load_n(&hg_sweep_gen, __ATOMIC_RELAXED);
	req = hgt_in_child("hg sweep no-ipc", hgt_child_sweep, s) &&
	      hg_sweep_poll() == 1;
	req_again = hg_sweep_poll();
	g1 = __atomic_load_n(&hg_sweep_gen, __ATOMIC_RELAXED);
	ok(req && req_again == 0 && g1 == g0 + 1, "a process without IPC gets "
		"a sweep request it takes once at its next poll");

	/* ... and with its pipe: the flush comes as an RPC */
	if (IPC_FD_WRITE(process_no) > 0 && IPC_FD_READ(process_no) > 0) {
		s->ipc = 1;
		rpc = hgt_in_child("hg sweep ipc", hgt_child_sweep, s);
		if (rpc)
			ipc_handle_all_pending_jobs(IPC_FD_READ(process_no));
		g2 = __atomic_load_n(&hg_sweep_gen, __ATOMIC_RELAXED);
		rpc = rpc && g2 > g1;
	}
	skip(rpc < 0, 1, "this process has no IPC pipe: the RPC dispatch is "
		"not checked");
	ok(rpc == 1, "a process with IPC gets the flush as an RPC");
	end_skip;
	shm_free(s);
}

/* GROW-BLOCKED: a resource refusal arms, a refusal after a GC pass latches;
 * at the sweep an armed episode with new refusals latches, a quiet one is
 * disarmed. Host RAM is made short by the floor; all is restored */
static void test_hg_grow_blocked(void)
{
	struct hg_block *hb = shm_block;
	unsigned long refused, gc, refuse0, mark;
	unsigned int why, said, mlock_said, blocked, due;
	int floor = hg_ram_floor_mb, skipped;
	int armed1 = 0, held1 = 0, latched = 0, cleared = 0;
	int quiet_disarm = 0, tick_latch = 0;

	hg_lock_enter(hb, HG_LK_OTHER);
	skipped = !hb->buddy_ready || hb->grow_inflight || hb->grow_blocked ||
	          hb->grow_blocked_mark || hb->punched_pages ||
	          hb->tier == HG_MEM_HUGETLB || hb->committed_bytes >= hb->hcap;
	if (!skipped) {
		refused = hb->grow_refused;
		gc = hb->gc_passes;
		why = hb->grow_refuse_why;
		said = hb->grow_refuse_said;
		mlock_said = hb->grow_refuse_mlock;
		refuse0 = hb->grow_blocked_refuse0;
		mark = hb->grow_blocked_mark;
		blocked = hb->grow_blocked;
		due = hb->grow_event_due;
		hg_ram_floor_mb = INT_MAX;

		hg_buddy_grow_unlocks(hb, hb->hps, HG_GROW_EXHAUSTION);
		armed1 = hb->grow_blocked_mark && !hb->grow_blocked;
		hg_buddy_grow_unlocks(hb, hb->hps, HG_GROW_EXHAUSTION);
		held1 = !hb->grow_blocked;            /* no GC pass between */
		hb->gc_passes++;
		hg_buddy_grow_unlocks(hb, hb->hps, HG_GROW_EXHAUSTION);
		latched = hb->grow_blocked && hb->grow_event_due;
		hg_grow_unblock(hb, "unit test");
		cleared = !hb->grow_blocked && !hb->grow_blocked_mark &&
		          !hb->grow_event_due;

		hg_buddy_grow_unlocks(hb, hb->hps, HG_GROW_EXHAUSTION);
		hg_grow_blocked_tick(hb);
		quiet_disarm = !hb->grow_blocked && !hb->grow_blocked_mark;
		hg_buddy_grow_unlocks(hb, hb->hps, HG_GROW_EXHAUSTION);
		hg_buddy_grow_unlocks(hb, hb->hps, HG_GROW_EXHAUSTION);
		hg_grow_blocked_tick(hb);
		tick_latch = hb->grow_blocked && hb->grow_event_due;

		hg_ram_floor_mb = floor;
		hb->grow_refused = refused;
		hb->gc_passes = gc;
		hb->grow_refuse_why = why;
		hb->grow_refuse_said = said;
		hb->grow_refuse_mlock = mlock_said;
		hb->grow_blocked_refuse0 = refuse0;
		hb->grow_blocked_mark = mark;
		hb->grow_blocked = blocked;
		hb->grow_event_due = due;
	}
	hg_lock_leave(hb);

	skip(skipped, 1, "the shm arena cannot be refused a grow by host RAM "
		"here (hugetlb, at its cap, holes or an episode open)");
	ok(armed1 && held1 && latched && cleared && quiet_disarm && tick_latch,
		"GROW-BLOCKED arms at a resource refusal, latches after a GC pass "
		"or a sweep with new refusals, is disarmed by a quiet sweep and "
		"cleared by an unblock (%d %d %d %d %d %d)", armed1, held1, latched,
		cleared, quiet_disarm, tick_latch);
	end_skip;
}

/* the sweep's first second takes the grow-blocked and lock-stall events
 * that are due, whether or not anyone subscribed */
static void test_hg_sweep_events(void)
{
	struct hg_block *hb = shm_block;
	int stall_us = hg_lock_stall_us, stalled, consumed;
	unsigned long stalls;
	hg_ns_t t0;

	hg_lock_stall_us = 1;
	hg_lock_enter(hb, HG_LK_OTHER);
	stalls = hb->lk_stalls;
	t0 = hg_now_ns();
	while (hg_now_ns() - t0 < 50000)
		;
	hg_lock_leave(hb);
	hg_lock_stall_us = stall_us;

	hg_lock_enter(hb, HG_LK_OTHER);
	stalled = hb->lk_stall_event_due && hb->lk_stalls == stalls + 1;
	hb->grow_event_due = 1;
	hg_lock_leave(hb);

	hg_cache_sweep(HGT_SW_EVERY * 2, NULL);   /* the interval's 1st second */

	hg_lock_enter(hb, HG_LK_OTHER);
	consumed = !hb->lk_stall_event_due && !hb->grow_event_due;
	hg_lock_leave(hb);
	ok(stalled && consumed, "a lock hold past hg_lock_stall_us makes a "
		"lock-stall event due, and the sweep takes it and a due "
		"grow-blocked event (stalled %d, taken %d)", stalled, consumed);
}

/* core:hg_stats names each HG arena and reports its figures as they are */
static double hgt_mi_num(const mi_item_t *o, const char *name)
{
	const mi_item_t *n = o ? cJSON_GetObjectItem(o, name) : NULL;

	return n && (n->type & cJSON_Number) ? n->valuedouble : -1;
}

static void test_hg_mi_stats(void)
{
	struct hg_block *s = shm_block, *a = hgt_xfer_arena;
	mi_params_t params;
	mi_response_t *resp;
	mi_item_t *res, *shm, *pkg, *mod;
	int good;

	memset(&params, 0, sizeof params);
	resp = mi_hg_cmds[0].recipes[0].cmd(&params, NULL);
	res = resp ? cJSON_GetObjectItem(resp, JSONRPC_RESULT_S) : NULL;
	shm = res ? cJSON_GetObjectItem(res, "shm") : NULL;
	pkg = res ? cJSON_GetObjectItem(res, "pkg") : NULL;
	mod = res && a ? cJSON_GetObjectItem(res, a->name) : NULL;
	good = shm && pkg && (!a || mod) &&
	       hgt_mi_num(shm, "cap") == (double)s->hcap &&
	       hgt_mi_num(shm, "committed") == (double)s->committed_bytes &&
	       hgt_mi_num(shm, "grow_blocked") == (double)s->grow_blocked &&
	       hgt_mi_num(pkg, "cap") ==
	           (double)((struct hg_block *)mem_block)->hcap &&
	       hgt_mi_num(pkg, "pid") == (double)my_pid() &&
	       (!a || hgt_mi_num(mod, "cap") == (double)a->hcap) &&
	       hgt_mi_num(res, "cross_arena_frees_this_proc") >= 0;
	ok(!strcmp(mi_hg_cmds[0].name, "hg_stats") && good,
		"core:hg_stats reports the shm, pkg and module arenas with their "
		"cap, committed bytes and GROW-BLOCKED state");
	if (resp)
		free_mi_response(resp);
}

/* a block's last cell ends HG_BLOCK_SLACK (32) bytes before the next block,
 * and the top class fills its block */
static void test_hg_block_slack(void)
{
	struct hg_block *hb = shm_block;
	void *p = shm_malloc(40), *q = shm_malloc(60000);
	struct hg_chunk *ch = p ? hg_buddy_block_of(hb, HG_HDR(p)) : NULL;
	struct hg_chunk *ch2 = q ? hg_buddy_block_of(hb, HG_HDR(q)) : NULL;
	unsigned long used = 0, blk = 0, unused = 0, blk2 = 0;

	if (ch) {
		blk = HG_LEAF_SIZE << ch->order;
		used = sizeof(struct hg_chunk) + (unsigned long)ch->cells *
			ch->cell_size;
	}
	if (ch2) {
		blk2 = HG_LEAF_SIZE << ch2->order;
		unused = blk2 - sizeof(struct hg_chunk) -
			(unsigned long)ch2->cells * ch2->cell_size;
	}
	ok(ch && used + 32 <= blk, "a small class's block keeps 32 bytes past "
		"its last cell (%lu of %lu bytes used), out of the next block's "
		"header", used, blk);
	ok(ch2 && unused < ch2->cell_size / 8, "the top class fills its %lu KB "
		"block: %u cells of %u bytes, %lu bytes unused", blk2 >> 10,
		ch2 ? ch2->cells : 0, ch2 ? ch2->cell_size : 0, unused);
	if (p)
		shm_free(p);
	if (q)
		shm_free(q);
}

int hg_gpool_push(struct hg_block *hb, int c, void *cell_start);

/* a LIVE cell reached through a rewritten link must not enter the pool */
static void test_hg_gpool_live(void)
{
	struct hg_block *hb = shm_block;
	unsigned long d0 = hb->corrupt[HG_C_DOUBLE_FREE];
	union hg_hdr_w w;
	unsigned short base;
	void *q = shm_malloc(100);
	int r = 0;

	if (!q) {
		ok(0, "shm_malloc(100)");
		return;
	}
	hg_hdr_read(HG_HDR(q), &w, &base);
	hg_lock_enter(hb, HG_LK_RETURN);
	r = hg_gpool_push(hb, w.f.cls, HG_HDR(q));
	hg_lock_leave(hb);
	ok(r < 0 && hb->corrupt[HG_C_DOUBLE_FREE] == d0 + 1, "the shared pool "
		"refuses a cell that is still in use, and counts it");
	shm_free(q);
}

/* the cells a carve left in a thread's bump region come back at the second
 * sweep once the class is idle, so the block can drain */
#define HGT_BUMP_SIZE 10000
static void test_hg_bump_return(void)
{
	struct hg_block *a = hgt_xfer_arena;
	void *p;
	int c;

	if (!a || a->dbg) {
		skip(1, 1, "no plain module arena for the bump-cell sweep");
		end_skip;
		return;
	}
	c = a->size2class[(HGT_BUMP_SIZE + HG_ROUNDTO - 1) / HG_ROUNDTO];
	if (!(p = mem_arena_malloc(a, HGT_BUMP_SIZE))) {
		ok(0, "mem_arena_malloc(%d)", HGT_BUMP_SIZE);
		return;
	}
	mem_arena_free(a, p);
	hg_cache_flush_self();   /* the class was used: kept */
	hg_cache_flush_self();   /* idle now: its bump cells go back */
	ok(hgt_class_pooled(a, c), "an idle class's unused bump cells return "
		"to the pool at the sweep, so its block is whole again");
}

#ifdef __OS_linux
static void *hgt_thread_alloc(void *arg)
{
	void *p = shm_malloc(64);

	*(int *)arg = hg_pstat_slot;
	if (p)
		shm_free(p);
	return NULL;
}
#endif

/* a library thread gets its own stats slot: the process's has no atomics */
static void test_hg_thread_slot(void)
{
#ifdef __OS_linux
	pthread_t t;
	int slot = -2;

	if (pthread_create(&t, NULL, hgt_thread_alloc, &slot) != 0) {
		skip(1, 1, "pthread_create failed, thread stats slot not tested");
		end_skip;
		return;
	}
	pthread_join(t, NULL);
	ok(slot >= 0, "a thread other than the main one gets its own stats slot "
		"at its first allocation (slot %d)", slot);
#else
	skip(1, 1, "thread stats slots are Linux-only");
	end_skip;
#endif
}

#ifdef __OS_linux
/* the VmFlags of the mapping holding @at: 1 if found, with dd/nr set */
static int hgt_vma_flags(unsigned long at, int *dd, int *nr)
{
	unsigned long lo, hi;
	char line[512];
	int in = 0, found = 0;
	FILE *f = fopen("/proc/self/smaps", "r");

	*dd = *nr = -1;
	if (!f)
		return 0;
	while (fgets(line, sizeof line, f)) {
		if (sscanf(line, "%lx-%lx ", &lo, &hi) == 2) {
			in = at >= lo && at < hi;
			continue;
		}
		if (in && !strncmp(line, "VmFlags:", 8)) {
			*dd = strstr(line, " dd") != NULL;
			*nr = strstr(line, " nr") != NULL;
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}
#endif

/* the shm arena is in core dumps by default, and its cap is NORESERVE */
static void test_hg_vma_flags(void)
{
#ifdef __OS_linux
	struct hg_block *hb = shm_block;
	int dd, nr, cdd, cnr = -1;
	void *ctl;

	if (!hgt_vma_flags((unsigned long)hb->hbase, &dd, &nr)) {
		skip(1, 2, "no VmFlags for the shm arena, its flags not tested");
		end_skip;
		return;
	}
	/* the control: a mapping of our own with MAP_NORESERVE - an emulated
	 * run (qemu-user) does not report the flag at all */
	ctl = mmap(NULL, 1UL << 20, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	if (ctl != MAP_FAILED) {
		hgt_vma_flags((unsigned long)ctl, &cdd, &cnr);
		munmap(ctl, 1UL << 20);
	}
	ok(dd == 0, "the shm arena is in core dumps by default (no dd flag)");
	if (hb->tier == HG_MEM_HUGETLB || cnr != 1) {
		skip(1, 1, "MAP_NORESERVE not checked: %s",
			cnr != 1 ? "this environment does not report the nr flag "
			"even for a mapping made with it" : "the arena is on hugetlb");
		end_skip;
	} else {
		ok(nr == 1, "the shm arena's cap is reserved MAP_NORESERVE (nr "
			"flag), tier %s", hg_mem_tier_str(hb->tier));
	}
#else
	skip(1, 2, "VMA flags are Linux-only");
	end_skip;
#endif
}

static int hgt_child_status_locked(void *arg)
{
	struct hg_block *hb = (struct hg_block *)mem_block;

	(void)arg;
	hg_lock_enter(hb, HG_LK_STATS);
	hg_status(hb);
	hg_lock_leave(hb);
	return 0;
}

/* a crash handler's pkg_status() inside a locked section must not wait for
 * the lock its own thread holds */
static void test_hg_status_locked(void)
{
	ok(hgt_in_child("hg status locked", hgt_child_status_locked, NULL),
		"a status dump from inside a locked section does not wait for the "
		"thread's own lock");
}

/* past 256 MB a large chunk was clamped to a huge page minus 64 bytes, 8 too
 * few for a request that rounds to the page minus 120: the split underflowed
 * and the next large allocation wrote past the block */
#define HGT_FLOOR_ARENA  (260UL << 20)
#define HGT_FLOOR_NEXT   100000

static struct hg_block *hgt_floor_arena;

static int hgt_child_large_floor(void *arg)
{
	struct hg_block *a = hgt_floor_arena;
	unsigned long sz, i;
	char *p, *q;
	int fails = 0;

	/* every size whose need lands in the clamped window, whatever the
	 * header, guard or DBG tail add */
	for (sz = a->hps - 256; sz <= a->hps - 32; sz += 8) {
		p = mem_arena_malloc(a, sz);
		if (!p) {
			LM_ERR("large floor: %lu bytes refused\n", sz);
			fails++;
			continue;
		}
		memset(p, 0x5a, sz);
		q = mem_arena_malloc(a, HGT_FLOOR_NEXT);
		if (q) {
			memset(q, 0xa5, HGT_FLOOR_NEXT);
			mem_arena_free(a, q);
		}
		for (i = 0; i < sz && (unsigned char)p[i] == 0x5a; i++)
			;
		if (i < sz) {
			LM_ERR("large floor: %lu-byte block damaged at byte %lu\n",
				sz, i);
			fails++;
		}
		mem_arena_free(a, p);
	}
	return fails ? -1 : 0;
}

static void test_hg_large_floor(void)
{
	unsigned long c0;

	if (!hgt_floor_arena)
		hgt_floor_arena = shm_arena_create("hgfloor", HGT_FLOOR_ARENA,
			HGT_FLOOR_ARENA);
	if (!hgt_floor_arena) {
		ok(0, "a %lu MB module arena", HGT_FLOOR_ARENA >> 20);
		return;
	}
	c0 = hg_corrupt_total(hgt_floor_arena);
	ok(hgt_in_child("hg large floor", hgt_child_large_floor, NULL) &&
		hg_corrupt_total(hgt_floor_arena) == c0,
		"on a %lu MB arena, large requests just under a %lu KB page are "
		"served whole and the next large allocation stays in its block",
		HGT_FLOOR_ARENA >> 20, hgt_floor_arena->hps >> 10);
}

/* the boundary tag before a large fragment's cell header is outside its
 * checksum: a short overflow of the fragment before rewrites it, and a free
 * must refuse it rather than follow it */
static int hgt_child_lfrag_tag(void *arg)
{
	struct hg_block *a = hgt_floor_arena;
	char *x, *y;
	struct hg_lfrag *f;

	x = mem_arena_malloc(a, HGT_FLOOR_NEXT);
	y = mem_arena_malloc(a, HGT_FLOOR_NEXT);
	if (!x || !y)
		return -1;
	f = (struct hg_lfrag *)(void *)(y - HG_CELL_HDR - HG_LFRAG_HDR);
	f->size = ~(unsigned long)0 << 4;
	mem_arena_free(a, y);            /* refused: y leaks */
	mem_arena_free(a, x);
	return 0;
}

static void test_hg_lfrag_tag(void)
{
	unsigned long c0;

	if (!hgt_floor_arena || hgt_floor_arena->dbg) {
		skip(1, 1, "no module arena, or HG_MALLOC_DBG defers the free");
		end_skip;
		return;
	}
	c0 = hgt_floor_arena->corrupt[HG_C_OVERFLOW];
	ok(hgt_in_child("hg lfrag tag", hgt_child_lfrag_tag, NULL) &&
		hgt_floor_arena->corrupt[HG_C_OVERFLOW] == c0 + 1,
		"a large fragment whose boundary tag was overwritten is refused "
		"and counted, not coalesced through");
}

#define HGT_RAW_SIZE  200

/* a child forked outside internal_fork() (a module's mailer, an exec) once
 * kept its parent's private lists and could hand out the parent's cells */
static void test_hg_raw_fork(void)
{
	char *p, *q;
	pid_t pid;
	int st = 0;

	p = shm_malloc(HGT_RAW_SIZE);
	if (!p) {
		ok(0, "a cell for the raw fork test");
		return;
	}
	shm_free(p);                      /* now the head of this thread's list */
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		q = shm_malloc(HGT_RAW_SIZE);
		_exit(!q ? 2 : q == p ? 1 : 0);
	}
	if (pid < 0) {
		ok(0, "fork() for the raw fork test");
		return;
	}
	while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
		;
	ok(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a child made by a plain "
		"fork() does not take its parent's cached cells (exit %d)",
		WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

static int hgt_child_double_free(void *arg)
{
	unsigned long size = (unsigned long)arg;
	void *p, *a, *b;

	p = shm_malloc(size);
	if (!p)
		return -1;
	shm_free(p);
	shm_free(p);

	a = shm_malloc(size);
	b = shm_malloc(size);
	if (!a || !b || a == b) {
		LM_ERR("after a double free of %p: two allocations returned %p "
			"and %p\n", p, a, b);
		return -1;
	}
	shm_free(a);
	shm_free(b);
	return 0;
}

static void test_hg_double_free(void)
{
	struct hg_block *hb = shm_block;
	unsigned long c0;

	c0 = hb->corrupt[HG_C_DOUBLE_FREE];
	ok(hgt_in_child("hg double free", hgt_child_double_free,
		(void *)200UL) && hb->corrupt[HG_C_DOUBLE_FREE] == c0 + 1,
		"a cell freed twice in a row is refused and counted, not handed "
		"out twice");

	c0 = hb->corrupt[HG_C_DOUBLE_FREE];
	ok(hgt_in_child("hg large double free", hgt_child_double_free,
		(void *)(200UL * 1024)) && hb->corrupt[HG_C_DOUBLE_FREE] == c0 + 1,
		"a large fragment freed twice is refused and counted");
}

/* a free past the committed span is refused without reading its header
 * (which would commit the page, or SIGBUS on hugetlb) */
static int hgt_child_unbacked(void *arg)
{
	shm_free(arg);
	return 0;
}

static void test_hg_unbacked(void)
{
#ifdef __OS_linux
	struct hg_block *hb = shm_block;
	unsigned long df0 = hb->corrupt[HG_C_DOUBLE_FREE];
	unsigned long hd0 = hb->corrupt[HG_C_HEADER];
	long pgsz = sysconf(_SC_PAGESIZE);
	unsigned char vec = 1;
	char *page;
	int in_child;

	if (hb->hcap < hb->span_end + (4UL << 20) || pgsz <= 0) {
		skip(1, 1, "shm arena has no uncommitted reservation, unbacked "
			"free not tested");
		end_skip;
		return;
	}
	/* deep in the part of the reservation never committed */
	page = hb->hbase + hb->hcap - (2UL << 20);
	if (mincore(page, (size_t)pgsz, &vec) != 0 || (vec & 1)) {
		skip(1, 1, "residency of %p unknown or already in memory, unbacked "
			"free not tested", page);
		end_skip;
		return;
	}
	in_child = hgt_in_child("hg unbacked free", hgt_child_unbacked,
		page + pgsz);
	vec = 1;
	ok(in_child && hb->corrupt[HG_C_DOUBLE_FREE] == df0 + 1 &&
		hb->corrupt[HG_C_HEADER] == hd0 &&
		mincore(page, (size_t)pgsz, &vec) == 0 && !(vec & 1),
		"a free of a pointer past the shm arena's committed span is "
		"refused and counted, and its page is not read into memory");
#else
	diag("mincore() residency check is Linux-only, unbacked free not tested");
#endif
}

#define HGT_HDR_SIZE  200

static int hgt_child_header(void *arg)
{
	char *a, *b, *x, *y, *z, *mid;
	int fails = 0;

	/* a freed twice, with b freed in between: a is no longer the head of
	 * the private list, so only the header's state can catch it */
	a = shm_malloc(HGT_HDR_SIZE);
	b = shm_malloc(HGT_HDR_SIZE);
	if (!a || !b)
		return -1;
	shm_free(a);
	shm_free(b);
	shm_free(a);
	/* undetected, the list is a -> b -> a: the duplicate is the third pop */
	x = shm_malloc(HGT_HDR_SIZE);
	y = shm_malloc(HGT_HDR_SIZE);
	z = shm_malloc(HGT_HDR_SIZE);
	if (!x || !y || !z || x == y || x == z || y == z) {
		LM_ERR("double free with a free in between: handed out %p, %p, %p\n",
			x, y, z);
		fails++;
	}

	/* a live cell's header overwritten, as by a neighbour's overflow: its
	 * free must be refused, not followed */
	a = shm_malloc(HGT_HDR_SIZE);
	if (!a)
		return -1;
	memset(a - HG_CELL_HDR, 0x41, 4);
	shm_free(a);

	b = shm_malloc(HGT_HDR_SIZE);
	if (!b)
		return -1;
	mid = b + 64;
	shm_free(mid);
	shm_free(b);

	b = shm_malloc(HGT_HDR_SIZE);
	if (!b)
		return -1;
	shm_free(b);
	if (shm_realloc(b, HGT_HDR_SIZE * 2)) {
		LM_ERR("realloc of a freed pointer succeeded\n");
		fails++;
	}

	return fails ? -1 : 0;
}

static void test_hg_header(void)
{
	struct hg_block *hb = shm_block;
	unsigned long df0 = hb->corrupt[HG_C_DOUBLE_FREE];
	unsigned long hd0 = hb->corrupt[HG_C_HEADER];
	int ok_child;

	ok_child = hgt_in_child("hg cell header", hgt_child_header, NULL);
	/* double_free: the in-between case and the realloc of a freed cell;
	 * header: the overwritten header and the mid-cell pointer */
	ok(ok_child && hb->corrupt[HG_C_DOUBLE_FREE] == df0 + 2 &&
		hb->corrupt[HG_C_HEADER] == hd0 + 2,
		"a double free with frees in between, a damaged header, a pointer "
		"into a cell and a realloc of freed memory are all refused "
		"(double_free +%lu, header +%lu)",
		hb->corrupt[HG_C_DOUBLE_FREE] - df0, hb->corrupt[HG_C_HEADER] - hd0);
}

#define HGT_DBG_SMALL  201
#define HGT_DBG_LARGE  (200UL * 1024 + 3)
#define HGT_DBG_REUSE  64

static int hgt_child_dbg(void *arg)
{
	struct hg_block *hb = shm_block;
	char *a, *b, *r, *u, *n[HGT_DBG_REUSE];
	unsigned long uf, hd;
	int i, fails = 0;

	a = shm_malloc(HGT_DBG_SMALL);
	b = shm_malloc(HGT_DBG_LARGE);
	r = shm_malloc(100);
	u = shm_malloc(HGT_DBG_SMALL);
	if (!a || !b || !r || !u)
		return -1;

	a[HGT_DBG_SMALL] = 0;
	b[HGT_DBG_LARGE] = 0;
	r[100] = 0;
	shm_free(a);
	shm_free(b);
	r = shm_realloc(r, 120);
	if (!r)
		return -1;
	r[120] = 0;
	shm_free(r);

	/* a write through a dangling pointer, then the quarantine let go: the
	 * cell is reported and leaked, never handed out again */
	shm_free(u);
	u[100] = 0x55;
	uf = hb->corrupt[HG_C_USE_AFTER_FREE];
	hd = hb->corrupt[HG_C_HEADER];
	hg_quarantine_drain(hb);
	if (hb->corrupt[HG_C_USE_AFTER_FREE] != uf + 1 ||
	    hb->corrupt[HG_C_HEADER] != hd) {
		LM_ERR("the stale write was not refused for its poison "
			"(use_after_free +%lu, header +%lu)\n",
			hb->corrupt[HG_C_USE_AFTER_FREE] - uf,
			hb->corrupt[HG_C_HEADER] - hd);
		fails++;
	}
	for (i = 0; i < HGT_DBG_REUSE; i++) {
		n[i] = shm_malloc(HGT_DBG_SMALL);
		if (n[i] == u) {
			LM_ERR("the cell written after its free was handed out "
				"again\n");
			fails++;
		}
	}
	for (i = 0; i < HGT_DBG_REUSE; i++)
		shm_free(n[i]);
	return fails ? -1 : 0;
}

/* forked while the parent's quarantine holds @arg: the child's copy of the
 * quarantine must be empty, and its stale write must be found by the parent */
static int hgt_child_dbg_xproc(void *arg)
{
	char *x = arg;
	unsigned int n = hg_quarantine_drain((struct hg_block *)shm_block);

	if (n) {
		LM_ERR("the child released %u cells of the parent's quarantine\n", n);
		return -1;
	}
	x[100] = 0x55;
	return 0;
}

static void test_hg_dbg(void)
{
	struct hg_block *hb = shm_block;
	unsigned long of0 = hb->corrupt[HG_C_OVERFLOW];
	unsigned long uf0 = hb->corrupt[HG_C_USE_AFTER_FREE];
	int ok_child, ok_xproc = 0;
	char *x;

	skip(!hb->dbg, 1, "the red zone and quarantine are HG_MALLOC_DBG's");
	ok_child = hgt_in_child("hg dbg checks", hgt_child_dbg, NULL);

	/* the parent's quarantine emptied - nothing in it may be damaged -
	 * then holding just x across the fork */
	hg_quarantine_drain(hb);
	x = shm_malloc(HGT_DBG_SMALL);
	if (x && hb->corrupt[HG_C_USE_AFTER_FREE] == uf0 + 1) {
		shm_free(x);
		ok_xproc = hgt_in_child("hg dbg cross-process",
			hgt_child_dbg_xproc, x);
		hg_quarantine_drain(hb);
	}

	ok(ok_child && ok_xproc && hb->corrupt[HG_C_OVERFLOW] == of0 + 4 &&
		hb->corrupt[HG_C_USE_AFTER_FREE] == uf0 + 2,
		"HG_MALLOC_DBG finds a write past the request at the free and "
		"around a realloc, and a write after the free - from this or "
		"another process - when the cell leaves quarantine; a child never "
		"releases the parent's quarantine (overflow +%lu, use_after_free "
		"+%lu)", hb->corrupt[HG_C_OVERFLOW] - of0,
		hb->corrupt[HG_C_USE_AFTER_FREE] - uf0);
	end_skip;
}

static int hgt_child_guard(void *arg)
{
	struct hg_block *hb = shm_block, *pb = mem_block;
	unsigned long exact = 128 - HG_CELL_HDR - HG_GUARD_ROOM, of;
	char *a, *b, *r, *e, *k, *p;
	int fails = 0;

	hb->guard = 0;
	k = shm_malloc(100);
	hb->guard = 1;
	a = shm_malloc(HGT_DBG_SMALL);
	b = shm_malloc(HGT_DBG_LARGE);
	r = shm_malloc(100);
	e = shm_malloc(exact);
	if (!a || !b || !r || !e || !k) {
		hb->guard = 0;
		return -1;
	}

	a[HGT_DBG_SMALL] = 0;
	b[HGT_DBG_LARGE] = 0;
	e[exact] = 0;
	r[100] = 0;
	shm_free(a);
	shm_free(b);
	shm_free(e);
	r = shm_realloc(r, 60);     /* in place: checked, then guarded at 60 */
	if (!r) {
		hb->guard = 0;
		return -1;
	}
	r[60] = 0;
	shm_free(r);
	k[100] = 0;                 /* in k's slack, and k carries no guard */
	shm_free(k);
	hb->guard = 0;

	if (!pb || pb->dbg)
		return 0;
	of = pb->corrupt[HG_C_OVERFLOW];
	pb->guard = 1;
	p = pkg_malloc(HGT_DBG_SMALL);
	pb->guard = 0;
	if (!p)
		return -1;
	p[HGT_DBG_SMALL] = 0;
	pkg_free(p);
	if (pb->corrupt[HG_C_OVERFLOW] != of + 1) {
		LM_ERR("the pkg overrun was not found (overflow +%lu)\n",
			pb->corrupt[HG_C_OVERFLOW] - of);
		fails++;
	}
	return fails ? -1 : 0;
}

static void test_hg_guard(void)
{
	struct hg_block *hb = shm_block;
	unsigned long of0 = hb->corrupt[HG_C_OVERFLOW];
	int ok_child;

	skip(hb->dbg, 1, "HG_MALLOC_DBG's red zone stands in for the guard");
	ok_child = hgt_in_child("hg guard", hgt_child_guard, NULL);
	hb->guard = 0;
	ok(ok_child && hb->corrupt[HG_C_OVERFLOW] == of0 + 5,
		"hg_mem_check's guard finds one byte past the request at the free "
		"(small cell, large fragment, a cell filled but for its guard byte, "
		"pkg) and around an in-place realloc, and leaves a cell taken "
		"without it alone (overflow +%lu)", hb->corrupt[HG_C_OVERFLOW] - of0);
	end_skip;
}

/* the hg_san.h hooks, read from ASan's shadow so nothing crashes; the
 * sizes keep every probe in the cell's slack under every header layout */
static void test_hg_san(void)
{
#ifdef HG_SAN_ASAN
	char *p, *r, *s;
	int good = 1;

	p = pkg_malloc(200);
	r = pkg_malloc(100);
	s = shm_malloc(200);
	if (!p || !r || !s) {
		ok(0, "allocations for the sanitizer hooks");
		return;
	}
	if (__asan_address_is_poisoned(p + 199) ||
	    !__asan_address_is_poisoned(p + 200)) {
		LM_ERR("pkg cell %p: byte 199 %s, byte 200 %s\n", p,
			__asan_address_is_poisoned(p + 199) ? "closed" : "open",
			__asan_address_is_poisoned(p + 200) ? "closed" : "open");
		good = 0;
	}
	r = pkg_realloc(r, 110);
	if (!r || __asan_address_is_poisoned(r + 109) ||
	    !__asan_address_is_poisoned(r + 110)) {
		LM_ERR("realloc'ed pkg cell %p is not open for exactly 110 bytes\n",
			r);
		good = 0;
	}
	if (__asan_address_is_poisoned(s + 200)) {
		LM_ERR("shm cell %p was closed - shared arenas must not be\n", s);
		good = 0;
	}
	pkg_free(p);
	if (!__asan_address_is_poisoned(p + 64)) {
		LM_ERR("freed pkg cell %p is still open\n", p);
		good = 0;
	}
	pkg_free(r);
	shm_free(s);
	ok(good, "ASan sees a pkg cell open for the bytes asked for and closed "
		"after them, closed once freed, and shm cells left alone");
#else
	skip(1, 1, "the sanitizer hooks are checked in an ASan build");
	end_skip;
#endif
}

static unsigned long hgt_corruption(void)
{
	unsigned long t = hg_corrupt_total((struct hg_block *)shm_block) +
		hg_corrupt_total((struct hg_block *)mem_block);
	int k;

	for (k = 0; k < HG_CORRUPT_KINDS; k++)
		t += hg_corrupt_noarena[k];
	return t;
}

void test_hg_malloc(void)
{
	ok(hg_ut_selected(), "HG_MALLOC serves pkg and shm (allocator %d/%d)",
		mem_allocator_pkg, mem_allocator_shm);
	if (!hg_ut_selected())
		return;

	hgt_verdict = shm_malloc(sizeof *hgt_verdict);
	hgt_go = shm_malloc(sizeof *hgt_go);
	if (!hgt_verdict || !hgt_go) {
		ok(0, "shm verdict slots");
		return;
	}

	test_hg_prefork_pkg();
	test_hg_cross_process_shm();
	test_hg_raw_fork();
	test_hg_large();
	test_hg_large_floor();
	test_hg_grow();
	test_hg_free_past_init();
	test_hg_size_bound();
	test_hg_xfer();
	test_hg_pkg_shrink();
	test_hg_inherited();
	test_hg_grow_refusal_cause();
	test_hg_advise();
	test_hg_exit_returns_cells();
	test_hg_block_slack();
	test_hg_bump_return();
	test_hg_thread_slot();
	test_hg_vma_flags();
	test_hg_large_lists();
	test_hg_pkg_pub();
	test_hg_sweep_dispatch();
	test_hg_grow_blocked();
	test_hg_sweep_events();
	test_hg_mi_stats();
	test_hg_shrink_cooldown();
	test_hg_san();
	test_hg_memlimit();

	ok(hgt_corruption() == 0, "no corruption detected in the parent's view "
		"of the shm and pkg arenas");

	/* last: these count a detection on purpose */
	test_hg_double_free();
	test_hg_lfrag_tag();
	test_hg_unbacked();
	test_hg_header();
	test_hg_dbg();
	test_hg_guard();
	test_hg_gpool_live();
	/* a hang here (the old self-deadlock) stops the run: after the rest */
	test_hg_status_locked();

	/* fuzz last: it uses the child runner, and the verdict slots go below */
	test_hg_fuzz();

	shm_free((void *)hgt_verdict);
	shm_free((void *)hgt_go);
}

#endif /* HG_MALLOC */
