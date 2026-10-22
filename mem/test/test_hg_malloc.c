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

/*
 * Run with HG_MALLOC selected, e.g.
 *   make test UT_ALLOC=HG_MALLOC UT_MEM="-m 64:1024 -M 16:256"
 * A child reports its verdict through shm and the parent waits for it with
 * a timeout, so a child that crashes or aborts fails its test instead of
 * hanging the run.
 */

#include "test_hg_malloc.h"

#ifdef HG_MALLOC

#include <tap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../pt.h"
#include "../../globals.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mem/hg_malloc.h"

#define HGT_WAIT_US   (30 * 1000 * 1000)
#define HGT_STEP_US   (10 * 1000)

#define HGT_PASS  1
#define HGT_FAIL  2

static volatile int *hgt_verdict;
/* set by the parent once internal_fork() has returned: a child that ran
 * and exited within the parent's start-up wait would otherwise be reported
 * as "failed to initialize" (internal_fork() checks for an exited child
 * before it re-reads the start-up result) */
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

/* run @fn in a child forked the way OpenSIPS forks its workers and return
 * 1 if it reported success, 0 if it failed, crashed or timed out */
static int hgt_in_child(char *desc, int (*fn)(void *), void *arg)
{
	const struct internal_fork_params ifp = {
		.proc_desc = desc,
		.flags = OSS_PROC_NO_IPC|OSS_PROC_NO_LOAD,
		.type = TYPE_NONE,
	};
	int pid, waited;

	*hgt_verdict = 0;
	*hgt_go = 0;
	/* or the child inherits the unflushed TAP lines and prints them again */
	fflush(stdout);
	pid = internal_fork(&ifp);
	if (pid < 0) {
		LM_ERR("failed to fork the '%s' child\n", desc);
		return 0;
	}

	if (pid == 0) {
		for (waited = 0; *hgt_go == 0 && waited < HGT_WAIT_US;
		        waited += HGT_STEP_US)
			usleep(HGT_STEP_US);
		*hgt_verdict = fn(arg) == 0 ? HGT_PASS : HGT_FAIL;
		exit(0);
	}
	*hgt_go = 1;

	for (waited = 0; *hgt_verdict == 0 && waited < HGT_WAIT_US;
	        waited += HGT_STEP_US)
		usleep(HGT_STEP_US);

	if (*hgt_verdict == 0)
		LM_ERR("the '%s' child gave no verdict within %d s - it crashed "
			"or aborted\n", desc, HGT_WAIT_US / 1000000);

	return *hgt_verdict == HGT_PASS;
}

/*
 * pkg memory allocated before fork() lives in the arena every child
 * inherits, not in the child's own: a child must be able to realloc and
 * free it (before 2026-10-16 the realloc returned NULL, and the debug
 * free path aborted)
 */
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

/*
 * shm cells of every size class, allocated by one process and freed by
 * another, must come back usable: the second process's frees travel
 * through its own cache and the shared pool
 */
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
	return hgt_check_free_cells();
}

static void test_hg_cross_process_shm(void)
{
	if (hgt_alloc_cells() != 0) {
		ok(0, "shm cells for the cross-process test");
		return;
	}

	ok(hgt_in_child("hg shm free", hgt_child_free_cells, NULL),
		"another process can free shm cells of every class");

	/* the same sizes again, now served from what the child freed */
	ok(hgt_alloc_cells() == 0 && hgt_check_free_cells() == 0,
		"shm cells freed by another process are reused intact");
}

/* requests above the largest size class go to the large tier */
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

/* an elastic shm arena (-m INIT:CAP) grows past INIT on demand */
#define HGT_GROW_CHUNK  (1024 * 1024)
#define HGT_GROW_MAX    256

static void test_hg_grow(void)
{
	struct hg_block *hb = shm_block;
	void *p[HGT_GROW_MAX];
	unsigned long gen0, grows0, committed0;
	int i, n;

	if (!hg_shm_cap_bytes || hg_shm_cap_bytes <= hb->committed_min) {
		diag("shm arena is fixed (-m without INIT:CAP), growth not tested");
		return;
	}

	gen0 = hb->grow_gen;
	grows0 = hb->grows;
	committed0 = hb->committed_bytes;

	/* allocate until the arena grows: what is committed already - more
	 * than INIT if the maintenance process grew it ahead of demand - has
	 * to be used up first */
	for (n = 0; n < HGT_GROW_MAX; n++) {
		p[n] = shm_malloc(HGT_GROW_CHUNK);
		if (!p[n])
			break;
		hgt_fill(p[n], 64, (unsigned char)n);
		if (hb->grow_gen != gen0)
			break;
	}
	if (n < HGT_GROW_MAX && p[n])
		n++;

	ok(hb->grow_gen != gen0 && hb->committed_bytes > committed0,
		"an elastic shm arena grows on demand (%lu -> %lu MB, %lu grows)",
		committed0 >> 20, hb->committed_bytes >> 20, hb->grows - grows0);

	for (i = 0; i < n; i++)
		shm_free(p[i]);
}

/*
 * A process leaving for good (auto-scaling down) must give back what it holds
 * in the shared arena: its cached cells and the unused rest of the chunks it
 * carved. The arena's real_used counts whole carved blocks, so it returns to
 * its baseline only if every block the child touched drained. The size is one
 * the idle processes of a test run do not use.
 */
#define HGT_EXIT_SIZE   20000
#define HGT_EXIT_CELLS  100

static int hgt_child_exit(void *arg)
{
	void *p[HGT_EXIT_CELLS];
	int i;

	for (i = 0; i < HGT_EXIT_CELLS; i++) {
		p[i] = shm_malloc(HGT_EXIT_SIZE);
		if (!p[i]) {
			LM_ERR("shm_malloc(%d) failed\n", HGT_EXIT_SIZE);
			return -1;
		}
	}
	for (i = 0; i < HGT_EXIT_CELLS; i++)
		shm_free(p[i]);

	/* report first: the exit below does not return */
	*hgt_verdict = HGT_PASS;
	dynamic_process_final_exit();
	return 0;
}

static void test_hg_exit_returns_cells(void)
{
	struct hg_block *hb = shm_block;
	unsigned long base = hb->real_used;
	int waited;

	if (!hgt_in_child("hg exit", hgt_child_exit, NULL)) {
		ok(0, "a process leaving for good gives back its cells");
		return;
	}

	/* the child gives its cells back right before it exits */
	for (waited = 0; hb->real_used > base && waited < HGT_WAIT_US;
	        waited += HGT_STEP_US)
		usleep(HGT_STEP_US);

	ok(hb->real_used <= base, "a process leaving for good gives back its "
		"cached cells and unused chunk tails (real_used %lu -> %lu KB)",
		base >> 10, hb->real_used >> 10);
}

/*
 * A double free must be refused and counted, never hand the same memory to
 * two callers: the same cell freed twice in a row (it stays on the freeing
 * process's private list, which the shared pool's free map cannot see), and
 * a large-tier fragment freed twice.
 */
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
	test_hg_large();
	test_hg_grow();
	test_hg_exit_returns_cells();

	ok(hgt_corruption() == 0, "no corruption detected in the parent's view "
		"of the shm and pkg arenas");

	/* last: these count a detection on purpose */
	test_hg_double_free();

	shm_free((void *)hgt_verdict);
	shm_free((void *)hgt_go);
}

#endif /* HG_MALLOC */
