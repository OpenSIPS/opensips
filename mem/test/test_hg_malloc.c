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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

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

	ok(hgt_alloc_cells() == 0 && hgt_check_free_cells() == 0,
		"shm cells freed by another process are reused intact");
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
		diag("a %lu MB INIT is a page multiple here (%lu KB pages), "
			"nothing to carve past", HGT_FPI_INIT >> 20, a->hps >> 10);
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

/* frees past priv_max park a chain, a refill after the private list runs dry
 * takes it, and a drain hands every parked cell back to its block */
#define HGT_XF_ARENA  (8UL << 20)
#define HGT_XF_SIZE   200
#define HGT_XF_MAX    1024

static void test_hg_xfer(void)
{
	static struct hg_block *a;
	static unsigned int *p[HGT_XF_MAX];
	unsigned long puts0, gets0, drained0;
	unsigned int c, n, i, bad = 0, parked;

	if (!a)
		a = shm_arena_create("hgxfer", HGT_XF_ARENA, HGT_XF_ARENA);
	if (!a) {
		ok(0, "a %lu MB module arena", HGT_XF_ARENA >> 20);
		return;
	}
	c = a->size2class[(HGT_XF_SIZE + HG_ROUNDTO - 1) / HG_ROUNDTO];
	n = a->priv_max[c] * 3;
	if (!a->xfer[c].cap || n > HGT_XF_MAX || a->dbg || a->guard) {
		diag("class %u keeps %u cells, transfer cap %u: nothing to "
			"park here", c, a->priv_max[c], a->xfer[c].cap);
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

	hg_lock_enter(a, HG_LK_STATS);
	parked = hg_xfer_drain_all(a);
	hg_lock_leave(a);
	ok(a->xfer_drained - drained0 == parked && !a->xfer[c].n,
		"a drain returns all %u parked cells to their blocks", parked);
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
		served = 1;
		pkg_free(p);
	}
	ok(refused == 2 * sizeof sizes / sizeof sizes[0] + 1 && intact && served,
		"sizes near ULONG_MAX are refused by pkg and shm malloc and by a "
		"shm realloc, which leaves the allocation intact (%u of %u "
		"refused), and the arenas serve normally after",
		refused, (unsigned int)(2 * sizeof sizes / sizeof sizes[0] + 1));
}

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

	/* allocate until the arena grows; what is committed (more than INIT if
	 * the maintenance process grew it ahead) is used up first */
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
		diag("pkg arena is fixed (-M without INIT:CAP), shrink not tested");
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
		diag("pkg arena is fixed (-M without INIT:CAP), inherited copy not tested");
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

/* a size no idle process uses */
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
	__atomic_store_n(hgt_verdict, HGT_PASS, __ATOMIC_RELEASE);
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
		diag("shm arena has no uncommitted reservation, unbacked free "
			"not tested");
		return;
	}
	/* deep in the part of the reservation never committed */
	page = hb->hbase + hb->hcap - (2UL << 20);
	if (mincore(page, (size_t)pgsz, &vec) != 0 || (vec & 1)) {
		diag("residency of %p unknown or already in memory, unbacked free "
			"not tested", page);
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
	char *a, *b, *x, *y, *mid;
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
	x = shm_malloc(HGT_HDR_SIZE);
	y = shm_malloc(HGT_HDR_SIZE);
	if (!x || !y || x == y) {
		LM_ERR("double free with a free in between: %p handed out twice\n", x);
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
	test_hg_large();
	test_hg_grow();
	test_hg_free_past_init();
	test_hg_size_bound();
	test_hg_xfer();
	test_hg_pkg_shrink();
	test_hg_inherited();
	test_hg_grow_refusal_cause();
	test_hg_exit_returns_cells();
	test_hg_san();
	test_hg_memlimit();

	ok(hgt_corruption() == 0, "no corruption detected in the parent's view "
		"of the shm and pkg arenas");

	/* last: these count a detection on purpose */
	test_hg_double_free();
	test_hg_unbacked();
	test_hg_header();
	test_hg_dbg();
	test_hg_guard();

	/* fuzz last: it uses the child runner, and the verdict slots go below */
	test_hg_fuzz();

	shm_free((void *)hgt_verdict);
	shm_free((void *)hgt_go);
}

#endif /* HG_MALLOC */
