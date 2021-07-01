/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include <tap.h>

#include "../../str.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../lib/list.h"
#include "../../mem/mem_funcs.h"
#include "../../lib/osips_malloc.h"

#include "test_malloc.h"

static osips_malloc_t  MALLOC;
static osips_realloc_t REALLOC;
static osips_free_t    FREE;

/* keep in sync with Makefile.test "-m" option! */
#define HPT_SHM             (1 * 1024L * 1024 * 1024)

#define HPT_MAX_PROC_USAGE  .8

#define MY_MAX_USED ((long)((double)HPT_SHM / TEST_MALLOC_PROCS * HPT_MAX_PROC_USAGE))
#define check_limit() (hpt_my_used < MY_MAX_USED)

/* ensure all allocations are aligned to this multiple (match this to ROUNDTO) */
#define MEM_ALIGN           8UL

#define HPT_MAX_ALLOC_SZ    65536
#define HPT_FAC             65536
#define HPT_OPS             100000

static long hpt_my_used = 0;
static long mallocs, reallocs, frees;
static long aligned_mallocs, aligned_reallocs;
static long should_grow = 1;

OSIPS_LIST_HEAD(hpt_frags);
static long fragments;

static stat_var *workers;

struct hpt_frag {
	void *chunk;
	ssize_t size;
	struct list_head list;
};

static void _hpt_malloc(void)
{
	struct hpt_frag *ret;
	ssize_t size;

	if (!check_limit()) {
		should_grow = 0;
		return;
	}

	size = (rand() % HPT_FAC) * (HPT_MAX_ALLOC_SZ/HPT_FAC) + 1;

	ret = MALLOC(sizeof *ret + size);
	if (!ret) {
		LM_ERR("oom\n");
		should_grow = 0;
		return;
	}
	memset(ret, -1, sizeof *ret + size);

	if ((unsigned long)ret % MEM_ALIGN == 0)
		aligned_mallocs++;

	ret->chunk = (void *)(ret + 1);
	ret->size = size;

	list_add(&ret->list, &hpt_frags);

	hpt_my_used += size + sizeof *ret + HP_FRAG_OVERHEAD;
	mallocs++;
	fragments++;
}

static void _hpt_realloc(void)
{
	struct hpt_frag *f, *ret;
	ssize_t size;

	if (list_empty(&hpt_frags))
		return _hpt_malloc();

	f = list_entry(hpt_frags.prev, struct hpt_frag, list);
	list_del(&f->list);

	hpt_my_used -= f->size;

	if (should_grow) {
		if (!check_limit() || f->size >= MY_MAX_USED) {
			should_grow = 0;
			goto out;
		}

		size = f->size + (rand() % HPT_FAC) * (HPT_MAX_ALLOC_SZ/HPT_FAC) + 1;
	} else {
		size = rand() % f->size + 1;
	}

	ret = REALLOC(f, sizeof *ret + size);
	if (!ret) {
		LM_ERR("oom\n");
		should_grow = 0;
		goto out;
	}
	memset(ret, -1, sizeof *ret + size);

	if ((unsigned long)ret % MEM_ALIGN == 0)
		aligned_reallocs++;

	ret->chunk = (void *)(ret + 1);
	ret->size = size;
	hpt_my_used += size;

	list_add(&ret->list, &hpt_frags);

	reallocs++;
	return;

out:
	FREE(f);
	frees++;
	fragments--;
}

#define hpt_malloc() (rand() & 1 ? _hpt_malloc() : _hpt_realloc())

static void hpt_free(void)
{
	struct hpt_frag *f;

	if (list_empty(&hpt_frags)) {
		should_grow = 1;
		return;
	}

	f = list_entry(hpt_frags.prev, struct hpt_frag, list);

	hpt_my_used -= (f->size + sizeof *f + HP_FRAG_OVERHEAD);

	list_del(&f->list);

	FREE(f);
	frees++;
	fragments--;
}

static void _test_malloc(int procs)
{
	int i;
	int my_pid = 0;

	update_stat(workers, +1);

	for (i = 1; i < procs; i++) {
		update_stat(workers, +1);
		if (internal_fork("malloc test", OSS_PROC_NO_IPC|OSS_PROC_NO_LOAD, TYPE_NONE) == 0) {
			my_pid = i;
			printf("forked extra test worker #%d!\n", i);
			break;
		}
	}

	srand(getpid());

	for (i = HPT_OPS; i; i--) {
		if (i % 100000 == 0)
			LM_INFO("ops left: %d, F: %ld, M: %ld, R: %ld, F: %ld, usage: %ld/%ld, frags: %lu\n",
			        i, fragments, mallocs, reallocs, frees,
			        hpt_my_used, MY_MAX_USED, get_stat_val(get_stat(_str("fragments"))));

		if (should_grow) {
			if (rand() % 10 >= 1)
				hpt_malloc();
			else
				hpt_free();
		} else {
			if (rand() % 10 < 1)
				hpt_malloc();
			else
				hpt_free();
		}
	}

	for (i = 0; !list_empty(&hpt_frags); i++)
		hpt_free();

	LM_INFO("Worker %d ended, freed up remaining %d chunks.\n", my_pid, i);
	update_stat(workers, -1);

	if (my_pid != 0) {
		exit(0);
	} else {
		while (get_stat_val(workers) > 0) {
			LM_INFO("waiting for everyone to finish...\n");
			sleep(1);
		}
	}
}

static inline void test_pkg_malloc(void)
{
	MALLOC  = osips_pkg_malloc;
	REALLOC = osips_pkg_realloc;
	FREE    = osips_pkg_free;

	LM_INFO("Starting PKG stress test...\n");
	LM_INFO("================================\n");

	_test_malloc(1);

	LM_INFO("PKG test complete.  Final stats:\n");
	LM_INFO("================================\n");

	LM_INFO("mallocs %ld : %ld aligned-mallocs\n", mallocs, aligned_mallocs);
	LM_INFO("reallocs %ld : %ld aligned-reallocs\n", reallocs, aligned_reallocs);
	LM_INFO("frees %ld\n", frees);

	ok(mallocs == aligned_mallocs,   "check pkg_malloc() alignment");
	ok(reallocs == aligned_reallocs,   "check pkg_realloc() alignment");

	mallocs = aligned_mallocs = 0;
	reallocs = aligned_reallocs = 0;
	frees = 0;
}

static inline void test_shm_malloc(void)
{
	unsigned long used, rused, frags, new_used, new_rused, new_frags;

	MALLOC  = osips_shm_malloc;
	REALLOC = osips_shm_realloc;
	FREE    = osips_shm_free;

	used = get_stat_val(get_stat(_str("used_size")));
	rused = get_stat_val(get_stat(_str("real_used_size")));
	frags = get_stat_val(get_stat(_str("fragments")));

	LM_INFO("Starting SHM stress test...\n");
	LM_INFO("================================\n");
	LM_INFO("used: %ld\n", used);
	LM_INFO("real_used: %ld\n", rused);
	LM_INFO("max_real_used: %ld\n", get_stat_val(get_stat(_str("max_used_size"))));
	LM_INFO("fragments: %ld\n", get_stat_val(get_stat(_str("fragments"))));
	LM_INFO("================================\n");

	_test_malloc(TEST_MALLOC_PROCS);

	new_used = get_stat_val(get_stat(_str("used_size")));
	new_rused = get_stat_val(get_stat(_str("real_used_size")));
	new_frags = get_stat_val(get_stat(_str("fragments")));

	LM_INFO("SHM test complete.  Final stats:\n");
	LM_INFO("================================\n");
	LM_INFO("used: %ld -> %ld\n", used, new_used);
	LM_INFO("real_used: %ld -> %ld\n", rused, new_rused);
	LM_INFO("max_real_used: %ld\n", get_stat_val(get_stat(_str("max_used_size"))));
	LM_INFO("fragments: %ld -> %ld\n", frags, new_frags);
	LM_INFO("mallocs %ld : %ld aligned-mallocs\n", mallocs, aligned_mallocs);
	LM_INFO("reallocs %ld : %ld aligned-reallocs\n", reallocs, aligned_reallocs);
	LM_INFO("frees %ld\n", frees);
	LM_INFO("================================\n");

	ok(new_used == used,   "check stats: shm_used");
	/* we don't yet have a way of testing the correctness of real_used
		ok(new_rused == rused, "check stats: shm_rused"); */

	ok(mallocs == aligned_mallocs,   "check shm_malloc() alignment");
	ok(reallocs == aligned_reallocs,   "check shm_realloc() alignment");
}

void test_malloc(void)
{
	test_pkg_malloc();
	test_shm_malloc();
}

void init_malloc_tests(void)
{
	if (load_module("mi_fifo.so") != 0) {
		printf("failed to load mi_fifo\n");
		exit(-1);
	}

	if (register_stat("test_malloc", "test-workers", &workers, 0) != 0) {
		LM_ERR("failed to register stat\n");
		return;
	}
}
