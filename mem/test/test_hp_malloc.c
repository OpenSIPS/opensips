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

#ifdef HP_MALLOC

#include <tap.h>

#include "../../str.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../modparam.h"
#include "../../lib/list.h"
#include "../../lib/osips_malloc.h"
#include "../hp_malloc.h"

#include "test_hp_malloc.h"

static osips_malloc_t  MALLOC;
static osips_realloc_t REALLOC;
static osips_free_t    FREE;

/* keep in sync with Makefile.test "-m" option! */
#define HPT_SHM             (1 * 1024L * 1024 * 1024)

#define HPT_MAX_PROC_USAGE  .7

#define MY_MAX_USED ((long)((double)HPT_SHM / TEST_MALLOC_PROCS * HPT_MAX_PROC_USAGE))
#define check_limit() (hpt_my_used < MY_MAX_USED)

#define HPT_MAX_ALLOC_SZ    65536
#define HPT_FAC             65536
#define HPT_OPS             5000000

#define HP_FRAG_OVERHEAD	(sizeof(struct hp_frag))

static long hpt_my_used = 0;
static long mallocs, reallocs, frees;
static long should_grow = 1;

extern stat_var *shm_frags;

OSIPS_LIST_HEAD(hpt_frags);
static long fragments;

static stat_var *forked_workers;
static stat_var *active_workers;

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

static void _test_malloc(int my_pid)
{
	int i;

	srand(getpid());

	for (i = HPT_OPS; i; i--) {
		if (i % 100000 == 1)
			LM_INFO("ops left: %d, F: %ld, M: %ld, R: %ld, F: %ld, usage: %ld/%ld, frags: %lu\n",
			        i, fragments, mallocs, reallocs, frees,
			        hpt_my_used, MY_MAX_USED, shm_frags ? get_stat_val(shm_frags) : -1);

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

	LM_INFO("worker %d ended, freed up remaining %d chunks.\n", my_pid, i);
}

static inline void test_pkg_malloc(void)
{
	unsigned long used, rused;

	MALLOC  = osips_pkg_malloc;
	REALLOC = osips_pkg_realloc;
	FREE    = osips_pkg_free;

	LM_INFO("Starting PKG stress test...\n");
	LM_INFO("================================\n");
	LM_INFO("used: %ld\n", mem_block->used);
	LM_INFO("real_used: %ld\n", mem_block->real_used);
	LM_INFO("max_real_used: %ld\n", mem_block->max_real_used);
	LM_INFO("fragments: %ld\n", mem_block->total_fragments);
	LM_INFO("================================\n");

	used = mem_block->used;
	rused = mem_block->real_used;

	_test_malloc(0);

	LM_INFO("PKG stress test complete.  Final stats:\n");
	LM_INFO("================================\n");
	LM_INFO("used: %ld\n", mem_block->used);
	LM_INFO("real_used: %ld\n", mem_block->real_used);
	LM_INFO("max_real_used: %ld\n", mem_block->max_real_used);
	LM_INFO("fragments: %ld\n", mem_block->total_fragments);
	LM_INFO("================================\n");

	ok(used == mem_block->used,   "check stats: pkg used");
	ok(rused == mem_block->real_used, "check stats: pkg real_used");
}

static inline void test_shm_malloc(void)
{
	int i, my_pid = 0;
	unsigned long used, rused;
	unsigned long new_used, new_rused;

	MALLOC  = osips_shm_malloc;
	REALLOC = osips_shm_realloc;
	FREE    = osips_shm_free;

	update_stat(forked_workers, +1);
	update_stat(active_workers, +1);

	for (i = 1; i < TEST_MALLOC_PROCS; i++) {
		if (internal_fork("malloc test", OSS_FORK_NO_IPC|OSS_FORK_NO_LOAD) == 0) {
			my_pid = i;
			printf("forked extra test worker #%d!\n", i);
			update_stat(forked_workers, +1);
			update_stat(active_workers, +1);
			break;
		}
	}

	/* this is required because internal_fork() does SHM mallocs on <= 2.4, so
	 * the SHM stats will keep on changing until all workers are forked... */
	if (my_pid == 0) {
		while (get_stat_val(forked_workers) < TEST_MALLOC_PROCS)
			usleep(10);

		used = get_stat_val(get_stat(_str("used_size")));
		rused = get_stat_val(get_stat(_str("real_used_size")));

		LM_INFO("Starting SHM stress test...\n");
		LM_INFO("================================\n");
		LM_INFO("used: %ld\n", used);
		LM_INFO("real_used: %ld\n", rused);
		LM_INFO("max_real_used: %ld\n", get_stat_val(get_stat(_str("max_used_size"))));
		LM_INFO("fragments: %ld\n", get_stat_val(get_stat(_str("fragments"))));
		LM_INFO("================================\n");

		reset_stat(forked_workers);
	} else {
		while (get_stat_val(forked_workers))
			usleep(10);
	}

	_test_malloc(my_pid);

	update_stat(active_workers, -1);

	if (my_pid != 0) {
		exit(0);
	} else {
		while (get_stat_val(active_workers) > 0) {
			LM_INFO("waiting for everyone to finish...\n");
			sleep(1);
		}
	}

	/* only attendant left by this point */

	new_used = get_stat_val(get_stat(_str("used_size")));
	new_rused = get_stat_val(get_stat(_str("real_used_size")));

	LM_INFO("SHM test complete.  Final stats:\n");
	LM_INFO("================================\n");
	LM_INFO("used: %ld\n", new_used);
	LM_INFO("real_used: %ld\n", new_rused);
	LM_INFO("max_real_used: %ld\n", get_stat_val(get_stat(_str("max_used_size"))));
	LM_INFO("fragments: %ld\n", get_stat_val(get_stat(_str("fragments"))));
	LM_INFO("================================\n");

	ok(new_used == used,   "check stats: shm_used");
	ok(new_rused == rused, "check stats: shm_rused");
}

void test_hp_malloc(void)
{
	test_pkg_malloc();
	test_shm_malloc();
}

void init_hp_malloc_tests(void)
{
	if (load_module("mi_fifo.so") != 0) {
		printf("failed to load mi_fifo\n");
		exit(-1);
	}

	if (set_mod_param_regex("mi_fifo", "fifo_name", STR_PARAM,
	    "/tmp/opensips_fifo") != 0) {
		printf("failed to set FIFO name\n");
		exit(-1);
	}

	if (register_stat("test_malloc", "forked-workers", &forked_workers, 0) != 0) {
		LM_ERR("failed to register stat\n");
		return;
	}

	if (register_stat("test_malloc", "active-workers", &active_workers, 0) != 0) {
		LM_ERR("failed to register stat\n");
		return;
	}
}

#endif /* HP_MALLOC */
