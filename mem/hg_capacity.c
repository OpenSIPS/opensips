/*
 * slab allocator with elastic arenas - host memory and capacity checks
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

#ifdef HG_MALLOC

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "hg_version.h"
#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "hg_memlimit.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../pt_scaling.h"
#include "shm_mem.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#include "../lib/dbg/struct_hist.h"
#include "hg_backing.h"

/* the host floor in MB; not cached, as MemTotal and the config change */
static long hg_ram_floor_of(long total_kb)
{
	if (hg_ram_floor_mb > 0)
		return hg_ram_floor_mb;
	if (total_kb <= 0)
		return 256;
	return hg_floor_mb_for(total_kb >> 10);
}

static long hg_ram_floor(void)
{
	if (hg_ram_floor_mb > 0)
		return hg_ram_floor_mb;
	return hg_ram_floor_of(hg_meminfo_kb("MemTotal"));
}

/* bytes the hugetlb pool can still hand out: free pages not already
 * promised to a mapping; 64-bit, as the pool is the host's */
static unsigned long long hg_pool_free_bytes(void)
{
	long free_pg = hg_meminfo_kb("HugePages_Free");
	long rsvd_pg = hg_meminfo_kb("HugePages_Rsvd");
	long page_kb = hg_meminfo_kb("Hugepagesize");

	if (free_pg < 0 || rsvd_pg < 0 || page_kb <= 0 || free_pg <= rsvd_pg)
		return 0;
	return (unsigned long long)(free_pg - rsvd_pg) *
		((unsigned long long)page_kb << 10);
}

/* general RAM still committable: the host's or the memory cgroup's room,
 * whichever is tighter (HG_ROOM_ANY if neither); @ci gets the binding level */
static unsigned long long hg_ram_room_why(struct hg_cg_info *ci)
{
	long total_kb, avail_kb;
	unsigned long long floor_b, avail_b, room, cg;
	struct hg_cg_info c;

	hg_meminfo_kb2("MemTotal", &total_kb, "MemAvailable", &avail_kb);
	floor_b = (unsigned long long)hg_ram_floor_of(total_kb) << 20;

	if (avail_kb < 0) {
		room = HG_ROOM_ANY;
	} else {
		avail_b = (unsigned long long)avail_kb << 10;
		room = avail_b <= floor_b ? 0 : avail_b - floor_b;
	}
	cg = hg_cgroup_room(&c);
	if (cg < room)
		room = cg;
	else
		c.version = 0;
	if (ci)
		*ci = c;
	return room;
}

static unsigned long long hg_ram_room(void)
{
	return hg_ram_room_why(NULL);
}

/* can a new arena commit @init bytes now (hugetlb pool or RAM above the
 * floor)? 1 if so, else 0 with the reason logged for @what */
int hg_init_fits(const char *what, unsigned long init,
		unsigned long cap, int no_pool)
{
	unsigned long apage = hg_arena_page(init, cap);
	int huge_grid = (apage == HG_HPS);
	/* an INIT under one huge page may be raised to one on huge pages */
	unsigned long need = hg_page_round(init, huge_grid ? HG_HPS : apage);
	struct hg_cg_info ci;
	unsigned long long room = hg_ram_room_why(&ci), pool;

	if (need <= room)
		return 1;
	pool = (huge_grid && !no_pool) ? hg_pool_free_bytes() : 0;
	if (need <= pool)
		return 1;
	if (ci.version)
		LM_ERR("%s: the memory cgroup (v%d) is the tighter limit: %lu MB "
			"limit, %lu MB in use, %lu MB floor\n", what, ci.version,
			ci.limit_mb, ci.used_mb, ci.floor_mb);
	LM_ERR("%s: committing %lu %s now does not fit - %lu MB of RAM is "
		"available above the %ld MB floor (hg_ram_floor_mb) and the "
		"hugetlb pool has %lu MB free. Lower INIT (-m/-M), the number of "
		"processes, or the floor, or add memory or huge pages.\n", what,
		HG_SZ_VAL(need), HG_SZ_UNIT(need),
		room == HG_ROOM_ANY ? 0 : (unsigned long)(room >> 20), hg_ram_floor(),
		(unsigned long)(pool >> 20));
	return 0;
}

struct hg_pkg_pub {
	unsigned long grow_refused;
	unsigned int grow_blocked;
};
static struct hg_pkg_pub *hg_pkg_pub;
static unsigned int hg_pkg_pub_n;

int hg_pkg_pub_init(unsigned int nproc)
{
#ifdef PKG_MALLOC
	unsigned long bytes;

	if (mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 0;
	bytes = (unsigned long)nproc * sizeof *hg_pkg_pub;
	if (bytes / sizeof *hg_pkg_pub != nproc) {
		LM_ERR("%u processes overflow the pkg growth statistics\n", nproc);
		return -1;
	}
	hg_pkg_pub = shm_malloc(bytes);
	if (!hg_pkg_pub) {
		LM_ERR("no shm for the pkg growth statistics\n");
		return -1;
	}
	memset(hg_pkg_pub, 0, bytes);
	hg_pkg_pub_n = nproc;
#endif
	return 0;
}

void hg_pkg_publish(struct hg_block *hb)
{
	if (!hg_pkg_pub || process_no < 0 ||
	    (unsigned int)process_no >= hg_pkg_pub_n)
		return;
	hg_pkg_pub[process_no].grow_refused = hb->grow_refused;
	hg_pkg_pub[process_no].grow_blocked = hb->grow_blocked;
}

void hg_pkg_pub_reset(int proc)
{
	if (hg_pkg_pub && proc >= 0 && (unsigned int)proc < hg_pkg_pub_n)
		memset(&hg_pkg_pub[proc], 0, sizeof *hg_pkg_pub);
}

/* @ctx: 0 = refused grows summed over all processes, 1 = processes whose
 * pkg arena is GROW-BLOCKED now */
unsigned long hg_pkg_pub_stat(void *ctx)
{
	unsigned long sum = 0;
	unsigned int i;

	if (!hg_pkg_pub)
		return 0;
	for (i = 0; i < hg_pkg_pub_n; i++)
		sum += ctx ? (hg_pkg_pub[i].grow_blocked ? 1 : 0) :
		             hg_pkg_pub[i].grow_refused;
	return sum;
}

int hg_fork_fits(void)
{
#ifdef PKG_MALLOC
	static int said;

	if (mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 1;
	if (hg_ram_room() >= hg_page_round(pkg_mem_size,
	        hg_arena_page(pkg_mem_size, hg_pkg_cap_bytes) == HG_HPS ?
	        HG_HPS : HG_SMALL_PAGE)) {
		said = 0;
		return 1;
	}
	if (!said) {
		said = 1;
		hg_init_fits("new process's pkg arena", pkg_mem_size,
			hg_pkg_cap_bytes, 1);
		LM_ERR("not forking more processes until memory frees up\n");
	}
	return 0;
#else
	return 1;
#endif
}

int hg_capacity_check(unsigned int start_procs, unsigned int max_procs)
{
#ifndef PKG_MALLOC
	return 0;
#else
	unsigned long init = pkg_mem_size, cap, initr_ram;
	/* sums over every process: 64-bit, as the room they are held to */
	unsigned long long room, ram_start = 0, ram_max = 0, caps;
	long total_kb;
	unsigned int i, children;
	int huge_grid;

	if (mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG)
		return 0;

	cap = hg_pkg_cap_bytes > init ? hg_pkg_cap_bytes : init;
	huge_grid = (hg_arena_page(init, cap) == HG_HPS);
	initr_ram = hg_page_round(init, huge_grid ? HG_HPS : HG_SMALL_PAGE);
	room = hg_ram_room();

	/* the attendant keeps its pre-fork arena; every other process
	 * creates its own */
	children = max_procs > 1 ? max_procs - 1 : 0;
	for (i = 0; i < children; i++)
		*((i + 1 < start_procs) ? &ram_start : &ram_max) += initr_ram;
	ram_max += ram_start;
	LM_INFO("pkg: %u processes at startup, up to %u with auto-scaling, "
		"-M INIT %lu %s: %lu MB (%lu MB at the maximum) from RAM; %ld MB "
		"of RAM available above the %ld MB floor\n", start_procs,
		max_procs, HG_SZ_VAL(init), HG_SZ_UNIT(init),
		(unsigned long)(ram_start >> 20), (unsigned long)(ram_max >> 20),
		room == HG_ROOM_ANY ? -1L : (long)(room >> 20), hg_ram_floor());

	if (room != HG_ROOM_ANY && ram_start > room) {
		LM_ERR("pkg: the %u processes started now need %lu MB of RAM for "
			"their -M INIT of %lu %s, but %lu MB is available above the "
			"%ld MB floor. Lower -M INIT or the worker counts, or add "
			"memory.\n", start_procs, (unsigned long)(ram_start >> 20),
			HG_SZ_VAL(init), HG_SZ_UNIT(init),
			(unsigned long)(room >> 20), hg_ram_floor());
		return -1;
	}
	if (room != HG_ROOM_ANY && ram_max > room)
		LM_WARN("pkg: auto-scaling up to %u processes would need %lu MB "
			"of RAM for their -M INIT, but %lu MB is available above "
			"the %ld MB floor - processes beyond what fits will not be "
			"forked. Lower the scale-up maximums or -M INIT to make "
			"them all fit.\n", max_procs, (unsigned long)(ram_max >> 20),
			(unsigned long)(room >> 20), hg_ram_floor());

	total_kb = hg_meminfo_kb("MemTotal");
	caps = (unsigned long long)children * cap;
	if ((mem_allocator_shm == MM_HG_MALLOC ||
	     mem_allocator_shm == MM_HG_MALLOC_DBG) && shm_block)
		caps += ((struct hg_block *)shm_block)->hcap;
	if (total_kb > 0 && caps > ((unsigned long long)total_kb << 10))
		LM_WARN("the -m cap plus -M cap x %u processes is %lu MB, more "
			"than the host's %ld MB of memory: those caps can never all "
			"be met, and growth will be refused at the %ld MB floor\n",
			children, (unsigned long)(caps >> 20), total_kb >> 10,
			hg_ram_floor());
	return 0;
#endif
}

unsigned int hg_grow_room_short(const struct hg_block *hb,
		unsigned long delta, struct hg_room_short *rs)
{
	long total_kb;
	unsigned long long cg_room;
	int host_short, cg_short;

	rs->why = 0;
	/* tier 1: the whole cap was reserved from the hugetlb pool at map
	 * time, so a commit takes no new host RAM */
	if (hb->tier == HG_MEM_HUGETLB)
		return 0;

	hg_meminfo_kb2("MemTotal", &total_kb, "MemAvailable", &rs->avail_kb);
	rs->floor_mb = hg_ram_floor_of(total_kb);
	cg_room = hg_cgroup_room(&rs->ci);

	rs->delta = delta;
	rs->nproc = 1;
	rs->effective = delta;
	if (!hb->shared) {
		rs->nproc = counted_max_processes ? counted_max_processes : 1;
		rs->effective = (unsigned long long)delta * rs->nproc;
	}

	/* the host (unknown MemAvailable: let mlock decide), then the memory
	 * cgroup, which a container or a unit's MemoryMax hits first */
	host_short = rs->avail_kb >= 0 &&
		((unsigned long long)rs->avail_kb << 10) <
		rs->effective + ((unsigned long long)rs->floor_mb << 20);
	cg_short = cg_room != HG_ROOM_ANY && cg_room < rs->effective;
	if (host_short)
		rs->why = HG_GR_HOST_FLOOR;
	else if (cg_short)
		rs->why = HG_GR_CGROUP;
	return rs->why;
}

void hg_grow_room_refused(struct hg_block *hb, const struct hg_room_short *rs)
{
	hb->grow_refuse_why = rs->why;
	if (hb->grow_refuse_said)
		return;
	hb->grow_refuse_said = 1;
	if (rs->why == HG_GR_HOST_FLOOR)
		LM_WARN("%s: refusing to grow by %lu MB: %lu MB effective"
			" (x%lu processes) would leave the host under the "
			"%ld MB floor (MemAvailable %ld MB). Freeing host "
			"memory or lowering the floor lifts this.\n",
			hb->name, rs->delta >> 20,
			(unsigned long)(rs->effective >> 20), rs->nproc,
			rs->floor_mb, rs->avail_kb / 1024);
	else
		LM_WARN("%s: refusing to grow by %lu MB: %lu MB effective"
			" (x%lu processes) would leave the memory cgroup (v%d) "
			"under its %lu MB floor (limit %lu MB, %lu MB in use). "
			"Raising the cgroup's memory limit or freeing memory in "
			"it lifts this.\n", hb->name, rs->delta >> 20,
			(unsigned long)(rs->effective >> 20), rs->nproc,
			rs->ci.version, rs->ci.floor_mb, rs->ci.limit_mb,
			rs->ci.used_mb);
}
#endif /* HG_MALLOC */
