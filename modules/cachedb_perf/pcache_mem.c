/*
 * cachedb_perf - high-performance local memory cache
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * Huge-page tier detection (DESIGN 2.6.1 / CP-20, detection half).
 *
 * Every tier is detected by TRYING it on a scratch mapping and verifying
 * the result through /proc/self/smaps - never inferred from the kernel
 * version or from sysfs configuration (the 6.8/6.12 MADV_COLLAPSE
 * divergence proves such checks lie).  The scratch mapping is unmapped
 * after the probe; the never-unmap invariant (DESIGN 3.2) applies to the
 * arena, which holds entries - not to a probe that never does.
 *
 * The probe is advisory: the arena allocator (CP-02/CP-20) re-runs the
 * ladder per chunk, so a pool that appears or drains after startup is
 * handled at allocation time.  This runs pre-fork, from mod_init.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "../../dprint.h"

#include "pcache_mem.h"

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

#define PCACHE_HPS (2UL * 1024 * 1024)   /* huge page size, x86_64 */

struct pcache_mem_info pcache_mem;

static int read_vm_int(const char *path)
{
	FILE *f;
	int v = -1;

	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d", &v) != 1)
		v = -1;
	fclose(f);
	return v;
}

/* global huge shmem, /proc/meminfo "ShmemHugePages:" in kB.  This is the
 * verification for MADV_COLLAPSE: a shmem collapse creates the huge folio
 * but does NOT install the PMD mapping in the caller's page table, so
 * per-process smaps shows nothing until a re-fault - the bench verified
 * through this same global counter (DESIGN 2.6.1) */
static long read_shmem_huge_kb(void)
{
	FILE *f;
	char line[256];
	long kb = -1;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, "ShmemHugePages:", 15)) {
			kb = strtol(line + 15, NULL, 10);
			break;
		}
	}
	fclose(f);
	return kb;
}

/* is the 2M range starting at @addr PMD-mapped in this process?
 * ("verify, never infer" - DESIGN 2.6.1) */
static int range_is_huge(unsigned long addr)
{
	FILE *f;
	char line[256], *p;
	unsigned long start, end, kb;
	int in_range = 0, huge = 0;

	f = fopen("/proc/self/smaps", "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof line, f)) {
		if (sscanf(line, "%lx-%lx ", &start, &end) == 2) {
			in_range = (start <= addr && addr < end);
			continue;
		}
		if (!in_range)
			continue;
		if (!strncmp(line, "AnonHugePages:", 14) ||
		        !strncmp(line, "ShmemPmdMapped:", 15) ||
		        !strncmp(line, "FilePmdMapped:", 14)) {
			p = strchr(line, ':');
			kb = strtoul(p + 1, NULL, 10);
			if (kb >= PCACHE_HPS / 1024) {
				huge = 1;
				break;
			}
		}
	}

	fclose(f);
	return huge;
}

void pcache_mem_probe(void)
{
	char *resv, *aligned;
	void *p;
	size_t len;
	long shmem_kb;
	int rc;

	memset(&pcache_mem, 0, sizeof pcache_mem);
	pcache_mem.tier = PCACHE_MEM_4K;

	pcache_mem.huge_static =
		read_vm_int("/proc/sys/vm/nr_hugepages");
	pcache_mem.huge_overcommit =
		read_vm_int("/proc/sys/vm/nr_overcommit_hugepages");

	/* tier 1: MAP_HUGETLB.  Pages are secured against the pool (static
	 * or overcommit) at mmap time, so a successful map plus one touched
	 * byte proves the route; failure (ENOMEM/EINVAL) drops a tier */
	p = mmap(NULL, PCACHE_HPS, PROT_READ|PROT_WRITE,
	         MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
	if (p != MAP_FAILED) {
		*(volatile char *)p = 1;
		munmap(p, PCACHE_HPS);
		pcache_mem.tier = PCACHE_MEM_HUGETLB;
		return;
	}

	/* Tiers 2 and 3 need a 2M-aligned shmem scratch, and aligning the VA
	 * inside an unaligned mapping is NOT enough: shmem THP requires the
	 * VA and the shmem *file offset* to be congruent mod 2M, and offset
	 * 0 is pinned to wherever the mapping starts.  A VA-aligned range
	 * inside an unaligned mapping sits at offset != 0 there and is
	 * simply ineligible (THPeligible 0, MADV_COLLAPSE EINVAL) - found
	 * the hard way: the probe passed standalone and failed in-process
	 * purely on ASLR luck.  So: reserve VA PROT_NONE first, then
	 * MAP_FIXED the shmem at a 2M boundary inside the reservation - an
	 * atomic replace, no race with other mappings. */
	len = 2 * PCACHE_HPS;
	resv = mmap(NULL, len, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (resv == MAP_FAILED)
		return;
	aligned = (char *)(((unsigned long)resv + PCACHE_HPS - 1)
	                   & ~(PCACHE_HPS - 1));
	p = mmap(aligned, PCACHE_HPS, PROT_READ|PROT_WRITE,
	         MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		munmap(resv, len);
		return;
	}

	/* tier 2: advice set before first touch -> huge at fault time */
	rc = madvise(aligned, PCACHE_HPS, MADV_HUGEPAGE);
	memset(aligned, 1, PCACHE_HPS);
	if (rc == 0 && range_is_huge((unsigned long)aligned)) {
		pcache_mem.tier = PCACHE_MEM_THP_ADVISE;
		goto out;
	}

	/* tier 3: collapse the already-faulted 4K pages in place.  Verified
	 * by the ShmemHugePages delta, not smaps: shmem collapse creates the
	 * huge folio without PMD-mapping it here (later faults do that) */
	shmem_kb = read_shmem_huge_kb();
	rc = madvise(aligned, PCACHE_HPS, MADV_COLLAPSE);
	if (rc == 0 && shmem_kb >= 0 &&
	        read_shmem_huge_kb() - shmem_kb >= (long)(PCACHE_HPS / 1024)) {
		pcache_mem.tier = PCACHE_MEM_THP_COLLAPSE;
		goto out;
	}
	if (rc != 0)
		LM_DBG("MADV_COLLAPSE: %s\n", strerror(errno));

out:
	munmap(resv, len);
}

/*
 * CP-20: reserve a large 2M-aligned MAP_SHARED region for the arena, backed
 * by huge pages via the same ladder as the probe, mlock-pinned against swap.
 * Created pre-fork and never unmapped, so every worker inherits it (the
 * invariant the lock-free read path and CP-09 growth both need).  Returns
 * the base (NULL on total failure -> caller falls back to shm_malloc),
 * sets *tier to what was achieved and *locked_mb to the pinned amount.
 */
void *pcache_mem_reserve(size_t size, enum pcache_mem_tier *tier,
		unsigned long *locked_mb)
{
	size_t asize = (size + PCACHE_HPS - 1) & ~(PCACHE_HPS - 1);
	char *resv, *base;
	long shmem_kb;
	void *p;

	*locked_mb = 0;
	*tier = PCACHE_MEM_4K;

	/* tier 1: MAP_HUGETLB - unswappable, exempt from RLIMIT_MEMLOCK */
	p = mmap(NULL, asize, PROT_READ|PROT_WRITE,
	         MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
	if (p != MAP_FAILED) {
		memset(p, 0, asize);           /* commit the pool pages */
		*tier = PCACHE_MEM_HUGETLB;
		return p;
	}

	/* tiers 2-4: 2M-aligned MAP_SHARED|ANON (reserve PROT_NONE, then
	 * MAP_FIXED at a 2M boundary - VA/offset congruence, DESIGN 2.6.1) */
	resv = mmap(NULL, asize + PCACHE_HPS, PROT_NONE,
	            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (resv == MAP_FAILED)
		return NULL;
	base = (char *)(((unsigned long)resv + PCACHE_HPS - 1)
	                & ~(PCACHE_HPS - 1));
	p = mmap(base, asize, PROT_READ|PROT_WRITE,
	         MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		munmap(resv, asize + PCACHE_HPS);
		return NULL;
	}

	/* advise huge before first touch (tier 2), then pin+populate: a cold
	 * mlock populates to pin, so it doubles as the pre-fault (DESIGN 2.6.2) */
	madvise(base, asize, MADV_HUGEPAGE);
	shmem_kb = read_shmem_huge_kb();
	if (mlock(base, asize) == 0) {
		*locked_mb = asize >> 20;
	} else {
		LM_WARN("mlock of the %zu MB arena failed (%s): continuing "
			"unpinned (swappable). If running under systemd, add "
			"LimitMEMLOCK=infinity to the unit.\n",
			asize >> 20, strerror(errno));
		memset(base, 0, asize);        /* still pre-fault */
	}

	if (range_is_huge((unsigned long)base)) {
		*tier = PCACHE_MEM_THP_ADVISE;
	} else if (shmem_kb >= 0 &&
	           madvise(base, asize, MADV_COLLAPSE) == 0 &&
	           read_shmem_huge_kb() - shmem_kb >= (long)(asize / 1024)) {
		*tier = PCACHE_MEM_THP_COLLAPSE;
	} else {
		*tier = PCACHE_MEM_4K;         /* reserved+pinned but 4K */
	}
	return base;
}

const char *pcache_mem_tier_str(enum pcache_mem_tier tier)
{
	switch (tier) {
	case PCACHE_MEM_HUGETLB:
		return "MAP_HUGETLB 2M pages";
	case PCACHE_MEM_THP_ADVISE:
		return "THP 2M pages via MADV_HUGEPAGE (huge at fault)";
	case PCACHE_MEM_THP_COLLAPSE:
		return "THP 2M pages via MADV_COLLAPSE (post-fill retrofit)";
	case PCACHE_MEM_4K:
		return "plain 4K pages";
	}
	return "unknown";
}
