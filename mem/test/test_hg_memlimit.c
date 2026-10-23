/*
 * HG_MALLOC host and cgroup memory limits - unit tests
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
 * The floor formula, and the cgroup room read from fake cgroup trees laid
 * out in a temporary directory - cgroup v2 with the limit on an ancestor
 * and then on the process's own level, a limit above 4 GB, cgroup v1 on a
 * hybrid host, no limit anywhere, no membership file - so CI checks the
 * parsing and the walk without needing a limited cgroup of its own. Then
 * the host check on a fake /proc/meminfo with more than 4 GB available,
 * which a 32-bit build must count whole.
 */

#ifdef HG_MALLOC

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../mem/hg_malloc.h"
#include "../../mem/hg_memlimit.h"
#include "test_hg_memlimit.h"

#define MB (1UL << 20)

static char hml_dir[64];
static char *hml_made[48];
static int hml_n;

/* @rel under the temp dir: a file with @content, or a directory if NULL */
static int hml_put(const char *rel, const char *content)
{
	char p[256];
	FILE *f;

	snprintf(p, sizeof p, "%s/%s", hml_dir, rel);
	if (hml_n >= (int)(sizeof hml_made / sizeof hml_made[0]))
		return -1;
	if (!content) {
		if (mkdir(p, 0700) < 0)
			return -1;
	} else {
		f = fopen(p, "w");
		if (!f)
			return -1;
		fputs(content, f);
		fclose(f);
	}
	hml_made[hml_n++] = strdup(p);
	return 0;
}

static void hml_cleanup(void)
{
	struct stat st;

	while (hml_n > 0) {
		char *p = hml_made[--hml_n];

		if (stat(p, &st) == 0 && S_ISDIR(st.st_mode))
			rmdir(p);
		else
			unlink(p);
		free(p);
	}
	rmdir(hml_dir);
}

static unsigned long long hml_room(const char *self, struct hg_cg_info *ci)
{
	char root[128], selfp[128];

	snprintf(root, sizeof root, "%s/cg", hml_dir);
	snprintf(selfp, sizeof selfp, "%s/%s", hml_dir, self);
	hg_cgroup_test_paths(root, selfp);
	return hg_cgroup_room(ci);
}

/*
 * The host check, through a grow of the shm arena by 16 MB, on a fake
 * /proc/meminfo: 8 GB of RAM, floor 409 MB (a twentieth). 4 GB + 100 MB
 * available must pass - a 32-bit build that counted it in an unsigned long
 * saw 100 MB, under the floor, and refused every grow - and 8 MB above the
 * floor must be refused, so the check is shown live on every build. The
 * cgroup is pointed at a missing membership file, so only the host counts.
 */
static void test_hg_host_room(void)
{
	struct hg_block *hb = shm_block;
	char p[96], root[96];
	unsigned int said = hb->grow_refuse_said;
	int pass_big = -1, refuse_low = -1, bad;

	skip(hb->tier == HG_MEM_HUGETLB, 1,
		"a hugetlb arena takes nothing from host RAM at a grow");
	snprintf(p, sizeof p, "%s/meminfo", hml_dir);
	snprintf(root, sizeof root, "%s/cg", hml_dir);
	hg_cgroup_test_paths(root, "/nonexistent/hg-cgroup");
	hg_meminfo_test_path(p);

	bad = hml_put("meminfo", "MemTotal:        8388608 kB\n"
		"MemAvailable:    4296704 kB\n");
	if (!bad)
		pass_big = hg_grow_ram_refused(hb, 16 * MB);
	bad |= hml_put("meminfo", "MemTotal:        8388608 kB\n"
		"MemAvailable:     427008 kB\n");
	hb->grow_refuse_said = 1;   /* the refusal below is expected: no WARN */
	if (!bad)
		refuse_low = hg_grow_ram_refused(hb, 16 * MB);

	hb->grow_refuse_said = said;
	hg_meminfo_test_path(NULL);
	ok(!bad && pass_big == 0 && refuse_low == 1,
		"host memory above 4 GB counted whole: a 16 MB grow with 4196 MB "
		"available above a 409 MB floor passes (%d, 0 expected), with 8 MB "
		"above it is refused (%d, 1 expected)", pass_big, refuse_low);
	end_skip;
}

void test_hg_memlimit(void)
{
	struct hg_cg_info ci;
	unsigned long long r;
	int bad = 0;

	ok(hg_floor_mb_for(128) == 16 && hg_floor_mb_for(256) == 32 &&
		hg_floor_mb_for(1024) == 128 && hg_floor_mb_for(2048) == 256 &&
		hg_floor_mb_for(4096) == 256 && hg_floor_mb_for(16384) == 819,
		"the default floor: 16 MB of 128 MB, 128 MB of 1 GB, 256 MB from "
		"2 GB to 5 GB, a twentieth above (%ld %ld %ld %ld %ld %ld)",
		hg_floor_mb_for(128), hg_floor_mb_for(256), hg_floor_mb_for(1024),
		hg_floor_mb_for(2048), hg_floor_mb_for(4096), hg_floor_mb_for(16384));

	snprintf(hml_dir, sizeof hml_dir, "/tmp/hgmemlimitXXXXXX");
	if (!mkdtemp(hml_dir)) {
		ok(0, "a temporary directory for the fake cgroup trees");
		return;
	}

	/* cgroup v2: the 256 MB limit sits on the parent, the process's own
	 * cgroup has none - the walk must find it there. 100 MB in use, floor
	 * 32 MB: 124 MB of room */
	bad |= hml_put("cg", NULL) | hml_put("cg/a", NULL) | hml_put("cg/a/b", NULL);
	bad |= hml_put("self2", "0::/a/b\n");
	bad |= hml_put("cg/a/memory.max", "268435456\n");
	bad |= hml_put("cg/a/memory.current", "104857600\n");
	bad |= hml_put("cg/a/memory.stat", "anon 104857600\ninactive_file 0\n");
	bad |= hml_put("cg/a/b/memory.max", "max\n");
	bad |= hml_put("cg/a/b/memory.current", "52428800\n");
	bad |= hml_put("cg/a/b/memory.stat", "inactive_file 0\n");
	r = hml_room("self2", &ci);
	ok(!bad && r == 124 * MB && ci.version == 2 && ci.limit_mb == 256,
		"cgroup v2, limit on an ancestor: %llu MB of room (124 expected), "
		"limit %lu MB", r / MB, ci.limit_mb);

	/* now a tighter 128 MB limit on the process's own cgroup: 50 MB charged,
	 * 8 MB of it inactive file cache - 42 MB held, floor 16 MB: 70 MB */
	bad |= hml_put("cg/a/b/memory.max", "134217728\n");
	bad |= hml_put("cg/a/b/memory.stat", "anon 44040192\ninactive_file 8388608\n");
	r = hml_room("self2", &ci);
	ok(!bad && r == 70 * MB && ci.limit_mb == 128 && ci.used_mb == 42 &&
		ci.floor_mb == 16,
		"cgroup v2, a tighter limit on its own level, cache counted as free: "
		"%llu MB of room (70 expected), %lu MB held, %lu MB floor",
		r / MB, ci.used_mb, ci.floor_mb);

	/* a limit above 4 GB, read whole on a 32-bit build too: 6 GB limit,
	 * 5.5 GB held, floor 307 MB (a twentieth): 205 MB of room */
	bad |= hml_put("selfb", "0::/big\n");
	bad |= hml_put("cg/big", NULL);
	bad |= hml_put("cg/big/memory.max", "6442450944\n");
	bad |= hml_put("cg/big/memory.current", "5905580032\n");
	bad |= hml_put("cg/big/memory.stat", "inactive_file 0\n");
	r = hml_room("selfb", &ci);
	ok(!bad && r == 205 * MB && ci.limit_mb == 6144 && ci.used_mb == 5632 &&
		ci.floor_mb == 307,
		"cgroup v2, a limit above 4 GB: %llu MB of room (205 expected), "
		"limit %lu MB, %lu MB held, %lu MB floor",
		r / MB, ci.limit_mb, ci.used_mb, ci.floor_mb);

	/* cgroup v1 on a hybrid host: the memory controller's line wins over
	 * "0::"; the root reports "unlimited" as a number near 2^63. 64 MB
	 * limit, 10 MB charged of which 4 MB inactive cache, floor 8 MB: 50 MB */
	bad |= hml_put("self1", "7:memory:/x\n1:name=systemd:/x\n0::/x\n");
	bad |= hml_put("cg/memory", NULL) | hml_put("cg/memory/x", NULL);
	bad |= hml_put("cg/memory/memory.limit_in_bytes", "9223372036854771712\n");
	bad |= hml_put("cg/memory/memory.usage_in_bytes", "999999999\n");
	bad |= hml_put("cg/memory/x/memory.limit_in_bytes", "67108864\n");
	bad |= hml_put("cg/memory/x/memory.usage_in_bytes", "10485760\n");
	bad |= hml_put("cg/memory/x/memory.stat", "cache 0\ntotal_inactive_file 4194304\n");
	r = hml_room("self1", &ci);
	ok(!bad && r == 50 * MB && ci.version == 1,
		"cgroup v1 on a hybrid host: %llu MB of room (50 expected), v%d",
		r / MB, ci.version);

	/* no limit anywhere, and no membership file at all: no cgroup limit */
	bad |= hml_put("selfu", "0::/u\n");
	bad |= hml_put("cg/u", NULL) | hml_put("cg/u/memory.max", "max\n");
	bad |= hml_put("cg/u/memory.current", "1048576\n");
	r = hml_room("selfu", &ci);
	ok(!bad && r == HG_ROOM_ANY && ci.version == 0 &&
		hml_room("nosuch", NULL) == HG_ROOM_ANY,
		"no limited level, or no membership file: no cgroup limit");

	test_hg_host_room();

	hg_cgroup_test_paths(NULL, NULL);
	hml_cleanup();
}

#endif /* HG_MALLOC */
