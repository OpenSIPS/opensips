/*
 * slab allocator with elastic arenas - host and cgroup memory limits
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

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "hg_memlimit.h"
#include "../globals.h"

long hg_floor_mb_for(long total_mb)
{
	long floor_mb = total_mb / 8 < 256 ? total_mb / 8 : 256;

	if (total_mb / 20 > floor_mb)
		floor_mb = total_mb / 20;
	return floor_mb;
}

static const char *cg_root = "/sys/fs/cgroup";
static const char *cg_self = "/proc/self/cgroup";

void hg_cgroup_test_paths(const char *root, const char *self_cgroup)
{
	cg_root = root ? root : "/sys/fs/cgroup";
	cg_self = self_cgroup ? self_cgroup : "/proc/self/cgroup";
}

#ifdef __OS_linux

/* the number @path starts with; 0 when it does not (missing, or "max").
 * The cgroup files count in 64-bit bytes on every build */
static int read_ull(const char *path, unsigned long long *v)
{
	FILE *f = fopen(path, "r");
	int ok;

	if (!f)
		return 0;
	ok = fscanf(f, "%llu", v) == 1;
	fclose(f);
	return ok;
}

/* @key's value in a memory.stat file, 0 when it is not there */
static unsigned long long stat_value(const char *path, const char *key)
{
	char name[64];
	unsigned long long v, r = 0;
	FILE *f = fopen(path, "r");

	if (!f)
		return 0;
	while (fscanf(f, "%63s %llu", name, &v) == 2)
		if (!strcmp(name, key)) {
			r = v;
			break;
		}
	fclose(f);
	return r;
}

/*
 * One level of the hierarchy: if it has a limit, its room above its floor
 * goes into @best when tighter. What the level holds is its charge less its
 * inactive file cache - the cgroup's counterpart of what MemAvailable counts
 * as reclaimable on the host.
 */
static void cg_level(const char *dir, int v, unsigned long *best,
                     struct hg_cg_info *ci)
{
	/* @dir is at most 1099 bytes (see hg_cgroup_room()), the longest file
	 * name "memory.limit_in_bytes" 21 */
	char p[1100 + 32];
	unsigned long long limit, cur, cache, used, floor, room;
	long limit_mb;

	snprintf(p, sizeof p, "%s/%s", dir,
		v == 2 ? "memory.max" : "memory.limit_in_bytes");
	if (!read_ull(p, &limit))
		return;
	/* cgroup v1 says "unlimited" with a number near 2^63 */
	if (v == 1 && limit >= (1ULL << 62))
		return;
	snprintf(p, sizeof p, "%s/%s", dir,
		v == 2 ? "memory.current" : "memory.usage_in_bytes");
	if (!read_ull(p, &cur))
		return;
	snprintf(p, sizeof p, "%s/memory.stat", dir);
	cache = stat_value(p, v == 2 ? "inactive_file" : "total_inactive_file");
	used = cur > cache ? cur - cache : 0;
	limit_mb = (limit >> 20) > LONG_MAX ? LONG_MAX : (long)(limit >> 20);
	floor = (unsigned long long)(hg_ram_floor_mb > 0 ? hg_ram_floor_mb :
		hg_floor_mb_for(limit_mb)) << 20;
	room = limit > used + floor ? limit - used - floor : 0;
	if (room < *best) {
		*best = (unsigned long)room;
		if (ci) {
			ci->version = v;
			ci->limit_mb = (unsigned long)(limit >> 20);
			ci->used_mb = (unsigned long)(used >> 20);
			ci->floor_mb = (unsigned long)(floor >> 20);
		}
	}
}

/* is @c one of the comma-separated controllers in @list? */
static int has_controller(const char *list, const char *c)
{
	size_t n = strlen(c);

	while (*list) {
		if (!strncmp(list, c, n) && (list[n] == ',' || list[n] == 0))
			return 1;
		list = strchr(list, ',');
		if (!list)
			break;
		list++;
	}
	return 0;
}

unsigned long hg_cgroup_room(struct hg_cg_info *ci)
{
	char line[1024], rel[512] = "", dir[1100], *c1, *c2, *slash;
	unsigned long best = ~0UL;
	int v = 0;
	FILE *f;

	if (ci)
		memset(ci, 0, sizeof *ci);
	f = fopen(cg_self, "r");
	if (!f)
		return ~0UL;
	/* "hierarchy:controllers:path" per line. A cgroup v1 memory line wins
	 * - on a hybrid host the memory controller is there, and the "0::"
	 * line only tracks processes; otherwise "0::" is cgroup v2 */
	while (fgets(line, sizeof line, f)) {
		line[strcspn(line, "\n")] = 0;
		c1 = strchr(line, ':');
		c2 = c1 ? strchr(c1 + 1, ':') : NULL;
		if (!c2)
			continue;
		*c1 = 0;        /* line: the hierarchy id */
		*c2 = 0;        /* c1 + 1: the controllers; c2 + 1: the path */
		if (has_controller(c1 + 1, "memory")) {
			v = 1;
			snprintf(rel, sizeof rel, "%s", c2 + 1);
		} else if (v != 1 && !strcmp(line, "0") && !c1[1]) {
			v = 2;
			snprintf(rel, sizeof rel, "%s", c2 + 1);
		}
	}
	fclose(f);
	if (!v || rel[0] != '/')
		return ~0UL;

	/* the process's own cgroup, then each ancestor: the tightest limit
	 * anywhere above it is the one the kernel enforces first. Inside a
	 * container the walk reaches the namespace root, whose files are the
	 * container's; on a host the real root has no limit files at all */
	for (;;) {
		snprintf(dir, sizeof dir, "%s%s%s", cg_root, v == 1 ? "/memory" : "",
			strcmp(rel, "/") ? rel : "");
		cg_level(dir, v, &best, ci);
		if (!strcmp(rel, "/"))
			break;
		slash = strrchr(rel, '/');
		if (slash == rel)
			rel[1] = 0;
		else
			*slash = 0;
	}
	return best;
}

#else /* not Linux: no cgroups */

unsigned long hg_cgroup_room(struct hg_cg_info *ci)
{
	if (ci)
		memset(ci, 0, sizeof *ci);
	return ~0UL;
}

#endif /* __OS_linux */

#endif /* HG_MALLOC */
