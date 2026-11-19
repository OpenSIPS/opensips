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

#ifndef hg_memlimit_h
#define hg_memlimit_h

/* the floor a commit must leave free, in MB, on @total_mb of memory: a
 * twentieth, but at least the smaller of 256 MB and an eighth */
long hg_floor_mb_for(long total_mb);

/* the tightest memory cgroup the calling process is in, for the messages;
 * in MB, which an unsigned long holds on a 32-bit build too */
struct hg_cg_info {
	int version;            /* 1 or 2; 0 = no limited level found */
	unsigned long limit_mb;
	unsigned long used_mb;  /* charged, less the reclaimable file cache */
	unsigned long floor_mb;
};

/* room above a floor, in 64-bit bytes even on 32-bit builds: the host is
 * not held to the process's 4 GB; HG_ROOM_ANY = no limit known */
#define HG_ROOM_ANY (~0ULL)

/* room the caller's memory cgroups leave above their floors, the tightest
 * level; HG_ROOM_ANY if none is limited or readable. @ci gets that level */
unsigned long long hg_cgroup_room(struct hg_cg_info *ci);

/* would committing @delta more bytes break the host or cgroup floor? _short()
 * reads files, so runs without hb->lock; _refused() records, under the lock */
struct hg_block;

struct hg_room_short {
	unsigned int why;           /* 0, HG_GR_HOST_FLOOR or HG_GR_CGROUP */
	unsigned long delta, nproc;
	unsigned long long effective;
	long floor_mb, avail_kb;
	struct hg_cg_info ci;
};
unsigned int hg_grow_room_short(const struct hg_block *hb,
		unsigned long delta, struct hg_room_short *rs);
void hg_grow_room_refused(struct hg_block *hb, const struct hg_room_short *rs);

/* test hook: read cgroup files under @root and membership from @self_cgroup
 * instead of /sys/fs/cgroup and /proc/self/cgroup; NULL restores them */
void hg_cgroup_test_paths(const char *root, const char *self_cgroup);

/* test hook: read @meminfo instead of /proc/meminfo; NULL restores it */
extern const char *hg_meminfo_file;
void hg_meminfo_test_path(const char *meminfo);

#endif /* hg_memlimit_h */
