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

/*
 * How much memory may still be committed: the tighter of the host's room
 * (/proc/meminfo) and the memory cgroup's (a container limit, systemd
 * MemoryMax). A limited cgroup meets its limit first, and the kernel's OOM
 * killer then acts on the cgroup alone.
 */

/* the floor a commit must leave free, in MB, on @total_mb of memory: a
 * twentieth, but at least the smaller of 256 MB and an eighth */
long hg_floor_mb_for(long total_mb);

/* the tightest memory cgroup the calling process is in, for the messages;
 * in MB, which an unsigned long holds on a 32-bit build too */
struct hg_cg_info {
	int version;            /* 1 or 2; 0 = no limited level found */
	unsigned long limit_mb;
	unsigned long used_mb;  /* charged, less the reclaimable file cache */
	unsigned long floor_mb; /* what the floor keeps free */
};

/*
 * Room - what the host or a cgroup leaves above its floor - is in 64-bit
 * bytes on every build: a 32-bit process addresses at most 4 GB, but the
 * host and the processes together are not held to that. HG_ROOM_ANY: no
 * limit known.
 */
#define HG_ROOM_ANY (~0ULL)

/*
 * The room the calling process's memory cgroups leave above their floors:
 * the tightest of its own and every limited ancestor. HG_ROOM_ANY when none
 * is limited or the files cannot be read (not Linux, no memory controller);
 * the host check then decides alone. @ci, if given, gets the binding level.
 */
unsigned long long hg_cgroup_room(struct hg_cg_info *ci);

/* test hook: read the cgroup files under @root and the membership from
 * @self_cgroup instead of /sys/fs/cgroup and /proc/self/cgroup; NULL
 * restores the defaults */
void hg_cgroup_test_paths(const char *root, const char *self_cgroup);

/* the file host memory is read from, /proc/meminfo; test hook: read it
 * from @meminfo instead, NULL restores the default */
extern const char *hg_meminfo_file;
void hg_meminfo_test_path(const char *meminfo);

#endif /* hg_memlimit_h */
