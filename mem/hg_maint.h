/*
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * HG_MALLOC maintenance process: a dedicated core process that
 * grows an elastic shm arena AHEAD of demand so no SIP worker ever pays
 * a populate, and that runs the profile and shrink policy on its own
 * clock instead of inside whichever worker picks up the sweep timer.
 */
#ifndef hg_maint_h
#define hg_maint_h

#ifdef HG_MALLOC
/* 1 if the process will be forked (HG_MALLOC shm with a growth cap) */
int hg_maint_count_processes(void);
/* fork it; 0 = ok or not wanted, -1 = fork failed */
int hg_maint_start(void);
#else
static inline int hg_maint_count_processes(void) { return 0; }
static inline int hg_maint_start(void) { return 0; }
#endif

#endif /* hg_maint_h */
