/*
 * Copyright (C) 2026 VoIPcloud
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * The generation of the hugepage allocator this binary carries, as one
 * string, used everywhere the allocator names itself: the compile-flag list
 * in "opensips -V", the "allocator: ..." line each arena logs at startup,
 * and mm_str().
 *
 * It exists because those three places used to spell the name as three
 * separate literals.  A binary built from the v2 branch that still announced
 * itself as plain HG_MALLOC would be indistinguishable from a v1 build in a
 * log or a -V paste - which is exactly the evidence an A/B between the two
 * arenas is judged on.
 *
 * Deliberately NOT the accepted spelling on the command line: -a HG_MALLOC
 * keeps working (see parse_mm), because every /etc/default/opensips in the
 * fleet passes that name and a build should never require the sizing file to
 * be edited in lockstep.  This is an identity, not a selector.
 */

#ifndef HG_VERSION_H
#define HG_VERSION_H

#define HG_MALLOC_NAME  "HG_MALLOC_V3"

#endif /* HG_VERSION_H */
