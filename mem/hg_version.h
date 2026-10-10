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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * The hugepage allocator's name, as one string, used everywhere the
 * allocator names itself: the compile-flag list in "opensips -V", the
 * "allocator: ..." line each arena logs at startup, and mm_str().  One
 * definition keeps the three in agreement, so a log line or a -V paste
 * identifies exactly which allocator a binary was built with.
 *
 * Deliberately NOT the accepted spelling on the command line: -a HG_MALLOC
 * keeps working (see parse_mm), because existing /etc/default/opensips files
 * pass that name and a build should never require the sizing file to
 * be edited in lockstep.  This is an identity, not a selector.
 */

#ifndef HG_VERSION_H
#define HG_VERSION_H

#define HG_MALLOC_NAME  "HG_MALLOC_V3"

#endif /* HG_VERSION_H */
