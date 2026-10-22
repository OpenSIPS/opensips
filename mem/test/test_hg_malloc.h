/*
 * HG_MALLOC unit tests
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

#ifndef __TEST_HG_MALLOC_H__
#define __TEST_HG_MALLOC_H__

/* children forked by test_hg_malloc(), one at a time (pt.c reserves them) */
#define TEST_HG_MALLOC_PROCS  5

/* non-zero when HG_MALLOC (or HG_MALLOC_DBG) serves both pkg and shm */
int hg_ut_selected(void);

void test_hg_malloc(void);

#endif /* __TEST_HG_MALLOC_H__ */
