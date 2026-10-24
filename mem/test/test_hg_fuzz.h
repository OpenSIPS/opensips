/*
 * HG_MALLOC fuzz test against an independent shadow model
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

#ifndef __TEST_HG_FUZZ_H__
#define __TEST_HG_FUZZ_H__

/* children it forks, one at a time: one per seed, plus the capped arena */
#define TEST_HG_FUZZ_PROCS  4

/* run from test_hg_malloc(), whose child runner it uses */
void test_hg_fuzz(void);

#endif /* __TEST_HG_FUZZ_H__ */
