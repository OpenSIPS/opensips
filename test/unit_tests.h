/*
 * Starting point for writing and including OpenSIPS unit tests
 *
 * Copyright (C) 2018 OpenSIPS Solutions
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

#ifndef __UNIT_TESTS_H__
#define __UNIT_TESTS_H__

#ifdef UNIT_TESTS
void init_unit_tests(void);
int run_unit_tests(void);
#else
#define init_unit_tests()
#define run_unit_tests() ({0;})
#endif

#endif /* __UNIT_TESTS_H__ */
