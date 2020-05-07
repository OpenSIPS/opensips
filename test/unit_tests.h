/*
 * Entry point for including and running OpenSIPS unit tests (core + modules)
 *
 * Copyright (C) 2018-2020 OpenSIPS Solutions
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

/**
 * IMPORTANT: modules which need to export a unit testing entry-point function
 * must use this function signature and name the function exactly: 'mod_tests'
 *
 * Module testing code: any module testing code should be placed inside a
 * "test/" subdirectory, so it doesn't always get built into the .so
 *
 * opensips.cfg for module testing: currently, there is only support for a
 * single "opensips.cfg" testing file per module, which must be located in
 * modules/<module>/test/opensips.cfg, and will be automatically used.
 *    TODO: expand this ^ to a "N x opensips.cfg testing files" mechanism
 */
typedef void (*mod_tests_f) (void);

#ifdef UNIT_TESTS
void init_unit_tests(void);
int run_unit_tests(void);
#else
#define init_unit_tests()
#define run_unit_tests() ({0;})
#endif

#endif /* __UNIT_TESTS_H__ */
