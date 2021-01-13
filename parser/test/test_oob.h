/*
 * Copyright (C) 2020 Maksym Sobolyev
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

enum oob_position {OOB_UNDERFLOW, OOB_OVERFLOW};

#define OOB_CHECK_OK_MSG(fut, tstr, where) "oob check: %s(%s\"%.*s\"%s)", (fut), \
    (where) == OOB_UNDERFLOW ? "->" : "", (tstr)->len, (tstr)->s, \
    (where) == OOB_OVERFLOW ? "<-" : ""

void test_oob(const str *, void (*)(const str *, enum oob_position, void *), void *);
