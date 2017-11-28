/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef __LIB_CSV__
#define __LIB_CSV__

#include "../str_list.h"

/*
 * disable the RFC 4180 quoting mechanism
 *
 * Example:
 *	input: 123,"""foo"" bar",abc
 *
 * with CSV_REC_NO_DQUOTE:
 *		123
 *		"""foo"" bar"
 *		abc
 *
 * default:
 *		123
 *		"foo" bar
 *		abc
 */
#define CSV_REC_NO_DQUOTE     (1<<0)

/*
 * trim all leading and trailing whitespace (' ', '\t', '\r', '\n')
 *
 * Example:
 *	input: "123\n",  \tfoo ,  abc
 *
 * with CSV_REC_NO_OUTSIDE_WS:
 *		123\n
 *		foo
 *		abc
 *
 * default:
 *		123\n
 *		  \tfoo
 *		  abc
 */
#define CSV_REC_NO_OUTSIDE_WS (1<<1)

#define CSV_SIMPLE            (CSV_REC_NO_DQUOTE|CSV_REC_NO_OUTSIDE_WS)

/*
 * Chop an input string by the given separator
 *
 * Notes:
 *	- does NOT dup the resulting strings!
 *	- remember to free result field holders with free_csv_record()
 */
struct str_list *__parse_csv_record(const str *in, int parse_flags,
                                    unsigned char sep);
#define _parse_csv_record(in, flags) __parse_csv_record(in, flags, ',')
#define parse_csv_record(in) _parse_csv_record(in, 0)

static inline void free_csv_record(struct str_list *record)
{
	_free_str_list(record, osips_pkg_free, NULL);
}

#endif /* __LIB_CSV__ */
