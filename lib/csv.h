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

enum csv_flags {
	/*
	 * disable the RFC 4180 quoting mechanism
	 *
	 * Example:
	 *	input: 123,"""foo"" bar",abc
	 *
	 * with CSV_NO_DQUOTE:
	 *		123
	 *		"""foo"" bar"
	 *		abc
	 *
	 * default:
	 *		123
	 *		"foo" bar
	 *		abc
	 */
	CSV_NO_DQUOTE     = (1<<0),

	/*
	 * trim all leading and trailing whitespace (' ', '\t', '\r', '\n')
	 *
	 * Example:
	 *	input: "123\n",  \tfoo ,  abc
	 *
	 * with CSV_NO_OUTSIDE_WS:
	 *		123\n
	 *		foo
	 *		abc
	 *
	 * default:
	 *		123\n
	 *		  \tfoo
	 *		  abc
	 */
	CSV_NO_OUTSIDE_WS = (1<<1),

	CSV_PKG           = (1<<2), /* the default */
	CSV_SHM           = (1<<3), /* overrides CSV_PKG */

	CSV_DUP_FIELDS    = (1<<4),
};

#define CSV_SIMPLE            (CSV_NO_DQUOTE|CSV_NO_OUTSIDE_WS)

typedef struct str_list csv_record;

/*
 * Chop an input string by the given separator
 *
 * Note: free the result with free_csv_record()
 */
csv_record *__parse_csv_record(const str *in, enum csv_flags parse_flags,
                               unsigned char sep);
#define _parse_csv_record(in, flags) __parse_csv_record(in, flags, ',')
#define parse_csv_record(in) _parse_csv_record(in, 0)

/*
 * Use this to easily free your CSV records, regardless of any
 * CSV_DUP_FIELDS, CSV_PKG or CSV_SHM flags you may have set during parsing
 */
void free_csv_record(csv_record *record);

#endif /* __LIB_CSV__ */
