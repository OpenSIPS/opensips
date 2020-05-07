/*
 * Copyright (C) 2017-2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LIB_CSV__
#define __LIB_CSV__

#include "../str_list.h"

enum csv_flags {
	/**
	 * 1. "dquote-enclosing" and "2x dquote escape sequence" mechanisms:
	 *    Input: '"""a"" \nb",c'
	 *    Output: '"a" \nb', 'c'
	 *
	 * 2. Whitespace does not get trimmed:
	 *    Input: 'a , b'
	 *    Output: 'a ', ' b'
	 */
	CSV_RFC_4180    = (1<<0),

	CSV_PKG         = (1<<1), /* the default */
	CSV_SHM         = (1<<2), /* overrides CSV_PKG */

	CSV_DUP_FIELDS  = (1<<3),
};

typedef str_list csv_record;

/*
 * Chop an input string by the given separator
 *
 * Note: free the result with free_csv_record()
 */
csv_record *__parse_csv_record(const str *in, enum csv_flags parse_flags,
                               unsigned char sep);
#define _parse_csv_record(in, flags) __parse_csv_record(in, flags, ',')
#define parse_csv_record(in) _parse_csv_record(in, 0)

/* Easily free your CSV records, regardless of any flags set during parsing */
void free_csv_record(csv_record *record);

#endif /* __LIB_CSV__ */
