/*
 * Copyright (C) 2001-2003 FhG Fokus
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

#ifndef str_h
#define str_h

#include <string.h>

/**
 * \file
 * \brief Common data type for text variables.
 * - \ref DataTypeText
 */

/*!
  * \page DataTypeText Common data type for text variables.
  *
  * This data type encapsulates a standard C char array. It's recommended to
  * use this type if you need variables holding text. It caches the length of
  * the C string to avoid repetive calls to strlen, thus improving performance.
  *
  * It's also safer to explicitly give the length to string operations of the
  * core or C libraries to prevent problems because of buffer overflows and
  * missing null-termination.
  *
  * Important: The char array inside this type is not null-terminated. So if
  * you need to work with external functions that rely on this termination you
  * must add a zero at the end by yourself. Keep in mind that the length of the
  * char array is normally not large enough to store this additional
  * null-termination.
  *
  * So you must copy the char array to a new buffer that is (len + 1) big,
  * otherwise memory corruption and undefined behavour will occur.
  * Most libraries often provide functions that can work with an explicit given
  * length, thus avoiding the need for this copy operation.
  */
struct __str {
	char* s; /**< string as char array */
	int len; /**< string length, not including null-termination */
};

typedef struct __str str;

/* str initialization */
#define STR_NULL (str){NULL, 0}
#define str_init(_string)  (str){_string, sizeof(_string) - 1}
static inline void init_str(str *dest, const char *src)
{
	dest->s = (char *)src;
	dest->len = strlen(src);
}

/* zero-str tests */
#define ZSTR(_s)    (!(_s).s || (_s).len == 0)
#define ZSTRP(_sp)  (!(_sp) || ZSTR(*(_sp)))

static inline str *str_cpy(str *dest, const str *src)
{
	memcpy(dest->s, src->s, src->len);
	dest->len = src->len;
	return dest;
}

#define STR_L(s) s, strlen(s)

/**
 * Handy function for writing unit tests which compare str's
 *
 * WARNING: _only_ use when passing (str *) to _basic_ functions,
 *          since it is not re-entrant and may cause ugly bugs!
 */
static inline str *_str(const char *s)
{
	static str st;

	init_str(&st, s);
	return &st;
}

#endif
