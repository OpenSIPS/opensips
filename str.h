/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef str_h
#define str_h

/**
 * \file
 * \brief Common data type for text variables.
 * - \ref DataTypeText
 */

/*!
  * \page DataTypeText Common data type for text variables.
  *
  * This data type encapsulate a standard C char array. Its recommended to use
  * this type if you need variables holding text. Its caches the length of the
  * C string to avoid repetive calls to strlen, thus improving performance.
  * Its also safer to explicitly give the length to string operations of the core
  * or C libraries to prevent problems because of buffer overflows and missing
  * null-termination.
  * Important: The char array inside this type is not null-terminated. So if you
  * need to work with external functions that rely on this termination you must
  * add a zero at the end by yourself. Keep in mind that the length of the char
  * array is normally not large enough to store this additional null-termination.
  * So you must copy the char array to a new buffer that is (len + 1) big,
  * otherwise memory corruption and undefinied behavour will occur.
  * Most libraries provides also functions that can work with an explicit given
  * length, thus avoiding the need for this copy operation.
  */
struct _str{
	char* s; /**< string as char array */
	int len; /**< string length, not including null-termination */
};

typedef struct _str str;


#endif
