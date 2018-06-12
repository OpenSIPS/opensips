/* 
 * $Id$
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef TRIM_H
#define TRIM_H

#include "str.h"


/*
 * This switch-case statement is used in
 * trim_leading and trim_trailing. You can
 * define characters that should be skipped 
 * here.
 */
#define TRIM_SWITCH(c) switch(c) {     \
                       case ' ':       \
                       case '\t':      \
                       case '\r':      \
                       case '\n':      \
                               break;  \
                                       \
                       default:        \
                               return; \
                       }


/*
 * Remove any leading whitechars, like spaces,
 * horizontal tabs, carriage returns and line
 * feeds
 *
 * WARNING: String descriptor structure will be
 *          modified ! Make a copy otherwise you
 *          might be unable to free _s->s for
 *          example !
 *
 */
static inline void trim_leading(str* _s)
{
	for(; _s->len > 0; _s->len--, _s->s++) {
		TRIM_SWITCH(*(_s->s));
	}
}


/*
 * Remove any trailing white char, like spaces,
 * horizontal tabs, carriage returns and line feeds
 *
 * WARNING: String descriptor structure will be
 *          modified ! Make a copy otherwise you
 *          might be unable to free _s->s for
 *          example !
 */
static inline void trim_trailing(str* _s)
{
	for(; _s->len > 0; _s->len--) {
		TRIM_SWITCH(_s->s[_s->len - 1]);
	}
}


/*
 * Do trim_leading and trim_trailing
 *
 * WARNING: String structure will be modified !
 *          Make a copy otherwise you might be
 *          unable to free _s->s for example !
 */
static inline void trim(str* _s)
{
	trim_leading(_s);
	trim_trailing(_s);
}


#endif /* TRIM_H */
