/*
 * $Id$
 *
 * BLACKWHITE module
 *
 * Copyright (C) 2016 sa
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
 *
 */

#ifndef BW_FUNCS_H
#define BW_FUNCS_H

#include "../../str.h"
#include <string.h>


static inline int str_cmp(const str *s1, const str *s2)
{
#define str_min_len(a,b)  ((a)<(b))?(a):(b)

	int ret;

	ret = strncmp( s1->s, s2->s, str_min_len( s1->len, s2->len) );

	if( ret == 0)
		ret =  s1->len - s2->len;

	return ret;
}


#endif
