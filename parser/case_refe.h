/* 
 * $Id$
 * 
 * Refer-To Header Field Name Parsing Macros
 *
 * Copyright (C) 2005 Juha Heinanen
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

#ifndef CASE_REFE_H
#define CASE_REFE_H

#define r_to_CASE                          \
        if (LOWER_DWORD(val) == _r_to_) {  \
                hdr->type = HDR_REFER_TO_T;  \
                p += 4;                    \
                goto dc_end;               \
        }


#define refe_CASE      \
     p += 4;           \
     val = READ(p);    \
     r_to_CASE;         \
     goto other;


#endif /* CASE_REFE_H */
