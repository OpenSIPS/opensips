/*
 * Session-Expires Header Field Name Parsing Macros
 *
 * Copyright (c) 2006 SOMA Networks, Inc. <http://www.somanetworks.com/>
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
 *
 * History:
 * --------
 * 2006-02-17 Initial revision (dhsueh@somanetworks.com)
 */

#ifndef CASE_MIN__H
#define CASE_MIN__H 1

#define res__CASE                          \
	switch(LOWER_DWORD(val)) {             \
		case _res1_ :                      \
			hdr->type = HDR_MIN_EXPIRES_T; \
			hdr->name.len = 11;            \
			return (p + 4);                \
		case _res2_ :                      \
			hdr->type = HDR_MIN_EXPIRES_T; \
			hdr->name.len = 11;            \
			p += 4;                        \
			goto dc_cont;                  \
	}


#define SE_EXPI_CASE    \
	if ( LOWER_BYTE(*p) == 's' ) {          \
		p++;                                \
		switch ( LOWER_BYTE(*p) ) {     \
			case 'e':                       \
				hdr->type = HDR_MIN_SE_T;   \
				hdr->name.len = 6;          \
				p++;                        \
				goto dc_cont;               \
		}                                   \
		goto other;                         \
	}                                       \
	val = READ(p);                          \
	switch(LOWER_DWORD(val)) {              \
		case _expi_:                        \
			p += 4;                         \
			val = READ(p);                  \
			res__CASE;                      \
			goto other;                     \
	}


#define min__CASE    \
	p += 4;          \
	SE_EXPI_CASE;    \
	goto other;


#endif /* ! CASE_MIN__H */
