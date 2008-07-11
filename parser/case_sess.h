/* 
 * $Id$
 * 
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2006-02-17 Initial revision (dhsueh@somanetworks.com)
 */

#ifndef CASE_SESS_H
#define CASE_SESS_H 1


#ifndef RES_CASE
#define RES_CASE	 						\
	switch( LOWER_DWORD(val) ) {			\
	case _res1_:							\
		hdr->type = HDR_SESSION_EXPIRES_T;	\
		hdr->name.len = 15;					\
		return p + 4;						\
	case _res2_:							\
		hdr->type = HDR_SESSION_EXPIRES_T;	\
		p += 4;								\
		goto dc_end;						\
	}
#else
#error existing #define of RES_CASE currently needed for \
	parsing Session-Expires
#endif

#ifndef EXPI_CASE
#define EXPI_CASE	 					\
	if ( LOWER_DWORD(val) == _expi_ ) {	\
		p += 4;							\
		val = READ(p);					\
		RES_CASE;						\
		goto other;						\
	}
#else
#error existing #define of EXPI_CASE currently needed for \
	parsing Session-Expires
#endif

#ifndef ION__CASE
#define ION__CASE						\
	if ( LOWER_DWORD(val) == _ion__ ) {	\
		p += 4;							\
		val = READ(p);					\
		EXPI_CASE;						\
		goto other;						\
	}
#else
#error existing #define of ION__CASE currently needed for \
	parsing Session-Expires
#endif

#ifndef sess_CASE
#define sess_CASE	\
	p += 4;			\
	val = READ(p);	\
	ION__CASE;		\
	goto other;
#else
#error existing #define of sess_CASE currently needed for \
	parsing Session-Expires
#endif


#endif /* ! CASE_SESS_H */
