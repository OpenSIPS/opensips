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

#ifndef CASE_MIN__H
#define CASE_MIN__H 1


#ifndef SE_CASE
#define SE_CASE	\
	if ( LOWER_BYTE(*p) == 's' && LOWER_BYTE(*(p+1)) == 'e' ) {	\
		hdr->type = HDR_MIN_SE_T;								\
		p += 2;													\
		goto dc_end;											\
	}
#else
#error existing #define of SE_CASE currently needed for parsing Min-SE header
#endif


#ifndef min__CASE
#define min__CASE	\
	p += 4;			\
	SE_CASE;		\
	goto other;
#else
#error existing #define of min__CASE currently needed for \
	parsing "Min-"-prefixed headers
#endif


#endif /* ! CASE_MIN__H */
