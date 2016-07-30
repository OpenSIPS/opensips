/*
 * P-Asserted-Identity Header Field Name Parsing Macros
 *
 * Copyright (C) 2007 Voice System SRL
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

#ifndef CASE_RETR_H
#define CASE_RETR_H


#define ter_CASE                            \
	switch( LOWER_DWORD(val) ) {            \
		case _ter1_:                        \
			hdr->type = HDR_RETRY_AFTER_T;  \
			hdr->name.len = 11;             \
			return p + 4;                   \
		case _ter2_:                        \
			hdr->type = HDR_RETRY_AFTER_T;  \
			hdr->name.len = 11;             \
			p += 4;                         \
			goto dc_cont;                   \
	}


#define y_af_CASE                      \
	if (LOWER_DWORD(val) == _y_af_) {  \
		p += 4;                        \
		val = READ(p);                 \
		ter_CASE;                      \
		goto other;                    \
	}


#define retr_CASE     \
	p += 4;           \
	val = READ(p);    \
	y_af_CASE;        \
	goto other;


#endif /* CASE_RETR_H */
