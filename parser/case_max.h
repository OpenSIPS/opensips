/*
 * Max-Forwards Header Field Name Parsing Macros
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


#ifndef CASE_MAX_H
#define CASE_MAX_H


#define ARDS_CASE                      \
	if (LOWER_DWORD(val) == _ards_) {  \
		hdr->type = HDR_MAXFORWARDS_T; \
		hdr->name.len = 12;            \
		p += 4;                        \
		goto dc_cont;                  \
	}


#define FORW_CASE              \
	switch(LOWER_DWORD(val)) { \
		case _forw_:           \
			p += 4;            \
			val = READ(p);     \
			ARDS_CASE;         \
		goto other;            \
	}


#define max_CASE      \
	p += 4;           \
	val = READ(p);    \
	FORW_CASE;        \
	goto other;       \


#endif /* CASE_MAX_H */
