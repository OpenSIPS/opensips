/*
 * Remote-Party-ID Header Field Name Parsing Macros
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

#ifndef CASE_REMO_H
#define CASE_REMO_H


#define _ID_CASE                     \
	switch(LOWER_DWORD(val)) {       \
		case __id1_:                 \
			hdr->type = HDR_RPID_T;  \
			hdr->name.len = 15;      \
			return (p + 4);          \
		case __id2_:                 \
			hdr->type = HDR_RPID_T;  \
			hdr->name.len = 15;      \
			p += 4;                  \
			goto dc_cont;            \
		}

#define ARTY_CASE                 \
	if (LOWER_DWORD(val) == _arty_) { \
		p += 4;                   \
		val = READ(p);            \
		_ID_CASE;                 \
		goto other;               \
	}

#define TE_P_CASE                      \
		if (LOWER_DWORD(val) == _te_p_) {  \
			p += 4;                    \
			val = READ(p);             \
			ARTY_CASE;                 \
			goto other;                \
		}


#define remo_CASE      \
	p += 4;           \
	val = READ(p);    \
	TE_P_CASE;        \
	goto other;


#endif /* CASE_REMO_H */
