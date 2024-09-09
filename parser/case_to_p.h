/*
 * Copyright (C) 2022 OpenSIPS Solutions
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


#ifndef CASE_TO_P_H
#define CASE_TO_P_H


#define ATH1_CASE                            \
	switch( LOWER_DWORD(val) ) {             \
		case _ath1_:                         \
			hdr->type = HDR_TO_PATH_T;       \
			hdr->name.len = 7;               \
			return p + 4;                    \
		case _ath2_:                         \
			hdr->type = HDR_TO_PATH_T;       \
			hdr->name.len = 7;               \
			p += 4;                          \
			goto dc_cont;                    \
	}


#define to_p_CASE         \
		p += 4;           \
		if (!HAVE(4))     \
			goto other;   \
		val = READ(p);    \
		ATH1_CASE;        \
		goto other;


#endif /* CASE_TO_P_H */

