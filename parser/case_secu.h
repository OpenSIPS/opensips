/*
 * Secyrity-{Client,Server,Verify} Header Field Name Parsing Macros
 *
 * Copyright (c) 2024 OpenSIPS Solutions
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
 */
#ifndef CASE_SECU_H
#define CASE_SECU_H

#define ENT_CASE                                \
	switch( LOWER_DWORD(val) ) {                \
		case _ent1_:                            \
			hdr->type = HDR_SECURITY_CLIENT_T;  \
			hdr->name.len = 15;                 \
			return p + 4;                       \
		case _ent2_:                            \
			hdr->type = HDR_SECURITY_CLIENT_T;  \
			hdr->name.len = 15;                 \
			p += 4;                             \
			goto dc_cont;                       \
	}

#define VER_CASE                                \
	switch( LOWER_DWORD(val) ) {                \
		case _ver1_:                            \
			hdr->type = HDR_SECURITY_SERVER_T;  \
			hdr->name.len = 15;                 \
			return p + 4;                       \
		case _ver2_:                            \
			hdr->type = HDR_SECURITY_SERVER_T;  \
			hdr->name.len = 15;                 \
			p += 4;                             \
			goto dc_cont;                       \
	}

#define IFY_CASE                                \
	switch( LOWER_DWORD(val) ) {                \
		case _ify1_:                            \
			hdr->type = HDR_SECURITY_VERIFY_T;  \
			hdr->name.len = 15;                 \
			return p + 4;                       \
		case _ify2_:                            \
			hdr->type = HDR_SECURITY_VERIFY_T;  \
			hdr->name.len = 15;                 \
			p += 4;                             \
			goto dc_cont;                       \
	}

#define RITY_CASE                        \
	if ( LOWER_DWORD(val) == _rity_ ) {  \
		p += 4;                          \
		val = READ(p);                   \
		switch( LOWER_DWORD(val) ) {     \
			case __cli_:                 \
				p += 4;                  \
				val = READ(p);           \
				ENT_CASE;                \
				goto other;              \
			case __ser_:                 \
				p += 4;                  \
				val = READ(p);           \
				VER_CASE;                \
				goto other;              \
			case __ver_:                 \
				p += 4;                  \
				val = READ(p);           \
				IFY_CASE;                \
				goto other;              \
			default:                     \
				goto other;              \
		}                                \
	}

#define secu_CASE    \
	p += 4;          \
	if (!HAVE(12))   \
		goto other;  \
	val = READ(p);   \
	RITY_CASE;       \
	goto other;

#endif

