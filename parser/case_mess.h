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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef CASE_MESS_H
#define CASE_MESS_H

#define id12_CASE                               \
	switch(LOWER_DWORD(val)) {                  \
		case _id12_:                            \
			hdr->type = HDR_MESSAGE_ID_T;       \
			hdr->name.len = 12;                 \
			return p + 4;                       \
		}


#define age__CASE              \
	switch(LOWER_DWORD(val)) { \
		case _age__:           \
			p += 4;            \
			val = READ(p);     \
			id12_CASE;         \
			goto other;        \
	}


#define mess_CASE          \
		p += 4;            \
		val = READ(p);     \
		age__CASE;         \
		goto other;



#endif /* CASE_MESS_H */
