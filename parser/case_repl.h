/*
 * Replaces Header Field Name Parsing Macros
 *
 * Copyright (C) 2020 OpenSIPS Solutions
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

#ifndef CASE_REPL_H
#define CASE_REPL_H

#define repl_CASE              \
	switch(LOWER_DWORD(val)) { \
		case _repl_:           \
			p += 4;            \
			val = READ(p);     \
			aces_CASE;         \
			goto other;        \
	}

#define aces_CASE                               \
	switch(LOWER_DWORD(val)) {                  \
		case _aces_:                            \
			p += 4;                             \
			if (*p == ':') {                    \
				hdr->type = HDR_REPLACES_T;     \
				hdr->name.len = 8;              \
				return p + 1;                   \
			}                                   \
			p++;                                \
			goto dc_cont;                       \
		}

#endif /* CASE_REPL_H */
