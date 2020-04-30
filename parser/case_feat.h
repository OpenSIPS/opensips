/*
 * Feature-Caps Header Field Name Parsing Macros
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

#ifndef CASE_FEAT_H
#define CASE_FEAT_H

#define feat_CASE              \
	switch(LOWER_DWORD(val)) { \
		case _feat_:           \
			p += 4;            \
			val = READ(p);     \
			ure__CASE;         \
			goto other;        \
	}

#define ure__CASE              \
	switch(LOWER_DWORD(val)) { \
		case _ure__:           \
			p += 4;            \
			val = READ(p);     \
			caps_CASE;         \
			goto other;        \
	}

#define caps_CASE                               \
	switch(LOWER_DWORD(val)) {                  \
		case _caps_:                            \
			p += 4;                             \
			if (*p == ':') {                    \
				hdr->type = HDR_FEATURE_CAPS_T; \
				hdr->name.len = 12;             \
				return p + 1;                   \
			}                                   \
			p++;                                \
			goto dc_cont;                       \
		}

#endif /* CASE_FEAT_H */
