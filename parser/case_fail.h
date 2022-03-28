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

#ifndef CASE_FAIL_H
#define CASE_FAIL_H


#define repo_CASE              \
	switch(LOWER_DWORD(val)) { \
		case _repo_:           \
			p += 4;            \
			if (LOWER_BYTE(*(p))=='r' && LOWER_BYTE(*(p+1))=='t') { \
				hdr->type = HDR_FAILURE_REPORT_T;   \
				hdr->name.len = 12;                 \
				p += 2;                             \
				goto dc_cont;                       \
			}                  \
			goto other;        \
	}


#define ure__CASE1             \
	switch(LOWER_DWORD(val)) { \
		case _ure__:           \
			p += 4;            \
			val = READ(p);     \
			repo_CASE;         \
			goto other;        \
	}


#define fail_CASE          \
		p += 4;            \
		if (!HAVE(10))     \
			goto other;    \
		val = READ(p);     \
		ure__CASE1;        \
		goto other;


#endif /* CASE_FAIL_H */
