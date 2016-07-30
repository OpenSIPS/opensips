/*
 * Contact, Content-Type, Content-Length, Content-Disposition
 * Header Field Name Parsing Macros
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
 *
 * History:
 * ----------
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-01-27 next baby-step to removing ZT - PRESERVE_ZT (jiri)
 */


#ifndef CASE_CONT_H
#define CASE_CONT_H


#define TH_CASE                                     \
		switch(LOWER_DWORD(val)) {                  \
		case _th12_:                                \
				hdr->type = HDR_CONTENTLENGTH_T;    \
				hdr->name.len = 14;                 \
				return (p + 4);                     \
		}                                           \
		if (LOWER_BYTE(*p) == 't') {                \
				p++;                                \
				if (LOWER_BYTE(*p) == 'h') {        \
						hdr->type = HDR_CONTENTLENGTH_T; \
						hdr->name.len = 14;         \
						p++;                        \
						goto dc_cont;               \
				}                                   \
		}


#define ion_CASE                                      \
	switch(LOWER_DWORD(val)) {                        \
		case _ion1_:                                  \
			hdr->type = HDR_CONTENTDISPOSITION_T;     \
			hdr->name.len = 19;                       \
			return (p + 4);                           \
		case _ion2_:                                  \
			hdr->type = HDR_CONTENTDISPOSITION_T;     \
			hdr->name.len = 19;                       \
			p += 4;                                   \
			goto dc_end;                              \
	}


#define DISPOSITION_CASE           \
	switch(LOWER_DWORD(val)) {     \
		case _osit_:               \
		p += 4;                    \
		val = READ(p);             \
		ion_CASE;                  \
		goto other;                \
	}


#define CONTENT_CASE                        \
	switch(LOWER_DWORD(val)) {              \
		case _leng_:                        \
				p += 4;                     \
				val = READ(p);              \
				TH_CASE;                    \
				goto other;                 \
		case _type_:                        \
				hdr->type = HDR_CONTENTTYPE_T; \
				hdr->name.len = 12;         \
				p += 4;                     \
				goto dc_cont;               \
		case _disp_:                        \
				p += 4;                     \
				val = READ(p);              \
				DISPOSITION_CASE;           \
				goto other;                 \
		}


#define ACT_ENT_CASE                    \
	switch(LOWER_DWORD(val)) {          \
		case _act1_:                    \
			hdr->type = HDR_CONTACT_T;  \
			hdr->name.len = 7;          \
			return (p + 4);             \
		case _act2_:                    \
			hdr->type = HDR_CONTACT_T;  \
			hdr->name.len = 7;          \
			p += 4;                     \
			goto dc_end;                \
		case _ent__:                    \
			p += 4;                     \
			val = READ(p);              \
			CONTENT_CASE;               \
			goto other;                 \
	}

#define cont_CASE    \
	p += 4;          \
	val = READ(p);   \
	ACT_ENT_CASE;    \
	goto other;


#endif /* CASE_CONT_H */
