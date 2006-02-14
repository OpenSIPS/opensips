/*
 * $Id$
 *
 * Supported parser.
 *
 * Copyright (C) 2006 Andreas Granig <agranig@linguin.org>
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "../mem/mem.h"
#include "keys.h"
#include "parse_supported.h"

#define IS_DELIM(c) (*(c) == ' ' || *(c) == '\t' || *(c) == '\r' || *(c) == '\n' || *(c) == ',')

/* from parser/parse_hname2.c: */
#define LOWER_BYTE(b) ((b) | 0x20)
#define LOWER_DWORD(d) ((d) | 0x20202020)
#define READ(val) \
	(*(val + 0) + (*(val + 1) << 8) + (*(val + 2) << 16) + (*(val + 3) << 24))


/*
 * Parse Supported HF body.
 */
static int parse_supported_body(struct hdr_field* _h)
{
	register char* p;
	register unsigned int val;
	char *buf;
	int len, pos = 0;
	unsigned int *sup;

	buf = _h->body.s;
	len = _h->body.len;
	if (!buf || len <= 0) {
		LOG(L_ERR, "ERROR: parse_supported_body(): No body for Supported HF\n");
		return -1;
	}

	_h->parsed = pkg_malloc(sizeof(unsigned int));
	if(!_h->parsed) {
		LOG(L_ERR, "ERROR: parse_supported_body(): No memory left for supported-bitmap\n");
		return -1;
	}
	sup = (unsigned int*)_h->parsed;
	*sup = 0;

	p = buf;
	while (pos < len) {
		/* skip spaces and commas */
		for (; pos < len && IS_DELIM(p); ++pos, ++p);

		val = LOWER_DWORD(READ(p));
		switch (val) {

			/* "path" */
			case _path_:
				if(pos + 4 <= len && IS_DELIM(p+4)) {
					*sup |= F_SUPPORTED_PATH;
					pos += 5; p += 5;
				}
				break;

			/* "100rel" */
			case _100r_:
				if ( pos+6 <= len
					 && LOWER_BYTE(*(p+4))=='e' && LOWER_BYTE(*(p+5))=='l'
					 && IS_DELIM(p+6)) {
					*sup |= F_SUPPORTED_100REL;
					pos += SUPPORTED_100REL_LEN + 1;
					p   += SUPPORTED_100REL_LEN + 1;
				}
				break;

			/* "timer" */
			case _time_:
				if ( pos+5 <= len && LOWER_BYTE(*(p+4))=='r'
					 && IS_DELIM(p+5) ) {
					*sup |= F_SUPPORTED_TIMER;
					pos += SUPPORTED_TIMER_LEN + 1;
					p   += SUPPORTED_TIMER_LEN + 1;
				}
				break;

			/* unknown */
			default:
				/* skip element */
				for (; pos < len && !IS_DELIM(p); ++pos, ++p);
				break;
		}
	}
	
	return 0;
}

/*
 * Parse Supported header.
 */
int parse_supported(struct hdr_field* _h, unsigned int *supported)
{
	if (!supported) {
		LOG(L_ERR, "parse_supported(): NULL pointer for supported-bitmap passed\n");
		return -1;
	}

	if (!_h->parsed && parse_supported_body(_h) < 0) {
		return -1;
	}

	*supported = *(unsigned int*)_h->parsed;
	return 0;
}
