/*
 * Feature-Caps header field body parser
 *
 * Copyright (c) 2020 OpenSIPS Solutions
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

#include "../mem/mem.h"
#include "../ut.h"

#include "parse_fcaps.h"

static str fcaps_pns = str_init("+sip.pns");

/* Feature-Caps: +sip.pns="apns";+sip.pnsreg="130" */
int parse_fcaps(struct hdr_field* _h)
{
	fcaps_body_t *b = NULL;
	int len = _h->body.len;
	char *s = _h->body.s, *end = s + len, *p;

	if (_h->parsed)
		return 0;

	/* optimized, simplistic parser.  Ideal for the PN proxy use case! */
	while (len > 0 && (p = q_memchr(s, '+', len))) {
		len -= p + 1 - s;
		s = p + 1;

		if (end - p >= (fcaps_pns.len + 4) &&
		        !memcmp(p, fcaps_pns.s, fcaps_pns.len)) {

			p += fcaps_pns.len;
			len -= p - s;
			s = p;

			/* start LDQUOT */
			if (*p != '=' || *(p + 1) != '"')
				continue;

			/* end LDQUOT */
			p += 2;
			len -= 2;
			s = p;

			if (!(p = q_memchr(s + 1, '"', len - 1)))
				goto out;

			/* successfully matched a +sip.pns="..." string */

			if (!b) {
				b = pkg_malloc(sizeof *b);
				if (!b) {
					LM_ERR("oom\n");
					return -1;
				}
				memset(b, 0, sizeof *b);
			}

			b->pns.s = s;
			b->pns.len = p - s;

			p++;
			len -= p - s;
			s = p;
		}
	}

out:
	if (!b)
		return -1;

	_h->parsed = (void *)b;
	return 0;
}

void free_fcaps(fcaps_body_t** _fc)
{
	pkg_free(*_fc);
	*_fc = NULL;
}
