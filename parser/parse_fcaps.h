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

#ifndef PARSE_FCAPS_H
#define PARSE_FCAPS_H

#include <stdio.h>

#include "hf.h"

typedef struct fcaps_body {
	str pns;     /* +sip.pns */
#if 0
	str pnsreg;  /* +sip.pnsreg (not parsed since we skip it as a proxy) */
	str pnspurr; /* +sip.pnspurr (not parsed since we skip it as a proxy) */
	str vapid;   /* +sip.vapid (not parsed since we skip it as a proxy) */
#endif

} fcaps_body_t;


/*
 * Parse Feature-Caps header field body
 *
 * Return
 *      0: success, @_h->parsed was allocated and a "pns" was parsed
 *    < 0: otherwise
 */
int parse_fcaps(struct hdr_field* _h);


/*
 * Free all memory
 */
void free_fcaps(fcaps_body_t** _fc);


#endif /* PARSE_FCAPS_H */
