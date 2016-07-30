/*
 * Expires header field body parser
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
 */


#ifndef PARSE_EXPIRES_H
#define PARSE_EXPIRES_H

#include "../str.h"
#include "hf.h"


typedef struct exp_body {
	str text;            /* Original text representation */
	unsigned char valid; /* Was parsing successful ? */
	int val;             /* Parsed value */
} exp_body_t;


/*
 * Parse expires header field body
 */
int parse_expires(struct hdr_field* _h);


/*
 * Free all memory associated with exp_body_t
 */
void free_expires(exp_body_t** _e);


/*
 * Print exp_body_t content, for debugging only
 */
void print_expires(exp_body_t* _e);


#endif /* PARSE_EXPIRES_H */
