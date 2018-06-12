/*
 * $Id$
 *
 * Event header field body parser
 * This parser was written for Presence Agent module only.
 * it recognizes presence package only, no subpackages, no parameters
 * It should be replaced by a more generic parser if subpackages or
 * parameters should be parsed too.
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef PARSE_EVENT_H
#define PARSE_EVENT_H

#include "../str.h"
#include "hf.h"

#define EVENT_OTHER    0
#define EVENT_PRESENCE 1


typedef struct event {
	str text;       /* Original string representation */
	int parsed;     /* Parsed variant */
} event_t;


/*
 * Parse Event HF body
 */
int parse_event(struct hdr_field* _h);


/*
 * Release memory
 */
void free_event(event_t** _e);


/*
 * Print structure, for debugging only
 */
void print_event(event_t* _e);


#endif /* PARSE_EVENT_H */
