/*
 * Event header field body parser
 * This parser was written for Presence Agent module only.
 * it recognizes presence package only, no subpackages, no parameters
 * It should be replaced by a more generic parser if subpackages or
 * parameters should be parsed too.
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


#ifndef PARSE_EVENT_H
#define PARSE_EVENT_H

#include "../str.h"
#include "hf.h"
#include "parse_param.h"

#define EVENT_OTHER          0
#define EVENT_PRESENCE       1
#define EVENT_PRESENCE_WINFO 2
#define EVENT_SIP_PROFILE    3
#define EVENT_XCAP_DIFF      4
#define EVENT_DIALOG         5
#define EVENT_MWI            6
#define EVENT_DIALOG_SLA     7
#define EVENT_CALL_INFO      8
#define EVENT_LINE_SEIZE     9
#define EVENT_AS_FEATURE     10
#define EVENT_REFER          11

typedef struct event {
	str text;       /* Original string representation */
	int parsed;     /* Parsed variant */
	param_t* params;
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

int event_parser(char* _s, int _l, event_t* _e);

#endif /* PARSE_EVENT_H */
