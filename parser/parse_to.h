/*
 * Copyright (C) 2001-2003 Fhg Fokus
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
 */


#ifndef PARSE_TO
#define PARSE_TO

#include "../str.h"
#include "msg_parser.h"

enum {
	TAG_PARAM = 400, GENERAL_PARAM
};

struct to_param{
	int type;              /* Type of parameter */
	str name;              /* Name of parameter */
	str value;             /* Parameter value */
	struct to_param* next; /* Next parameter in the list */
};

struct to_body{
	int error;                    /* Error code */
	str body;                     /* The whole header field body */
	str uri;                      /* URI */
	str display;                  /* Display Name */
	str tag_value;                /* Value of tag */
	struct sip_uri parsed_uri;    /* Parsed URI */
	struct to_param *param_lst;   /* Linked list of parameters */
	struct to_param *last_param;  /* Last parameter in the list */
};


/* casting macro for accessing To body */
#define get_to(p_msg)     ((struct to_body*)(p_msg)->to->parsed)


/*
 * To header field parser
 */
char* parse_to(char* buffer, char *end, struct to_body *to_b);

int parse_to_header( struct sip_msg *msg);

struct sip_uri *parse_to_uri(struct sip_msg *msg);

void free_to(struct to_body* tb);

void free_to_params(struct to_body *tb);

#endif
