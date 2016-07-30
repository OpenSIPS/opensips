/*
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


#ifndef _PARSE_FROM_H
#define _PARSE_FROM_H

#include "msg_parser.h"


/* casting macro for accessing From body */
#define get_from(p_msg)  ((struct to_body*)(p_msg)->from->parsed)

#define free_from(_to_body_)  free_to(_to_body_)


/*
 * From header field parser
 */
int parse_from_header( struct sip_msg *msg);

struct sip_uri *parse_from_uri(struct sip_msg *msg);

#endif
