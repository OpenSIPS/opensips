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

#ifndef PARSE_DIVERSION_H
#define PARSE_DIVERSION_H

#include "msg_parser.h"


/* casting macro for accessing Diversion body */
#define get_diversion(p_msg)  ((struct to_body*)(p_msg)->diversion->parsed)


/*
 * Diversion header field parser
 */
int parse_diversion_header(struct sip_msg *msg);


/*
 * Get value of given diversion parameter
 */
str *diversion_param(struct sip_msg *msg, str name);

#endif /* PARSE_DIVERSION_H */
