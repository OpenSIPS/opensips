/*
 * Copyright (C) 2005 Juha Heinanen
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


#ifndef PARSE_REFER_TO_H
#define PARSE_REFER_TO_H

#include "msg_parser.h"


/* casting macro for accessing Refer-To body */
#define get_refer_to(p_msg)  ((struct to_body*)(p_msg)->refer_to->parsed)


/*
 * Refer-To header field parser
 */
int parse_refer_to_header( struct sip_msg *msg);

#endif /* PARSE_REFER_TO_H */
