/*
 * Copyright (C) 2011 VoIP Embedded, Inc.
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
 * History:
 * --------
 * 2011-06-28  initial implementation (Ovidiu Sas)
 */


#ifndef PARSE_REPLACES_H
#define PARSE_REPLACES_H

#include "msg_parser.h"

/* rfc3891: The SIP "Replaces" Header */
struct replaces_body{
	str to_tag;
	str from_tag;
	str early_only;
	str callid_val;
	str to_tag_val;
	str from_tag_val;
	str early_only_val;
};



int parse_replaces_body(char* buf, int buf_len, struct replaces_body* replaces_b);

///* casting macro for accessing Replace body */
//#define get_replaces(p_msg)  ((struct to_body*)(p_msg)->refer_to->parsed)
//
///* Replace header field parser */
//int parse_replaces_header( struct sip_msg *msg);

#endif /* PARSE_REPLACES_H */
