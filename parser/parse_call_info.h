/*
 * Copyright (c) 2010 VoIP Embedded Inc. <http://www.voipembedded.com/>
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
 * 2010-11-09 Initial revision (Ovidiu Sas)
 */

#ifndef PARSE_CALL_INFO_H
#define PARSE_CALL_INFO_H 1


#include "msg_parser.h"

struct call_info_body{
	struct to_body call_info_body;
	struct call_info_body *next;
};

/* casting macro for accessing Call-Info body */
#define get_call_info(p_msg)  ((struct call_info_body*)(p_msg)->call_info->parsed)

/*
 * Call-Info header field parser
 */
int parse_call_info_header( struct sip_msg *msg);

void free_call_info(struct call_info_body *call_info_b);

#endif /* ! PARSE_CALL_INFO_H */
