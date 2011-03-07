/* 
 * $Id$
 * 
 * Copyright (c) 2011 VoIP Embedded Inc. <http://www.voipembedded.com/>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2005-01-31  first version (ramona)
 *  2011-03-07  Initial revision (Ovidiu Sas)
 */

#ifndef PARSE_AUTHENTICATE_H
#define PARSE_AUTHENTICATE_H


#include "msg_parser.h"

#define AUTHENTICATE_MD5	(1<<0)
#define AUTHENTICATE_MD5SESS	(1<<1)
#define AUTHENTICATE_STALE	(1<<2)
#define QOP_AUTH		(1<<3)
#define QOP_AUTH_INT		(1<<4)

struct authenticate_body {
	int flags;
	str realm;
	str domain;
	str nonce;
	str opaque;
	str qop;
};

/* casting macro for accessing www/proxy authenticate body */
#define get_www_authenticate(p_msg)   ((struct authenticate_body*)(p_msg)->www_authenticate->parsed)
#define get_proxy_authenticate(p_msg) ((struct authenticate_body*)(p_msg)->proxy_authenticate->parsed)

/*
 * WWW/Proxy-Authenticate header field parser
 */
int parse_proxy_authenticate_header( struct sip_msg *msg );
int parse_www_authenticate_header( struct sip_msg *msg );

void free_authenticate(struct authenticate_body *authenticate_b);

#endif /* ! PARSE_AUTHENTICATE_H */
