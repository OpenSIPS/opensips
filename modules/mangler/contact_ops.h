/*
 * Sdp mangler module
 *
 * $Id$
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
/* History:
 * --------
 *  2003-04-07 first version.  
 */

/* TODO :decode2format unpleasant */

#ifndef CONTACT_OPS_H
#define CONTACT_OPS_H

#define DEFAULT_SEPARATOR '*'


#include "../../parser/msg_parser.h"	/* struct sip_msg */

struct uri_format
{
	str username;
	str password;
	str ip;
	str port;
	str protocol;
	int first;
	int second;
};

int encode_contact (struct sip_msg *msg, char *encoding_prefix,char *public_ip);
int decode_contact (struct sip_msg *msg, char *separator,char *unused);


int free_uri_format (struct uri_format format);
	
int encode2format (str uri, struct uri_format *format);
int decode2format (str uri, char separator, struct uri_format *format);

int encode_uri (str uri, char *encoding_prefix, char *public_ip,char separator, str * result);
int decode_uri (str uri, char separator, str * result);





#endif
