/*
 * $Id$
 *
 * Digest Authentication - generic AAA support
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice Systems
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
 */

#ifndef AUTHORIZE_H
#define AUTHORIZE_H

#include "../../parser/msg_parser.h"


/*
 * Authorize using Proxy-Authorize header field (no from parameter given)
 */
int aaa_proxy_authorize_1(struct sip_msg* _msg, char* _realm, char* _s2);


/*
 * Authorize using Proxy-Authorize header field (from parameter given)
 */
int aaa_proxy_authorize_2(struct sip_msg* _msg, char* _realm, char* _from);


/*
 * Authorize using WWW-Authorization header field
 */
int aaa_www_authorize(struct sip_msg* _msg, char* _realm, char* _s2);


#endif /* AUTHORIZE_H */
