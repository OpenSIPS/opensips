/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#ifndef STERMAN_H
#define STERMAN_H

#include "../../str.h"
#include "../../parser/digest/digest_parser.h"


/*
 * This function creates and submits aaa authentication request as per
 * draft-sterman-aaa-sip-00.txt.  In addition, _user parameter is included
 * in the request as value of a SER specific attribute type SIP-URI-User,
 * which can be be used as a check item in the request.  Service type of
 * the request is Authenticate-Only.
 */
int aaa_authorize_sterman(struct sip_msg* _msg, dig_cred_t* _cred, str* _method, str* _user);

#endif /* STERMAN_H */
