/*
 * Header file for aaa based checks
 *
 * Copyright (C) 2002-2003 Juha Heinanen
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#ifndef AAA_CHECKS_H
#define AAA_CHECKS_H


#include "../../parser/msg_parser.h"


/*
 * Check from AAA if URI giving in pvar argument belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_exist(struct sip_msg* _m, str* val);


/*
 * Check from AAA if URI user giving in pvar argument belongs
 * to a local user. If so, loads AVPs based on reply items returned
 * from AAA.
 */
int w_aaa_does_uri_user_exist(struct sip_msg* _m, str* val);

#endif /* AAA_CHECKS_H */
