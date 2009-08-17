/*  
 * $Id: $
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef AAA_CHECKS_H
#define AAA_CHECKS_H


#include "../../parser/msg_parser.h"


/*
 * Check from AAA if Request URI belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_exist_0(struct sip_msg* _m, char* _s1, char* _s2);


/*
 * Check from AAA if URI giving in pvar argument belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_exist_1(struct sip_msg* _m, char* _sp, char* _s2);


/*
 * Check from AAA if Request URI user belongs to a local user.
 * If so, loads AVPs based on reply items returned from AAA.
 */
int aaa_does_uri_user_exist_0(struct sip_msg* _m, char* _s1, char* _s2);


/*
 * Check from AAA if URI user giving in pvar argument belongs
 * to a local user. If so, loads AVPs based on reply items returned
 * from AAA. 
 */
int aaa_does_uri_user_exist_1(struct sip_msg* _m, char* _sp, char* _s2);

#endif /* AAA_CHECKS_H */
