/*
 * Header file for Enum and E164 related functions
 *
 * Copyright (C) 2002-2008 Juha Heinanen
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


#ifndef ENUM_H
#define ENUM_H


#include "../../parser/msg_parser.h"


#define MAX_DOMAIN_SIZE 256
#define MAX_COMPONENT_SIZE 32  /* separator, apex, ... This simplifies checks */


/*
 * Check if from user is an e164 number and has a naptr record
 */
int is_from_user_enum_0(struct sip_msg* _msg, char* _str1, char* _str2);
int is_from_user_enum_1(struct sip_msg* _msg, char* _suffix, char* _str2);
int is_from_user_enum_2(struct sip_msg* _msg, char* _suffix, char* _service);

/*
 * do source number destination routing.
 * that is, make the ruri based on the from number
 * this is like source ip policy routing
 */
int enum_pv_query_1(struct sip_msg* _msg, char* _sp);
int enum_pv_query_2(struct sip_msg* _msg, char* _sp, char* _suffix);
int enum_pv_query_3(struct sip_msg* _msg, char* _sp, char* _suffix,
		    char* _service);

/*
 * Make enum query and if query succeeds, replace current uri with the
 * result of the query
 */
int enum_query_0(struct sip_msg* _msg, char* _str1, char* _str2);
int enum_query_1(struct sip_msg* _msg, char* _suffix, char* _str2);
int enum_query_2(struct sip_msg* _msg, char* _suffix, char* _service);

/*
 * Infrastructure ENUM versions.
 */
int i_enum_query_0(struct sip_msg* _msg, char* _str1, char* _str2);
int i_enum_query_1(struct sip_msg* _msg, char* _suffix, char* _str2);
int i_enum_query_2(struct sip_msg* _msg, char* _suffix, char* _service);

/*
 * Make ISN query and if query succeeds, replace current uri with the
 * result of the query
 */
int isn_query_0(struct sip_msg* _msg, char* _str1, char* _str2);
int isn_query_1(struct sip_msg* _msg, char* _suffix, char* _str2);
int isn_query_2(struct sip_msg* _msg, char* _suffix, char* _service);


#endif /* ENUM_H */
