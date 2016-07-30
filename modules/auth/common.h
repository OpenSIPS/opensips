/*
 * Digest Authentication Module
 *
 * Copyright (C) 2001-2003 FhG Fokus
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

#ifndef COMMON_H
#define COMMON_H

#include "../../parser/msg_parser.h"

#define MESSAGE_400 "Bad Request"
#define MESSAGE_500 "Server Internal Error"


/*
 * Return parsed To or From, host part of the parsed uri is realm
 */
int get_realm(struct sip_msg* _m, hdr_types_t _hftype, struct sip_uri** _u);


/*
 * Create a response with given code and reason phrase
 * Optionally add new headers specified in _hdr
 */
int send_resp(struct sip_msg* _m, int _code, str* _reason,
	char* _hdr, int _hdr_len);

#endif /* COMMON_H */
