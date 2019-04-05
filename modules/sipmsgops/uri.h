/*
 * Various URI checks
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
 *
 */


#ifndef CHECKS_H
#define CHECKS_H

#include "../../parser/msg_parser.h"


/*
 * Check if message includes a to-tag
 */
int has_totag(struct sip_msg* _m, char* _foo, char* _bar);

/*
 * Find if Request URI has a given parameter with/without matching value
 */
int ruri_has_param(struct sip_msg* _msg, str* param, str* value);

/*
 * Add a new parameter to Request URI
 */
int ruri_add_param(struct sip_msg* _msg, str* _param);

/*
 * Remove a given parameter from Request URI
 */
int ruri_del_param(struct sip_msg* _msg, str* _param);

/*
 * Converts Request-URI, if it is tel URI, to SIP URI.  Returns 1, if
 * conversion succeeded or if no conversion was needed, i.e., Request-URI
 * was not tel URI.  Returns -1, if conversion failed.
 */
int ruri_tel2sip(struct sip_msg* _msg);


/*
 * Check if user part of URI in pseudo variable is an e164 number
 */
int is_uri_user_e164(struct sip_msg* _m, str* uri);

#endif /* CHECKS_H */
