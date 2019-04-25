/*
 * Digest Authentication - Database support
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


#ifndef AUTHORIZE_H
#define AUTHORIZE_H


#include "../../parser/msg_parser.h"

int auth_db_init(const str* db_url);
int auth_db_bind(const str* db_url);
void auth_db_close();

/*
 * Authorize using Proxy-Authorization header field
 */
int proxy_authorize(struct sip_msg* _msg, str* _realm, str* _table);


/*
 * Authorize using WWW-Authorization header field
 */
int www_authorize(struct sip_msg* _msg, str* _realm, str* _table);


#endif /* AUTHORIZE_H */
