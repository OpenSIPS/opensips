/*
 * Various URI checks
 *
 * Copyright (C) 2001-2004 FhG FOKUS
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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
 * History:
 * --------
 * 2003-03-26 created by janakj
 * 2009-03-10: Added get_auth_id() function to retrieve auth id and realm for
 *             a given uri (overturn technologies GmbH, Andreas Westermaier)
 * 2009-08-12: renamed from checks.h of the db module
 */


#ifndef DB_CHECKS_H
#define DB_CHECKS_H

#include "../../parser/msg_parser.h"


/*
 * Check if To header field contains the same username
 * as digest credentials
 */
int check_to(struct sip_msg* _msg, str* _table);


/*
 * Check if From header field contains the same username
 * as digest credentials
 */
int check_from(struct sip_msg* _msg, str* _table);


/*
 * Check if uri belongs to a local user, contributed by Juha Heinanen
 */
int does_uri_exist(struct sip_msg* _msg, str* _table, str* _uri);


/*
 * Retrieves authentication id and realm for a given uri from uri_table
 */
int get_auth_id(struct sip_msg* _msg, str *_table, str* uri,
			pv_spec_t* _auth_user, pv_spec_t* _auth_realm);


#endif /* DB_CHECKS_H */
