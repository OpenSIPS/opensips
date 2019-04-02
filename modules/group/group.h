/*
 * Group membership
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
 * History:
 * --------
 * 2003-02-25 - created by janakj
 *
 */


#ifndef GROUP_H
#define GROUP_H

#include "../../parser/msg_parser.h"
#include "../../pvar.h"

typedef struct _group_check
{
	int id;
	pv_spec_t sp;
} group_check_t, *group_check_p;


/*
 * extracts username and domain from MSG
 */
int get_username_domain(struct sip_msg *msg, str *hf_s,
		str *username, str *domain);


/*
 * Check if username in specified header field is in a table
 */
int db_is_user_in(struct sip_msg* _msg, str* hf_s, str* grp_s);

/*
 * Check from AAA if a user belongs to a group. User-Name is digest
 * username or digest username@realm, SIP-Group is group, and Service-Type
 * is Group-Check.  SIP-Group is SER specific attribute and Group-Check is
 * SER specific service type value.
 */
int aaa_is_user_in(struct sip_msg* _m, void* _hf, str* grp);

int group_db_init(const str* db_url);
int group_db_bind(const str* db_url);
void group_db_close();

#endif /* GROUP_H */
