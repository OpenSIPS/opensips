/*
 * OpenSIPS LDAP Module
 *
 * Copyright (C) 2007 University of North Carolina
 *
 * Original author: Christian Schlatter, cs@unc.edu
 *
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
 * 2007-02-18: Initial version
 */


#ifndef LDAP_CONNECT_H
#define LDAP_CONNECT_H

#include "../../str.h"
#include "../../dprint.h"

#define NEVE 0x4556454E
#define DEMA 0x414D4544
#define ALLO 0x4F4C4C41
#define HARD 0x44524148
#define  TRY 0x00595254

/* forward declaration for this structure */
struct ld_conn;

extern int ldap_connect(char* _ld_name, struct ld_conn* conn);
extern int ldap_disconnect(char* _ld_name, struct ld_conn* conn);
extern int ldap_reconnect(char* _ld_name, struct ld_conn* conn);
extern int ldap_get_vendor_version(char** _version);

#endif /* LDAP_CONNECT_H */

