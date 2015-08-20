/*
 * ALIAS_DB Module
 *
 * Copyright (C) 2004 Voice Sistem
 *
 * This file is part of a module for opensips, a free SIP server.
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
 * 2004-09-01: first version (ramona)
 * 2009-04-30: alias_db_find() added; NO_DOMAIN and REVERT flags added;
 *             use_domain param removed (bogdan)
 */


#ifndef _ALIAS_DB_H_
#define _ALIAS_DB_H_

#include "../../db/db.h"
#include "../../parser/msg_parser.h"


/* Module parameters variables */

extern str user_column;     /* 'username' column name */
extern str domain_column;   /* 'domain' column name */
extern str alias_user_column;     /* 'alias_username' column name */
extern str alias_domain_column;   /* 'alias_domain' column name */
extern str domain_prefix;
extern int ald_append_branches;  /* append branches after an alias lookup */

extern db_con_t* db_handle;   /* Database connection handle */

#endif /* _ALIAS_DB_H_ */
