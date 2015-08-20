/*
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 * 2009-02-07 Initial version of closeddial module (saguti)
 */


#ifndef _CLOSEDDIAL_H_
#define _CLOSEDDIAL_H_

#include "../../db/db.h"
#include "../../parser/msg_parser.h"


/* Module parameters variables */

extern str user_column;     	/* 'username' column name */
extern str domain_column;   	/* 'domain' column name */
extern str cd_user_column;     	/* 'cd_username' column name */
extern str cd_domain_column;   	/* 'cd_domain' column name */
extern str group_id_column;   	/* 'group_id' column name */
extern str new_uri_column;   	/* 'new_uri' column name */
extern int use_domain;      	/* use or not the domain for cd lookup */

extern db_func_t db_functions;    /* Database functions */
extern db_con_t* db_connection;   /* Database connection handle */

#endif /* _CLOSEDDIAL_H_ */
