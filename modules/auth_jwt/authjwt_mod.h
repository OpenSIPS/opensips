/*
 * JWT Authentication Module
 *
 * Copyright (C) 2020 OpenSIPS Project
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * --------
 * 2020-03-12 initial release (vlad)
 */

#ifndef AUTHJWT_MOD_H
#define AUTHJWT_MOD_H

#include "../../str.h"
#include "../../db/db.h"
#include "../../parser/msg_parser.h"


/*
 * Module parameters variables
 */

extern str profiles_table;
extern str secrets_table;
extern str tag_column;
extern str username_column;
extern str secret_tag_column;
extern str secret_column;
extern str start_ts_column;
extern str end_ts_column;
extern str jwt_tag_claim;

extern db_con_t* auth_db_handle; /* database connection handle */
extern db_func_t auth_dbf;

extern struct jwt_avp* jwt_credentials;
extern int credentials_n;

#endif /* AUTHJWT_MOD_H */
