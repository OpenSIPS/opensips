/*
 * URI checks
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
 * 2003-03-15 - Created by janakj
 * 2008-08-07 - Renamed into uri_mod.h by Irina Stanescu
 */

#ifndef URI_MOD_H
#define URI_MOD_H

#include "../../aaa/aaa.h"
#include "../../db/db.h"
#include "../../str.h"
#include "../../statistics.h"

/*
 * Module parameters variables
 */
extern str db_table;                  /**< Name of URI table */
extern str uridb_user_col;            /**< Name of username column in URI table */
extern str uridb_domain_col;          /**< Name of domain column in URI table */
extern str uridb_uriuser_col;         /**< Name of uri_user column in URI table */
extern int use_uri_table;             /**< Whether or not should be uri table used */
extern int use_domain;                /**< Should does_uri_exist honor the domain part ? */


extern int use_sip_uri_host;
extern aaa_map attrs[];
extern aaa_map vals[];
extern aaa_conn *conn;
extern aaa_prot proto;

/*
 * Variables to hold module statistics
 */

extern stat_var *positive_checks;
extern stat_var *negative_checks;

#endif /* URI_MOD_H */
