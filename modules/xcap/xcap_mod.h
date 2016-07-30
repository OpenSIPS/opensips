/*
 * xcap module - XCAP operations module
 *
 * Copyright (C) 2012 AG Projects
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


#ifndef _XCAP_MOD_H_
#define _XCAP_MOD_H_

#include "../../str.h"
#include "../../db/db_con.h"
#include "../../db/db.h"


extern str xcap_db_url;
extern str xcap_table;
extern int integrated_xcap_server;

extern db_con_t *xcap_db;
extern db_func_t xcap_dbf;

extern str xcap_username_col;
extern str xcap_domain_col;
extern str xcap_doc_col;
extern str xcap_doc_type_col;
extern str xcap_doc_uri_col;
extern str xcap_doc_etag_col;

#endif

