/*
 * xcap_client module - XCAP client for OpenSIPS
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 *  2007-08-20  initial version (anca)
 */

#ifndef XCAP_CL_H
#define XCAP_CL_H

#include "../../db/db.h"
#include "../xcap/api.h"
#include "xcap_callbacks.h"

extern xcap_callback_t* xcapcb_list;
extern str xcap_db_url;
extern str xcap_db_table;

extern str str_source_col;
extern str str_path_col;
extern str str_doc_col;
extern str str_etag_col;
extern str str_username_col;
extern str str_domain_col;
extern str str_doc_type_col;
extern str str_doc_uri_col;
extern str str_port_col;

/* database connection */
extern db_con_t *xcap_db;
extern db_func_t xcap_dbf;

extern int periodical_query;
extern unsigned int query_period;

#endif
