/*
 * http_db_handler module
 *
 * Copyright (C) 2012 VoIP Embedded, Inc.
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
 *  2012-03-19  initial version (Ovidiu Sas)
 */

#ifndef PI_HTTP_HTTP_DB_HANDLER
#define PI_HTTP_HTTP_DB_HANDLER


int init_http_db(ph_framework_t *framework_data, int index);
int use_table(ph_db_table_t *db_table);
int connect_http_db(ph_framework_t *framework_data, int index);
void destroy_http_db(ph_framework_t *framework_data);

#endif
