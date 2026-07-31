/*
 * PI framework database support
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

#ifndef _PI_FRAMEWORK_DB_H_
#define _PI_FRAMEWORK_DB_H_

#include "pi_framework.h"


int pi_init_db(pi_framework_t *framework_data, int index);
int pi_use_table(pi_db_table_t *db_table);
int pi_connect_db(pi_framework_t *framework_data, int index);
void pi_destroy_db(pi_framework_t *framework_data);

#endif
