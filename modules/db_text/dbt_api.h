/*
 * DBText library
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * 2003-02-05  created by Daniel
 *
 */


#ifndef _DBT_API_H_
#define _DBT_API_H_

#include "../../db/db_op.h"
#include "../../db/db_res.h"
#include "../../db/db_con.h"
#include "../../db/db_row.h"

/*
 * Retrieve result set
 */
int dbt_get_result(db_con_t* _h, db_res_t** _r);

int dbt_use_table(db_con_t* _h, const str* _t);

#endif
