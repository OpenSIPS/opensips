/*
 * Oracle module result related functions
 *
 * Copyright (C) 2007,2008 TRUNK MOBILE
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
 */

#ifndef RES_H
#define RES_H

#include "../../db/db_res.h"
#include "../../db/db_con.h"


#define STATIC_BUF_LEN	65536
extern char st_buf[STATIC_BUF_LEN];


/*
 * Read database answer and fill the structure
 */
int db_oracle_store_result(const db_con_t* _h, db_res_t** _r);

#endif /* RES_H */
