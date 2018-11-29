/*
 * db_berkeley MI functions
 *
 * Copyright (C) 2007  Cisco Systems
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
 *  2007-11-05  created (wiquan)
 */


#include "../../dprint.h"
#include "../../db/db.h"
#include "db_berkeley.h"
#include "bdb_mi.h"


/*
 * MI function to reload db table or env
 * expects 1 node: the tablename or dbenv name to reload
 */
mi_response_t *mi_bdb_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str db_path;

	if (get_mi_string_param(params, "table_path", &db_path.s, &db_path.len) < 0)
		return init_mi_param_error();

	if (bdb_reload(db_path.s) == 0)
	{
		return init_mi_result_ok();
	}
	else
	{
		return init_mi_error(500, MI_SSTR("db_berkeley Reload Failed"));
	}
}

