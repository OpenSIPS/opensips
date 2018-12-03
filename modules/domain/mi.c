/*
 * Domain MI functions
 *
 * Copyright (C) 2006 Voice Sistem SRL
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
 *  2006-10-05  created (bogdan)
 */


#include "../../dprint.h"
#include "../../db/db.h"
#include "domain_mod.h"
#include "domain.h"
#include "hash.h"
#include "mi.h"


/*
 * MI function to reload domain table
 */
mi_response_t *mi_domain_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if(db_mode==0)
		return init_mi_error( 500, MI_SSTR("command not activated"));

	if (reload_domain_table () == 1) {
		return init_mi_result_ok();
	} else {
		return init_mi_error( 500, MI_SSTR("Domain table reload failed"));
	}
}


/*
 * MI function to print domains from current hash table
 */
mi_response_t *mi_domain_dump(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *domains_arr;

	if(db_mode==0)
		return init_mi_error(500, MI_SSTR("command not activated"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;
	domains_arr = add_mi_array(resp_obj, MI_SSTR("Domains"));
	if (!domains_arr)
		goto error;

	if(hash_table_mi_print(*hash_table, domains_arr)< 0)
	{
		LM_ERR("Error while adding item\n");
		goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}
