/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#include "../str.h"
#include "../mi/mi.h"

 static str pi_conns[] = {
    str_init("auth_db"),
    str_init("call_center"),
    str_init("domain"),
    str_init("dialplan"),
    str_init("rtpproxy"),
 };

mi_response_t *w_mi_pi_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
    int i;
	mi_item_t *resp_arr;
	mi_response_t *resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;
    /* quick hack to return a list of provisioned connectors */
    for (i = 0; i < sizeof(pi_conns)/sizeof(pi_conns[0]); i++)
        add_mi_string(resp_arr, 0, 0, pi_conns[i].s, pi_conns[i].len);
    return resp;
}
