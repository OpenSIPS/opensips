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
#include "../db/db.h"

struct pi_conns {
    str name;           /* the name of the connector */
    str table;          /* the name of the table */
    db_con_t *con;      /* database connector */
    unsigned int flags; /* different flags */
    struct pi_conns *next;
} *pi_conns_list;

int db_pi_add(str *name, str *table, db_con_t *con, unsigned int flags)
{
    LM_INFO("adding %.*s connector to PI table=%.*s\n",
            name->len, name->s, table->len, table->s);
    /* TODO: add a new element in pi_conns_list */
    return 0;
}

mi_response_t *w_mi_pi_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
    static str pi_conns[] = {
        str_init("auth_db"),
        str_init("call_center"),
        str_init("domain"),
        str_init("dialplan"),
        str_init("rtpproxy"),
    };

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
