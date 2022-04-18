/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "tcp_mi.h"
#include "tcp_db.h"

#include "../../dprint.h"

/* reloads data from the db */
mi_response_t *tcp_reload(const mi_params_t *_, struct mi_handler *__)
{
	struct tcp_path *new_paths, *old_paths;
	int new_paths_sz;

	LM_INFO("reload data MI command received!\n");

	if (!tcp_db_url.s)
		return init_mi_error(500, MI_SSTR("DB url not set"));

	if (reload_data(&new_paths, &new_paths_sz) < 0) {
		LM_ERR("failed to load TCP data\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	lock_start_write(tcp_paths_lk);

	old_paths = tcp_paths;
	tcp_paths = new_paths;
	*tcp_paths_sz = new_paths_sz;

	lock_stop_write(tcp_paths_lk);

	shm_free(old_paths);
	return init_mi_result_ok();
}
