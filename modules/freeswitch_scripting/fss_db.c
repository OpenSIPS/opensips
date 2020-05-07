/*
 * SQL DB provisioning
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "../../db/db.h"
#include "../../rw_locking.h"
#include "../../lib/list.h"
#include "../../lib/csv.h"

#include "fss_db.h"
#include "fss_evs.h"
#include "fss_ipc.h"

str db_url;

static db_func_t db;
static db_con_t *db_handle;

extern str fss_mod_tag;

extern str fss_table;
extern str fss_col_user;
extern str fss_col_pass;
extern str fss_col_ip;
extern str fss_col_port;
extern str fss_col_events;

rw_lock_t *db_reload_lk;

int fss_db_init(void)
{
	init_db_url(db_url, 1);

	db_reload_lk = lock_init_rw();
	if (!db_reload_lk) {
		LM_ERR("oom\n");
		return -1;
	}

	if (!have_db())
		return 0;

	if (db_bind_mod(&db_url, &db) < 0) {
		LM_ERR("failed to load DB API\n");
		return -1;
	}

	if (fss_db_reload() != 0)
		LM_ERR("failed to (re)load DB data\n");

	return 0;
}

void fss_db_close(void)
{
	if (!have_db())
		return;

	if (db_handle && db.close)
		db.close(db_handle);

	db_handle = NULL;
}

int fss_db_connect(void)
{
	if (!have_db() || db_handle)
		return 0;

	db_handle = db.init(&db_url);
	if (!db_handle){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}

int fss_db_reload(void)
{
	struct list_head new_sockets, old_sockets;
	struct fs_evs_list *sock_list;
	str_list *evlist;
	fs_evs *sock;
	db_res_t *res = NULL;
	db_val_t *values;
	db_key_t query_cols[5] = { &fss_col_user, &fss_col_pass, &fss_col_ip,
	                           &fss_col_port, &fss_col_events };
	str user, pass, ip, events;
	int i, port = 0;

	if (!have_db())
		return 0;

	if (fss_db_connect() != 0)
		return -1;

	if (db_check_table_version(&db, db_handle, &fss_table,
	                           TABLE_VERSION) < 0) {
		LM_ERR("table version check failed\n");
		return -1;
	}

	if (db.use_table(db_handle, &fss_table) != 0) {
		LM_ERR("failed to use table\n");
		return -1;
	}

	if (db.query(db_handle, 0, 0, 0, query_cols, 0, 5, 0, &res) < 0) {
		LM_ERR("failed to query\n");
		return -1;
	}

	if (RES_ROW_N(res) == 0)
		LM_INFO("table %.*s is empty, clearing all sockets\n",
		        fss_table.len, fss_table.s);

	INIT_LIST_HEAD(&new_sockets);

	for (i = 0; i < RES_ROW_N(res); i++) {
		values = ROW_VALUES(RES_ROWS(res) + i);

		get_str_from_dbval("username", values, 0, 0, user, out);
		get_str_from_dbval("password", values+1, 1, 1, pass, out);
		get_str_from_dbval("ip", values+2, 1, 1, ip, out);
		if (!VAL_NULL(values+3))
			port = VAL_INT(values+3);
		get_str_from_dbval("events", values+4, 1, 1, events, out);

		if (ZSTR(events))
			continue;

		sock = fs_api.get_evs(&ip, port, &user, &pass);
		if (!sock) {
			LM_ERR("failed to fetch sock for %.*s:%d\n", ip.len, ip.s, port);
			continue;
		}

		evlist = _parse_csv_record(&events, CSV_SHM|CSV_DUP_FIELDS);
		if (!evlist) {
			LM_ERR("failed to parse events: %.*s\n", events.len, events.s);
			goto skip_socket;
		}

		sock_list = mk_fs_sock_list(sock, evlist);
		if (!sock_list) {
			LM_ERR("failed to alloc holder, oom?\n");
			goto skip_socket;
		}

		if (fs_api.evs_sub(sock, &fss_mod_tag, evlist,
		                   ipc_hdl_rcv_event) != 0) {
			LM_ERR("failed to subscribe for one or more events on %s:%d\n",
			       sock->host.s, sock->port);
		}

		list_add(&sock_list->list, &new_sockets);
		continue;

skip_socket:
		fs_api.put_evs(sock);
	}

	lock_start_write(db_reload_lk);

	/* backup the old sockets */
	list_add(&old_sockets, fss_sockets);
	list_del(fss_sockets);

	/* replace the new sockets */
	list_add(fss_sockets, &new_sockets);
	list_del(&new_sockets);

	lock_stop_write(db_reload_lk);

	free_fs_sock_list(&old_sockets);

out:
	db.free_result(db_handle, res);
	return 0;
}
