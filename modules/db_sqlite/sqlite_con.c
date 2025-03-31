/**
 *
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 * History
 * -------
 *  2015-02-18  initial version (Ionut Ionita)
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "../../dprint.h"
#include "../../db/db_query.h"
#include "../../db/db_async.h"
#include "../../db/db_ut.h"
#include "../../db/db_insertq.h"
#include "../../db/db_id.h"
#include "../../mem/mem.h"
#include "sqlite_con.h"
#include "db_sqlite.h"

extern int db_sqlite_busy_timeout;
extern struct db_sqlite_extension_list *extension_list;
extern struct db_sqlite_pragma_list *pragma_list;

#define SQLITE_ID "sqlite:/"
#define URL_BUFSIZ 1024
#define PRAGMA_BUFSIZE 256
char url_buf[URL_BUFSIZ];

int db_sqlite_connect(struct sqlite_con* ptr)
{
	sqlite3* con;
	char* errmsg = NULL;
	char pragma_sql[PRAGMA_BUFSIZE];
	struct db_sqlite_extension_list *iter;
	struct db_sqlite_pragma_list *p_iter;

	/* if connection already in use, close it first*/
	if (ptr->init)
		sqlite3_close(ptr->con);

	ptr->init = 1;

	memcpy(url_buf, ptr->id->url.s+sizeof(SQLITE_ID)-1,
				ptr->id->url.len - (sizeof(SQLITE_ID)-1));
	url_buf[ptr->id->url.len - (sizeof(SQLITE_ID)-1)] = '\0';

	if (sqlite3_open(url_buf, &con) != SQLITE_OK) {
		LM_ERR("Can't open database: %s\n", sqlite3_errmsg(con));
		return -1;
	}

	/* enable busy timeout (can also be PRAGMA busy_timeout = milliseconds) */
	if (sqlite3_busy_timeout(con, db_sqlite_busy_timeout) != SQLITE_OK) {
		LM_ERR("Failed to set busy timeout: %s\n", sqlite3_errmsg(con));
		return -1;
	} else {
		LM_DBG("Busy timeout is set to [%d]\n", db_sqlite_busy_timeout);
	}

	/* Executing pragmas */
	if (pragma_list) {
		p_iter=pragma_list;
		for (p_iter=pragma_list; p_iter; p_iter=p_iter->next) {
			if (strlen(p_iter->pragma) > (PRAGMA_BUFSIZE - 9)) {
				LM_ERR("Pragma size is too big: %d (max: %d)\n", 
					(int)strlen(p_iter->pragma), (int)(PRAGMA_BUFSIZE - 9));
				continue;
			}
			snprintf(pragma_sql, PRAGMA_BUFSIZE, "PRAGMA %s;", p_iter->pragma);
			if (sqlite3_exec(con, pragma_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
				LM_ERR("Failed to execute PRAGMA [%s]! Errmsg [%s]!\n",
						p_iter->pragma, errmsg);
				sqlite3_free(errmsg);
			}
			LM_DBG("Pragma [%s] executed\n", pragma_sql);
		}
	}

	/* trying to load extensions */
	if (extension_list) {
#ifdef SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION
		if (sqlite3_db_config(con, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 1, NULL) != SQLITE_OK) {
#else
		if (sqlite3_enable_load_extension(con, 1)) {
#endif
			LM_ERR("failed to enable extension loading: %s\n", sqlite3_errmsg(con));
			return -1;
		}

		iter=extension_list;
		for (iter=extension_list; iter; iter=iter->next) {
			if (sqlite3_load_extension(con, iter->ldpath,
					iter->entry_point, &errmsg) != SQLITE_OK) {
				LM_ERR("failed to load!"
						"Extension [%s]! Entry point [%s]!"
						"Errmsg [%s]!\n",
						iter->ldpath, iter->entry_point,
						errmsg);
				sqlite3_free(errmsg);
				goto out_free;
			}
			LM_DBG("Extension [%s] loaded!\n", iter->ldpath);
		}

#ifdef SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION
		if (sqlite3_db_config(con, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL) != SQLITE_OK) {
#else
		if (sqlite3_enable_load_extension(con, 1)) {
#endif
			LM_ERR("failed to disable extension loading: %s\n", sqlite3_errmsg(con));
			return -1;
		}
	}

	ptr->con = con;

	return 0;

out_free:
	while (extension_list) {
		iter=extension_list;
		extension_list=extension_list->next;
		pkg_free(iter);
	}
	return -1;
}

/**
 * Create a new connection structure,
 * open the sqlite connection and set reference count to 1
 */
struct sqlite_con* db_sqlite_new_connection(const struct db_id* id)
{

	struct sqlite_con* ptr;

	if (!id) {
		LM_ERR("invalid parameter value\n");
		return 0;
	}

	ptr = (struct sqlite_con*)pkg_malloc(sizeof(struct sqlite_con));
	if (!ptr) {
		LM_ERR("no private memory left\n");
		return 0;
	}

	memset(ptr, 0, sizeof(struct sqlite_con));
	ptr->ref = 1;

	ptr->id = (struct db_id*)id;

	if (db_sqlite_connect(ptr)!=0) {
		LM_ERR("initial connect failed\n");
		goto err;
	}
	return ptr;
err:
	if (ptr && ptr->con) pkg_free(ptr->con);
	if (ptr) pkg_free(ptr);
	return 0;
}

/**
 * Close the connection and release memory
 */
void db_sqlite_free_connection(struct pool_con* con)
{
	if (!con) return;

	struct sqlite_con * _c;
	_c = (struct sqlite_con*) con;

	if (_c->id) free_db_id(_c->id);
	if (_c->con) {
		sqlite3_close(_c->con);
	}
	pkg_free(_c);
}
