/*
 * Copyright (C) 2001-2004 iptel.org
 * Copyright (C) 2008 1&1 Internet AG
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

#include "pg_con.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include <string.h>
#include <time.h>


/*
 * Create a new connection structure,
 * open the PostgreSQL connection and set reference count to 1
 */
struct pg_con* db_postgres_new_connection(struct db_id* id)
{
	struct pg_con* ptr;
	char *ports;

	LM_DBG("db_id = %p\n", id);

	if (!id) {
		LM_ERR("invalid db_id parameter value\n");
		return 0;
	}

	ptr = (struct pg_con*)pkg_malloc(sizeof(struct pg_con));
	if (!ptr) {
		LM_ERR("failed trying to allocated %lu bytes for connection structure."
				"\n", (unsigned long)sizeof(struct pg_con));
		return 0;
	}
	LM_DBG("%p=pkg_malloc(%lu)\n", ptr, (unsigned long)sizeof(struct pg_con));

	memset(ptr, 0, sizeof(struct pg_con));
	ptr->ref = 1;

	if (id->port) {
		ports = int2str(id->port, 0);
		LM_DBG("opening connection: postgres://xxxx:xxxx@%s:%d/%s\n", ZSW(id->host),
			id->port, ZSW(id->database));
	} else {
		ports = NULL;
		LM_DBG("opening connection: postgres://xxxx:xxxx@%s/%s\n", ZSW(id->host),
			ZSW(id->database));
	}

 	ptr->con = PQsetdbLogin(id->host, ports, NULL, NULL, id->database, id->username, id->password);
	LM_DBG("PQsetdbLogin(%p)\n", ptr->con);

	if( (ptr->con == 0) || (PQstatus(ptr->con) != CONNECTION_OK) )
	{
		LM_ERR("%s\n", PQerrorMessage(ptr->con));
		PQfinish(ptr->con);
		goto err;
	}

	ptr->connected = 1;
	ptr->timestamp = time(0);
	ptr->id = id;

	return ptr;

 err:
	if (ptr) {
		LM_ERR("cleaning up %p=pkg_free()\n", ptr);
		pkg_free(ptr);
	}
	return 0;
}


/*
 * Close the connection and release memory
 */
void db_postgres_free_connection(struct pool_con* con)
{

	if (!con) return;

	struct pg_con * _c;
	_c = (struct pg_con*)con;

	if (_c->res) {
		LM_DBG("PQclear(%p)\n", _c->res);
		PQclear(_c->res);
		_c->res = 0;
	}
	if (_c->id) free_db_id(_c->id);
	if (_c->con) {
		LM_DBG("PQfinish(%p)\n", _c->con);
		PQfinish(_c->con);
		_c->con = 0;
	}
	LM_DBG("pkg_free(%p)\n", _c);
	pkg_free(_c);
}
