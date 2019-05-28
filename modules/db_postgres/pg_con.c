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

#include "db_postgres.h"
#include "pg_con.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include <string.h>
#include <time.h>

#define PSQL_PARAMS_MAX 7

/*
 * Create a new connection structure,
 * open the PostgreSQL connection and set reference count to 1
 */
struct pg_con* db_postgres_new_connection(struct db_id* id)
{
#define PSQL_PARAM(_k, _v) \
	do { \
		keywords[p] = (_k); \
		values[p] = (_v); \
		p++; \
	} while (0);
	struct pg_con* ptr;
	const char *keywords[PSQL_PARAMS_MAX];
	const char *values[PSQL_PARAMS_MAX];
	char *ports;
	char *dbname;
	int p = 0, lend, lenp;

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
	LM_DBG("%p=pkg_malloc(%zu)\n", ptr, sizeof(struct pg_con));

	memset(ptr, 0, sizeof(struct pg_con));
	ptr->ref = 1;

	if (id->parameters) {
		lend = strlen(id->database);
		lenp = strlen(id->parameters);
		dbname = pkg_malloc(7 /* "dbname=" */ +
				lend + 1 /* ? */ + lenp + 1 /* '\0' */);
		if (!dbname) {
			LM_ERR("oom for building database name!\n");
			goto err;
		}
		memcpy(dbname, "dbname=", 7);
		memcpy(dbname + 7, id->database, lend);
		lend += 7;
		dbname[lend] = ' ';
		lend += 1;
		memcpy(dbname + lend, id->parameters, lenp);
		dbname[lend + lenp] = '\0';
		/* convert '&' to spaces */
		for (; dbname[lend] != '\0'; lend++) {
			if (dbname[lend] == '&' && lend > 2 &&
					(dbname[lend-1] != '\\' || (dbname[lend-2] != '\\')))
				dbname[lend] = ' ';
		}
	} else
		dbname = id->database;

	if (id->port) {
		ports = int2str(id->port, 0);
		LM_DBG("opening connection: postgres://xxxx:xxxx@%s:%d/%s\n", ZSW(id->host),
			id->port, ZSW(dbname));
		PSQL_PARAM("port", ports);
	} else {
		ports = NULL;
		LM_DBG("opening connection: postgres://xxxx:xxxx@%s/%s\n", ZSW(id->host),
			ZSW(dbname));
	}

	if (id->host)
		PSQL_PARAM("host", id->host);
	if (id->username)
		PSQL_PARAM("user", id->username);
	if (id->password)
		PSQL_PARAM("password", id->password);

	PSQL_PARAM("dbname", dbname);

	/* force the default timeout */
	if (pq_timeout > 0)
		PSQL_PARAM("connect_timeout", int2str(pq_timeout, 0));
	PSQL_PARAM(0, 0);

	ptr->con = PQconnectdbParams(keywords, values, 1);
	if (dbname != id->database)
		pkg_free(dbname);

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
#undef PSQL_PARAM
}

/*
 * Create a new async connection structure,
 * open the PostgreSQL connection and set reference count to 1
 */
struct pg_con* db_postgres_new_async_connection(struct db_id* id)
{
	struct pg_con * ret = db_postgres_new_connection(id);
	if (ret) {
		PQsetnonblocking(ret->con, 1);
	}

	return ret;
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
