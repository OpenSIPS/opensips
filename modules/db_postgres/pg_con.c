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


#include <string.h>
#include <time.h>

#include "pg_con.h"
#include "db_postgres.h"
#include "dbase.h"

#include "../tls_mgm/api.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ut.h"

#define PSQL_PARAMS_MAX 15
#define DB_TLS_DOMAIN_PARAM_EQ_LEN 11
#define EXPAND_DBNAME 1

/* locate tls_domain=[dom] in the parameter string */
/* if found, a new string with tls_domain=[dom] is returned and MUST be freed */
/* if not found, NULL is returned */
char *get_postgres_tls_dom(struct db_id* id)
{
	char *output = NULL;
	char *index = strstr(id->parameters, DB_TLS_DOMAIN_PARAM_EQ);

	if (index) {
		int len;
		char *end = strchr(index, '&');
		if (end) {
			len = end - index;
		} else {
			len = strlen(index);
		}
		output = (char *)pkg_malloc(len+1);
		memcpy(output, index, len);
		output[len] = '\0';
	}
	return output;
}

/* helper routine to remove a substring from a string */
void rmSubstr(char *str, const char *toRemove)
{
	size_t length = strlen(toRemove);
	while((str = strstr(str, toRemove)))
	{
		memmove(str, str + length, 1 + strlen(str + length));
	}
}

/* helper routine to remove a character at an index from a string */
void removeChar(char *str, unsigned int index) {
	char *src;
	for (src = str+index; *src != '\0'; *src = *(src+1),++src) ;
	*src = '\0';
}

int db_postgres_connect(struct pg_con* ptr)
{
#define PSQL_PARAM(_k, _v) \
	do { \
		keywords[p] = (_k); \
		values[p] = (_v); \
		p++; \
	} while (0);
	const char *keywords[PSQL_PARAMS_MAX];
	const char *values[PSQL_PARAMS_MAX];
	int p = 0;

	char *ports = NULL;
	int len = 0;
	char *tls_domain = NULL;
	char *copy = NULL;
	str tls_domain_name = {0, 0};
	struct db_id* id = NULL;
	int i;

	if (ptr) {
		id = ptr->id;
	} else {
		LM_ERR("connection ptr parameter invalid\n");
		return -1;
	}

	if (id->parameters) {	
		int len = strlen(id->parameters);	
		copy = (char *)pkg_malloc(len+1);	
		memcpy(copy, id->parameters, len);
		copy[len] = '\0';

		/* locate tls_domain=[dom] in the parameter string */
		/* if found, a new string with tls_domain=[dom] is returned and MUST be freed */
		/* if not found, NULL is returned */
		tls_domain = get_postgres_tls_dom(id);
	}

	/* If tls_domain=[dom] is found in the parameter list, set str tls_domain_name and remove it */
	if (tls_domain) {
		tls_domain_name.s = tls_domain + DB_TLS_DOMAIN_PARAM_EQ_LEN;               // tls_domain=
		tls_domain_name.len = (int)strlen(tls_domain + DB_TLS_DOMAIN_PARAM_EQ_LEN);  // len of [dom]

		LM_DBG("TLS domain(%d): %.*s\n", tls_domain_name.len, tls_domain_name.len, tls_domain_name.s);

		// remove tls_domain=[dom]
		rmSubstr(copy, tls_domain);

		// if tls_domain was the first parameter
		// before rmSubstr() tls_domain=[dom]&application_name=opensips&connect_timeout=100
		// after  rmSubstr() &application_name=opensips&connect_timeout=100
		if (*copy == '&') {
			memmove(copy, copy+1, strlen(copy));
		}
		// if tls_domain was the last parameter
		// before rmSubstr() application_name=opensips&connect_timeout=100&tls_domain=[dom]
		// after  rmSubstr() &application_name=opensips&connect_timeout=100&
		len = strlen(copy);
		if (copy[len-1] == '&') {
			copy[len-1] = '\0';
		}

		// if tls_domain was a middle parameter
		// before rmSubstr() application_name=opensips&tls_domain=[dom]&connect_timeout=100
		// after  rmSubstr() &application_name=opensips&&connect_timeout=100
		char *index = strstr(copy, "&&");
		if (index) {
			removeChar(copy, index-copy);
		}

		pkg_free(tls_domain);
	}

	/* If use_tls is specified and tls_domain=[dom] was found in the parameter list */
	/* configure the SSL connection parameters */
	if (use_tls && tls_domain_name.len) {
		/* the connection should use TLS */
		if (!ptr->tls_dom) {
			ptr->tls_dom = tls_api.find_client_domain_name(&tls_domain_name);
			if (!ptr->tls_dom) {
				LM_ERR("TLS domain: %.*s not found\n", tls_domain_name.len, tls_domain_name.s);
				return -1;
			}
		}

		LM_DBG("SSL key file: %.*s\n", ptr->tls_dom->pkey.len, ptr->tls_dom->pkey.s);
		LM_DBG("SSL cert file: %.*s\n", ptr->tls_dom->cert.len, ptr->tls_dom->cert.s);
		LM_DBG("SSL ca file: %.*s\n", ptr->tls_dom->ca.len, ptr->tls_dom->ca.s);
		LM_DBG("SSL verify_cert: %d\n", ptr->tls_dom->verify_cert);

		if (ptr->tls_dom->verify_cert == 1) {
			PSQL_PARAM("sslmode", "verify-ca");
		}

		PSQL_PARAM("sslkey", ptr->tls_dom->pkey.s);
		PSQL_PARAM("sslcert", ptr->tls_dom->cert.s);
		PSQL_PARAM("sslrootcert", ptr->tls_dom->ca.s);
	}

	/* force the default timeout */
	/* If connect_timeout is specified in the parameter list, it will override this value */
	if (pq_timeout > 0) {
		PSQL_PARAM("connect_timeout", int2str(pq_timeout, 0));
	}

	if (copy) {
		/* Change parameters to connection string: convert '&' to space */
		for (i=0; copy[i] != '\0'; i++) {
			if (copy[i] == '&' ) {
				copy[i] = ' ';
			}
		}

		/* PQconnectdbParams(keywords, values, EXPAND_DBNAME) */
		/* When expand_dbname is non-zero, the value for the first dbname key word is checked to see if it is a connection string. */
		/* If so, it is expanded into the individual connection parameters extracted from the string. */
		/* The value is considered to be a connection string, rather than just a database name, */
		/* if it contains an equal sign (=) or it begins with a URI scheme designator. */
		/* Only the first occurrence of dbname is treated in this way; any subsequent dbname parameter is processed as a plain database name. */
		LM_DBG("connection string (%ld): %s\n", (long)strlen(copy), copy);
		PSQL_PARAM("dbname", copy);
	}

	if (id->host)
		PSQL_PARAM("host", id->host);
	if (id->username)
		PSQL_PARAM("user", id->username);
	if (id->password)
		PSQL_PARAM("password", id->password);
	if (id->database) {
		PSQL_PARAM("dbname", id->database);
	}

	if (id->port) {
		ports = int2str(id->port, 0);
		LM_DBG("opening connection: postgres://xxxx:xxxx@%s:%d/%s %s\n", ZSW(id->host), id->port, ZSW(id->database), ZSW(copy));
		PSQL_PARAM("port", ports);
	} else {
		ports = NULL;
		LM_DBG("opening connection: postgres://xxxx:xxxx@%s/%s %s\n", ZSW(id->host), ZSW(id->database), ZSW(copy));
	}

	/* End of the parameter list */
	PSQL_PARAM(0, 0);

	/* Print the parameter list created by PGSQL_PARAM */
	for (i=0; i<PSQL_PARAMS_MAX; i++) {
		if (!keywords[i]) {
			break;
		}
		if (!strncmp(keywords[i], "password", 8) || !strncmp(keywords[i], "user", 4)) {
			continue;
		}
		LM_DBG("PSQL_PARAM %s=%s\n", keywords[i], values[i]);
	}

	/* Perform the connection with the parameters added by PSQL_PARAM() */
	ptr->con = PQconnectdbParams(keywords, values, EXPAND_DBNAME);

	/* After the connection is attempted, there is no need to keep the copy of the parameter list */
	if (copy) {
		pkg_free(copy);
	}

	/* If an error  happened while trying to connect, cleanup */
	if(!ptr->con || (PQstatus(ptr->con) != CONNECTION_OK) )
	{
		LM_ERR("PQconnectdbParams: %s\n", PQerrorMessage(ptr->con));
		PQfinish(ptr->con);
		return -1;
	}

	ptr->connected = 1;
	ptr->timestamp = time(0);

	return 0;
}

/*
 * Create a new connection structure,
 * open the PostgreSQL connection and set reference count to 1
 */
struct pg_con* db_postgres_new_connection(struct db_id* id)
{
	struct pg_con* ptr = NULL;

	if (!id) {
		LM_ERR("invalid db_id parameter value\n");
		return 0;
	} else {
		LM_DBG("db_id = %p\n", id);
	}

	ptr = (struct pg_con*)pkg_malloc(sizeof(struct pg_con));
	if (!ptr) {
		LM_ERR("failed trying to allocated %lu bytes for connection structure."
				"\n", (unsigned long)sizeof(struct pg_con));
		return 0;
	}

	LM_DBG("db_id: %p %p=pkg_malloc(%zu)\n", id, ptr, sizeof(struct pg_con));
	memset(ptr, 0, sizeof(struct pg_con));

	ptr->ref = 1;
	ptr->id = id;

	LM_DBG("calling db_postgres_connect ptr = %p, db_id = %p\n", ptr, ptr->id);

	if (db_postgres_connect(ptr)!=0) {
		LM_ERR("initial connect failed, cleaning up %p=pkg_free()\n", ptr);
		if (ptr) {
			pkg_free(ptr);
		}
		return 0;
	}

	return ptr;
}

/*
 * Create a new async connection structure,
 * open the PostgreSQL connection and set reference count to 1
 */
struct pg_con* db_postgres_new_async_connection(struct db_id* id)
{
	struct pg_con *ptr;

	if (!id) {
		LM_ERR("invalid db_id parameter value\n");
		return 0;
	} else {
		LM_DBG("db_id = %p\n", id);
	}

	ptr = db_postgres_new_connection(id);

	if (ptr) {
		PQsetnonblocking(ptr->con, 1);
	}

	return ptr;
}

/*
 * Close the connection and release memory
 */
void db_postgres_free_connection(struct pool_con* con)
{

	if (!con) {
		LM_ERR("invalid connection parameter value\n");
		return;
	} else {
		LM_DBG("connection = %p\n", con);
	}

	struct pg_con * _c;
	_c = (struct pg_con*)con;

	if (_c->tls_dom) {
		tls_api.release_domain(_c->tls_dom);
		_c->tls_dom = NULL;
	}

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
	LM_DBG("cleaning up connection pkg_free(%p)\n", _c);
	pkg_free(_c);
}
