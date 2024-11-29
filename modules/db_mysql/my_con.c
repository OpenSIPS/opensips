/*
 * Copyright (C) 2001-2004 iptel.org
 * Copyright (C) 2008 1&1 Internet AG
 * Copyright (C) 2016 OpenSIPS Solutions
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

#include "my_con.h"
#include "db_mysql.h"
#include "dbase.h"
#include <mysql.h>

#define _list_h_skip_list_add_
#include "../../lib/csv.h"
#include "../tls_mgm/api.h"
#include "../../mod_fix.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ut.h"

unsigned int db_mysql_tls_opts;

static str *get_mysql_tls_dom(struct db_id* id, unsigned int *opts)
{
	static str dom = {0,0};
	csv_record *rec;
	str params;
	int have_opts = 0;

	if (!id->parameters)
		return NULL;

	init_str(&params, id->parameters);
	rec = __parse_csv_record(&params, 0, '&');
	for (; rec; rec = rec->next) {
		/* tls_domain= */
		if (rec->s.len >= DB_TLS_DOMAIN_PARAM_EQ_S && !memcmp(
		        rec->s.s, DB_TLS_DOMAIN_PARAM_EQ, DB_TLS_DOMAIN_PARAM_EQ_S)) {
			dom.s = rec->s.s + DB_TLS_DOMAIN_PARAM_EQ_S;
			dom.len = rec->s.len - DB_TLS_DOMAIN_PARAM_EQ_S;
			if (!dom.len) {
				LM_ERR("Empty TLS domain name\n");
				goto error;
			}

		/* tls_opts= */
		} else if (rec->s.len >= DB_TLS_OPTS_PARAM_EQ_S && !memcmp(
		        rec->s.s, DB_TLS_OPTS_PARAM_EQ, DB_TLS_OPTS_PARAM_EQ_S)) {
			str tokens, f_names[] = {
			    str_init("PKEY"),
			    str_init("CERT"),
			    str_init("CA"),
			    str_init("CA_DIR"),
			    str_init("CIPHERS"),
				{0},
			    };
			void *inout = &tokens;

			tokens.s = rec->s.s + DB_TLS_OPTS_PARAM_EQ_S;
			tokens.len = rec->s.len - DB_TLS_OPTS_PARAM_EQ_S;
			if (fixup_named_flags(&inout, f_names, NULL, NULL) != 0) {
				LM_ERR("failed to parse 'tls_opts=' value: '%s'\n", tokens.s);
				goto error;
			}

			*opts = (unsigned int)(unsigned long)inout;
			have_opts = 1;

			LM_INFO("using custom MySQL TLS opts: %s (mask: %u)\n",
			        tokens.s, *opts);
		} else {
			LM_ERR("unknown MySQL URL param: '%.*s'\n", rec->s.len, rec->s.s);
		}
	}

	if (!dom.len) {
		if (have_opts)
			LM_ERR("Missing 'tls_domain=' URL parameter\n");
		goto error;
	}

	if (!have_opts)
		*opts = MY_CON_TLS_ALL_OPTS;

	free_csv_record(rec);
	return &dom;
error:
	free_csv_record(rec);
	return NULL;
}

int db_mysql_connect(struct my_con* ptr)
{
	str *tls_domain_name;
	unsigned int tls_opts;

	/* if connection already in use, close it first*/
	if (ptr->init)
		mysql_close(ptr->con);

	mysql_init(ptr->con);
	ptr->init = 1;

	tls_domain_name = get_mysql_tls_dom(ptr->id, &tls_opts);
	if (use_tls && tls_domain_name) {
		/* the connection should use TLS */
		if (!ptr->tls_dom) {
			ptr->tls_dom = tls_api.find_client_domain_name(tls_domain_name);
			if (!ptr->tls_dom) {
				LM_ERR("TLS domain: %.*s not found\n",
					tls_domain_name->len, tls_domain_name->s);
				mysql_close(ptr->con);
				ptr->init = 0;
				return -1;
			}
		}

		LM_DBG("TLS key file: %s\n", (tls_opts & MY_CON_TLS_PKEY) ? ptr->tls_dom->pkey.s:NULL);
		LM_DBG("TLS cert file: %s\n", (tls_opts & MY_CON_TLS_CERT) ? ptr->tls_dom->cert.s:NULL);
		LM_DBG("TLS ca file: %s\n", (tls_opts & MY_CON_TLS_CA) ? ptr->tls_dom->ca.s:NULL);
		LM_DBG("TLS ca dir: %s\n", (tls_opts & MY_CON_TLS_CA_DIR) ? ptr->tls_dom->ca_directory:NULL);
		LM_DBG("TLS ciphers: %s\n", (tls_opts & MY_CON_TLS_CIPHERS) ? ptr->tls_dom->ciphers_list:NULL);
		LM_DBG("TLS opts: %u\n", tls_opts);

		mysql_ssl_set(ptr->con,
			(tls_opts & MY_CON_TLS_PKEY) ? ptr->tls_dom->pkey.s:NULL,
			(tls_opts & MY_CON_TLS_CERT) ? ptr->tls_dom->cert.s:NULL,
			(tls_opts & MY_CON_TLS_CA) ? ptr->tls_dom->ca.s:NULL,
			(tls_opts & MY_CON_TLS_CA_DIR) ? ptr->tls_dom->ca_directory:NULL,
			(tls_opts & MY_CON_TLS_CIPHERS) ? ptr->tls_dom->ciphers_list:NULL);
	}
#if (defined LIBMARIADB) || (MYSQL_VERSION_ID < 80000)
#if (MYSQL_VERSION_ID >= 50700)
	mysql_options(ptr->con, MYSQL_OPT_SSL_ENFORCE, (void *)&use_tls);
#endif
#else
	tls_opts = (use_tls?SSL_MODE_PREFERRED:SSL_MODE_DISABLED);
	mysql_options(ptr->con, MYSQL_OPT_SSL_MODE, (void *)&tls_opts);
#endif

	/* set connect, read and write timeout, the value counts three times */
	mysql_options(ptr->con, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&db_mysql_timeout_interval);
	mysql_options(ptr->con, MYSQL_OPT_READ_TIMEOUT, (void *)&db_mysql_timeout_interval);
	mysql_options(ptr->con, MYSQL_OPT_WRITE_TIMEOUT, (void *)&db_mysql_timeout_interval);

	/* explicitly disable auto-reconnect on older libraries (default: 0) */
#if MYSQL_VERSION_ID < 50013
	ptr->con->reconnect = 0;
#elif MYSQL_VERSION_ID < 80034
	{
		my_bool reconnect = 0;
		mysql_options(ptr->con, MYSQL_OPT_RECONNECT, &reconnect);
	}
#endif

	if (ptr->id->port) {
		LM_DBG("opening connection: mysql://xxxx:xxxx@%s:%d/%s\n",
			ZSW(ptr->id->host), ptr->id->port, ZSW(ptr->id->database));
	} else {
		LM_DBG("opening connection: mysql://xxxx:xxxx@%s/%s\n",
			ZSW(ptr->id->host), ZSW(ptr->id->database));
	}

	if (!mysql_real_connect(ptr->con, ptr->id->host,
			ptr->id->username, ptr->id->password,
			ptr->id->database, ptr->id->port, 0,
#if (MYSQL_VERSION_ID >= 40100)
			CLIENT_MULTI_STATEMENTS|CLIENT_REMEMBER_OPTIONS
#else
			CLIENT_REMEMBER_OPTIONS
#endif
	)) {
		LM_ERR("driver error(%d): %s\n",
			mysql_errno(ptr->con), mysql_error(ptr->con));
		mysql_close(ptr->con);
		ptr->init = 0;
		return -1;
	}

	LM_DBG("connection type is %s\n", mysql_get_host_info(ptr->con));
	LM_DBG("protocol version is %d\n", mysql_get_proto_info(ptr->con));
	LM_DBG("server version is %s\n", mysql_get_server_info(ptr->con));

	return 0;
}



/**
 * Create a new connection structure,
 * open the MySQL connection and set reference count to 1
 */
struct my_con* db_mysql_new_connection(const struct db_id* id)
{
	struct my_con* ptr;

	if (!id) {
		LM_ERR("invalid parameter value\n");
		return 0;
	}

	ptr = (struct my_con*)pkg_malloc(sizeof(struct my_con));
	if (!ptr) {
		LM_ERR("no private memory left\n");
		return 0;
	}

	memset(ptr, 0, sizeof(struct my_con));
	ptr->ref = 1;

	ptr->con = (MYSQL*)pkg_malloc(sizeof(MYSQL));
	if (!ptr->con) {
		LM_ERR("no private memory left\n");
		goto err;
	}

	ptr->id = (struct db_id*)id;

	if (db_mysql_connect(ptr)!=0) {
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
void db_mysql_free_connection(struct pool_con* con)
{
	if (!con) return;

	struct my_con * _c;
	_c = (struct my_con*) con;

	if (_c->tls_dom) {
		tls_api.release_domain(_c->tls_dom);
		_c->tls_dom = NULL;
	}

	if (_c->ps_list) db_mysql_free_stmt_list(_c->ps_list);
	if (_c->res) mysql_free_result(_c->res);
	if (_c->id) free_db_id(_c->id);
	if (_c->con) {
		if (_c->init)
			mysql_close(_c->con);
		pkg_free(_c->con);
	}
	pkg_free(_c);
}
