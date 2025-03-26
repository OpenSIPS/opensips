/*
 * Copyright (C) 2018-2021 OpenSIPS Solutions
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

#include <tap.h>

#include "../../str.h"
#include "../../db/db_id.h"
#include "../../lib/osips_malloc.h"
#include "../../sr_module.h"
#include "../../modparam.h"

static void test_db_url(void);

void test_db(void)
{
	test_db_url();
}

static void test_db_url(void)
{
#define DB_PARSE(__url) db = new_db_id(_str(__url)); if (!ok(db != NULL)) return;
	struct db_id *db;
	int i = 1;

	DB_PARSE("mysql://user:pass@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, "pass"),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	//Test a password with special characters.
	i = 2;

	DB_PARSE("mysql://user:p/a,ss@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, "p/a,ss"),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 3;

	DB_PARSE("mysql://user:pa/ss@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, "pa/ss"),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 4;

	DB_PARSE("mysql://user@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 5;

	DB_PARSE("mysql://user:p//a!,ss@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, "p//a!,ss"),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 6;

	DB_PARSE("mysql://user:pa//ss@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, "pa//ss"),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 7;
	DB_PARSE("mysql://user:@host:6033/database?parameters");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, ""),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "host"),             "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 6033),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "parameters"), "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 8;
	DB_PARSE("http://localhost/opensips/x");
	ok(!strcmp(db->scheme, "http"),           "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!db->username,                         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!db->password,                         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),        "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 0),                       "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"),   "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!db->parameters,                       "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 9;
	DB_PARSE("http://localhost:8081/opensips/x");
	ok(!strcmp(db->scheme, "http"),           "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!db->username,                         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!db->password,                         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),        "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 8081),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"),   "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!db->parameters,                       "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 10;
	DB_PARSE("http://localhost:8081/opensips/x?params");
	ok(!strcmp(db->scheme, "http"),           "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!db->username,                         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!db->password,                         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),        "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 8081),                    "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),             "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"),   "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, "params"),     "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 11;
	DB_PARSE("mysql://user:pass@unix(/var/mysqld/mysqld.sock)/database?");
	ok(!strcmp(db->scheme, "mysql"),          "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok(!strcmp(db->username, "user"),         "parse_db_url: %d-username: '%s'", i, db->username);
	ok(!strcmp(db->password, "pass"),         "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),        "parse_db_url: %d-host: '%s'", i, db->host);
	ok(!strcmp(db->unix_socket, "/var/mysqld/mysqld.sock"), "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok((db->port == 0),                       "parse_db_url: %d-port: '%d'", i, db->port);
	ok(!strcmp(db->database, "database"),     "parse_db_url: %d-database: '%s'", i, db->database);
	ok(!strcmp(db->parameters, ""),              "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 12;
	DB_PARSE("http://localhost:8081/opensips");
	ok(!strcmp(db->scheme, "http"),       "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok((db->username == NULL),            "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),            "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),    "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 8081),                "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),         "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips"), "parse_db_url: %d-database: '%s'", i, db->database);
	ok((db->parameters == NULL),          "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 13;
	DB_PARSE("http://localhost:8081/opensips/x");
	ok(!strcmp(db->scheme, "http"),       "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok((db->username == NULL),            "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),            "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),    "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 8081),                "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),         "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"), "parse_db_url: %d-database: '%s'", i, db->database);
	ok((db->parameters == NULL),          "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 14;
	DB_PARSE("http://localhost/opensips/x");
	ok(!strcmp(db->scheme, "http"),       "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok((db->username == NULL),            "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),            "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),    "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 0),                   "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),         "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"), "parse_db_url: %d-database: '%s'", i, db->database);
	ok((db->parameters == NULL),          "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 15;
	DB_PARSE("mysql://localhost/opensips/x");
	ok(!strcmp(db->scheme, "mysql"),      "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok((db->username == NULL),            "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),            "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),    "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 0),                   "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),         "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"), "parse_db_url: %d-database: '%s'", i, db->database);
	ok((db->parameters == NULL),          "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 16;
	DB_PARSE("postgres://localhost/opensips/x");
	ok(!strcmp(db->scheme, "postgres"),   "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok((db->username == NULL),            "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),            "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),    "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 0),                   "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),         "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"), "parse_db_url: %d-database: '%s'", i, db->database);
	ok((db->parameters == NULL),          "parse_db_url: %d-parameters: '%s'", i, db->parameters);

	i = 17;
	DB_PARSE("postgres://localhost:5544/opensips/x");
	ok(!strcmp(db->scheme, "postgres"),   "parse_db_url: %d-schema: '%s'", i, db->scheme);
	ok((db->username == NULL),            "parse_db_url: %d-username: '%s'", i, db->username);
	ok((db->password == NULL),            "parse_db_url: %d-password: '%s'", i, db->password);
	ok(!strcmp(db->host, "localhost"),    "parse_db_url: %d-host: '%s'", i, db->host);
	ok((db->port == 5544),                "parse_db_url: %d-port: '%d'", i, db->port);
	ok((db->unix_socket == NULL),         "parse_db_url: %d-unix_socket: '%s'", i, db->unix_socket);
	ok(!strcmp(db->database, "opensips/x"), "parse_db_url: %d-database: '%s'", i, db->database);
	ok((db->parameters == NULL),          "parse_db_url: %d-parameters: '%s'", i, db->parameters);
}
