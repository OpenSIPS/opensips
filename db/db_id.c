/*
 * Copyright (C) 2001-2005 iptel.org
 * Copyright (C) 2007-2008 1&1 Internet AG
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

/**
 * \file db/db_id.c
 * \brief Functions for parsing a database URL and work with db identifier.
 */

#include "db_id.h"
#include "../dprint.h"
#include "../mem/mem.h"
#include "../ut.h"
#include <stdlib.h>
#include <string.h>


/**
 * Duplicate a string
 * \param dst destination
 * \param begin start of the string
 * \param end end of the string
 */
static int dupl_string(char** dst, const char* begin, const char* end)
{
	str old, new;

	if (*dst) pkg_free(*dst);

	*dst = pkg_malloc(end - begin + 1);
	if ((*dst) == NULL) {
		return -1;
	}

	old.s = (char*)begin;
	old.len = end - begin;
	new.s = *dst;
	un_escape(&old, &new );

	new.s[new.len] = '\0';
	return 0;
}


/**
 * Parse a database URL of form
 * scheme://[username[:password]@]hostname[:port]/database[?parameters]
 *
 * \param id filled id struct
 * \param url parsed URL
 * \return 0 if parsing was successful and -1 otherwise
 */
static int parse_db_url(struct db_id* id, const str* url)
{
#define SHORTEST_DB_URL "s://a/b"
#define SHORTEST_DB_URL_LEN (sizeof(SHORTEST_DB_URL) - 1)

	enum state {
		ST_SCHEME,     /* Scheme part */
		ST_SLASH1,     /* First slash */
		ST_SLASH2,     /* Second slash */
		ST_USER_HOST,  /* Username or hostname */
		ST_PASS_PORT,  /* Password or port part */
		ST_PASSWORD,   /* Explicitly the password */
		ST_HOST,       /* Hostname part */
		ST_HOST6,      /* Hostname part IPv6 */
		ST_PORT,       /* Port part */
		ST_UNIX_SOCKET, /* Unix socket */
		ST_DB,         /* Database part */
		ST_PARAMS       /* Parameters part */
	};

	enum state st;
	unsigned int len, i, ipv6_flag = 0;
	const char* begin;
	char* prev_token = NULL;
	str unix_socket_host = str_init("localhost");

	if (!id || !url || !url->s) {
		return -1;
	}

	len = url->len;
	if (len < SHORTEST_DB_URL_LEN) {
		return -1;
	}

	/* Initialize all attributes to 0 */
	memset(id, 0, sizeof(struct db_id));
	st = ST_SCHEME;
	begin = url->s;

	for(i = 0; i < len; i++) {
		switch(st) {
		case ST_SCHEME:
			switch(url->s[i]) {
			case ':':
				st = ST_SLASH1;
				if (dupl_string(&id->scheme, begin, url->s + i) < 0) goto err;
				break;
			}
			break;

		case ST_SLASH1:
			switch(url->s[i]) {
			case '/':
				st = ST_SLASH2;
				break;

			default:
				goto err;
			}
			break;

		case ST_SLASH2:
			switch(url->s[i]) {
			case '/':
				st = ST_USER_HOST;
				begin = url->s + i + 1;
				break;

			default:
				goto err;
			}
			break;

		case ST_USER_HOST:
			switch(url->s[i]) {
			case '@':
				st = ST_HOST;
				if (dupl_string(&id->username, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				break;

			case ':':
				st = ST_PASS_PORT;
				if (dupl_string(&prev_token, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				break;

			case '[':
				st = ST_HOST6;
				begin = url->s + i + 1;
				break;

			case '/':
				st = ST_DB;
				if (dupl_string(&id->host, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
			}
			break;

		case ST_PASS_PORT:
			switch(url->s[i]) {
			case '@':
				st = ST_HOST;
				id->username = prev_token; prev_token = NULL;
				if (dupl_string(&id->password, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				break;

			case ':':  // Explicitly mark we are now in the password state
				st = ST_PASSWORD;
				if (dupl_string(&prev_token, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				break;
			}
			break;

		case ST_PASSWORD:
			switch (url->s[i]) {
			case '@':  // Only @ terminates password
				st = ST_HOST;
				id->username = prev_token; prev_token = NULL;
				if (dupl_string(&id->password, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				break;
			}
			break;

		case ST_HOST:
			if (strncasecmp(begin, "unix(", 5) == 0) {
				st = ST_UNIX_SOCKET;
				i+=5;
				begin = url->s + i;
				break;
			}
			switch(url->s[i]) {
			case '[':
				st = ST_HOST6;
				begin = url->s + i + 1;
				break;

			case ':':
				st = ST_PORT;
				if (dupl_string(&id->host, begin, url->s + i - ipv6_flag) < 0) goto err;
				begin = url->s + i + 1;
				break;

			case '/':
				if (dupl_string(&id->host, begin, url->s + i - ipv6_flag) < 0) goto err;
				st = ST_DB;
				begin = url->s + i + 1;
			}
			break;

		case ST_HOST6:
			switch(url->s[i]) {
			case ']':
				ipv6_flag = 1;
				st = ST_HOST;
				break;

			}
			break;

		case ST_UNIX_SOCKET:
			switch(url->s[i]) {
			case ')':
				if (dupl_string(&id->unix_socket, begin, url->s + i) < 0) goto err;
				if (dupl_string(&id->host, unix_socket_host.s, unix_socket_host.s + unix_socket_host.len) < 0) goto err;
				begin = url->s + i + 1;
				if (*begin == '/') {
					i++;
					begin = url->s + i + 1;
				}
				st = ST_DB;
			}
			break;

		case ST_PORT:
			switch(url->s[i]) {
			case '/':
				id->port = str2s(begin, url->s + i - begin, 0);
				st = ST_DB;
				begin = url->s + i + 1;
			}
			break;

		case ST_DB:
			switch(url->s[i]) {
			case '?':
				st = ST_PARAMS;
				if (dupl_string(&id->database, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
			}
			break;

		case ST_PARAMS:
			break;
		}
	}

	if (st != ST_DB && st != ST_PARAMS) goto err;

	if (st == ST_DB) {
		if (dupl_string(&id->database, begin, url->s + len) < 0) goto err;
	} else {
		if (dupl_string(&id->parameters, begin, url->s + len) < 0) goto err;
	}

	return 0;

 err:
	if (id->scheme) pkg_free(id->scheme);
	if (id->username) pkg_free(id->username);
	if (id->password) pkg_free(id->password);
	if (id->host) pkg_free(id->host);
	if (id->unix_socket) pkg_free(id->unix_socket);
	if (id->database) pkg_free(id->database);
	if (prev_token) pkg_free(prev_token);
	return -1;
}


/**
 * Create a new connection identifier
 * \param url database URL
 * \return connection identifier, or zero on error
 */
struct db_id* new_db_id(const str* url)
{
	struct db_id* ptr;

	if (!url || !url->s) {
		LM_ERR("invalid parameter\n");
		return 0;
	}

	ptr = (struct db_id*)pkg_malloc(sizeof(struct db_id));
	if (!ptr) {
		LM_ERR("no private memory left\n");
		goto err;
	}
	memset(ptr, 0, sizeof(struct db_id));

	if (parse_db_url(ptr, url) < 0) {
		LM_ERR("error while parsing database URL: '%.*s' \n", url->len, url->s);
		goto err;
	}

	/* store the original url */
	ptr->url.s = url->s;
	ptr->url.len = url->len;

	return ptr;

 err:
	if (ptr) pkg_free(ptr);
	return 0;
}


/**
 * Compare two connection identifiers
 * \param id1 first identifier
 * \param id2 second identifier
 * \return one if both are equal, zero otherwise
 */
unsigned char cmp_db_id(const struct db_id* id1, const struct db_id* id2)
{
	if (!id1 || !id2) return 0;

	if (id1->port != id2->port) return 0;

	if (strcmp(id1->scheme, id2->scheme)) return 0;

	if (id1->username != 0 && id2->username != 0) {
		if (strcmp(id1->username, id2->username)) return 0;
	} else {
		if (id1->username!=0 || id2->username!=0) return 0;
	}

	if (id1->password!=0 && id2->password!=0) {
		if(strcmp(id1->password, id2->password)) return 0;
	} else {
		if (id1->password!=0 || id2->password!=0) return 0;
	}

	if (strcasecmp(id1->host, id2->host)) return 0;

	if (id1->unix_socket!=0 && id2->unix_socket!=0) {
		if (strcasecmp(id1->unix_socket, id2->unix_socket)) return 0;
	} else {
		if (id1->unix_socket!=0 || id2->unix_socket!=0) return 0;
	}

	if (strcmp(id1->database, id2->database)) return 0;

	if (id1->parameters != 0 && id2->parameters != 0) {
		if(strcmp(id1->parameters, id2->parameters)) return 0;
	} else {
		if (id1->parameters!=0 || id2->parameters!=0) return 0;
	}

	return 1;
}


/**
 * Free a connection identifier
 * \param id identifier
 */
void free_db_id(struct db_id* id)
{
	if (!id) return;

	if (id->scheme) pkg_free(id->scheme);
	if (id->username) pkg_free(id->username);
	if (id->password) pkg_free(id->password);
	if (id->host) pkg_free(id->host);
	if (id->unix_socket) pkg_free(id->unix_socket);
	if (id->database) pkg_free(id->database);
	if (id->parameters) pkg_free(id->parameters);
	pkg_free(id);
}
