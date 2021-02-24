/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-09-xx  created (vlad-paiu)
 */


#include "cachedb_id.h"
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
	if (*dst) pkg_free(*dst);

	*dst = pkg_malloc(end - begin + 1);
	if ((*dst) == NULL) {
		return -1;
	}

	memcpy(*dst, begin, end - begin);
	(*dst)[end - begin] = '\0';
	return 0;
}


/**
 * Parse a database URL of form
 * scheme[:group]://[username[:password]@]hostname[:port]/database[?options]
 *
 * \param id filled id struct
 * \param url parsed URL
 * \return 0 if parsing was successful and -1 otherwise
 */
static int parse_cachedb_url(struct cachedb_id* id, const str* url)
{
#define SHORTEST_DB_URL "s://"
#define SHORTEST_DB_URL_LEN (sizeof(SHORTEST_DB_URL) - 1)

	enum state {
		ST_SCHEME,     /* Scheme part */
		ST_SLASH1,     /* First slash */
		ST_SLASH1_GRP, /* Group Name or first / */
		ST_SLASH2,     /* Second slash */
		ST_USER_HOST,  /* Username or hostname */
		ST_PASS_PORT,  /* Password or port part */
		ST_HOST,       /* Hostname part */
		ST_HOST6,      /* Hostname part IPv6 */
		ST_PORT,       /* Port part */
		ST_DB,         /* Database part */
		ST_OPTIONS     /* Options part */
	};

	enum state st;
	unsigned int len, i, ipv6_flag=0;
	char* begin;
	char* prev_token,*start_host=NULL,*start_prev=NULL,*ptr;

	prev_token = 0;

	if (!id || !url || !url->s) {
		goto err;
	}

	len = url->len;
	if (len < SHORTEST_DB_URL_LEN) {
		goto err;
	}

	LM_DBG("parsing [%.*s]\n",url->len,url->s);
	/* Initialize all attributes to 0 */
	memset(id, 0, sizeof(struct cachedb_id));
	st = ST_SCHEME;
	begin = url->s;

	if (dupl_string(&id->initial_url,url->s,url->s+url->len) < 0)
		goto err;

	for(i = 0; i < len; i++) {
		switch(st) {
		case ST_SCHEME:
			switch(url->s[i]) {
			case ':':
				st = ST_SLASH1_GRP;
				if (dupl_string(&id->scheme, begin, url->s + i) < 0) goto err;
				begin = url->s+i+1;
				break;
			}
			break;

		case ST_SLASH1_GRP:
			switch(url->s[i]) {
				case ':':
					st = ST_SLASH1;
					if (dupl_string(&id->group_name,begin,url->s+i) < 0) goto err;
					break;
				case '/':
					/* a '/' not right after ':' ?? */
					if (begin!=(url->s+i))
						goto err;
					st = ST_SLASH2;
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
				start_prev = begin;
				begin = url->s + i + 1;
				break;

			case '[':
				st = ST_HOST6;
				begin = url->s + i + 1;
				break;

			case '/':
				if (dupl_string(&id->host, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				st = ST_DB;
				break;
			}
			break;

		case ST_PASS_PORT:
			switch(url->s[i]) {
			case '@':
				st = ST_HOST;
				id->username = prev_token;
				if (dupl_string(&id->password, begin, url->s + i) < 0) goto err;
				begin = url->s + i + 1;
				break;

			case '/':
				id->host = prev_token;
				id->port = str2s(begin, url->s + i - begin, 0);
				begin = url->s + i + 1;
				st = ST_DB;
				break;

			case ',':
				st=ST_HOST;
				start_host=start_prev;
				id->flags |= CACHEDB_ID_MULTIPLE_HOSTS;
				break;
			}
			break;

		case ST_HOST:
			switch(url->s[i]) {
			case '[':
				st = ST_HOST6;
				begin = url->s + i + 1;
				break;

			case ':':
				LM_DBG("in host - :\n");
				if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
					LM_DBG("multiple hosts, skipping\n");
					break;
				}

				st = ST_PORT;
				if (dupl_string(&id->host, begin, url->s + i - ipv6_flag) < 0) goto err;
				start_host = begin;
				begin = url->s + i + 1;
				break;

			case '/':
				if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS)
					ptr = start_host;
				else
					ptr = begin;

				if (dupl_string(&id->host, ptr, url->s + i - ipv6_flag) < 0) goto err;
				begin = url->s + i + 1;
				st = ST_DB;
				break;
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

		case ST_PORT:
			switch(url->s[i]) {
			case '/':
				id->port = str2s(begin, url->s + i - begin, 0);
				begin = url->s + i + 1;
				st = ST_DB;
				break;

			case ',':
				st = ST_HOST;
				pkg_free(id->host);
				id->host=NULL;
				begin = start_host;
				id->flags |= CACHEDB_ID_MULTIPLE_HOSTS;
				break;
			}
			break;

		case ST_DB:
			switch(url->s[i]) {
			case '?':
				if (dupl_string(&id->database, begin, url->s + i) < 0) goto err;
				if (url->s + i + 1 == url->s + len) {
					st = ST_OPTIONS;
					break;
				}
				if (dupl_string(&id->extra_options, url->s + i + 1, url->s + len) < 0) goto err;
				return 0;
			}
			break;

		case ST_OPTIONS:
			break;
		}
	}

	if (st == ST_PORT) {
		if (url->s + i - begin == 0)
			goto err;

		id->port = str2s(begin, url->s + i - begin, 0);
		return 0;
	}

	if (st == ST_DB) {
		if (begin < url->s + len &&
				dupl_string(&id->database, begin, url->s + len) < 0) goto err;
		return 0;
	}

	if (st == ST_USER_HOST && begin == url->s+url->len) {
		/* Not considered an error - to cope with modules that
		 * offer cacheDB functionality backed up by OpenSIPS mem */
		id->flags |= CACHEDB_ID_NO_URL;
		LM_DBG("Just scheme, no actual url\n");
		return 0;
	}

	if (st != ST_DB && st != ST_OPTIONS) goto err;
	return 0;

 err:
	if (id && id->initial_url) pkg_free(id->initial_url);
	if (id && id->scheme) pkg_free(id->scheme);
	if (id && id->username) pkg_free(id->username);
	if (id && id->password) pkg_free(id->password);
	if (id && id->host) pkg_free(id->host);
	if (id && id->database) pkg_free(id->database);
	if (id && id->extra_options) pkg_free(id->extra_options);
	if (prev_token && prev_token != id->host && prev_token != id->username)
		pkg_free(prev_token);

	return -1;
}


/**
 * Create a new connection identifier
 * \param url database URL
 * \return connection identifier, or zero on error
 */
struct cachedb_id* new_cachedb_id(const str* url)
{
	struct cachedb_id* ptr;

	if (!url || !url->s) {
		LM_ERR("invalid parameter\n");
		return 0;
	}

	ptr = pkg_malloc(sizeof(struct cachedb_id));
	if (!ptr) {
		LM_ERR("no private memory left\n");
		goto err;
	}
	memset(ptr, 0, sizeof(struct cachedb_id));

	if (parse_cachedb_url(ptr, url) < 0) {
		LM_ERR("error while parsing database URL: '%s'\n",
				db_url_escape(url));
		goto err;
	}

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
int cmp_cachedb_id(struct cachedb_id* id1, struct cachedb_id* id2)
{
	if (!id1 || !id2) return 0;

	/* connections with different flags never match */
	if (id1->flags != id2->flags) return 0;
	/* different scehemes - never match */
	if (strcmp(id1->scheme,id2->scheme)) return 0;

	if (id1->flags == CACHEDB_ID_NO_URL) {
		/* no url - always match, based just on scheme */
		return 1;
	}

	/* different group names - never match */
	if ((id1->group_name == NULL && id2->group_name != NULL) ||
			(id1->group_name != NULL && id2->group_name == NULL))
		return 0;
	if (id1->group_name && strcmp(id1->group_name,id2->group_name)) return 0;

	/* different usernames - never match */
	if ((id1->username == NULL && id2->username != NULL) ||
			(id1->username != NULL && id2->username == NULL))
		return 0;
	if (id1->username && strcmp(id1->username,id2->username)) return 0;

	/* different passwords - never match */
	if ((id1->password == NULL && id2->password != NULL) ||
			(id1->password != NULL && id2->password == NULL))
		return 0;
	if (id1->password && strcmp(id1->password,id2->password)) return 0;

	if (strcmp(id1->host,id2->host)) return 0;

	if ((id1->database == NULL && id2->database != NULL) ||
			(id1->database != NULL && id2->database == NULL))
		return 0;
	if (id1->database && strcmp(id1->database,id2->database)) return 0;

	if ((!id1->extra_options && id2->extra_options) ||
			(id1->extra_options && !id2->extra_options))
		return 0;
	if (id1->extra_options &&
			strcmp(id1->extra_options, id2->extra_options)) return 0;

	if (id1->flags != CACHEDB_ID_MULTIPLE_HOSTS) {
		/* also check port as it is not included in host member */
		if (id1->port != id2->port) return 0;
	}

	return 1;
}


/**
 * Free a connection identifier
 * \param id identifier
 */
void free_cachedb_id(struct cachedb_id* id)
{
	if (!id) return;

	if (id->initial_url) pkg_free(id->initial_url);
	if (id->scheme) pkg_free(id->scheme);
	if (id->group_name) pkg_free(id->group_name);
	if (id->username) pkg_free(id->username);
	if (id->password) pkg_free(id->password);
	if (id->host) pkg_free(id->host);
	if (id->database) pkg_free(id->database);
	if (id->extra_options) pkg_free(id->extra_options);
	pkg_free(id);
}
