/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef __LIB_URL__
#define __LIB_URL__

#include "../str.h"

/*
 * [scheme:[group:]//]
 * [username@|[username]:password@]
 *	host1[:port1][,host2[:port2][, ...]]
 * [/database]
 * [?foo=bar,raz]
 * */

enum url_parse_flags {
	URL_REQ_SCHEME         = (1<<0),
	URL_REQ_SCHEME_GROUP   = (1<<1),
	URL_REQ_USER           = (1<<2),
	URL_REQ_PASS           = (1<<3),
	URL_REQ_PORT           = (1<<4),
	URL_REQ_DB             = (1<<5),
	URL_REQ_PARAMS         = (1<<6),
	URL_ALLOW_EXTRA_HOSTS  = (1<<7),
};

struct url_host_list {
	str host;
	unsigned short port;
	struct url_host_list *next;
};

struct url_param_list {
	str key;
	str val;
	struct url_param_list *next;
};

struct url {
	str scheme;
	str group_name;
	str username;
	str password;
	struct url_host_list *hosts;
	str database;
	struct url_param_list *params;
};

struct url *parse_url(const str *string, enum url_parse_flags opts, int pkg_dup);

/* free all the metadata (hooks, lists, etc.) associated with a URL string */
void free_url(struct url *url);

#endif /* __LIB_URL__ */
