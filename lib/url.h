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
 * Support for generic URL parsing. Various URL requirements/enforcements may
 * be obtained by combining the below "url_parse_flags" enum bits.
 *
 * The currently supported URL syntax is:
 *
 * [scheme:[group:]//]
 * [username@|[username]:password@]
 *	host1[:port1][,host2[:port2][, ...]]
 * [/database]
 * [?foo=bar,baz]
 *
 * Some explanations:
 *   - "scheme" may be optional. if a scheme is present, a "group" is optional
 *   - any combination of "username" and "password" (F/F, T/F, F/T, T/T)
 *   - a single, first "host" is mandatory. Additional hosts are optional.
 *   - any host may have a designated "port"
 *   - a "database" portion is optional
 *   - "parameter" support is included
 *	 - a parameter may or may not have a value
 *
 * Returned structure (allocated in pkg):
 *   - if a "part" is mandatory (i.e. flag is set) and the function returns
 *     a non-NULL value, its value will _not_ be empty (part.len > 0)
 *     (this includes: scheme, group, user, password, host, database, >1 param)
 *   - if a "port" is not present, its value will be zero
 *   - if a "param" has no value (i.e. "foo,bar"), params.val == {NULL, 0}
 *   - if a "param" has empty value (i.e. "foo=,bar"), params.val == {0x7b*, 0}
 *	 >>> remember to call free_url() afterwards
 */

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

/* parse a generic URL according to "opts".
 *	@pkg_dup: if true, any returned strings will be dup'ed in PKG
 */
struct url *parse_url(const str *in, enum url_parse_flags opts, int pkg_dup);

/* free all the metadata (hooks, lists, etc.) associated with a URL string */
void free_url(struct url *url);

void print_url(struct url *url);

#endif /* __LIB_URL__ */
