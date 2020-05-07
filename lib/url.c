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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#undef _GNU_SOURCE

#include "../mem/mem.h"
#include "../ut.h"

#include "csv.h"

#include "url.h"

#define SCHEME_SEP     "://"
#define SCHEME_SEP_LEN (sizeof(SCHEME_SEP) - 1)

static int dup_pkg_fields(struct url *url)
{
	// TODO: implement when refactoring the cachedb_id & db_id code
	return 0;
}

struct url *parse_url(const str *in, enum url_parse_flags opts, int pkg_dup)
{
	struct url *url = NULL;
	char *ch, *p;
	str st, port;
	struct url_host_list *last, *hostlist;
	struct url_param_list *lastp, *paramlist;
	str_list *hosts_db = NULL, *hosts_chunk = NULL, *hosts = NULL;
	str_list *params, *rec;

#define ENSURE_N_LEFT(n) \
	do { \
		if (st.len < n) { \
			LM_ERR("incomplete URL: '%.*s'\n", in->len, in->s); \
			goto out_err; \
		} \
	} while (0)

	if (!in || !in->s || in->len == 0) {
		LM_ERR("null or empty URL!\n");
		return NULL;
	}

	LM_DBG("parsing '%.*s'\n", in->len, in->s);

	st = *in;
	if (opts & (URL_REQ_SCHEME|URL_REQ_SCHEME_GROUP))
		ENSURE_N_LEFT(SCHEME_SEP_LEN);

	url = pkg_malloc(sizeof *url + in->len);
	if (!url) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(url, 0, sizeof *url + in->len);

	/* scheme:[group:]//" */
	ch = memmem(in->s, in->len, SCHEME_SEP, SCHEME_SEP_LEN);
	if (ch && ch > in->s) {
		url->scheme.s = in->s;

		p = memchr(in->s, ':', ch - in->s);
		if (!p) {
			url->scheme.len = ch - in->s;
		} else {
			url->scheme.len = p - in->s;
			url->group_name.s = p + 1;
			url->group_name.len = ch - (p + 1);
		}

		st.len = in->len - (ch + SCHEME_SEP_LEN - in->s);
		st.s = ch + SCHEME_SEP_LEN;
	}

	if (opts & (URL_REQ_SCHEME|URL_REQ_SCHEME_GROUP)) {
		if (!url->scheme.s || url->scheme.len <= 0) {
			LM_ERR("incomplete \"scheme://\" part in URL %.*s\n",
			       in->len, in->s);
			goto out_err;
		}

		if ((opts & URL_REQ_SCHEME_GROUP) &&
		    (!url->group_name.s || url->group_name.len <= 0)) {
			LM_ERR("bad or missing \"scheme:group://\" part in URL %.*s\n",
			       in->len, in->s);
			goto out_err;
		}
	}

	ENSURE_N_LEFT(1);

	/* [username@|[username]:password@] */
	ch = memchr(st.s, '@', st.len);
	if (ch && ch > st.s) {
		url->username.s = st.s;

		p = memchr(st.s, ':', ch - st.s);
		if (!p) {
			url->username.len = ch - st.s;
		} else {
			url->username.len = p - st.s;
			url->password.s = p + 1;
			url->password.len = ch - (p + 1);
		}

		st.len = st.len - (ch + 1 - st.s);
		st.s = ch + 1;
	}

	if (opts & URL_REQ_USER) {
		if (!url->username.s || url->username.len <= 0) {
			LM_ERR("missing \"username\" part in URL %.*s\n", in->len, in->s);
			goto out_err;
		}
	}

	if (opts & URL_REQ_PASS) {
		if (!url->password.s || url->password.len <= 0) {
			LM_ERR("missing \"password\" part in URL %.*s\n", in->len, in->s);
			goto out_err;
		}
	}

	ENSURE_N_LEFT(1);

	/* hosts[/database][?params] */
	hosts_db = __parse_csv_record(&st, 0, '?');
	hosts_chunk = __parse_csv_record(&hosts_db->s, 0, '/');

	if (!hosts_chunk->s.s || hosts_chunk->s.len <= 0) {
		LM_ERR("empty/missing \"host\" part in URL %.*s\n", in->len, in->s);
		goto out_err;
	}

	/* host1[:port1][,host2[:port2]...]] */
	hosts = parse_csv_record(&hosts_chunk->s);
	if (hosts->next && !(opts & URL_ALLOW_EXTRA_HOSTS)) {
		LM_ERR("multiple hosts not allowed in URL %.*s\n", in->len, in->s);
		goto out_err;
	}

	last = NULL;
	/* host[:port] chunks */
	for (rec = hosts; rec; rec = rec->next) {
		hostlist = pkg_malloc(sizeof *hostlist);
		if (!hostlist) {
			LM_ERR("oom\n");
			goto out_err;
		}
		memset(hostlist, 0, sizeof *hostlist);
		if (!last)
			url->hosts = hostlist;
		else
			last->next = hostlist;

		last = hostlist;

		hostlist->host.s = rec->s.s;
		ch = memchr(rec->s.s, ':', rec->s.len);
		if (ch) {
			if (ch == rec->s.s) {
				LM_ERR("empty \"host\" in URL %.*s\n", in->len, in->s);
				goto out_err;
			}

			port.len = rec->s.len - (ch + 1 - rec->s.s);
			port.s = ch + 1;
			if (port.len <= 0 && (opts & URL_REQ_PORT)) {
				LM_ERR("empty \"port\" in URL %.*s\n", in->len, in->s);
				goto out_err;
			}
			if (str2short(&port, &hostlist->port) != 0) {
				LM_ERR("bad \"port\" in URL %.*s\n", in->len, in->s);
				goto out_err;
			}

			hostlist->host.len = ch - rec->s.s;
		} else {
			hostlist->host.len = rec->s.len;
		}
	}

	/* [/database] */
	if (hosts_chunk->next &&
	    hosts_chunk->next->s.s &&
	    hosts_chunk->next->s.len > 0)
			url->database = hosts_chunk->next->s;

	if (!url->database.s && (opts & URL_REQ_DB)) {
		LM_ERR("missing \"database\" part in URL %.*s\n", in->len, in->s);
		goto out_err;
	}

	/* [?foo=bar,baz] */
	if (hosts_db->next &&
	    hosts_db->next->s.s && hosts_db->next->s.len > 0) {

		params = parse_csv_record(&hosts_db->next->s);
		lastp = NULL;
		for (rec = params; rec; rec = rec->next) {
			paramlist = pkg_malloc(sizeof *paramlist);
			if (!paramlist) {
				LM_ERR("oom\n");
				goto out_err;
			}
			memset(paramlist, 0, sizeof *paramlist);
			if (!lastp)
				url->params = paramlist;
			else
				lastp->next = paramlist;

			lastp = paramlist;

			paramlist->key.s = rec->s.s;
			ch = memchr(rec->s.s, '=', rec->s.len);
			if (ch) {
				if (ch == rec->s.s) {
					LM_ERR("empty \"key\" parameter part in URL %.*s\n",
					       in->len, in->s);
					goto out_err;
				}

				paramlist->val.len = rec->s.len - (ch + 1 - rec->s.s);
				paramlist->val.s = ch + 1;

				paramlist->key.len = ch - rec->s.s;
			} else {
				paramlist->key.len = rec->s.len;
			}
		}

		free_csv_record(params);
	}

	if (!url->params && (opts & URL_REQ_PARAMS)) {
		LM_ERR("missing \"parameters\" part in URL %.*s\n", in->len, in->s);
		goto out_err;
	}

	free_csv_record(hosts);
	free_csv_record(hosts_chunk);
	free_csv_record(hosts_db);

	if (pkg_dup && dup_pkg_fields(url) != 0) {
		LM_ERR("oom\n");
		free_url(url);
		return NULL;
	}

	return url;

out_err:
	free_csv_record(hosts);
	free_csv_record(hosts_chunk);
	free_csv_record(hosts_db);
	free_url(url);
	return NULL;
}

void free_url(struct url *url)
{
	struct url_host_list *host;
	struct url_param_list *params;

	if (!url)
		return;

	while (url->hosts) {
		host = url->hosts;
		url->hosts = url->hosts->next;
		pkg_free(host);
	}

	while (url->params) {
		params = url->params;
		url->params = url->params->next;
		pkg_free(params);
	}

	pkg_free(url);
}

void print_url(struct url *url)
{
	struct url_host_list *host;
	struct url_param_list *param;

	if (!url)
		return;

	LM_GEN1(L_DBG, ":::URL DEBUG\nscheme[%d]: '%.*s'\ngroup_name[%d]: '%.*s'\n"
	      "username[%d]: '%.*s'\npassword[%d]: '%.*s'\ndatabase[%d]: '%.*s'\n",
	      url->scheme.len, url->scheme.len, url->scheme.s, url->group_name.len,
	      url->group_name.len, url->group_name.s, url->username.len,
	      url->username.len,url->username.s, url->password.len,
	      url->password.len,url->password.s, url->database.len,
	      url->database.len, url->database.s);

	LM_GEN1(L_DBG, "== Hosts ==\n");
	for (host = url->hosts; host; host = host->next)
		LM_GEN1(L_DBG, "Host[%d]: '%.*s:%d'\n", host->host.len, host->host.len,
		        host->host.s, host->port);

	LM_GEN1(L_DBG, "== Params ==\n");
	for (param = url->params; param; param = param->next)
		LM_GEN1(L_DBG, "Param[%d]: '%.*s=%.*s'\n", param->key.len,
				param->key.len, param->key.s, param->val.len, param->val.s);
}
