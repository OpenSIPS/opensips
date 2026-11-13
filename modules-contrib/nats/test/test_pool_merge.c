/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 * The server list of the shared pool: each registration gives a
 * comma-separated URL string; surrounding blanks and empty entries are
 * dropped, a URL already listed is not added again (inside one string or
 * by a later module), one tls:// URL turns TLS on, and at most 16 servers
 * are kept -- more is an error for the first registration and ignored
 * with a warning for the later ones.
 *
 * The real nats_pool_register() / nats_pool_get(); the list is read from
 * what the fake libnats (nats_ut_fake.c) receives in SetServers.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

#define MAX_SERVERS 16

static int reg(const char *url, const char *module)
{
	return nats_pool_register(url, module, 2000, 3);
}

/* "nats://h<from>:1,...,nats://h<to>:1" */
static const char *hosts(int from, int to)
{
	static char buf[2][512];
	static int which;
	char *b = buf[which ^= 1];
	size_t used = 0;
	int i;

	b[0] = '\0';
	for (i = from; i <= to; i++)
		used += (size_t)snprintf(b + used, sizeof(buf[0]) - used,
			"%snats://h%d:1", i == from ? "" : ",", i);
	return b;
}

static int s_blanks_and_empty_entries(void)
{
	return reg(" nats://h1:4222 , , nats://h2:4222 ,\t", "test") == 0
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://h1:4222,nats://h2:4222") == 0
		&& nf.last_secure == -1;
}

static int s_only_separators(void)
{
	return reg(" , ,\t,", "test") == -1 && !nats_pool_is_registered()
		&& reg("", "test") == -1 && reg(NULL, "test") == -1;
}

static int s_duplicate_in_one_string(void)
{
	return reg("nats://h1:1,nats://h1:1,nats://h2:1", "test") == 0
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://h1:1,nats://h2:1") == 0;
}

static int s_duplicate_across_modules(void)
{
	return reg("nats://h1:1,nats://h2:1", "first") == 0
		&& reg("nats://h2:1,nats://h3:1", "second") == 0
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers,
			"nats://h1:1,nats://h2:1,nats://h3:1") == 0;
}

static int s_urls_compared_exactly(void)
{
	/* a backslash, a different case or a trailing slash is another URL:
	 * nothing is normalized for plain URLs */
	return reg("nats://h1:1,nats://H1:1,nats://h1:1/,nats://h1\\:1",
			"test") == 0
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers,
			"nats://h1:1,nats://H1:1,nats://h1:1/,nats://h1\\:1") == 0;
}

static int s_tls_url_turns_tls_on(void)
{
	/* no tls_mgm in this suite: the connect stops at the TLS setup,
	 * after SetSecure */
	if (reg("nats://h1:1,tls://h2:1", "test") != 0)
		return 0;
	(void)nats_pool_get();
	return nf.last_secure == 1;
}

static int s_tls_url_from_later_module(void)
{
	if (reg("nats://h1:1", "first") != 0 || reg("tls://h2:1", "second") != 0)
		return 0;
	(void)nats_pool_get();
	return nf.last_secure == 1;
}

static int s_sixteen_fit(void)
{
	return reg(hosts(1, MAX_SERVERS), "test") == 0
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers, hosts(1, MAX_SERVERS)) == 0;
}

static int s_first_registration_overflow_refused(void)
{
	/* nothing of the refused list stays behind */
	return reg(hosts(1, MAX_SERVERS + 1), "test") == -1
		&& !nats_pool_is_registered() && !nats_pool_has_servers()
		&& strstr(nats_ut_log(), "too many NATS servers") != NULL;
}

static int s_later_registration_overflow_ignored(void)
{
	return reg(hosts(1, MAX_SERVERS), "first") == 0
		&& reg("nats://extra1:1,nats://extra2:1", "second") == 0
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers, hosts(1, MAX_SERVERS)) == 0
		&& strstr(nats_ut_log(), "max servers reached") != NULL;
}

static int s_later_registration_fills_to_the_cap(void)
{
	/* 15 + 3: the first of the three still fits */
	if (reg(hosts(1, MAX_SERVERS - 1), "first") != 0
	    || reg(hosts(MAX_SERVERS, MAX_SERVERS + 2), "second") != 0
	    || nats_pool_get() == NULL)
		return 0;
	return strcmp(nf.last_servers, hosts(1, MAX_SERVERS)) == 0;
}

static int s_reconnect_values_largest_win(void)
{
	return nats_pool_register("nats://h1:1", "first", 1000, 3) == 0
		&& nats_pool_register("nats://h1:1", "second", 3000, 2) == 0
		&& nats_pool_register("nats://h1:1", "third", 2000, 0) == 0
		&& nats_pool_get() != NULL
		&& nf.last_reconnect_wait == 3000;
}

void nats_ut_pool_merge(void)
{
	nats_ut_run("blanks and empty entries are dropped",
		s_blanks_and_empty_entries);
	nats_ut_run("a string without any URL is refused", s_only_separators);
	nats_ut_run("a URL listed twice in one string is kept once",
		s_duplicate_in_one_string);
	nats_ut_run("a later module adds only the servers not yet listed",
		s_duplicate_across_modules);
	nats_ut_run("URLs are compared byte for byte", s_urls_compared_exactly);
	nats_ut_run("one tls:// URL in the list turns TLS on",
		s_tls_url_turns_tls_on);
	nats_ut_run("a tls:// URL from a later module turns TLS on",
		s_tls_url_from_later_module);
	nats_ut_run("16 servers fit", s_sixteen_fit);
	nats_ut_run("first registration with 17 servers: refused, nothing kept",
		s_first_registration_overflow_refused);
	nats_ut_run("later registration past 16 servers: ignored with a warning",
		s_later_registration_overflow_ignored);
	nats_ut_run("later registration: servers are added up to the 16th",
		s_later_registration_fills_to_the_cap);
	nats_ut_run("reconnect_wait: the largest value of the modules wins",
		s_reconnect_values_largest_win);
}
