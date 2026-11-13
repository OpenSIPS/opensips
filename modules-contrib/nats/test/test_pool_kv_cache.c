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
 * The KV handles of the shared pool: one per bucket, bound once and
 * handed out again from a per-process cache of 16; the handles are the
 * pool's to destroy, so a bucket that does not fit the cache is refused
 * instead of handed out uncached (the callers never destroy a handle:
 * each call would bind and leak another one).  After a reconnect the
 * cached handles are destroyed and bound again.
 *
 * The real pool (nats_pool.c) against the fake libnats of nats_ut_fake.c.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../nats_pool.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

static int open_js(void)
{
	return nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) == 0
		&& nats_pool_get_js() != NULL;
}

static kvStore *bucket(int i)
{
	char name[32];

	snprintf(name, sizeof name, "bucket_%d", i);
	return nats_pool_get_kv(name, 1, 1, 0);
}

static int s_bound_once(void)
{
	kvStore *a, *b;

	if (!open_js())
		return 0;
	a = nats_pool_get_kv("users", 1, 1, 0);
	b = nats_pool_get_kv("users", 1, 1, 0);
	return a != NULL && a == b && nf.n_kv_bind == 1 && nf.n_kv_create == 0;
}

static int s_missing_bucket_created(void)
{
	nf.kv_bind_status = NATS_NOT_FOUND;
	return open_js() && nats_pool_get_kv("users", 3, 5, 60) != NULL
		&& nf.n_kv_create == 1
		/* and cached like a bound one */
		&& nats_pool_get_kv("users", 3, 5, 60) != NULL
		&& nf.n_kv_create == 1;
}

static int s_cache_full_refused_not_leaked(void)
{
	int i;

	if (!open_js())
		return 0;
	for (i = 0; i < NATS_POOL_MAX_KV_BUCKETS; i++)
		if (!bucket(i))
			return 0;
	if (nf.n_kv_bind != NATS_POOL_MAX_KV_BUCKETS || nf.n_kv_destroy != 0)
		return 0;
	/* the 17th: bound, then destroyed and refused -- every time */
	for (i = 1; i <= 3; i++)
		if (bucket(100) != NULL
		    || nf.n_kv_bind != NATS_POOL_MAX_KV_BUCKETS + i
		    || nf.n_kv_destroy != i)
			return 0;
	/* the cached ones are still handed out, without a bind */
	return bucket(0) != NULL && bucket(NATS_POOL_MAX_KV_BUCKETS - 1) != NULL
		&& nf.n_kv_bind == NATS_POOL_MAX_KV_BUCKETS + 3
		&& strstr(nats_ut_log(), "KV bucket cache full") != NULL;
}

static int s_reconnect_rebinds(void)
{
	if (!open_js() || !bucket(1) || !bucket(2) || nf.n_kv_bind != 2)
		return 0;
	nf.reconnected_cb(nats_pool_get(), NULL);
	/* the old handles are destroyed, not dropped */
	return bucket(1) != NULL && nf.n_kv_destroy == 2 && nf.n_kv_bind == 3
		&& bucket(1) != NULL && nf.n_kv_bind == 3;
}

static int s_disconnect_rebinds(void)
{
	if (!open_js() || !bucket(1))
		return 0;
	nf.disconnected_cb(nats_pool_get(), NULL);
	return bucket(1) != NULL && nf.n_kv_destroy == 1 && nf.n_kv_bind == 2;
}

static int s_bad_names(void)
{
	char longest[128], too_long[129];

	memset(longest, 'b', sizeof longest - 1);
	longest[sizeof longest - 1] = '\0';
	memset(too_long, 'b', sizeof too_long - 1);
	too_long[sizeof too_long - 1] = '\0';
	/* a name cut to fit the cache key would collide with another one */
	return open_js()
		&& nats_pool_get_kv(NULL, 1, 1, 0) == NULL
		&& nats_pool_get_kv("", 1, 1, 0) == NULL
		&& nats_pool_get_kv(too_long, 1, 1, 0) == NULL
		&& nf.n_kv_bind == 0
		&& nats_pool_get_kv(longest, 1, 1, 0) != NULL;
}

static int s_no_connection_no_handle(void)
{
	/* not registered: no JetStream context, no bind */
	return nats_pool_get_kv("users", 1, 1, 0) == NULL && nf.n_kv_bind == 0;
}

static int s_reconnect_log_without_url(void)
{
	/* libnats could not tell the URL and left the buffer alone: the
	 * line ends after "to", nothing of the stack is logged */
	char raw[512];
	size_t n;

	if (!open_js())
		return 0;
	nats_ut_log_clear();
	nf.connurl_status = NATS_CONNECTION_CLOSED;
	nf.reconnected_cb(nats_pool_get(), NULL);
	n = nats_ut_log_raw(raw, sizeof raw);
	return n == strlen("NATS pool: reconnected to \n")
		&& memcmp(raw, "NATS pool: reconnected to \n", n) == 0;
}

static int s_reconnect_log_redacted(void)
{
	if (!open_js())
		return 0;
	nats_ut_log_clear();
	nf.connurl = "nats://bob:s3cr3t@n1.example.test:4222";
	nf.reconnected_cb(nats_pool_get(), NULL);
	return strstr(nats_ut_log(), "[redacted]@n1.example.test:4222") != NULL
		&& strstr(nats_ut_log(), "s3cr3t") == NULL;
}

void nats_ut_pool_kv_cache(void)
{
	nats_ut_run("a bucket is bound once and then served from the cache",
		s_bound_once);
	nats_ut_run("a bucket that does not exist is created, then cached",
		s_missing_bucket_created);
	nats_ut_run("17th bucket: its handle is destroyed and the call refused",
		s_cache_full_refused_not_leaked);
	nats_ut_run("after a reconnect the handles are destroyed and bound again",
		s_reconnect_rebinds);
	nats_ut_run("after a disconnect too", s_disconnect_rebinds);
	nats_ut_run("NULL, empty and over-long bucket names are refused",
		s_bad_names);
	nats_ut_run("no handle without a registered pool", s_no_connection_no_handle);
	nats_ut_run("reconnect log line when libnats gives no URL",
		s_reconnect_log_without_url);
	nats_ut_run("reconnect log line: credentials of the URL redacted",
		s_reconnect_log_redacted);
}
