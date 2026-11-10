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
 * What the shared pool asks libnats for at connect time: the no_randomize
 * modparam (server order), the reconnect buffer, and DNS SRV server URLs
 * (nats+srv:// and tls+srv://), which the nats module resolves itself (a
 * fake resolver here), so libnats only gets the plain URLs of the SRV
 * targets.
 *
 * The real pool (nats_pool.c) against the fake libnats of nats_ut_fake.c,
 * which records the options it receives.  Each scenario starts from a
 * pristine pool: nothing registered, no connection, default modparams.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../sr_module.h"
#include "../nats_pool.h"
#include "../nats_srv.h"

#include "nats_ut.h"
#include "nats_ut_fake.h"

/* ── no_randomize ───────────────────────────────────────────────── */

static int s_default_randomizes(void)
{
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_no_randomize == 0;
}

static int s_no_randomize_set(void)
{
	if (nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)1) != 0)
		return 0;
	if (nats_pool_register("nats://127.0.0.1:4222,nats://127.0.0.1:4223",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_no_randomize == 1;
}

static int s_no_randomize_zero(void)
{
	if (nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)0) != 0)
		return 0;
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_no_randomize == 0;
}

static int s_no_randomize_rejects(void)
{
	return nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)2) == -1
		&& nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)-1) == -1
		&& nats_pool_no_randomize_setter(STR_PARAM, (void *)"1") == -1
		&& nats_pool_no_randomize == 0;
}

static int s_no_randomize_or_merge(void)
{
	/* one module asks for it, another leaves it off: the shared
	 * connection keeps the requested order */
	return nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)1) == 0
		&& nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)0) == 0
		&& nats_pool_no_randomize == 1;
}

/* ── reconnect_buf_size ─────────────────────────────────────────── */

static int s_reconnect_buf_default(void)
{
	/* the libnats default, passed explicitly */
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_reconnect_buf == 8 * 1024 * 1024;
}

static int s_reconnect_buf_set(void)
{
	if (nats_pool_reconnect_buf_size_setter(INT_PARAM, (void *)(long)4096) != 0)
		return 0;
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_reconnect_buf == 4096;
}

static int s_reconnect_buf_rejects(void)
{
	/* 0 would mean "libnats default" to libnats: refused, not passed */
	return nats_pool_reconnect_buf_size_setter(INT_PARAM, (void *)(long)0) == -1
		&& nats_pool_reconnect_buf_size_setter(INT_PARAM, (void *)(long)-5) == -1
		&& nats_pool_reconnect_buf_size_setter(STR_PARAM, (void *)"4096") == -1
		&& nats_pool_reconnect_buf_size == 8 * 1024 * 1024;
}

static int s_reconnect_buf_merge(void)
{
	/* the first explicit value replaces the default (below it too);
	 * then the largest wins, in either order */
	return nats_pool_reconnect_buf_size_setter(INT_PARAM, (void *)(long)1000) == 0
		&& nats_pool_reconnect_buf_size == 1000
		&& nats_pool_reconnect_buf_size_setter(INT_PARAM, (void *)(long)5000) == 0
		&& nats_pool_reconnect_buf_size == 5000
		&& nats_pool_reconnect_buf_size_setter(INT_PARAM, (void *)(long)2000) == 0
		&& nats_pool_reconnect_buf_size == 5000;
}

/* ── SRV URLs ───────────────────────────────────────────────────── */

/* the nats module resolves SRV URLs itself (nats_srv.c): the fake resolver
 * answers _nats._tcp.example.test with two targets of two priorities,
 * fails for broken.test; libnats only ever sees plain URLs. */
static int n_srv_queries;
static int fake_resolve(const char *qname, nats_srv_rec *out, int max, void *ctx)
{
	(void)ctx;
	n_srv_queries++;
	if (!strcmp(qname, "_nats._tcp.example.test") && max >= 2) {
		out[0].priority = 20; out[0].weight = 10; out[0].port = 4223;
		snprintf(out[0].target, sizeof out[0].target, "n2.example.test.");
		out[1].priority = 10; out[1].weight = 10; out[1].port = 4222;
		snprintf(out[1].target, sizeof out[1].target, "n1.example.test.");
		return 2;
	}
	return -1;
}
#define EXP_NATS "nats://n1.example.test:4222,nats://n2.example.test:4223"

static int s_srv_any_libnats(void)
{
	/* no libnats SRV capability is needed any more */
	if (nats_pool_register("nats+srv://example.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, EXP_NATS) == 0
		&& nf.last_secure == -1;
}

static int s_srv_any_case(void)
{
	if (nats_pool_register("NATS+SRV://example.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && strcmp(nf.last_servers, EXP_NATS) == 0;
}

static int s_srv_in_list(void)
{
	/* expanded in place, after the plain URL listed before it */
	if (nats_pool_register("nats://127.0.0.1:4222, nats+srv://example.test",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://127.0.0.1:4222," EXP_NATS) == 0;
}

static int s_srv_merge(void)
{
	if (nats_pool_register("nats://127.0.0.1:4222", "first", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats+srv://example.test", "second", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://127.0.0.1:4222," EXP_NATS) == 0;
}

static int s_tls_srv_is_tls(void)
{
	if (nats_pool_register("tls+srv://example.test", "test", 2000, 3) != 0)
		return 0;
	/* no tls_mgm in this harness: the connect fails after SetSecure */
	(void)nats_pool_get();
	return nf.last_secure == 1
		&& strcmp(nf.last_servers, "tls://n1.example.test:4222,tls://n2.example.test:4223") == 0;
}

static int s_tls_srv_upper_is_tls(void)
{
	if (nats_pool_register("TLS+SRV://example.test", "test", 2000, 3) != 0)
		return 0;
	(void)nats_pool_get();
	return nf.last_secure == 1;
}

static int s_srv_userinfo_kept(void)
{
	/* a port or path is dropped with a warning; the user information
	 * goes to every target */
	if (nats_pool_register("nats+srv://u:p@example.test:4222/x", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && strcmp(nf.last_servers,
		"nats://u:p@n1.example.test:4222,nats://u:p@n2.example.test:4223") == 0;
}

static int s_srv_corrected_dedup(void)
{
	/* the corrected URL is a duplicate of one already listed: one lookup */
	n_srv_queries = 0;
	if (nats_pool_register("nats+srv://example.test,nats+srv://example.test:4222",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, EXP_NATS) == 0 && n_srv_queries == 1;
}

static int s_srv_spellings_dedup(void)
{
	n_srv_queries = 0;
	if (nats_pool_register("nats+srv://example.test/,NATS+SRV://example.test.",
	    "test", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats+srv://example.test", "second", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, EXP_NATS) == 0 && n_srv_queries == 1;
}

static int s_srv_lookup_fails_plain_stays(void)
{
	if (nats_pool_register("nats+srv://broken.test,nats://127.0.0.1:4222",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://127.0.0.1:4222") == 0
		&& strstr(nats_ut_log(), "nats+srv://broken.test") != NULL;
}

static int s_srv_lookup_fails_degraded(void)
{
	/* nothing resolvable: no connection, and has_servers() says "no
	 * usable server" so cachedb_nats starts degraded instead of failing */
	nf.n_connect = 0;
	if (nats_pool_register("nats+srv://u:s3cr3t@broken.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() == NULL && nf.n_connect == 0
		&& nats_pool_has_servers() == 0
		&& strstr(nats_ut_log(), "[redacted]@broken.test") != NULL
		&& strstr(nats_ut_log(), "s3cr3t") == NULL;
}

static int s_srv_lookup_retry_bounded(void)
{
	/* a failed lookup is not repeated on every call, only after the
	 * retry interval */
	n_srv_queries = 0;
	if (nats_pool_register("nats+srv://broken.test", "test", 2000, 3) != 0)
		return 0;
	(void)nats_pool_get();
	(void)nats_pool_get();
	(void)nats_pool_get();
	if (n_srv_queries != 1)
		return 0;
	nats_pool_srv_retry_s = 0;
	(void)nats_pool_get();
	return n_srv_queries == 2;
}

static int s_srv_keeps_rfc_order(void)
{
	/* libnats would shuffle the list and lose the RFC 2782 priority
	 * order: with an SRV URL in the list it is told to keep the order
	 * (the weighted choice already spread the processes) */
	if (nats_pool_register("nats+srv://example.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_no_randomize == 1;
}

static int s_plain_still_randomized(void)
{
	/* the negative control: plain URLs only, no_randomize unset */
	if (nats_pool_register("nats://127.0.0.1:4222,nats://127.0.0.1:4223",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_no_randomize == 0;
}

static int s_srv_no_randomize(void)
{
	/* the order handed to libnats follows nats_srv_order() */
	if (nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)1) != 0)
		return 0;
	if (nats_pool_register("nats+srv://example.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && strcmp(nf.last_servers, EXP_NATS) == 0
		&& nf.last_no_randomize == 1;
}

static int s_srv_unusable_skipped(void)
{
	/* no usable domain: skipped with a warning, the other servers stay */
	if (nats_pool_register("nats://127.0.0.1:4222,nats+srv://exa mple.test",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://127.0.0.1:4222") == 0;
}

static int s_srv_unusable_only(void)
{
	/* nothing usable left: startup goes on, NATS stays unavailable */
	if (nats_pool_register("nats+srv://exa%41mple.test", "test", 2000, 3) != 0)
		return 0;
	nf.n_connect = 0;
	return nats_pool_get() == NULL && nats_pool_get() == NULL && nf.n_connect == 0;
}

static int s_srv_warn_corrected_redacted(void)
{
	/* libnats takes all before the last '@' as credentials: none of it
	 * may reach the log, even past a '/' */
	if (nats_pool_register("nats+srv://u:s3cr3t@b/t41l@example.test:4222",
	    "test", 2000, 3) != 0)
		return 0;
	return strstr(nats_ut_log(), "nats+srv://[redacted]@example.test") != NULL
		&& !strstr(nats_ut_log(), "s3cr3t") && !strstr(nats_ut_log(), "t41l");
}

static int s_srv_warn_unusable_redacted(void)
{
	if (nats_pool_register("nats://127.0.0.1:4222,nats+srv://u:s3cr3t@b/t41l@bad dom",
	    "test", 2000, 3) != 0)
		return 0;
	return strstr(nats_ut_log(), "[redacted]@bad dom") != NULL
		&& !strstr(nats_ut_log(), "s3cr3t") && !strstr(nats_ut_log(), "t41l");
}

static int s_srv_unusable_only_quiet(void)
{
	/* warned once before forking: the processes asking for the
	 * connection afterwards do not log it again */
	if (nats_pool_register("nats+srv://exa%41mple.test", "test", 2000, 3) != 0)
		return 0;
	if (!strstr(nats_ut_log(), "no usable NATS server URL"))
		return 0;
	nats_ut_log_clear();
	return nats_pool_get() == NULL && nats_ut_log()[0] == '\0';
}

/* ── module defaults ────────────────────────────────────────────── */

/* A module whose nats_url is not set contributes its default URL only if
 * no module configures servers, whatever the module load order: a
 * localhost server must not join (or, if the DNS lookups fail, replace)
 * the servers another module configured. */

static int s_default_then_explicit(void)
{
	if (nats_pool_register_default("nats://127.0.0.1:4222", "event_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats+srv://example.test", "cachedb_nats", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, EXP_NATS) == 0;
}

static int s_explicit_then_default(void)
{
	if (nats_pool_register("nats+srv://example.test", "cachedb_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register_default("nats://127.0.0.1:4222", "event_nats", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, EXP_NATS) == 0;
}

static int s_defaults_only(void)
{
	if (nats_pool_register_default("nats://127.0.0.1:4222", "event_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register_default("nats://localhost:4222", "nats_consumer", 2000, 3) != 0)
		return 0;
	return nats_pool_is_registered()
		&& nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://127.0.0.1:4222") == 0;
}

static int s_default_explicit_default(void)
{
	if (nats_pool_register_default("nats://127.0.0.1:4222", "event_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats://n1:4222,nats://n2:4222", "cachedb_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register_default("nats://localhost:4222", "nats_consumer", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://n1:4222,nats://n2:4222") == 0;
}

static int s_explicits_merge_after_default(void)
{
	if (nats_pool_register_default("nats://127.0.0.1:4222", "event_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats://n1:4222", "cachedb_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats://n2:4222,nats://n1:4222", "nats_consumer", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(nf.last_servers, "nats://n1:4222,nats://n2:4222") == 0;
}

static int s_default_then_unusable_explicit(void)
{
	/* the configured URL is unusable: NATS stays unavailable, the
	 * default does not stand in for it */
	if (nats_pool_register_default("nats://127.0.0.1:4222", "event_nats", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats+srv://exa mple.test", "cachedb_nats", 2000, 3) != 0)
		return 0;
	nf.n_connect = 0;
	return nats_pool_get() == NULL && nf.n_connect == 0 && !nats_pool_has_servers();
}

static int s_has_servers(void)
{
	/* lets a module tell "no usable server configured" (degraded start)
	 * from a connect error with servers configured (TLS, auth: fatal) */
	if (nats_pool_has_servers())
		return 0;               /* nothing registered yet */
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_has_servers() == 1;
}

static int s_has_no_servers(void)
{
	if (nats_pool_register("nats+srv://exa%41mple.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_has_servers() == 0;
}

static int s_not_srv_needs_nothing(void)
{
	if (nats_pool_register("nats+srvx://example.test:4222,tls+srv:/x", "test",
	    2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && nf.last_secure == -1;
}

/* the scenarios below run with the fake resolver */
static nats_ut_scenario_f srv_scenario;

static int with_resolver(void)
{
	nats_pool_set_srv_resolver(fake_resolve, NULL);
	return srv_scenario();
}

static void run_srv(const char *name, nats_ut_scenario_f f)
{
	srv_scenario = f;
	nats_ut_run(name, with_resolver);
}

void nats_ut_pool_connect_opts(void)
{
	/* no_randomize */
	nats_ut_run("default: the server list is randomized", s_default_randomizes);
	nats_ut_run("no_randomize=1: libnats keeps the configured order", s_no_randomize_set);
	nats_ut_run("no_randomize=0: randomized", s_no_randomize_zero);
	nats_ut_run("values other than 0/1 and non-integers are rejected", s_no_randomize_rejects);
	nats_ut_run("any module asking for it turns it on (OR merge)", s_no_randomize_or_merge);

	/* reconnect_buf_size */
	nats_ut_run("default: the libnats 8 MB buffer, passed explicitly", s_reconnect_buf_default);
	nats_ut_run("reconnect_buf_size=4096 reaches libnats", s_reconnect_buf_set);
	nats_ut_run("values below 1 and non-integers are rejected", s_reconnect_buf_rejects);
	nats_ut_run("first explicit value replaces the default, then the max wins", s_reconnect_buf_merge);

	/* SRV URLs */
	run_srv("nats+srv:// works with any libnats (resolved in the nats module)", s_srv_any_libnats);
	run_srv("the scheme check is case-insensitive", s_srv_any_case);
	run_srv("an SRV URL in a list is expanded in place", s_srv_in_list);
	run_srv("an SRV URL from a later module is expanded too", s_srv_merge);
	run_srv("tls+srv:// turns TLS on and gives tls:// targets", s_tls_srv_is_tls);
	run_srv("TLS+SRV:// in upper case too", s_tls_srv_upper_is_tls);
	run_srv("port and path dropped; user information kept on every target", s_srv_userinfo_kept);
	run_srv("a corrected duplicate is looked up once", s_srv_corrected_dedup);
	run_srv("spellings of one SRV URL are looked up once", s_srv_spellings_dedup);
	run_srv("a failed lookup leaves the other servers", s_srv_lookup_fails_plain_stays);
	run_srv("only failed lookups: degraded start, URL redacted in the log", s_srv_lookup_fails_degraded);
	run_srv("a failed lookup is retried after the interval, not on every call", s_srv_lookup_retry_bounded);
	run_srv("no_randomize: the deterministic RFC 2782 order", s_srv_no_randomize);
	run_srv("an SRV URL in the list: libnats keeps the RFC 2782 order", s_srv_keeps_rfc_order);
	run_srv("plain URLs only: libnats still shuffles them", s_plain_still_randomized);
	run_srv("look-alike schemes are not SRV URLs", s_not_srv_needs_nothing);
	run_srv("SRV URL without a usable domain skipped, others kept", s_srv_unusable_skipped);
	run_srv("only unusable SRV URLs: startup goes on, no connection", s_srv_unusable_only);
	run_srv("only unusable SRV URLs: warned once, not per process",
		s_srv_unusable_only_quiet);
	run_srv("corrected SRV URL warning: no part of the password logged",
		s_srv_warn_corrected_redacted);
	run_srv("skipped SRV URL warning: no part of the password logged",
		s_srv_warn_unusable_redacted);
	run_srv("nats_pool_has_servers(): servers configured", s_has_servers);
	run_srv("nats_pool_has_servers(): none usable", s_has_no_servers);

	/* module defaults */
	run_srv("a default, then configured servers: the default is dropped",
		s_default_then_explicit);
	run_srv("configured servers, then a default: the default is not added",
		s_explicit_then_default);
	run_srv("defaults only: the first one is used", s_defaults_only);
	run_srv("default, configured, default: the configured servers only",
		s_default_explicit_default);
	run_srv("configured servers of several modules still merge",
		s_explicits_merge_after_default);
	run_srv("an unusable configured URL is not replaced by the default",
		s_default_then_unusable_explicit);

}
