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
 * Depth/coverage test for nats_handle_parse() -- the parser that turns an
 * untrusted "k=v;k=v" bind/persist config string into a nats_handle_t.
 * test_parser.c covers the happy path; this exercises every sub-parser branch
 * and every error path with adversarial input, asserting the SPECIFIC error
 * string (not merely "it failed"):
 *   - parse_bool: true/yes/on/1, false/no/off/0, and a bad value
 *   - parse_ack_policy / deliver_policy / replay_policy: all values + bad
 *   - parse_duration_ms: no-suffix ms, ms, s, m, h, d, and a bad value
 *   - parse_rfc3339_ns: Z, +HH:MM, -HH:MM, fractional seconds, and bad forms
 *   - parse_uint / parse_int: valid, bad, and the bound checks
 *     (ring_capacity pow2 / too-big, fetch_batch, fetch_timeout, sample_freq)
 *   - structural: missing '=', empty key, duplicate key, mutually-exclusive
 *     durable+ephemeral, missing required fields
 *   - hygiene: surrounding whitespace is trimmed
 *
 * Calls the module's real parser (../nats_handle_parse.c) in the
 * nats_consumer unit test suite (make test-nats_consumer).
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include "../nats_handle_parse.h"
#include "../nats_handle_registry.h"

#include "nc_ut.h"

#define OKV(cond, label) ok((cond), "parser_adversarial: %s", (label))

static nats_handle_t *P(const char *cfg, const char **err)
{
	str s; s.s = (char *)cfg; s.len = (int)strlen(cfg);
	*err = NULL;
	return nats_handle_parse(&s, err);
}

/* Expect parse failure whose error string contains @needle. */
static void BAD(const char *cfg, const char *needle)
{
	const char *e = NULL;
	nats_handle_t *h = P(cfg, &e);
	char label[256];
	snprintf(label, sizeof(label), "reject [%s] with '%s'", cfg, needle);
	OKV(h == NULL && e != NULL && strstr(e, needle) != NULL, label);
	if (h) nats_handle_free(h);
}

/* Expect parse success. */
static nats_handle_t *GOOD(const char *cfg)
{
	const char *e = NULL;
	nats_handle_t *h = P(cfg, &e);
	char label[256];
	snprintf(label, sizeof(label), "accept [%s]", cfg);
	OKV(h != NULL && e == NULL, label);
	return h; /* caller frees */
}

#define WITH(cfg, field, want, lbl) do { \
	nats_handle_t *h = GOOD(cfg); \
	if (h) { OKV(h->field == (want), lbl); nats_handle_free(h); } \
} while (0)

void nc_ut_parser_adversarial(void)
{
	/* ---- parse_bool: ephemeral (needs no durable) ---- */
	{
		nats_handle_t *h;
		const char *tv[] = {"true","yes","on","1"};
		const char *fv[] = {"false","no","off","0"};
		size_t i;
		char cfg[64];
		for (i = 0; i < 4; i++) {
			snprintf(cfg, sizeof(cfg), "id=x;stream=S;ephemeral=%s", tv[i]);
			h = GOOD(cfg);
			if (h) { OKV(h->type == NATS_CONSUMER_EPHEMERAL, tv[i]);
				nats_handle_free(h); }
		}
		for (i = 0; i < 4; i++) {
			/* ephemeral=false with no durable -> needs durable-or-ephemeral */
			snprintf(cfg, sizeof(cfg),
				"id=x;stream=S;durable=d;headers_only=%s", fv[i]);
			WITH(cfg, headers_only, 0, "headers_only false form");
		}
		BAD("id=x;stream=S;ephemeral=maybe", "invalid boolean");
		BAD("id=x;stream=S;durable=d;headers_only=2", "invalid boolean");
	}

	/* ---- ack_policy ---- */
	WITH("id=x;stream=S;durable=d;ack_policy=explicit", ack_policy,
		NATS_ACK_EXPLICIT, "ack_policy=explicit");
	WITH("id=x;stream=S;durable=d;ack_policy=none", ack_policy,
		NATS_ACK_NONE, "ack_policy=none");
	WITH("id=x;stream=S;durable=d;ack_policy=all", ack_policy,
		NATS_ACK_ALL, "ack_policy=all");
	BAD("id=x;stream=S;durable=d;ack_policy=bogus", "invalid ack_policy");

	/* ---- deliver_policy ---- */
	WITH("id=x;stream=S;durable=d;deliver_policy=all", deliver_policy,
		NATS_DELIVER_ALL, "deliver_policy=all");
	WITH("id=x;stream=S;durable=d;deliver_policy=new", deliver_policy,
		NATS_DELIVER_NEW, "deliver_policy=new");
	WITH("id=x;stream=S;durable=d;deliver_policy=last", deliver_policy,
		NATS_DELIVER_LAST, "deliver_policy=last");
	BAD("id=x;stream=S;durable=d;deliver_policy=sideways",
		"invalid deliver_policy");

	/* ---- replay_policy ---- */
	WITH("id=x;stream=S;durable=d;replay_policy=instant", replay_policy,
		NATS_REPLAY_INSTANT, "replay_policy=instant");
	WITH("id=x;stream=S;durable=d;replay_policy=original", replay_policy,
		NATS_REPLAY_ORIGINAL, "replay_policy=original");
	BAD("id=x;stream=S;durable=d;replay_policy=rewind", "invalid replay_policy");

	/* ---- parse_duration_ms: every unit ---- */
	WITH("id=x;stream=S;durable=d;ack_wait=750", ack_wait_ms, 750,
		"duration no-suffix => ms");
	WITH("id=x;stream=S;durable=d;ack_wait=500ms", ack_wait_ms, 500,
		"duration ms");
	WITH("id=x;stream=S;durable=d;ack_wait=5s", ack_wait_ms, 5000,
		"duration s");
	WITH("id=x;stream=S;durable=d;ack_wait=2m", ack_wait_ms, 120000,
		"duration m");
	WITH("id=x;stream=S;durable=d;ack_wait=1h", ack_wait_ms, 3600000,
		"duration h");
	WITH("id=x;stream=S;durable=d;inactive_threshold=1d",
		inactive_threshold_ms, 86400000, "duration d");
	BAD("id=x;stream=S;durable=d;ack_wait=abc", "invalid duration");
	BAD("id=x;stream=S;durable=d;ack_wait=5x", "invalid duration");

	/* ---- parse_rfc3339_ns: Z / +offset / -offset / fractional ---- */
	{
		nats_handle_t *h;
		h = GOOD("id=x;stream=S;durable=d;start_time=2026-07-02T12:00:00Z");
		if (h) nats_handle_free(h);
		h = GOOD("id=x;stream=S;durable=d;start_time=2026-07-02T12:00:00+02:00");
		if (h) nats_handle_free(h);
		h = GOOD("id=x;stream=S;durable=d;start_time=2026-07-02T12:00:00-05:30");
		if (h) nats_handle_free(h);
		h = GOOD("id=x;stream=S;durable=d;"
			"start_time=2026-07-02T12:00:00.123456789Z");
		if (h) nats_handle_free(h);
		h = GOOD("id=x;stream=S;durable=d;"
			"start_time=2026-07-02T12:00:00.5+01:30");
		if (h) nats_handle_free(h);
	}
	BAD("id=x;stream=S;durable=d;start_time=not-a-time",
		"invalid RFC3339 timestamp");
	BAD("id=x;stream=S;durable=d;start_time=2026-07-02T12:00:00",
		"invalid RFC3339 timestamp");          /* no Z/offset */
	BAD("id=x;stream=S;durable=d;start_time=2026-07-02T12:00:00Q",
		"invalid RFC3339 timestamp");          /* bad zone char */

	/* ---- parse_uint (start_seq / ring_capacity / fetch_*) ---- */
	WITH("id=x;stream=S;durable=d;start_seq=4294967296", start_seq,
		4294967296ULL, "start_seq beyond 32-bit");
	BAD("id=x;stream=S;durable=d;start_seq=-1", "invalid unsigned integer");
	BAD("id=x;stream=S;durable=d;start_seq=notnum", "invalid unsigned integer");
	WITH("id=x;stream=S;durable=d;ring_capacity=1024", ring_capacity, 1024u,
		"ring_capacity power of two");
	BAD("id=x;stream=S;durable=d;ring_capacity=1000",
		"power of two");                        /* not pow2 */
	BAD("id=x;stream=S;durable=d;ring_capacity=1", "power of two"); /* <2 */
	BAD("id=x;stream=S;durable=d;ring_capacity=131072", "maximum");
	BAD("id=x;stream=S;durable=d;fetch_batch=0", "fetch_batch out of range");
	BAD("id=x;stream=S;durable=d;fetch_batch=99999", "fetch_batch out of range");
	BAD("id=x;stream=S;durable=d;fetch_timeout_ms=0", "fetch_timeout_ms out of range");
	BAD("id=x;stream=S;durable=d;fetch_timeout_ms=120000",
		"fetch_timeout_ms out of range");

	/* ---- parse_int (max_deliver / sample_freq / rate_limit) ---- */
	WITH("id=x;stream=S;durable=d;max_deliver=7", max_deliver, 7,
		"max_deliver int");
	BAD("id=x;stream=S;durable=d;max_deliver=xx", "invalid integer");
	WITH("id=x;stream=S;durable=d;sample_freq=50", sample_freq, 50,
		"sample_freq in range");
	BAD("id=x;stream=S;durable=d;sample_freq=101", "sample_freq out of range");
	BAD("id=x;stream=S;durable=d;sample_freq=-5", "sample_freq out of range");

	/* ---- structural / required-field errors ---- */
	BAD("id=x;stream=S;durable=d;noequalshere", "malformed pair");
	BAD("id=x;stream=S;durable=d;=novalue", "malformed pair");   /* empty key */
	BAD("id=x;stream=S;durable=d;ack_wait=1s;ack_wait=2s", "duplicate key");
	BAD("id=x;stream=S;durable=d;ephemeral=1",
		"mutually exclusive");                  /* durable + ephemeral */
	BAD("stream=S;durable=d", "missing id");
	BAD("id=x;durable=d", "missing stream");
	BAD("id=x;stream=S", "requires either durable");   /* neither dur/eph */

	/* ---- hygiene: surrounding whitespace trimmed ---- */
	WITH("id=x;stream=S;durable=d;ack_wait= 5s ", ack_wait_ms, 5000,
		"value whitespace trimmed");

}
