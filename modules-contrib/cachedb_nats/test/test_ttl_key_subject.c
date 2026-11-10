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
 * /: one key→subject mapping, three
 * consumers.  Once we hand-build the JetStream subject for a raw publish, we own
 * the key→subject mapping — and it MUST be byte-identical to what the read path
 * (kvStore_Get) and the watcher derive, or a raw-published value lands on a
 * subject the reader never queries (silent split-brain: REGISTER "succeeds",
 * lookup returns nothing).
 *
 * cnats maps KV key K in bucket B to subject "$KV.<B>.<K>".  K is the already
 * encoded, KV-safe row key (no NATS-reserved bytes), so the subject is a
 * pure concatenation; the escaping correctness is the key encoder's job (proven
 * in test_kv_key_validate.c).  nats_kv_key_to_subject() centralizes it.
 *
 *   gcc ...               -> the byte-exact "$KV.<bucket>.<key>" => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the round-trip e2e — raw-publish then
 * kvStore_Get the same key and confirm a hit — vs production.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_key_subject test_ttl_key_subject.c
 */
#include <tap.h>
#include <stdio.h>
#include <string.h>
#include "../cachedb_nats_expiry.h"
#include "../cachedb_nats_json.h"

#include "cn_ut.h"


#define CHECK(cond, msg) do { if (!(cond)) { fail("ttl_key_subject: %s", msg); } \
	else pass("ttl_key_subject: %s", msg); } while (0)

static const char *subj(const char *bucket, const char *key)
{
	static char buf[512];
	return (nats_kv_key_to_subject(bucket, key, buf, sizeof buf) > 0) ? buf : "<err>";
}

void cn_ut_ttl_key_subject(void)
{

	diag("subject == \"$KV.<bucket>.<key>\" byte-exact:");
	CHECK(strcmp(subj("location", "usrloc.alice=40d"), "$KV.location.usrloc.alice=40d") == 0,
	      "location / usrloc.alice=40d");
	CHECK(strcmp(subj("opensips", "k1"), "$KV.opensips.k1") == 0, "opensips / k1");
	CHECK(strncmp(subj("location", "x"), "$KV.", 4) == 0, "always begins '$KV.'");

	diag("already-P1-encoded keys (=HH escapes) pass through verbatim:");
	CHECK(strcmp(subj("location", "usrloc.a=5Cb=40d"), "$KV.location.usrloc.a=5Cb=40d") == 0,
	      "escaped key (=5C backslash, =40 at) verbatim in subject");
	CHECK(strcmp(subj("location", "usrloc.alice.example.com"), "$KV.location.usrloc.alice.example.com") == 0,
	      "dotted (multi-token) key verbatim");

	diag("buffer-too-small fails cleanly (no overflow):");
	{ char small[8]; CHECK(nats_kv_key_to_subject("location", "averylongkey", small, sizeof small) == -1,
	      "too-small buffer => -1 (not truncated/overflowed)"); }
	{ char tight[20]; int n = nats_kv_key_to_subject("b", "k", tight, sizeof tight);
	  CHECK(n == 7 && strcmp(tight, "$KV.b.k") == 0, "reports the written length (7 = strlen '$KV.b.k')"); }

}
