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
 * Read `last_mod` as int64.
 *
 * The shared converter cdb_json_to_dict (cachedb/cachedb_dict.c:556-559) turns
 * every cJSON_Number into CDB_INT32 via cJSON's `valueint`, which cJSON CLAMPS
 * to INT_MAX/INT_MIN.  `last_mod` is a usrloc CDB_INT64 (read as i64 at
 * udomain.c:211), so a value > INT32_MAX silently narrows to 2147483647 on read
 * — the round-trip is not byte-exact.  Option A: cachedb_nats re-parses
 * `last_mod` as int64 from the raw row JSON and overwrites the clamped value.
 *
 * Only `last_mod` gets the int64 guarantee; `expires` is CDB_INT32 at
 * the usrloc boundary and re-clamps the instant usrloc consumes it, so its
 * Y2038 overflow is an accepted usrloc-wide limitation, not asserted here.
 *
 * On the real cdbn_contact_field_int64 (cachedb_nats_json_rowmeta.c); the
 * carried walkers/parser and the LASTMOD_CURRENT clamp model are gone.
 * Added: int64 overflow is refused (absent, not wrapped), INT64_MIN, and
 * the slice end is honoured (a last_mod past vend is not found).
 */

#include <tap.h>
#include <stdint.h>
#include <string.h>

#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

/* What the read path yields for last_mod: Option A (int64) vs today's clamp. */
/* found: 1 and the int64 in *v; absent or not an integer: 0 */
static int lastmod_read(const char *contact, int64_t *v)
{
	*v = 0;
	return cdbn_contact_field_int64(contact, contact + strlen(contact),
		"last_mod", 8, v) == 0;
}

#define EXPECT(contact, want, msg) do { \
	int64_t _g; \
	int _f = lastmod_read(contact, &_g); \
	ok(_f && _g == (want), "last_mod_int64: %s (found %d, got %lld want %lld)", \
		msg, _f, (long long)_g, (long long)(want)); } while (0)
#define EXPECT_ABSENT(contact, msg) do { \
	int64_t _g; \
	int _f = lastmod_read(contact, &_g); \
	ok(!_f, "last_mod_int64: %s (found %d, got %lld)", msg, _f, (long long)_g); \
	} while (0)

void cn_ut_last_mod_int64(void)
{

	diag("values within int32 round-trip either way:");
	EXPECT("{\"cseq\":1,\"last_mod\":1000,\"ua\":\"x\"}", 1000LL, "small last_mod preserved");
	EXPECT("{\"last_mod\":2147483647}", 2147483647LL, "INT32_MAX preserved (boundary)");
	EXPECT("{\"last_mod\":0}", 0LL, "zero preserved");
	EXPECT("{\"last_mod\":-2147483648}", -2147483648LL, "INT32_MIN preserved (boundary)");

	/* The assertions below are CONSTANT (always the true int64) so the
	 * int32-clamp arm genuinely FAILS them (RED). */
	diag("> INT32_MAX must survive (RED under the shared clamp):");
	EXPECT("{\"last_mod\":2147483648}", 2147483648LL, "INT32_MAX+1 preserved");
	EXPECT("{\"last_mod\":5000000000}", 5000000000LL, "5e9 (post-2038 ms epoch) preserved");
	EXPECT("{\"last_mod\":-5000000000}", -5000000000LL, "-5e9 preserved");

	diag("huge int64 last_mod preserved (RED under the shared clamp):");
	EXPECT("{\"last_mod\":1099511627776}", 1099511627776LL, "2^40 preserved");
	EXPECT("{\"last_mod\":9223372036854775807}", 9223372036854775807LL, "INT64_MAX preserved");

	diag("extraction correctness (field position, neighbours):");
	EXPECT("{\"ua\":\"a\",\"expires\":2000,\"last_mod\":5000000001,\"cseq\":7}",
	       5000000001LL,
	       "last_mod found among other fields (and > INT32_MAX preserved)");
	/* expires must NOT be confused with last_mod */
	EXPECT("{\"expires\":5000000000,\"last_mod\":42}", 42LL, "expires not mistaken for last_mod");

	diag("adversarial: missing / non-integer last_mod => absent sentinel:");
	EXPECT_ABSENT("{\"cseq\":1,\"ua\":\"x\"}", "absent last_mod => not found");
	EXPECT_ABSENT("{\"last_mod\":\"123\"}", "string last_mod => not an integer");
	EXPECT_ABSENT("{\"last_mod\":null}", "null last_mod => not an integer");

	diag("adversarial: int64 bounds and the slice end:");
	EXPECT("{\"last_mod\":-9223372036854775808}", INT64_MIN, "INT64_MIN preserved");
	EXPECT_ABSENT("{\"last_mod\":9223372036854775808}", "INT64_MAX+1 refused, not wrapped");
	EXPECT_ABSENT("{\"last_mod\":-9223372036854775809}", "INT64_MIN-1 refused, not wrapped");
	EXPECT_ABSENT("{\"last_mod\":99999999999999999999}", "20 digits refused");
	EXPECT_ABSENT("{\"last_mod\":-}", "lone '-' is not an integer");
	{
		/* the contact ends at vend; what follows in the buffer is not it */
		const char buf[] = "{\"cseq\":1}{\"last_mod\":7}";
		int64_t v = 0;
		int rc = cdbn_contact_field_int64(buf, buf + 10, "last_mod", 8, &v);
		ok(rc == -1, "last_mod_int64: a field past the slice end is not found (rc=%d)", rc);
	}
}
