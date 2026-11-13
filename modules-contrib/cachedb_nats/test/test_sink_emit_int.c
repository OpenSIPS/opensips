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
 * cdbn_sink_emit_int: the per-field snprintf("%lld") parsed a format
 * string for every integer emitted into a row document (expires, cseq,
 * last_mod, q, methods, row_exp ... a dozen per REGISTER); it is now a
 * plain divide-loop.  Characterization against printf on the real sink:
 * every edge value must serialize to exactly what printf produces --
 * including INT64_MIN, whose naive negation is UB.  Added: many values
 * appended into one small sink (growth across appends).
 * Replaces tests/test_sink_emit_int.c; its "no snprintf left in
 * cdbn_sink_emit_int" source grep is LOST.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

static void emits_exactly(int64_t v)
{
	json_sink_t s;
	char want[32], *got = NULL;
	int want_len, got_len = -1, good = 0;

	want_len = snprintf(want, sizeof(want), "%" PRId64, v);
	if (cdbn_sink_init(&s, 8) == 0) {
		if (cdbn_sink_emit_int(&s, v) == 0)
			got = cdbn_sink_take(&s, &got_len);
		else
			pkg_free(s.buf);
	}
	good = got && got_len == want_len && memcmp(got, want, want_len) == 0;
	ok(good, "sink_emit_int: %" PRId64 " serializes as printf does (got len %d)",
		v, got_len);
	if (got)
		pkg_free(got);
}

void cn_ut_sink_emit_int(void)
{
	static const int64_t vals[] = {
		0, 1, -1, 9, 10, 99, 100, -100,
		1234567890, -1234567890,
		1783254616,               /* an epoch-second, the common case */
		INT64_MAX, INT64_MIN,
		INT64_MAX - 1, INT64_MIN + 1,
		INT32_MAX, (int64_t)INT32_MAX + 1, INT32_MIN, (int64_t)INT32_MIN - 1,
	};
	unsigned i;

	for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++)
		emits_exactly(vals[i]);

	{
		/* appended one after the other into one sink */
		json_sink_t s;
		char want[1024], *got = NULL;
		int w = 0, got_len = -1, rc = 0;

		if (cdbn_sink_init(&s, 8) == 0) {
			for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
				w += snprintf(want + w, sizeof(want) - w, "%" PRId64 ",", vals[i]);
				if (cdbn_sink_emit_int(&s, vals[i]) < 0 ||
						cdbn_sink_putc(&s, ',') < 0)
					rc = -1;
			}
			got = cdbn_sink_take(&s, &got_len);
		}
		ok(rc == 0 && got && got_len == w && memcmp(got, want, w) == 0,
			"sink_emit_int: %u values appended into one 8-byte sink (got len %d, want %d)",
			i, got_len, w);
		if (got)
			pkg_free(got);
	}
}
