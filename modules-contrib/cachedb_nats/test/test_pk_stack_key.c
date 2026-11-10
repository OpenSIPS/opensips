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
 * The PK fast-path query builds its target key "<prefix><=HH-encoded AoR>"
 * into a caller's stack buffer, falling back to the heap only for a key
 * that cannot fit (cdbn_pk_target_key): typical keys are well under 100
 * bytes, and the old path paid two allocations per usrloc read.
 * On the real cdbn_pk_target_key with the module's prefix ("json_"),
 * incl. the exact stack/heap boundary (worst case = prefix + 3*len + 1).
 * Replaces tests/test_pk_stack_key.c: its carried copy (still keeping '\\'
 * literal) is gone; the source-pattern half (query_pk_fast_path uses the
 * helper, no pkg_malloc of the key) is LOST -- test_kv_key_validate.c
 * checks the helper encodes like the row key.
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

static void key_case(const char *label, const char *val, int len,
	int stackcap, int want_heap, const char *want)
{
	char stk[1024];
	int heap = -1;
	char *k;

	memset(stk, 'G', sizeof stk);
	k = cdbn_pk_target_key(val, len, stk, stackcap, &heap);
	ok(k && heap == want_heap && (heap ? k != stk : k == stk) &&
		(want ? !strcmp(k, want) : 1) && stk[stackcap] == 'G',
		"pk_stack_key: %s (heap %d, want %d)", label, heap, want_heap);
	if (k && heap)
		pkg_free(k);
}

void cn_ut_pk_stack_key(void)
{
	char big[600];
	int heap = -1;
	char stk[512];
	char *k;

	key_case("typical AoR on the stack, ':' '@' encoded", "sip:alice@biloxi", 16,
		512, 0, "json_sip=3Aalice=40biloxi");
	key_case("all-safe value verbatim", "abc-123_x", 9, 512, 0, "json_abc-123_x");
	key_case("backslash encoded", "a\\b", 3, 512, 0, "json_a=5Cb");
	key_case("empty value: prefix only", "", 0, 512, 0, "json_");

	/* worst case for 4 bytes: 5 + 12 + 1 = 18 */
	key_case("worst case == stack capacity: stack", "abcd", 4, 18, 0, "json_abcd");
	key_case("worst case one over the capacity: heap", "abcd", 4, 17, 1, "json_abcd");

	memset(big, '@', sizeof big);
	k = cdbn_pk_target_key(big, 600, stk, sizeof stk, &heap);
	ok(k && heap == 1 && k != stk && (int)strlen(k) == 5 + 600 * 3 &&
		!strncmp(k, "json_=40=40", 11),
		"pk_stack_key: oversized key falls back to the heap, fully encoded");
	if (k && heap)
		pkg_free(k);
}
