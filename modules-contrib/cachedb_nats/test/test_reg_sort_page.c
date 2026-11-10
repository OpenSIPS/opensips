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
 * Registration-observability MI: nats_reg_list ordering + pagination.
 *
 *   sort=aor       lexicographic on the decoded AoR (the stable default)
 *   sort=expiry    soonest non-permanent expiry first; rows with NO
 *                  expiring contact (permanent-only) sort LAST ascending
 *                  (sentinel INT64_MAX), so "what dies next" tops the list
 *   sort=contacts  stored-contact count
 *   sort=last_mod  most-recent contact modification
 *   desc=1         reverses; ties then break by AoR both ways (stable,
 *                  deterministic pagination across repeated calls)
 *
 *   cdbn_reg_page(total, limit, offset): window clamps -- offset past the end
 *   yields an empty page, never an error; count never exceeds the remainder.
 *
 *                             order leaks out) and pagination has no
 * Runs on the production code (carried copies and the variant
 * build are gone).
 */
#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../cachedb_nats_reg.h"
#include "../cachedb_nats_json_internal.h"

#include "cn_ut.h"

#define CHECK(cond, msg) do { if (!(cond)) { fail("reg_sort_page: %s", msg); } \
	else pass("reg_sort_page: %s", msg); } while (0)

static int g_sort, g_desc;
static int qcmp(const void *a, const void *b)
{
	return cdbn_reg_row_cmp((const struct reg_row_info *)a,
	                    (const struct reg_row_info *)b, g_sort, g_desc);
}
static const char *order(struct reg_row_info *r, int n, int sort, int desc,
	char *buf)
{
	int i; char *p = buf;
	g_sort = sort; g_desc = desc;
	qsort(r, n, sizeof(*r), qcmp);
	for (i = 0; i < n; i++) {
		memcpy(p, r[i].aor, r[i].aor_len); p += r[i].aor_len;
		if (i + 1 < n) *p++ = ',';
	}
	*p = '\0';
	return buf;
}

void cn_ut_reg_sort_page(void)
{
	char buf[256];
	/* c: 2 contacts, dies first; a: permanent-only; b: 1 contact, dies later;
	 * d: same expiry as c (tie) -- deliberately inserted out of order. */
	#define ROWS { \
		{ .aor = "d@x", .aor_len = 3, .n_contacts = 1, .soonest_exp = 500, .last_mod = 90 }, \
		{ .aor = "a@x", .aor_len = 3, .n_contacts = 3, .soonest_exp = INT64_MAX, .last_mod = 10 }, \
		{ .aor = "c@x", .aor_len = 3, .n_contacts = 2, .soonest_exp = 500, .last_mod = 40 }, \
		{ .aor = "b@x", .aor_len = 3, .n_contacts = 1, .soonest_exp = 900, .last_mod = 70 }, \
	}

	diag("sort=aor (default) is lexicographic:");
	{ struct reg_row_info r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_AOR, 0, buf), "a@x,b@x,c@x,d@x") == 0,
	        "aor asc"); }
	{ struct reg_row_info r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_AOR, 1, buf), "d@x,c@x,b@x,a@x") == 0,
	        "aor desc"); }

	diag("sort=expiry: what dies next first; permanent-only LAST:");
	{ struct reg_row_info r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_EXPIRY, 0, buf), "c@x,d@x,b@x,a@x") == 0,
	        "expiry asc (c/d tie -> AoR asc; permanent-only a@x last)"); }
	{ struct reg_row_info r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_EXPIRY, 1, buf), "a@x,b@x,c@x,d@x") == 0,
	        "expiry desc reverses the key but ties stay AoR-asc (deterministic)"); }

	diag("sort=contacts / sort=last_mod:");
	{ struct reg_row_info r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_CONTACTS, 0, buf), "b@x,d@x,c@x,a@x") == 0,
	        "contacts asc (b/d tie at 1 -> AoR asc)"); }
	{ struct reg_row_info r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_LAST_MOD, 1, buf), "d@x,b@x,c@x,a@x") == 0,
	        "last_mod desc (most recently modified first)"); }

	diag("pagination window clamps:");
	{
		long s, c;
		cdbn_reg_page(10, 4, 0, &s, &c);
		CHECK(s == 0 && c == 4, "first page: [0,4)");
		cdbn_reg_page(10, 4, 8, &s, &c);
		CHECK(s == 8 && c == 2, "last partial page: count clamps to remainder");
		cdbn_reg_page(10, 4, 10, &s, &c);
		CHECK(c == 0, "offset == total: empty page, not an error");
		cdbn_reg_page(10, 4, 9999, &s, &c);
		CHECK(c == 0, "offset far past the end: empty page");
		cdbn_reg_page(0, 50, 0, &s, &c);
		CHECK(c == 0, "empty result set: empty page");
		cdbn_reg_page(3, 200, 0, &s, &c);
		CHECK(s == 0 && c == 3, "limit larger than total: whole set");
	}
}
