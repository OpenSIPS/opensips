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
 * An index entry whose key array cannot grow (out of SHM).  Replaces
 * tests/test_entry_add_key_oom.c, which made its own allocator fail;
 * here the UNIT_TESTS hook fts_ut_fail_grow fails the next growth.  An
 * entry starts with 8 keys inside its own block; the 9th moves them to a
 * separate array, later ones grow it.  When either growth fails the add
 * must fail and give back the reference it took on the key, or the key
 * stays interned with nobody to release it.  On private instances.
 */

#include <tap.h>
#include <stdio.h>
#include <string.h>

#include "../fts_index.h"
#include "../fts_intern.h"

#include "fts_ut.h"

#define DOC "{\"grp\":\"one\"}"   /* every key lands in one entry */

extern int fts_ut_fail_grow;
int fts_ut_entry_add_key(nats_idx_entry *e, const char *key, int klen);

static int add_nth(int n)
{
	char key[32];

	snprintf(key, sizeof key, "oom.%d", n);
	return nats_json_index_add(key, (int)strlen(key), DOC, (int)strlen(DOC));
}

static int add_key(nats_idx_entry *e, int n)
{
	char key[32];

	snprintf(key, sizeof key, "oom.%d", n);
	return fts_ut_entry_add_key(e, key, (int)strlen(key));
}

static void grow(void)
{
	nats_idx_entry *e;
	int i, all = 1, size;

	for (i = 0; i < NATS_IDX_KEYS_INLINE; i++)
		if (add_nth(i) != 0)
			all = 0;
	e = fts_find_entry("grp:one", 7);
	ok(all && e && e->num_keys == NATS_IDX_KEYS_INLINE && e->keys_inline,
		"entry_oom: %d keys fill the entry's own block", NATS_IDX_KEYS_INLINE);
	if (!e)
		return;

	size = nats_intern_size();
	fts_ut_fail_grow = 1;
	ok(add_key(e, 100) < 0 && e->keys_inline,
		"entry_oom: moving out of the block fails without SHM: -1");
	ok(nats_intern_size() == size,
		"entry_oom: and the key's intern reference is given back");
	ok(add_key(e, 100) == 0 && !e->keys_inline,
		"entry_oom: with SHM again the keys move to an array of their own");

	for (i = NATS_IDX_KEYS_INLINE + 1; i < 2 * NATS_IDX_KEYS_INLINE; i++)
		if (add_key(e, i) != 0)
			all = 0;
	ok(all && e->num_keys == 2 * NATS_IDX_KEYS_INLINE,
		"entry_oom: the array fills to %d", 2 * NATS_IDX_KEYS_INLINE);
	/* a whole document add whose key-list growth fails is reported, not
	 * silently counted as indexed (it used to return 0) */
	fts_ut_fail_grow = 1;
	ok(add_nth(300) == -1 && fts_ut_fail_grow == 0,
		"entry_oom: an index add that cannot list the key in an entry returns -1");

	size = nats_intern_size();
	fts_ut_fail_grow = 1;
	ok(add_key(e, 200) < 0 && nats_intern_size() == size &&
		e->num_keys == 2 * NATS_IDX_KEYS_INLINE,
		"entry_oom: a failed realloc of the array: -1, reference given back, keys kept");
	ok(add_key(e, 200) == 0, "entry_oom: and the entry still takes keys after it");
	ok(fts_ut_fail_grow == 0, "entry_oom: every injected failure was taken");
}

void fts_ut_entry_oom(void)
{
	nats_search_idx *live_idx = NULL;
	void *live_rev = NULL;
	void *live_intern;

	fts_ut_index_swap(&live_idx, &live_rev);
	live_intern = fts_ut_intern_swap(NULL);
	if (nats_intern_init(64) == 0 && nats_json_index_init() == 0)
		grow();
	else
		ok(0, "entry_oom: a private index");
	fts_ut_fail_grow = 0;
	nats_json_index_destroy();
	ok(nats_intern_size() == 0, "entry_oom: tearing the index down releases every key");
	nats_intern_destroy();
	fts_ut_index_swap(&live_idx, &live_rev);
	fts_ut_intern_swap(live_intern);
}
