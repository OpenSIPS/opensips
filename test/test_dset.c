/*
 * Copyright (C) 2026 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <stdio.h>
#include <string.h>
#include <tap.h>

#include "../dset.h"
#include "../mem/mem.h"

#include "test_dset.h"

/* enough branches to grow the branch array twice (at 4 and at 8) */
#define TEST_BRANCHES 9

/*
 * append_msg_branch() grows the branch array with pkg_realloc(), which may
 * move it.  Every branch keeps its URI in its own buffer, inside the array,
 * so after a move the branches already in the array must still point to
 * their own (moved) buffers, not to the old, freed array.
 */
static void test_dset_append_realloc(void)
{
	struct msg_branch br, *mb;
	char uris[TEST_BRANCHES][32];
	void *blockers[TEST_BRANCHES];
	long off;
	int i;

	clear_dset();

	for (i = 0; i < TEST_BRANCHES; i++) {
		memset(&br, 0, sizeof br);
		br.uri.len = snprintf(uris[i], sizeof uris[i],
			"sip:user%d@192.0.2.1:%d", i, 5060 + i);
		br.uri.s = uris[i];
		ok(append_msg_branch(&br) == 1, "dset-append-%d", i);

		/* occupy the memory after the array, so that it cannot
		 * grow in place and pkg_realloc() has to move it */
		blockers[i] = pkg_malloc(4096);
	}

	/* the last branch was added after the last move */
	mb = get_msg_branch(TEST_BRANCHES - 1);
	off = mb->uri.s - (char *)mb;

	for (i = 0; i < TEST_BRANCHES; i++) {
		mb = get_msg_branch(i);
		/* check the pointer first, so a stale one is never read */
		ok(mb && mb->uri.s - (char *)mb == off &&
			mb->uri.len == strlen(uris[i]) &&
			!memcmp(mb->uri.s, uris[i], mb->uri.len),
			"dset-realloc-keeps-uri-%d", i);
	}

	for (i = 0; i < TEST_BRANCHES; i++)
		if (blockers[i])
			pkg_free(blockers[i]);
	clear_dset();
}

void test_dset(void)
{
	test_dset_append_realloc();
}
