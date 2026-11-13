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
 * Unit tests of the cachedb_nats module ("make test-cachedb_nats").  The
 * suite's opensips.cfg points the module at a port nothing listens on: it
 * starts degraded.
 */

#include <tap.h>
#include <string.h>

#include "../../../mem/mem.h"
#include "../../../cachedb/cachedb_types.h"
#include "cn_ut.h"

void mod_tests(void)
{
	cn_ut_all();
}

/* A pair laid out as cdb_mk_pair() lays it out -- key and subkey bytes
 * after the struct, so cdb_free_entries()' one pkg_free() releases it --
 * but filled with memcpy().  cdb_mk_pair() reads its key and subkey
 * through str2const()'s (str *) -> (str_const *) cast; inlined next to a
 * str the test has just filled on its stack, that type-punned read lets
 * clang -O3 drop the stores, and the pair gets stack bytes for a subkey. */
struct cdb_pair *cn_ut_mk_pair(const char *key, int klen,
	const char *subkey, int sklen)
{
	cdb_pair_t *p;

	if (!subkey)
		sklen = 0;
	p = pkg_malloc(sizeof *p + klen + sklen);
	if (!p)
		return NULL;
	memset(p, 0, sizeof *p);
	p->key.name.s = (char *)(p + 1);
	memcpy(p->key.name.s, key, klen);
	p->key.name.len = klen;
	if (subkey) {
		p->subkey.s = p->key.name.s + klen;
		memcpy(p->subkey.s, subkey, sklen);
		p->subkey.len = sklen;
	}
	p->val.type = CDB_NULL;
	return p;
}
