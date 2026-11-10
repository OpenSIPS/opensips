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
 * The cachedb_funcs._remove slot (delete a federation-metadata entry):
 * usrloc full-sharing never calls it, but a wrong-mode deployment that did
 * would dispatch through a NULL pointer and crash, so cachedb_nats
 * registers a non-NULL "unsupported" stub that fails loudly (-1).
 * On the engine the module registered with the core (lookup_cachedb
 * "nats"): the slot is the stub, and calling it returns -1 for any
 * argument shape without touching them (NULLs, empty, backslash,
 * embedded NUL).  Replaces tests/test_remove_stub.c (its carried types,
 * stub and REMOVE_CURRENT variant are gone).
 */

#include <tap.h>

#include "../../../str.h"
#include "../../../cachedb/cachedb.h"
#include "../cachedb_nats.h"

#include "cn_ut.h"

cachedb_engine *lookup_cachedb(str *name);

void cn_ut_remove_stub(void)
{
	str name = str_init("nats");
	cachedb_engine *cde = lookup_cachedb(&name);
	int (*rm)(cachedb_con *, str *, const str *) = cde ? cde->cdb_func._remove : NULL;
	str attr = str_init("aor"), key = str_init("meta"), empty = { "", 0 };
	str bslash = { "a\\b\\c=d", 7 }, embnul = { "a\0b.c", 5 }, neg = { NULL, -1 };

	ok(cde != NULL, "remove_stub: the \"nats\" cachedb engine is registered");
	ok(rm != NULL, "remove_stub: its _remove slot is non-NULL (no latent NULL call)");
	ok(rm == nats_cache_remove_unsupported, "remove_stub: _remove is the unsupported stub");
	skip(!rm, 6, "no _remove");
	ok(rm((cachedb_con *)0x1, &attr, &key) == -1, "remove_stub: populated args => -1");
	ok(rm(NULL, NULL, NULL) == -1, "remove_stub: NULL con/attr/key => -1 (no deref)");
	ok(rm(NULL, &empty, NULL) == -1, "remove_stub: empty attr => -1");
	ok(rm(NULL, &bslash, NULL) == -1, "remove_stub: backslash/special-char attr => -1");
	ok(rm(NULL, &embnul, &embnul) == -1, "remove_stub: embedded NUL attr/key => -1");
	ok(rm(NULL, &neg, &neg) == -1, "remove_stub: negative len, NULL s => -1 (no read)");
	end_skip;
}
