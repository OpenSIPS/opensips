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
 * Unit tests of the cachedb_nats_fts module ("make test-cachedb_nats_fts").
 * The suite's opensips.cfg points cachedb_nats at a port nothing listens
 * on: it starts degraded, and the FTS index starts empty.
 */

#include <tap.h>

#include "fts_ut.h"

void mod_tests(void)
{
	fts_ut_index_count();
	fts_ut_intern_unit();
	fts_ut_intern_wiring();
	fts_ut_entry_blob_combine();
	fts_ut_fts_key_len();
	fts_ut_query();
	fts_ut_revmap();
	fts_ut_entry_oom();
	fts_ut_index_partial_snapshot();
}
