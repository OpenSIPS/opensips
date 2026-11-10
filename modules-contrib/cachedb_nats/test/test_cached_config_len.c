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
 * fts_json_prefix is a config constant, so mod_init measures it once
 * (init_check_params) and the usrloc read/write/serialize paths, the
 * watch loop and the reaper use the cached fts_json_prefix_len.  This
 * checks the cache matches the prefix the module actually runs with.
 * Replaces tests/test_cached_config_len.c, a source grep; its "no
 * strlen(fts_json_prefix) left in the hot TUs" half has no runtime
 * observable (LOST).
 */

#include <tap.h>
#include <string.h>

#include "cn_ut.h"

extern char *fts_json_prefix;
extern int fts_json_prefix_len;

void cn_ut_cached_config_len(void)
{
	int want = fts_json_prefix ? (int)strlen(fts_json_prefix) : 0;

	ok(fts_json_prefix != NULL && want > 0,
		"cached_config_len: the module runs with a prefix (default \"json_\")");
	ok(fts_json_prefix_len == want,
		"cached_config_len: fts_json_prefix_len == strlen(fts_json_prefix) after mod_init (%d vs %d)",
		fts_json_prefix_len, want);
}
