/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 */

/*
 * Evaluating CacheDB query filters against a stored JSON document, for
 * the queries the search index cannot answer (non-equality, integer
 * values, or no cachedb_nats_fts loaded): usrloc's NAT-pinging
 * "aorhash in [min, max)" range query among them.
 */

#ifndef CACHEDB_NATS_QUERY_FILTER_H
#define CACHEDB_NATS_QUERY_FILTER_H

#include "../../cachedb/cachedb.h"

/*
 * 1 if the top-level fields of the JSON object @json (@len bytes, not
 * NUL-terminated) satisfy every filter of the AND list @filter, else 0.
 * A missing field, a value of another type, a non-integer number for an
 * integer filter, or a malformed document never match.  Strings compare
 * bytewise on their decoded value; integers as 64-bit numbers.
 */
int cdbn_doc_matches(const char *json, int len, const cdb_filter_t *filter);

#endif
