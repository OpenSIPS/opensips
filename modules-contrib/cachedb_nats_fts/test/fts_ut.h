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
 * Unit test suite of the cachedb_nats_fts module: one entry point per
 * test file, all run from mod_tests() (test.c).  The search index and
 * the intern table are the module's live ones, so tests use keys of their
 * own and compare counts as deltas.
 */

#ifndef FTS_UT_H
#define FTS_UT_H

void fts_ut_index_count(void);
void fts_ut_intern_unit(void);
void fts_ut_intern_wiring(void);
void fts_ut_entry_blob_combine(void);
void fts_ut_fts_key_len(void);
void fts_ut_query(void);
void fts_ut_revmap(void);
void fts_ut_entry_oom(void);
void fts_ut_index_partial_snapshot(void);

/* puts `t` in place of this process's intern table, returns the old one */
void *fts_ut_intern_swap(void *t);
/* swaps this process's search index and reverse map with *idx, *rev */
struct _nats_search_idx;
void fts_ut_index_swap(struct _nats_search_idx **idx, void **rev);

/* fts_query.c (reached through the module's API table in production) */
struct cdb_filter;
int fts_query_match_keys(const struct cdb_filter *filter, char ***out_keys,
	int *out_count);
void fts_release_keyset(char **keys, int count);

#endif /* FTS_UT_H */
