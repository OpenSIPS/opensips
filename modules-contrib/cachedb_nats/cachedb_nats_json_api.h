/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * cachedb_nats_json_api.h -- the binds API through which other modules
 * (cachedb_nats_fts) reach the JSON walkers of cachedb_nats.
 *
 * cachedb_nats is opened with the default dlopen flags (no RTLD_GLOBAL),
 * so none of its symbols reach the global scope; a module that needs the
 * walkers resolves the exported "cdbn_json_bind" command with
 * find_export() and calls it.  This is the reverse direction of
 * cachedb_nats_fts_api.h.
 */

#ifndef CACHEDB_NATS_JSON_API_H
#define CACHEDB_NATS_JSON_API_H

typedef struct cdbn_json_api {
	/**
	 * Advance past JSON whitespace (impl: cdbn_skip_ws).
	 *
	 * @return The first non-whitespace byte at or after @p, or @end.
	 */
	const char *(*skip_ws)(const char *p, const char *end);

	/**
	 * Parse a JSON quoted string starting at its opening quote (impl:
	 * cdbn_parse_json_string).  Escapes are skipped, not decoded.
	 *
	 * @param out     Out: the first byte after the opening quote.
	 * @param out_len Out: the raw length up to the closing quote.
	 * @return A pointer past the closing quote, or NULL on malformed
	 *         input (*out and *out_len are then left unchanged).
	 */
	const char *(*parse_json_string)(const char *p, const char *end,
	                                 const char **out, int *out_len);

	/**
	 * Skip one JSON value of any type (impl: cdbn_skip_json_value).
	 *
	 * @return A pointer past the value, or NULL on malformed input.
	 */
	const char *(*skip_json_value)(const char *p, const char *end);
} cdbn_json_api_t;

/**
 * Prototype of cachedb_nats's exported "cdbn_json_bind" command: fills
 * @api with the walkers above (functions of cachedb_nats, valid for the
 * process lifetime; nothing to free).
 *
 * @param api Caller-owned struct to fill.
 * @return 0 on success (@api fully populated), -1 on NULL @api.
 *
 * Locking: none.  Context: any; cachedb_nats_fts calls it from its
 * mod_init (pre-fork).  It needs no part of cachedb_nats to be
 * initialised.
 */
typedef int (*cdbn_json_bind_f)(cdbn_json_api_t *api);

#endif /* CACHEDB_NATS_JSON_API_H */
