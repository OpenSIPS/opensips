/*
 * Copyright (c) 2026 OpenSIPS Project fuzzing effort
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_cjson - exercise the bundled cJSON library (lib/cJSON.c).
 *
 * Threat model:
 * - Untrusted input: JSON payloads reach opensips through cachedb backends,
 *   management-interface data and message payloads; peers of those surfaces
 *   can feed adversarial JSON to the parser.
 * - Trust boundary crossed: cJSON_Parse()/cJSON_ParseWithOpts() (parse),
 *   cJSON_Print()/cJSON_PrintUnformatted() (serialise), and the tree access
 *   helpers.
 * - Attacker controls: the whole document.
 * - Real bug here: heap overflows / use-after-free / double frees /
 *   leaks on adversarial JSON (deep nesting, huge exponents, invalid
 *   escapes, truncated documents).
 *
 * Design notes:
 * - classic bytes-into-parser plus a print->reparse round trip, which also
 *   drives the serialiser on parser-produced trees;
 * - input capped at 64 KiB and NUL-terminated (the cJSON API is
 *   NUL-oriented by design);
 * - every cJSON_Delete/free is paired, so LSan reports only genuine leaks;
 * - symbols are prefixed (CJSON_PREFIX defaults to os_ inside the header).
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/cJSON.h"

#include "../dprint.h"
#include "../globals.h"
#include "../cmds.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"
#include "../socket_info.h"
#include "../msg_translator.h"

#include "../test/fuzz/fuzz_standalone.h"

#define MAX_JSON_LEN (64 * 1024)

int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
	char *wbuf, *printed1, *printed2;
	cJSON *root, *reparsed, *item;
	const char *parse_end;

	if (size == 0 || size > MAX_JSON_LEN)
		return 0;

	wbuf = (char *)malloc(size + 1);
	assert(wbuf != NULL);
	memcpy(wbuf, data, size);
	wbuf[size] = '\0';

	root = cJSON_Parse(wbuf);
	if (root != NULL) {
		/* tree accessors on parser-produced trees */
		cJSON_GetArraySize(root);
		item = cJSON_GetArrayItem(root, 0);
		if (item == NULL)
			item = cJSON_GetObjectItem(root, "a");
		if (item != NULL)
			cJSON_GetArraySize(item);

		/* serialise, then re-parse and re-serialise: the round trip
		 * drives the printer on fresh trees and the parser on
		 * printer-produced text */
		printed1 = cJSON_PrintUnformatted(root);
		if (printed1 != NULL) {
			reparsed = cJSON_ParseWithOpts(printed1, &parse_end, 0);
			if (reparsed != NULL) {
				printed2 = cJSON_Print(reparsed);
				free(printed2);
				cJSON_Delete(reparsed);
			}
			free(printed1);
		}
		cJSON_Delete(root);
	}

	free(wbuf);
	return 0;
}
