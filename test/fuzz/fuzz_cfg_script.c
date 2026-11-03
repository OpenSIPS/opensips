/*
 * Copyright (c) 2026 OpenSIPS Project fuzzing effort
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_cfg_script - exercise the opensips configuration-script frontend.
 *
 * Threat model:
 * - Untrusted input: the fuzz input is the text of an opensips.cfg script.
 *   Config files are admin-controlled in the classic deployment, but they
 *   are the single highest-value parsing surface of the proxy: everything a
 *   deployment does is compiled through this grammar at startup and on every
 *   reload, a crash/bug here is a full-proxy outage, and the same engine is
 *   re-entered by reload tooling and management paths.  History (both here
 *   and in sibling projects) shows grammar/lexer/expr-tree bugs are real.
 * - Trust boundary crossed: parse_opensips_cfg() (cfg_pp.c include
 *   flattening) -> the flex lexer (cfg.lex) -> the bison grammar (cfg.y):
 *   expression trees, route headers, string/int/bool/pv argument parsing,
 *   command lookups against core_cmds.
 * - Attacker controls: the whole script text.
 * - Real bug here: memory-safety violations in the lexer/parser/expr
 *   builders, grammar-stack blowups, leaks on error recovery.
 *
 * Design notes:
 * - mirrors main.c: fresh script-routes holder per iteration
 *   (new_sroutes_holder(0)), then parse_opensips_cfg() on a temp file, then
 *   best-effort fix_rls() (the reload flow in cfg_reload.c), then
 *   free_route_lists()+pkg_free();
 * - include_file/import_file and loadmodule directives are neutralised in
 *   the fuzz copy (same-length substitution): the fuzzer must not read
 *   arbitrary host files (e.g. /dev/zero -> infinite flatten loop) nor
 *   dlopen arbitrary system libraries; neither is part of the grammar
 *   surface under test;
 * - the preprocessor command line is NULL (that surface spawns processes
 *   by design and is not fuzzable);
 * - inputs are capped at 64 KiB; embedded NULs are rejected.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../cfg_pp.h"
#include "../route.h"

#include "../dprint.h"
#include "../globals.h"
#include "../cmds.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"
#include "../socket_info.h"
#include "../msg_translator.h"

#include "../test/fuzz/fuzz_standalone.h"

#define MAX_CFG_LEN (64 * 1024)

/* same-length neutralisation of file-loading / module-loading directives */
static void neutralise(char *buf, size_t len)
{
	static const char *dirs[] = { "include_file", "import_file",
		"loadmodule" };
	size_t i, d;
	char *p;

	for (d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
		size_t dl = strlen(dirs[d]);
		p = buf;
		while ((size_t)(p - buf) < len &&
		    (p = strstr(p, dirs[d])) != NULL) {
			for (i = 0; i < dl; i++)
				p[i] = 'x';
			p += dl;
		}
	}
}

int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
	static char wbuf[MAX_CFG_LEN + 1];
	char tmpl[] = "/tmp/fuzz_opensips_cfg_XXXXXX";
	struct os_script_routes *sr;
	int fd, rc;
	size_t i;

	if (size == 0 || size > MAX_CFG_LEN)
		return 0;

	for (i = 0; i < size; i++)
		if (data[i] == 0)
			return 0;

	memcpy(wbuf, data, size);
	wbuf[size] = '\0';
	neutralise(wbuf, size);

	fd = mkstemp(tmpl);
	assert(fd >= 0);
	rc = write(fd, wbuf, size);
	assert(rc == (int)size);
	close(fd);

	/* mirror main.c: script routes must exist before the parse */
	sr = new_sroutes_holder(0);
	assert(sr != NULL);
	sroutes = sr;

	parse_opensips_cfg(tmpl, NULL, NULL);
	/* best-effort: same fixup pass as the reload flow */
	fix_rls();

	free_route_lists(sr);
	pkg_free(sr);
	sroutes = NULL;

	unlink(tmpl);
	return 0;
}
