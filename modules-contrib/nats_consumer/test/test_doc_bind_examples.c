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
 */

/*
 * test_doc_bind_examples.c -- every bind string documented in
 * ../README.md and in the NATS overview (modules-contrib/nats/README.md) must be
 * accepted by the real bind parser.
 *
 * `opensips -C` does not run mod_init or the startup_route, so a bind
 * string with an unknown key passes a config check and only fails when
 * OpenSIPS starts.  This test extracts, from the ```opensips blocks of
 * those READMEs:
 *   - modparam("nats_consumer", "bind", "<cfg>")   -- used verbatim;
 *   - nats_consumer_bind("<cfg>")                  -- a script string,
 *     so "$$" is unescaped to "$" first;
 * and runs each through nats_handle_parse().
 *
 * The extractor itself is checked first against in-memory samples
 * (good and bad keys, "$$" escapes, a literal split across lines, an
 * empty literal, text outside a code block).
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_handle_registry.h"
#include "../nats_handle_parse.h"

#include "nc_ut.h"


#define CHECK(cond, ...) ok((cond), "doc_bind_examples: " __VA_ARGS__)

#define MAX_EX 64

typedef struct {
	char *cfg;   /* bind string, unescaped, malloc'd */
	int   line;  /* README line of the literal */
} bind_ex_t;

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	long n; char *buf; size_t got;
	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, n, f);
	buf[got] = '\0';
	fclose(f);
	return buf;
}

static int line_of(const char *text, const char *p)
{
	int l = 1;
	for (; text < p; text++)
		if (*text == '\n') l++;
	return l;
}

/* Copy the string literal starting at *q (which points at the opening
 * quote).  A literal that runs past the end of its line is returned as
 * NULL: OpenSIPS config strings cannot span lines.  With @script set,
 * "$$" becomes "$" (format-string escape). */
static char *take_literal(const char *q, int script)
{
	const char *e = q + 1;
	char *out, *o;

	while (*e && *e != '"' && *e != '\n')
		e++;
	if (*e != '"')
		return NULL;
	out = o = malloc(e - q);
	if (!out)
		return NULL;
	for (q++; q < e; q++) {
		if (script && q[0] == '$' && q[1] == '$')
			q++;
		*o++ = *q;
	}
	*o = '\0';
	return out;
}

/* Extract every bind string from the ```opensips blocks of @text.
 * A bind call whose argument is not one well-formed literal yields an
 * entry with cfg == NULL, so it is reported rather than skipped. */
static int extract(const char *text, bind_ex_t *ex, int max)
{
	static const char mp[] = "modparam(\"nats_consumer\", \"bind\",";
	static const char fn[] = "nats_consumer_bind(";
	const char *p = text, *block_end, *q;
	int n = 0;

	while ((p = strstr(p, "```opensips")) != NULL) {
		p = strchr(p, '\n');
		if (!p) break;
		block_end = strstr(p, "\n```");
		if (!block_end) break;
		for (q = p; q < block_end; q++) {
			int script;
			const char *a;

			if (strncmp(q, mp, sizeof(mp) - 1) == 0) {
				script = 0; a = q + sizeof(mp) - 1;
			} else if (strncmp(q, fn, sizeof(fn) - 1) == 0) {
				script = 1; a = q + sizeof(fn) - 1;
			} else {
				continue;
			}
			while (*a == ' ' || *a == '\t' || *a == '\n')
				a++;
			if (n == max) {
				CHECK(0, "more than %d bind examples: raise MAX_EX", max);
				return n;
			}
			ex[n].line = line_of(text, a);
			ex[n].cfg = (*a == '"') ? take_literal(a, script) : NULL;
			/* the call must close right after the one literal */
			if (ex[n].cfg) {
				const char *c = strchr(a + 1, '"') + 1;
				while (*c == ' ' || *c == '\t') c++;
				if (*c != ')') {
					free(ex[n].cfg);
					ex[n].cfg = NULL;
				}
			}
			n++;
			q = a;
		}
		p = block_end + 4;
	}
	return n;
}

static int parses(const char *cfg, const char **err)
{
	str s;
	nats_handle_t *h;

	*err = NULL;
	s.s = (char *)cfg;
	s.len = (int)strlen(cfg);
	h = nats_handle_parse(&s, err);
	if (!h)
		return 0;
	nats_handle_free(h);
	return 1;
}

static void free_all(bind_ex_t *ex, int n)
{
	int i;
	for (i = 0; i < n; i++)
		free(ex[i].cfg);
}

/* ── the extractor and parser behave as this test assumes ─────── */
static void self_check(void)
{
	bind_ex_t ex[8];
	const char *err;
	int n;

	const char *sample =
		"modparam(\"nats_consumer\", \"bind\", \"id=out;stream=S;durable=d\")\n"
		"```opensips title=\"t\"\n"
		"modparam(\"nats_consumer\", \"bind\",\n"
		"    \"id=a;stream=S;filter=$JS.x;durable=d\")\n"
		"startup_route {\n"
		"    nats_consumer_bind(\"id=b;stream=S;filter=$$JS.y;ephemeral=1\");\n"
		"    nats_consumer_bind(\"id=c;stream=S;subject=x.>;durable=d\");\n"
		"    nats_consumer_bind(\"id=d;stream=S;\n"
		"        durable=d\");\n"
		"    nats_consumer_bind(\n"
		"        \"id=e;stream=S;\" \"durable=d\");\n"
		"    nats_consumer_bind(\"\");\n"
		"}\n"
		"```\n";

	n = extract(sample, ex, 8);
	CHECK(n == 6, "extractor found %d bind strings in the sample, want 6"
		" (text outside a code block must be ignored)", n);
	if (n != 6) { free_all(ex, n); return; }

	CHECK(ex[0].cfg && strcmp(ex[0].cfg, "id=a;stream=S;filter=$JS.x;durable=d") == 0,
		"modparam literal on the next line, kept verbatim: got '%s'",
		ex[0].cfg ? ex[0].cfg : "(null)");
	CHECK(ex[0].line == 4, "modparam literal line %d, want 4", ex[0].line);
	CHECK(ex[1].cfg && strcmp(ex[1].cfg, "id=b;stream=S;filter=$JS.y;ephemeral=1") == 0,
		"script literal must unescape $$: got '%s'",
		ex[1].cfg ? ex[1].cfg : "(null)");
	CHECK(ex[2].cfg && !parses(ex[2].cfg, &err),
		"a bind string with an unknown key (subject=) must be rejected");
	CHECK(ex[3].cfg == NULL,
		"a literal spanning two lines must be reported, not joined");
	CHECK(ex[4].cfg == NULL,
		"adjacent literals (\"a\" \"b\") must be reported, not joined");
	CHECK(ex[5].cfg && !parses(ex[5].cfg, &err),
		"an empty bind string must be rejected");
	{
		int good;

		err = NULL;
		good = ex[1].cfg && parses(ex[1].cfg, &err);
		CHECK(good, "a valid ephemeral bind string must parse (err: %s)",
			err ? err : "-");
	}
	free_all(ex, n);
}

/* ── every documented example parses ─────────────────────────── */
static void readme_examples(const char *path, int min)
{
	bind_ex_t ex[MAX_EX];
	const char *err;
	char *text = slurp(path);
	int n, i;

	CHECK(text != NULL, "%s can be read", path);
	if (!text)
		return;
	n = extract(text, ex, MAX_EX);
	CHECK(n >= min, "found only %d bind examples in %s", n, path);
	for (i = 0; i < n; i++) {
		CHECK(ex[i].cfg != NULL,
			"%s:%d: bind argument is not one single-line "
			"string literal", path, ex[i].line);
		if (ex[i].cfg) {
			/* parse first: ok() evaluates its message arguments too,
			 * in no set order, and err is set by the parse */
			int good;

			err = NULL;
			good = parses(ex[i].cfg, &err);
			CHECK(good, "%s:%d: bind string accepted (%s): %s",
				path, ex[i].line, good ? "ok" : (err ? err : "?"), ex[i].cfg);
		}
	}
	diag("checked %d documented bind strings in %s", n, path);
	free_all(ex, n);
	free(text);
}

void nc_ut_doc_bind_examples(void)
{
	self_check();
	/* the suite runs in the repository root (opensips -T ... -w .) */
	readme_examples("modules-contrib/nats_consumer/README.md", 5);
	readme_examples("modules-contrib/nats/README.md", 1);
}
