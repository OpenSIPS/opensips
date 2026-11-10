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
 * cachedb_nats_fmt.c — table formatter.
 * Pure logic, unit-locked in test/test_fmt_table.c (carried copies must
 * stay byte-identical to this file).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cachedb_nats_fmt.h"

static int fmt_put(struct fmt_table *t, const char *p, int n)
{
	if (t->oom)
		return -1;
	if (t->len + n + 1 > t->cap) {
		int ncap = t->cap ? t->cap : 256;
		char *nb;
		while (t->len + n + 1 > ncap)
			ncap *= 2;
		nb = realloc(t->buf, ncap);
		if (!nb) { t->oom = 1; return -1; }
		t->buf = nb;
		t->cap = ncap;
	}
	memcpy(t->buf + t->len, p, n);
	t->len += n;
	t->buf[t->len] = '\0';
	return 0;
}

static void fmt_eol(struct fmt_table *t)
{
	if (t->eol_lf)
		fmt_put(t, "\n", 1);
	else
		fmt_put(t, "\r\n", 2);
}

static void fmt_sep(struct fmt_table *t)
{
	if (t->col++ == 0)
		return;
	fmt_put(t, t->kind == FMT_CSV ? "," : "\t", 1);
}

/* csv: RFC 4180 quoting; txt: TAB/CR/LF in the value -> one space */
static void fmt_value(struct fmt_table *t, const char *s, int n)
{
	int i, needs_quote = 0;

	if (t->kind == FMT_TXT) {
		for (i = 0; i < n; i++) {
			char c = s[i];
			if (c == '\t' || c == '\r' || c == '\n')
				c = ' ';
			fmt_put(t, &c, 1);
		}
		return;
	}
	for (i = 0; i < n; i++)
		if (s[i] == ',' || s[i] == '"' || s[i] == '\r' || s[i] == '\n') {
			needs_quote = 1;
			break;
		}
	if (!needs_quote) {
		fmt_put(t, s, n);
		return;
	}
	fmt_put(t, "\"", 1);
	for (i = 0; i < n; i++) {
		if (s[i] == '"')
			fmt_put(t, "\"\"", 2);
		else
			fmt_put(t, &s[i], 1);
	}
	fmt_put(t, "\"", 1);
}

void fmt_str(struct fmt_table *t, const char *s, int n)
{
	fmt_sep(t);
	fmt_value(t, s, n);
}

void fmt_int(struct fmt_table *t, long long v)
{
	char num[24];
	fmt_sep(t);
	fmt_put(t, num, snprintf(num, sizeof(num), "%lld", v));
}

void fmt_empty(struct fmt_table *t)
{
	fmt_sep(t);
}

void fmt_end_record(struct fmt_table *t)
{
	fmt_eol(t);
	t->col = 0;
}

int fmt_init(struct fmt_table *t, int kind, int eol_lf, int header,
	const char **cols, int ncols)
{
	int i;
	memset(t, 0, sizeof(*t));
	t->kind = kind;
	t->eol_lf = eol_lf;
	if (!header)
		return 0;
	if (kind == FMT_TXT)
		fmt_put(t, "# ", 2);
	for (i = 0; i < ncols; i++) {
		if (i)
			fmt_put(t, kind == FMT_CSV ? "," : "\t", 1);
		fmt_put(t, cols[i], (int)strlen(cols[i]));
	}
	fmt_end_record(t);
	t->col = 0;
	return t->oom ? -1 : 0;
}

char *fmt_take(struct fmt_table *t, int *out_len)
{
	char *b;
	if (t->oom) {
		free(t->buf);
		t->buf = NULL;
		return NULL;
	}
	b = t->buf ? t->buf : strdup("");
	if (out_len)
		*out_len = t->len;
	t->buf = NULL;
	return b;
}

void fmt_free(struct fmt_table *t)
{
	free(t->buf);
	t->buf = NULL;
	t->len = t->cap = 0;
}

int cdbn_fmt_kind_parse(const char *v, int n)
{
	if (n == 4 && memcmp(v, "json", 4) == 0) return FMT_JSON;
	if (n == 3 && memcmp(v, "csv", 3) == 0)  return FMT_CSV;
	if (n == 3 && memcmp(v, "txt", 3) == 0)  return FMT_TXT;
	return -1;
}

/* One row per k=v option; a leading bare token is the format
 * kind shorthand ("csv;eol=lf" == "format=csv;eol=lf"). */
static int fmt_apply_kv(const char *k, int klen, const char *v, int vlen,
	int *kind, int *eol_lf, int *header)
{
	if (klen == 6 && memcmp(k, "format", 6) == 0) {
		int fk = cdbn_fmt_kind_parse(v, vlen);
		if (fk < 0)
			return -1;
		*kind = fk;
		return 0;
	}
	if (klen == 3 && memcmp(k, "eol", 3) == 0) {
		if (vlen == 2 && memcmp(v, "lf", 2) == 0)       *eol_lf = 1;
		else if (vlen == 4 && memcmp(v, "crlf", 4) == 0) *eol_lf = 0;
		else return -1;
		return 0;
	}
	if (klen == 6 && memcmp(k, "header", 6) == 0) {
		if (vlen == 1 && (*v == '0' || *v == '1')) *header = *v - '0';
		else return -1;
		return 0;
	}
	return -1;              /* unknown option: reject */
}

int cdbn_fmt_opts_parse(const char *s, int len,
	int *kind, int *eol_lf, int *header)
{
	const char *p = s, *end = s + len;
	int first = 1;

	*kind = FMT_JSON; *eol_lf = 0; *header = 1;

	while (p < end) {
		const char *tok = p, *eq, *te;
		while (p < end && *p != ';')
			p++;
		te = p;
		if (p < end)
			p++;
		while (tok < te && (*tok == ' ' || *tok == '\t')) tok++;
		while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) te--;
		if (tok == te)
			continue;
		for (eq = tok; eq < te && *eq != '='; eq++)
			;
		if (eq == te) {
			int k;
			if (!first)
				return -1;                 /* bare kind only leads */
			k = cdbn_fmt_kind_parse(tok, (int)(te - tok));
			if (k < 0)
				return -1;
			*kind = k;
		} else if (fmt_apply_kv(tok, (int)(eq - tok),
				eq + 1, (int)(te - eq - 1),
				kind, eol_lf, header) < 0) {
			return -1;
		}
		first = 0;
	}
	return 0;
}
