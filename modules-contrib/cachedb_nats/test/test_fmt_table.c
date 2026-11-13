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
 *: the pure table formatter behind
 * format=csv / format=txt on the MI commands, plus the format
 * option parsing (bare "csv" or "csv;eol=lf;header=0").
 *
 *   csv  RFC 4180: CRLF records, header first, fields containing comma /
 *        quote / CR / LF are double-quoted with quotes doubled; values are
 *        otherwise VERBATIM (backslashes are not special in CSV).
 *   txt  TAB-separated, CRLF, "# "-prefixed header; TAB/CR/LF INSIDE a
 *        value become one space (documented lossy).
 *   eol=lf switches both to bare LF; header=0 drops the header record.
 *   Unknown format/eol/header values are REFUSED (fail loud, FMT-4).
 *
 * On the production formatter (cachedb_nats_fmt.c); the FMT_CURRENT naive
 * model is gone.  Added: the option string ends at its length.
 */
#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../cachedb_nats_fmt.h"

#include "cn_ut.h"

/* ─── harness ─────────────────────────────────────────────────────── */

#define CHECK(cond, msg) do { if (!(cond)) { fail("fmt_table: %s", msg); } \
	else pass("fmt_table: %s", msg); } while (0)
#define BLOB_IS(want, msg) do { \
	int _l; char *_b = fmt_take(&t, &_l); \
	if (!_b || strcmp(_b, want) != 0) { \
		fail("fmt_table: %s (got len %d, want len %d)", msg, \
			_b ? _l : -1, (int)strlen(want)); \
	} else pass("fmt_table: %s", msg); \
	free(_b); \
} while (0)

void cn_ut_fmt_table(void)
{
	struct fmt_table t;
	static const char *C3[] = {"aor", "contacts", "ua"};

	diag("csv basics: header, CRLF, plain fields:");
	fmt_init(&t, FMT_CSV, 0, 1, C3, 3);
	fmt_str(&t, "alice@x", 7); fmt_int(&t, 2); fmt_str(&t, "sipsak", 6);
	fmt_end_record(&t);
	BLOB_IS("aor,contacts,ua\r\nalice@x,2,sipsak\r\n",
		"header + record, CRLF-terminated");

	diag("csv quoting matrix:");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "a,b", 3); fmt_int(&t, 1); fmt_str(&t, "say \"hi\"", 8);
	fmt_end_record(&t);
	BLOB_IS("\"a,b\",1,\"say \"\"hi\"\"\"\r\n",
		"comma quoted; quotes doubled (header=0)");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "evil\r\nua", 8); fmt_int(&t, 1); fmt_str(&t, "back\\slash", 10);
	fmt_end_record(&t);
	BLOB_IS("\"evil\r\nua\",1,back\\slash\r\n",
		"embedded CRLF quoted VERBATIM; backslash NOT special");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "lf\nonly", 7); fmt_int(&t, 1); fmt_str(&t, "cr\ronly", 7);
	fmt_end_record(&t);
	BLOB_IS("\"lf\nonly\",1,\"cr\ronly\"\r\n",
		"a bare LF and a bare CR each force quoting");

	diag("txt: TAB join, '# ' header, sanitization:");
	fmt_init(&t, FMT_TXT, 0, 1, C3, 3);
	fmt_str(&t, "alice@x", 7); fmt_int(&t, 2); fmt_str(&t, "tab\there", 8);
	fmt_end_record(&t);
	BLOB_IS("# aor\tcontacts\tua\r\nalice@x\t2\ttab here\r\n",
		"TAB-separated, TAB-in-value becomes a space");
	fmt_init(&t, FMT_TXT, 0, 0, C3, 3);
	fmt_str(&t, "cr\rlf\n", 6); fmt_int(&t, 0); fmt_empty(&t);
	fmt_end_record(&t);
	BLOB_IS("cr lf \t0\t\r\n",
		"CR/LF in value sanitized; empty field renders empty");

	diag("eol=lf:");
	fmt_init(&t, FMT_CSV, 1, 1, C3, 3);
	fmt_str(&t, "a", 1); fmt_int(&t, 1); fmt_empty(&t);
	fmt_end_record(&t);
	BLOB_IS("aor,contacts,ua\na,1,\n", "csv with bare-LF records");

	diag("empty optional fields (never null/sentinel):");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "b@x", 3); fmt_empty(&t); fmt_empty(&t);
	fmt_end_record(&t);
	BLOB_IS("b@x,,\r\n", "csv empty fields are just separators");

	diag("option parsing:");
	{
		int k, e, h;
		CHECK(cdbn_fmt_opts_parse("csv", 3, &k, &e, &h) == 0 &&
		      k == FMT_CSV && e == 0 && h == 1,
		      "bare 'csv' => csv, CRLF, header (the defaults)");
		CHECK(cdbn_fmt_opts_parse("txt;eol=lf;header=0", 19, &k, &e, &h) == 0 &&
		      k == FMT_TXT && e == 1 && h == 0,
		      "'txt;eol=lf;header=0' fully parsed");
		CHECK(cdbn_fmt_opts_parse("format=csv;header=0", 19, &k, &e, &h) == 0 &&
		      k == FMT_CSV && h == 0,
		      "'format=csv;header=0' long form accepted");
		CHECK(cdbn_fmt_opts_parse("json", 4, &k, &e, &h) == 0 && k == FMT_JSON,
		      "explicit 'json' accepted");
		CHECK(cdbn_fmt_opts_parse("", 0, &k, &e, &h) == 0 && k == FMT_JSON,
		      "empty => json default");
		CHECK(cdbn_fmt_opts_parse("cvs", 3, &k, &e, &h) == -1,
		      "typo'd 'cvs' REFUSED (never silently json)");
		CHECK(cdbn_fmt_opts_parse("csv;eol=bogus", 13, &k, &e, &h) == -1,
		      "bad eol value refused");
		CHECK(cdbn_fmt_opts_parse("csv;header=2", 12, &k, &e, &h) == -1,
		      "bad header value refused");
		CHECK(cdbn_fmt_opts_parse("eol=lf;csv", 10, &k, &e, &h) == -1,
		      "bare kind only allowed as the FIRST token");
		CHECK(cdbn_fmt_opts_parse("csv;wat=1", 9, &k, &e, &h) == -1,
		      "unknown option key refused");
		CHECK(cdbn_fmt_opts_parse("csv;header=0", 3, &k, &e, &h) == 0 &&
		      k == FMT_CSV && h == 1,
		      "options past the length are not read ('csv' of 'csv;header=0')");
		CHECK(cdbn_fmt_opts_parse("csv;eol=bogus", 3, &k, &e, &h) == 0,
		      "a bad option past the length is not seen");
	}
}
