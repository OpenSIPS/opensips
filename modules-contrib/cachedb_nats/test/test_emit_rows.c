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
 * The row emitter behind the/
 * MI handlers.  One walk per handler; the backend decides whether a row
 * becomes a JSON-MI object or a csv/txt table record.  This test locks the
 * TABLE backend and the dispatch surface on the production emitter:
 *
 *   - nats_emit_open_fmt + rec/str/i64/absent/lit/end -> exact csv/txt bytes
 *     (RFC 4180 quoting, txt TAB/CR/LF sanitization, header/eol options),
 *   - `absent` renders an EMPTY cell (json would omit the field),
 *   - `lit` renders a table-structural cell (json ignores it),
 *   - i64 at the LLONG_MIN/LLONG_MAX boundaries,
 *   - adversarial values: separators, quotes, CRLF, backslash, empty,
 *   - abort mid-table releases the buffer (buffer gone and zeroed; the
 *     ASan leak check is lost).
 *
 * The MI (json) backend is covered by the MI tests.
 */
#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "../cachedb_nats_fmt.h"
#include "../cachedb_nats_emit.h"

#include "cn_ut.h"


#define CHECK(cond, msg) do { if (!(cond)) { fail("emit_rows: %s", msg); } \
	else pass("emit_rows: %s", msg); } while (0)
#define BLOB_IS(e, want, msg) do { \
	int _l; char *_b = nats_emit_take(e, &_l); \
	if (!_b || strcmp(_b, want) != 0 || _l != (int)strlen(want)) { \
		fail("emit_rows: %s (got len %d, want len %d)", msg, \
			_b ? _l : -1, (int)strlen(want)); \
	} else pass("emit_rows: %s", msg); \
	free(_b); \
} while (0)

void cn_ut_emit_rows(void)
{
	struct nats_emit e;
	static const char *C3[] = {"aor", "contacts", "last_mod"};
	static const char *C2[] = {"scope", "domain"};

	diag("csv walk: header, str/i64/absent, quoting through the emitter:");
	CHECK(nats_emit_open_fmt(&e, FMT_CSV, 0, 1, C3, 3) == 0 && e.table == 1,
	      "open_fmt(csv) selects the table backend");
	CHECK(nats_emit_rec(&e) == 0, "rec() begins a record");
	nats_emit_str(&e, "aor", 3, "a@x", 3);
	nats_emit_i64(&e, "contacts", 8, 2);
	nats_emit_absent(&e, "last_mod", 8);
	nats_emit_end(&e);
	nats_emit_rec(&e);
	nats_emit_str(&e, "aor", 3, "b,c", 3);          /* comma -> quoted */
	nats_emit_i64(&e, "contacts", 8, 1);
	nats_emit_i64(&e, "last_mod", 8, 7);
	nats_emit_end(&e);
	BLOB_IS(&e, "aor,contacts,last_mod\r\na@x,2,\r\n\"b,c\",1,7\r\n",
		"absent = empty cell; comma-field quoted; CRLF records");

	diag("lit = table-structural cell:");
	nats_emit_open_fmt(&e, FMT_CSV, 0, 1, C2, 2);
	nats_emit_rec(&e);
	nats_emit_lit(&e, "total", 5);
	nats_emit_absent(&e, "domain", 6);
	nats_emit_end(&e);
	BLOB_IS(&e, "scope,domain\r\ntotal,\r\n",
		"lit() lands in the table (json backend would drop it)");

	diag("txt sanitization + eol=lf through the emitter:");
	nats_emit_open_fmt(&e, FMT_TXT, 1, 1, C3, 3);
	nats_emit_rec(&e);
	nats_emit_str(&e, "aor", 3, "tab\there", 8);    /* TAB -> space */
	nats_emit_i64(&e, "contacts", 8, 0);
	nats_emit_str(&e, "last_mod", 8, "cr\rlf\n", 6);
	nats_emit_end(&e);
	BLOB_IS(&e, "# aor\tcontacts\tlast_mod\ntab here\t0\tcr lf \n",
		"txt: '# ' header, TAB/CR/LF in values become spaces, bare-LF eol");

	diag("adversarial values, header=0:");
	nats_emit_open_fmt(&e, FMT_CSV, 0, 0, C3, 3);
	nats_emit_rec(&e);
	nats_emit_str(&e, "aor", 3, "say \"hi\"", 8);   /* quotes doubled  */
	nats_emit_str(&e, "contacts", 8, "back\\slash", 10); /* verbatim   */
	nats_emit_str(&e, "last_mod", 8, "", 0);        /* empty value    */
	nats_emit_end(&e);
	nats_emit_rec(&e);
	nats_emit_str(&e, "aor", 3, "evil\r\nrow", 9);  /* CRLF quoted    */
	nats_emit_i64(&e, "contacts", 8, LLONG_MIN);
	nats_emit_i64(&e, "last_mod", 8, LLONG_MAX);
	nats_emit_end(&e);
	BLOB_IS(&e, "\"say \"\"hi\"\"\",back\\slash,\r\n"
		"\"evil\r\nrow\",-9223372036854775808,9223372036854775807\r\n",
		"quote-doubling, backslash NOT special, empty value, i64 bounds");

	diag("empty table + take/abort hygiene:");
	nats_emit_open_fmt(&e, FMT_CSV, 0, 0, C3, 3);
	BLOB_IS(&e, "", "no records + header=0 -> empty (non-NULL) blob");
	nats_emit_open_fmt(&e, FMT_TXT, 0, 1, C2, 2);
	BLOB_IS(&e, "# scope\tdomain\r\n", "no records -> header-only blob");
	nats_emit_open_fmt(&e, FMT_CSV, 0, 1, C3, 3);
	nats_emit_rec(&e);
	nats_emit_str(&e, "aor", 3, "half-emitted", 12);
	nats_emit_abort(&e);
	CHECK(e.t.buf == NULL && e.t.len == 0 && e.t.cap == 0,
		"abort mid-record releases the buffer");

}
