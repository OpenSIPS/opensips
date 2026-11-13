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
 * Registration-observability MI: the nats_reg_list filter language and
 * the per-contact state model.
 *
 * Operators drive the list command with ONE string parameter of
 * ';'-separated key=value pairs (avoids MI recipe explosion, stays typable):
 *
 *   aor=<glob>            fnmatch(3) over the DECODED AoR
 *   domain=<host>         case-insensitive exact match on the part after
 *                         the LAST '@' (SIP hosts compare case-insensitively);
 *                         rows without '@' match domain=(none)
 *   ua=<substr>           substring over the contact's raw user_agent value
 *   contact=<substr>      substring over the contact URI value
 *   state=active|expired|permanent|all     (default active = would be served)
 *   expiring_within=<s>   at least one contact with 0 < expires-now <= s
 *   min_contacts=<n>      stored contacts >= n
 *   sort=aor|expiry|contacts|last_mod      (+ desc=1)
 *   limit=<n> (default 50, HARD CAP 200 -- MI datagram size)  offset=<n>
 *
 * Contact state mirrors the read filter exactly:
 *   permanent: expires == 0
 *   active:    expires + grace >  now   (would be served)
 *   expired:   expires + grace <= now   (stored-but-hidden: lingering or
 *                                        awaiting the reaper)
 * Unknown keys / malformed values REFUSE the command (fail loudly, never
 * silently list the wrong subset).
 *
 * Runs on the production code (carried copies and the variant
 * build are gone).
 */
#include <tap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fnmatch.h>
#include "../cachedb_nats_reg.h"

#include "cn_ut.h"

#define CHECK(cond, msg) do { if (!(cond)) { fail("reg_filter: %s", msg); } \
	else pass("reg_filter: %s", msg); } while (0)

void cn_ut_reg_filter(void)
{
	struct reg_filter f;
	const time_t NOW = 1000000;
	const int G = 5;

	diag("contact state mirrors the read filter (grace, never linger):");
	CHECK(cdbn_reg_contact_state(0, NOW, G) == REG_C_PERMANENT, "expires=0 => permanent");
	CHECK(cdbn_reg_contact_state(NOW + 100, NOW, G) == REG_C_ACTIVE, "future => active");
	CHECK(cdbn_reg_contact_state(NOW - 2, NOW, G) == REG_C_ACTIVE,
	      "within grace => STILL active (served)");
	CHECK(cdbn_reg_contact_state(NOW - 5, NOW, G) == REG_C_EXPIRED,
	      "exactly expires+grace==now => expired (boundary)");
	CHECK(cdbn_reg_contact_state(NOW - 500, NOW, G) == REG_C_EXPIRED, "long past => expired");

	diag("domain = after the LAST '@', case-insensitive compare:");
	{
		const char *d; int dl;
		CHECK(cdbn_reg_domain_of("alice@example.com", 17, &d, &dl) == 0 &&
		      dl == 11 && memcmp(d, "example.com", 11) == 0, "user@host => host");
		CHECK(cdbn_reg_domain_of("we@ird@example.com", 18, &d, &dl) == 0 &&
		      dl == 11 && memcmp(d, "example.com", 11) == 0,
		      "'@' in user part: LAST '@' wins");
		CHECK(cdbn_reg_domain_of("nodomain", 8, &d, &dl) == -1, "no '@' => no domain");
		CHECK(cdbn_reg_domain_of("trailing@", 9, &d, &dl) == 0 && dl == 0,
		      "trailing '@' => empty domain (matches nothing)");
		CHECK(cdbn_reg_ci_eq("Example.COM", 11, "example.com", 11) == 1,
		      "SIP hosts compare case-insensitively");
		CHECK(cdbn_reg_ci_eq("example.com", 11, "example.co", 10) == 0,
		      "length mismatch never equal");
	}

	diag("filter parse — defaults and happy path:");
	CHECK(cdbn_reg_filter_parse("", 0, &f) == 0 && f.state == REG_F_ACTIVE &&
	      f.limit == REG_LIMIT_DEFAULT && f.offset == 0 && f.sort == REG_SORT_AOR,
	      "empty filter => defaults (state=active, limit=50, sort=aor)");
	{
		const char *q = "domain=Example.COM; state=all ;sort=expiry;desc=1;limit=10;offset=20";
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.domain, "Example.COM") == 0 && f.state == REG_F_ALL &&
		      f.sort == REG_SORT_EXPIRY && f.desc == 1 &&
		      f.limit == 10 && f.offset == 20,
		      "full filter round-trips (spaces around tokens tolerated)");
	}
	{
		const char *q = "ua=friendly panda 1.2;aor=*@example.com";
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.ua, "friendly panda 1.2") == 0 &&
		      strcmp(f.aor_glob, "*@example.com") == 0,
		      "spaces INSIDE a value survive (';' is the separator)");
		CHECK(fnmatch(f.aor_glob, "bob@example.com", 0) == 0,
		      "aor glob is fnmatch semantics");
		CHECK(fnmatch(f.aor_glob, "bob@other.net", 0) != 0,
		      "glob rejects non-matching AoR");
	}
	{
		const char *q = "aor=lit\\=eral";   /* '=' inside a value */
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      strcmp(f.aor_glob, "lit\\=eral") == 0,
		      "first '=' splits key/value; later '=' belongs to the value");
	}
	CHECK(cdbn_reg_filter_parse(";;", 2, &f) == 0, "empty tokens (';;') tolerated");

	diag("filter parse — fail loudly, never list the wrong subset:");
	CHECK(cdbn_reg_filter_parse("bogus=1", 7, &f) == -1, "unknown key => refused");
	CHECK(cdbn_reg_filter_parse("state=zombie", 12, &f) == -1, "bad enum value => refused");
	CHECK(cdbn_reg_filter_parse("sort=up", 7, &f) == -1, "bad sort key => refused");
	CHECK(cdbn_reg_filter_parse("limit=abc", 9, &f) == -1, "non-numeric number => refused");
	CHECK(cdbn_reg_filter_parse("limit=0", 7, &f) == -1, "limit 0 => refused");
	CHECK(cdbn_reg_filter_parse("limit=-5", 8, &f) == -1, "negative limit => refused");
	CHECK(cdbn_reg_filter_parse("offset=-1", 9, &f) == -1, "negative offset => refused");
	CHECK(cdbn_reg_filter_parse("expiring_within=0", 17, &f) == -1,
	      "expiring_within=0 => refused (meaningless)");
	CHECK(cdbn_reg_filter_parse("domain=", 7, &f) == -1, "empty value => refused");
	CHECK(cdbn_reg_filter_parse("=x", 2, &f) == -1, "empty key => refused");
	CHECK(cdbn_reg_filter_parse("aor", 3, &f) == -1, "token without '=' => refused");
	{
		/* an MI string may carry \u0000; the value would be cut at it */
		static const char nd[] = "domain=ex\0ample.com";
		static const char na[] = "aor=*@a\0";
		static const char nl[] = "limit=5\0junk";
		static const char nf[] = "format=\0json";
		CHECK(cdbn_reg_filter_parse(nd, (int)sizeof nd - 1, &f) == -1,
		      "an embedded NUL in a string value => refused (would filter on \"ex\")");
		CHECK(cdbn_reg_filter_parse(na, (int)sizeof na - 1, &f) == -1,
		      "an embedded NUL ending a glob => refused");
		CHECK(cdbn_reg_filter_parse(nl, (int)sizeof nl - 1, &f) == -1,
		      "an embedded NUL in a number => refused (would read 5)");
		CHECK(cdbn_reg_filter_parse(nf, (int)sizeof nf - 1, &f) == -1,
		      "an embedded NUL in a format value => refused");
	}

	diag("limit hard cap (MI datagram size):");
	CHECK(cdbn_reg_filter_parse("limit=200", 9, &f) == 0 && f.limit == 200,
	      "limit=200 (the cap) accepted verbatim");
	CHECK(cdbn_reg_filter_parse("limit=100000", 12, &f) == 0 && f.limit == 200,
	      "limit above the cap CLAMPS to 200 (not an error)");

	diag("output-format keys in the filter language:");
	CHECK(cdbn_reg_filter_parse("", 0, &f) == 0 && f.format == 0 &&
	      f.eol_lf == 0 && f.header == 1,
	      "defaults: json, CRLF, header on");
	{
		const char *q = "format=csv;eol=lf;header=0;sort=expiry";
		CHECK(cdbn_reg_filter_parse(q, (int)strlen(q), &f) == 0 &&
		      f.format == 1 && f.eol_lf == 1 && f.header == 0 &&
		      f.sort == REG_SORT_EXPIRY,
		      "format/eol/header compose with the other keys");
	}
	CHECK(cdbn_reg_filter_parse("format=txt", 10, &f) == 0 && f.format == 2,
	      "format=txt accepted");
	CHECK(cdbn_reg_filter_parse("format=cvs", 10, &f) == -1,
	      "typo'd format REFUSED (never silently json)");
	CHECK(cdbn_reg_filter_parse("eol=cr", 6, &f) == -1, "bad eol refused");
	CHECK(cdbn_reg_filter_parse("header=2", 8, &f) == -1, "bad header refused");

	diag("oversize values are refused, not truncated:");
	{
		char big[600];
		memset(big, 'a', sizeof(big));
		memcpy(big, "aor=", 4);
		CHECK(cdbn_reg_filter_parse(big, (int)sizeof(big), &f) == -1,
		      "256+ byte glob => refused (silent truncation would mis-filter)");
	}
}
