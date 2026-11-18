/*
 * Copyright (C) 2026 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <tap.h>

#include "../../str.h"
#include "../../ut.h"

#include "../digest/digest_parser.h"

#include "test_oob.h"
#include "test_parse_digest.h"

static void test_parse_digest_cred_oob(const str *, enum oob_position, void *);

static int str_is(const str *s, const char *val)
{
	return s->len == strlen(val) && memcmp(s->s, val, s->len) == 0;
}

static int parse_cred(const char *hdr, dig_cred_t *cred)
{
	str body;

	init_str(&body, hdr);
	init_dig_cred(cred);
	return parse_digest_cred(&body, cred);
}

/* each one is also read with every prefix of it ending on a guard page, so
 * a parameter name cut short by the end of the body (no '=' after it, or
 * nothing at all after a trailing ',') must not be looked past */
static const str oob_tset[] = {
	str_init("Digest username=\"alice\", realm=\"example.com\", "
		"nonce=\"abc\", uri=\"sip:example.com\", response=\"0123\", "
		"algorithm=MD5, qop=auth, nc=00000001, cnonce=\"x\", opaque=\"o\""),
	str_init("Digest uri=sip:a,realm=r,nc=1,auts=z,algorithm=SHA-256"),
	str_init("Digest realm"),
	str_init("Digest a"),
	str_init("Digest uri=x,"),
	{NULL, 0}
};

void test_parse_digest(void)
{
	dig_cred_t cred;
	int i;

	ok(parse_cred("Digest username=\"alice@example.com\", realm=\"example.com\", "
		"nonce=\"abc\", uri=\"sip:example.com\", response=\"0123\", "
		"algorithm=MD5, qop=auth, nc=00000001, cnonce=\"x\", opaque=\"o\"",
		&cred) == 0 &&
		str_is(&cred.username.user, "alice") &&
		str_is(&cred.username.domain, "example.com") &&
		str_is(&cred.realm, "example.com") &&
		str_is(&cred.nonce, "abc") &&
		str_is(&cred.uri, "sip:example.com") &&
		str_is(&cred.response, "0123") &&
		cred.alg.alg_parsed == ALG_MD5 &&
		cred.qop.qop_parsed == QOP_AUTH_D &&
		str_is(&cred.nc, "00000001") &&
		str_is(&cred.cnonce, "x") &&
		str_is(&cred.opaque, "o"), "digest-1");
	ok(parse_cred("Digest uri=sip:a,realm=r,nc=1,auts=z,algorithm=SHA-256",
		&cred) == 0 &&
		str_is(&cred.uri, "sip:a") && str_is(&cred.realm, "r") &&
		str_is(&cred.nc, "1") && str_is(&cred.auts, "z") &&
		cred.alg.alg_parsed == ALG_SHA256, "digest-2");
	ok(parse_cred("Digest foo=bar, realm=\"r\"", &cred) == 0 &&
		str_is(&cred.realm, "r"), "digest-3");

	/* a parameter name with no value is rejected */
	ok(parse_cred("Digest realm", &cred) == -2, "digest-4");
	ok(parse_cred("Digest a", &cred) == -2, "digest-5");
	ok(parse_cred("Digest uri=x,", &cred) == -2, "digest-6");
	ok(parse_cred("Basic realm=\"r\"", &cred) == 1, "digest-7");

	for (i = 0; oob_tset[i].s != NULL; i++)
		test_oob(&oob_tset[i], test_parse_digest_cred_oob, &cred);
}

static void test_parse_digest_cred_oob(const str *tstr, enum oob_position where,
		void *farg)
{
	dig_cred_t *cred = farg;
	str body = *tstr;

	init_dig_cred(cred);
	parse_digest_cred(&body, cred);
	ok(1, OOB_CHECK_OK_MSG("parse_digest_cred", tstr, where));
}
