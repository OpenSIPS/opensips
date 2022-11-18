/*
 * Copyright (C) 2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <tap.h>

#include "../../str.h"
#include "../../ut.h"

#include "../../parser/digest/digest.h"
#include "../../lib/digest_auth/digest_auth.h"
#include "../../lib/digest_auth/dauth_nonce.h"
#include "../../lib/digest_auth/dauth_calc.h"
#include "../../lib/digest_auth/dauth_hexops.h"

// not fully functional yet: also see TODO from Makefile.test
#if 0

static const struct digest_auth_credential crd = {
	.realm = str_init("opensips.org"),
	.user = str_init("opensips"),
	.passwd = str_init("OpenSIPSrulz"),
};

static char *hnt(HASHHEX ha)
{
	static char _buf[HASHHEXLEN_SHA256 + 1];
	memcpy(_buf, ha.SHA256, HASHHEXLEN_SHA256);
	return _buf;
}

static void test_digest_auth_sha256(void)
{
	str uri;
	HASHHEX ha1, ha1s, ha2, ha2b, r, rn;
	struct digest_auth_response resp;

	const struct digest_auth_calc *digest_calc = get_digest_calc(ALG_SHA256);
	ok(digest_calc != NULL, "digest_auth:sha256: digest_calc");

	ok(digest_calc->HA1(&crd, &ha1) == 0, "digest_auth:sha256: digest_calc_HA1");

	is(hnt(ha1), "bd56ee2223d0deb965b2b7fbe7da478d94f0f7ba7ef2a69f11a7ea1ae8ab44fd",
			"digest_auth:sha256: digest_calc_HA1 test");

	if (digest_calc->HA1sess != NULL) {
		ok(digest_calc->HA1sess(const_str("nonce"), const_str("cnonce"), &ha1s) == 0,
				"digest_auth:sha256: digest_calc_HA1sess");

		is(hnt(ha1s), "290d6f165a08f745714829cd80f1ac346ae42336a94fa3e40944e117df526ef6",
				"digest_auth:sha256: digest_calc_HA1sess test");
	}

	uri.s = pkg_malloc(4 /* sip: */ + crd.user.len + 1 /* @ */ + crd.realm.len);
	ok(uri.s != NULL, "digest_auth:sha256: digest uri");
	uri.len = 0;
	memcpy(uri.s + uri.len, "sip:", 4);
	uri.len += 4;
	memcpy(uri.s + uri.len, crd.user.s, crd.user.len);
	uri.len = crd.user.len;
	memcpy(uri.s + uri.len, "@", 1);
	uri.len += 1;
	memcpy(uri.s + uri.len, crd.realm.s, crd.realm.len);
	uri.len = crd.realm.len;

	ok(digest_calc->HA2(NULL, const_str("REGISTER"), str2const(&uri), 0, &ha2) == 0,
			"digest_auth:sha256: digest_calc_HA2");
	is(hnt(ha2), "6ad7e6d1d8d116d8e2129841e23c692b826ac61d1fe26570d16b565d91bf6afe",
			"digest_auth:sha256: digest_calc_HA2 test");

	ok(digest_calc->HA2(const_str("BODY"), const_str("REGISTER"), str2const(&uri), 1, &ha2b) == 0,
			"digest_auth:sha256: digest_calc_HA2 body");
	is(hnt(ha2b), "956a503371a4a6d6933a87ac8da296df9e134376126e1a507bfd0684c156e57a",
			"digest_auth:sha256: digest_calc_HA2 body test");

	ok(digest_calc->response(&ha1, &ha2, const_str("nonce"), NULL, NULL, NULL, &resp) == 0,
			"digest_auth:sha256: digest_response");
	cvt_hex128(resp.RespHash.SHA256, r.SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
	is(hnt(r), "002c411b7f29def0b4cea36bdc483131a973357bdd0848a53e58188b9d83e406",
			"digest_auth:sha256: digest_response test");

	ok(digest_calc->response(&ha1, &ha2, const_str("nonce"), const_str("nonce"),
				const_str("qop"), const_str("nc"), &resp) == 0,
			"digest_auth:sha256: digest_response qop");
	cvt_hex128(resp.RespHash.SHA256, rn.SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
	is(hnt(rn), "2d8111a7ea6af6c98f6eef175e19612eb5afde8aee0561ab98c5e2c418e396b7",
			"digest_auth:sha256: digest_response qop test");
}

void test_lib_digest_auth(void)
{
	test_digest_auth_sha256();
}
#endif
