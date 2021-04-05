/*
 * Copyright (C) 2020 Maksym Sobolyev
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

#include "../../parser/parse_authenticate.h"

#include "test_parse_authenticate_body.h"
#include "test_oob.h"

void test_parse_authenticate_body_oob(const str *, enum oob_position where, void *);

static const struct tts {
	const str ts;
	int tres;
	int aflags;
	const char *anonce;
	const char *aopaque;
	const char *arealm;
	alg_t aalg;
} tset[] = {
	{
	/* Case #1 */
		.ts = str_init("Digest realm=\"VoIPTests.Net\",nonce=\"ak/bKmGcoPPWdj0AUWv/ldViLInmkiJ2Kct5p/LapNo\","
                               "qop=auth,algorithm=SHA-512-256"),
		.tres = 0,
		.aflags = QOP_AUTH, .aalg = ALG_SHA512_256, .anonce = "ak/bKmGcoPPWdj0AUWv/ldViLInmkiJ2Kct5p/LapNo",
		.arealm = "VoIPTests.Net"
	}, {
	/* Case #2 */
		.ts = str_init("Digest realm=\"[::1]\",nonce=\"kp5XbciCMxVbeZm2d58YZCfaAjW/2T7XtuYwIeZoz1o\","
                               "qop=auth,algorithm=SHA-256"),
		.tres = 0,
		.aflags = QOP_AUTH, .aalg = ALG_SHA256, .anonce = "kp5XbciCMxVbeZm2d58YZCfaAjW/2T7XtuYwIeZoz1o",
		.arealm = "[::1]"
	}, {
	/* Case #3 */
		.ts = str_init("Digest stale=false,realm=\"[::1]\",nonce=\"esWk1wFa4bUBKzkmfKId++Y83eWzD9edBCGTwLV4Juk\","
                               "qop=auth,algorithm=MD5"),
		.tres = 0,
		.aflags = QOP_AUTH, .aalg = ALG_MD5, .anonce = "esWk1wFa4bUBKzkmfKId++Y83eWzD9edBCGTwLV4Juk",
		.arealm = "[::1]"
	}, {
	/* Case #4 */
		.ts = str_init("Digest realm=\"sip.test.com\",qop=\"auth\",opaque=\"1234567890abcedef\","
		               "nonce=\"145f5ca9aac6f0b9f93433188d446ae0d9f91a6ff80\",algorithm=MD5,stale=true"),
		.tres = 0,
		.aflags = QOP_AUTH | AUTHENTICATE_STALE, .aalg = ALG_MD5,
		.anonce = "145f5ca9aac6f0b9f93433188d446ae0d9f91a6ff80", .aopaque = "1234567890abcedef",
		.arealm = "sip.test.com"
	}, {
	/* Case #5 */
		.ts = str_init("DiGeSt\r\n\trealm=\"a\",\r\n\tqop=\"auth-int, auth\",\r\n\tnonce=\"n\",\r\n\topaque=\"0\",\r\n\t"
                               "algoriTHm=md5"),
		.tres = 0,
		.aflags = QOP_AUTH | QOP_AUTH_INT, .aalg = ALG_MD5,
		.anonce = "n", .aopaque = "0", .arealm = "a"
	} , {
	/* Case #6 */
		.ts = str_init("Digest realm=\"VoIPTests.NET\", nonce=\"gyGiv8LUr3U5ZQaRyzGsfcfGbLCraorDgEvUzk1WlSUA\","
			       " qop=\"auth,auth-int\", algorithm=SHA-256\nsess"),
		.tres = -1,
	} , {
	/* Case #7 */
		.ts = str_init("Digest realm=\"whocares?\", nonce=\"NonSense\","
			       " qop=\"auth,auth-int\", algorithm=CHACHA123"),
		.tres = -1,
	}, {}
};


void test_parse_authenticate_body(void)
{
	struct authenticate_body auth;
	int i, rval;

	for (i = 0; tset[i].ts.s != NULL; i++) {
		memset(&auth, 0, sizeof(struct authenticate_body));
		rval = parse_authenticate_body(tset[i].ts, &auth);
		ok(rval == tset[i].tres, "parse_authenticate_body(\"%s\") == %d, actual %d",
		    tset[i].ts.s, tset[i].tres, rval);
		if (tset[i].tres == 0 && rval == 0) {
			ok(auth.flags == tset[i].aflags, "auth.flags == %d", tset[i].aflags);
			ok(auth.algorithm == tset[i].aalg, "auth.algorithm == %d", tset[i].aalg);
			ok(auth.nonce.len == strlen(tset[i].anonce) &&
			    memcmp(auth.nonce.s, tset[i].anonce, auth.nonce.len) == 0,
			    "verify nonce");
			ok((tset[i].aopaque == NULL && auth.opaque.s == NULL) ||
			    (auth.opaque.len == strlen(tset[i].aopaque) &&
			    memcmp(auth.opaque.s, tset[i].aopaque, auth.opaque.len) == 0),
			    "verify opaque");
			ok(auth.realm.len == strlen(tset[i].arealm) &&
                            memcmp(auth.realm.s, tset[i].arealm, auth.realm.len) == 0,
                            "verify realm");
		}
		test_oob(&tset[i].ts, test_parse_authenticate_body_oob, &auth);
	}
}

void test_parse_authenticate_body_oob(const str *tstr, enum oob_position where, void *farg)
{
	struct authenticate_body *ap = farg;

	parse_authenticate_body(*tstr, ap);
	ok(1, OOB_CHECK_OK_MSG("parse_authenticate_body", tstr, where));
}
