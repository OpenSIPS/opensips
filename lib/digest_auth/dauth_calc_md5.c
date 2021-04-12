/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2013 OpenSIPS Solutions
 * Copyright (C) 2020 Maksym Sobolyev
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * Registrant OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ctype.h>
#include <string.h>

#include "../../str.h"
#include "../../md5global.h"
#include "../../md5.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/dassert.h"

#include "dauth_calc_md5.h"
#include "digest_auth.h"
#include "dauth_calc.h"
#include "dauth_hexops.h"

/*
 * calculate H(A1)
 */
static int digest_calc_HA1(const struct digest_auth_credential *crd,
    HASHHEX *sess_key)
{
	MD5_CTX Md5Ctx;
	HASH_MD5 HA1;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, crd->user.s, crd->user.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->realm.s, crd->realm.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->passwd.s, crd->passwd.len);
	MD5Final(HA1, &Md5Ctx);
	cvt_hex128(HA1, sess_key->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);

	return 0;
}

static int digest_calc_HA1sess(const str_const *nonce, const str_const *cnonce,
    HASHHEX *sess_key)
{
	MD5_CTX Md5Ctx;
	HASH_MD5 HA1;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, sess_key->MD5, HASHHEXLEN_MD5);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, nonce->s, nonce->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
	MD5Final(HA1, &Md5Ctx);
	cvt_hex128(HA1, sess_key->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);
	return 0;
}

/*
 * calculate H(A2)
 */
static int digest_calc_HA2(const str_const *msg_body, const str_const *method,
    const str_const *uri, int auth_int, HASHHEX *HA2Hex)
{
	MD5_CTX Md5Ctx;
	HASH_MD5 HA2;
	HASH_MD5 HENTITY;
	HASHHEX_MD5 HENTITYHex;

	if (auth_int) {
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, msg_body->s, msg_body->len);
		MD5Final(HENTITY, &Md5Ctx);
		cvt_hex128(HENTITY, HENTITYHex, HASHLEN_MD5, HASHHEXLEN_MD5);
	}

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, method->s, method->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, uri->s, uri->len);

	if (auth_int)
	{
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, HENTITYHex, HASHHEXLEN_MD5);
	};

	MD5Final(HA2, &Md5Ctx);
	cvt_hex128(HA2, HA2Hex->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);
	return 0;
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
static int _digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	MD5_CTX Md5Ctx;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, ha1->MD5, HASHHEXLEN_MD5);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, nonce->s, nonce->len);
	MD5Update(&Md5Ctx, ":", 1);

	if (qop_val && qop_val->s && qop_val->len != 0)
	{
		MD5Update(&Md5Ctx, nc->s, nc->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, qop_val->s, qop_val->len);
		MD5Update(&Md5Ctx, ":", 1);
	};
	MD5Update(&Md5Ctx, ha2->MD5, HASHHEXLEN_MD5);
	MD5Final(response->RespHash.MD5, &Md5Ctx);
	return 0;
}

static int digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	int rval;

	rval = _digest_calc_response(ha1, ha2, nonce, qop_val, nc, cnonce, response);
	response->digest_calc = &md5_digest_calc;
	return rval;
}

static int digest_calc_response_s(const HASHHEX *ha1, const HASHHEX *ha2,
    const str_const *nonce, const str_const *qop_val, const str_const *nc,
    const str_const *cnonce, struct digest_auth_response *response)
{
	int rval;

	rval = _digest_calc_response(ha1, ha2, nonce, qop_val, nc, cnonce, response);
	response->digest_calc = &md5sess_digest_calc;
	return rval;
}

static char *response_hash_fill(const struct digest_auth_response *response, char *hex, int len)
{
	DASSERT(len >= HASHHEXLEN_MD5);

	cvt_hex128(response->RespHash.MD5, hex, HASHLEN_MD5, HASHHEXLEN_MD5);
	return hex;
}

static int response_hash_bcmp(const struct digest_auth_response *response, const str_const *hex)
{
	if (hex->len != HASHHEXLEN_MD5)
		return 1;

	return bcmp_hex128(response->RespHash.MD5, hex->s, HASHLEN_MD5);
}

const struct digest_auth_calc md5_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA1sess = NULL,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.response_hash_bcmp = response_hash_bcmp,
	.response_hash_fill = response_hash_fill,
	.algorithm_val = str_const_init(ALG_MD5_STR),
	.HASHLEN = HASHLEN_MD5,
	.HASHHEXLEN = HASHHEXLEN_MD5
};

const struct digest_auth_calc md5sess_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA1sess = digest_calc_HA1sess,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response_s,
	.response_hash_bcmp = response_hash_bcmp,
	.response_hash_fill = response_hash_fill,
	.algorithm_val = str_const_init(ALG_MD5SESS_STR),
	.HASHLEN = HASHLEN_MD5,
	.HASHHEXLEN = HASHHEXLEN_MD5
};
